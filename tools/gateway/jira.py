"""Jira REST client — only the operations the Gateway needs.

Three entry points:
  find_open_ticket(dedup_key)     → existing ticket dict or None
  create_ticket(alert, dedup_key) → new Jira issue key (e.g. "SCDM-48")
  append_alert_occurrence(...)    → comment + bump Occurrence count / Last seen

Jira custom field IDs differ per instance — they come from env vars so this
code works against any Jira Cloud tenant without modification. Set:
  JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY, JIRA_ISSUE_TYPE
  JIRA_FIELD_SOURCE_SIEM, JIRA_FIELD_SOURCE_ALERT_ID, JIRA_FIELD_SEVERITY,
  JIRA_FIELD_ENTITIES, JIRA_FIELD_RAW_LINK, JIRA_FIELD_OCCURRENCE_COUNT,
  JIRA_FIELD_LAST_SEEN
"""
import base64
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from tools.gateway.schema import Alert
from tools.secrets import get_secret

log = logging.getLogger("gateway.jira")


@dataclass
class JiraFieldMap:
    """Custom field IDs in this Jira instance. All values come from env."""
    source_siem: str
    source_alert_id: str
    severity: str
    entities: str
    raw_link: str
    occurrence_count: str
    last_seen: str


class JiraError(RuntimeError):
    """Raised on any Jira HTTP failure. Caller translates to HTTP 502."""
    pass


class JiraClient:
    def __init__(self, base_url: str, email: str, token: str, project_key: str,
                 issue_type: str, fields: JiraFieldMap):
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        self.issue_type = issue_type
        self.fields = fields

        creds = base64.b64encode(f"{email}:{token}".encode("utf-8")).decode("ascii")
        self._headers = {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @classmethod
    def from_env(cls) -> "JiraClient":
        return cls(
            base_url=get_secret("JIRA_URL"),
            email=get_secret("JIRA_EMAIL"),
            token=get_secret("JIRA_API_TOKEN"),
            project_key=get_secret("JIRA_PROJECT_KEY") or "SOC",
            issue_type=get_secret("JIRA_ISSUE_TYPE") or "SOC Incident",
            fields=JiraFieldMap(
                source_siem      = get_secret("JIRA_FIELD_SOURCE_SIEM")      or "customfield_10100",
                source_alert_id  = get_secret("JIRA_FIELD_SOURCE_ALERT_ID")  or "customfield_10101",
                severity         = get_secret("JIRA_FIELD_SEVERITY")         or "customfield_10102",
                entities         = get_secret("JIRA_FIELD_ENTITIES")         or "customfield_10103",
                raw_link         = get_secret("JIRA_FIELD_RAW_LINK")         or "customfield_10104",
                occurrence_count = get_secret("JIRA_FIELD_OCCURRENCE_COUNT") or "customfield_10105",
                last_seen        = get_secret("JIRA_FIELD_LAST_SEEN")        or "customfield_10106",
            ),
        )

    # ── Find ────────────────────────────────────────────────────────────
    def find_open_ticket(self, dedup_key: str) -> Optional[dict]:
        """Return {'key': ..., 'occurrence_count': int} or None if no open match."""
        # JQL custom-field reference must use cf[NNNNN] shorthand. The string form
        # "customfield_NNNNN" (quoted) is silently treated as a non-match by Jira
        # Cloud's /search/jql endpoint — it returns 0 results without any error.
        field_num = self.fields.source_alert_id.replace("customfield_", "")
        jql = (
            f'project = {self.project_key} '
            f'AND cf[{field_num}] = "{dedup_key}" '
            f'AND resolution is EMPTY'
        )
        body = {
            "jql": jql,
            "maxResults": 1,
            "fields": [self.fields.occurrence_count, "summary"],
        }
        try:
            with httpx.Client(timeout=30) as http:
                # /rest/api/3/search was deprecated by Atlassian (returns 410 Gone). Use /search/jql.
                resp = http.post(f"{self.base_url}/rest/api/3/search/jql", headers=self._headers, json=body)
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise JiraError(f"Jira search failed: HTTP {e.response.status_code} — {e.response.text[:500]}") from e
        except httpx.HTTPError as e:
            raise JiraError(f"Jira search failed: {e}") from e

        issues = resp.json().get("issues") or []
        if not issues:
            return None

        issue = issues[0]
        count_field = issue.get("fields", {}).get(self.fields.occurrence_count)
        return {
            "key": issue["key"],
            "occurrence_count": int(count_field) if count_field else 1,
        }

    # ── Create ──────────────────────────────────────────────────────────
    def create_ticket(self, alert: Alert, dedup_key: str) -> str:
        """Create a new SOC Incident ticket. Returns the new Jira key."""
        payload = {
            "fields": {
                "project":   {"key": self.project_key},
                "summary":   f"[{alert.siem.upper()}] {alert.rule_id} — {alert.primary_entity}",
                "issuetype": {"name": self.issue_type},
                "description": _adf_description(alert),
                self.fields.source_siem:      {"value": alert.siem.title()},
                self.fields.source_alert_id:  dedup_key,
                self.fields.severity:         {"value": alert.severity},
                self.fields.entities:         _adf_doc("\n".join(alert.entities)),
                self.fields.raw_link:         _adf_doc(alert.raw_link),
                self.fields.occurrence_count: 1,
                self.fields.last_seen:        alert.timestamp,
            }
        }
        try:
            with httpx.Client(timeout=30) as http:
                resp = http.post(f"{self.base_url}/rest/api/3/issue", headers=self._headers, json=payload)
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise JiraError(f"Jira create failed: HTTP {e.response.status_code} — {e.response.text[:500]}") from e
        except httpx.HTTPError as e:
            raise JiraError(f"Jira create failed: {e}") from e
        return resp.json()["key"]

    # ── Append (dedup hit) ──────────────────────────────────────────────
    def append_alert_occurrence(self, ticket_key: str, alert: Alert, current_count: int) -> int:
        """On a dedup hit: add a comment, bump Occurrence count, update Last seen.
        Returns the new occurrence count."""
        new_count = current_count + 1

        comment_body = _adf_comment(alert)
        try:
            with httpx.Client(timeout=30) as http:
                http.post(
                    f"{self.base_url}/rest/api/3/issue/{ticket_key}/comment",
                    headers=self._headers,
                    json={"body": comment_body},
                ).raise_for_status()

                http.put(
                    f"{self.base_url}/rest/api/3/issue/{ticket_key}",
                    headers=self._headers,
                    json={
                        "fields": {
                            self.fields.occurrence_count: new_count,
                            self.fields.last_seen:        alert.timestamp,
                        }
                    },
                ).raise_for_status()
        except httpx.HTTPStatusError as e:
            raise JiraError(f"Jira update failed: HTTP {e.response.status_code} — {e.response.text[:500]}") from e
        except httpx.HTTPError as e:
            raise JiraError(f"Jira update failed: {e}") from e

        return new_count


# ── ADF helpers ─────────────────────────────────────────────────────────
# Jira Cloud REST v3 requires descriptions, comments, and textarea custom
# field values in Atlassian Document Format (structured JSON).

def _adf_description(alert: Alert) -> dict:
    paragraphs = [
        _adf_para(f"SIEM: {alert.siem} · Rule: {alert.rule_id}"),
        _adf_para(f"Primary entity: {alert.primary_entity}"),
        _adf_para(f"Severity: {alert.severity} · First seen: {alert.timestamp}"),
    ]
    if alert.entities:
        paragraphs.append(_adf_para(f"Entities: {', '.join(alert.entities)}"))
    if alert.raw_link:
        paragraphs.append({
            "type": "paragraph",
            "content": [
                {"type": "text", "text": "Raw event: "},
                {"type": "text", "text": "open in source SIEM",
                 "marks": [{"type": "link", "attrs": {"href": alert.raw_link}}]},
            ],
        })
    if alert.details:
        paragraphs.append(_adf_para("Details:"))
        paragraphs.append(_adf_para(alert.details[:2000]))  # truncate
    return {"type": "doc", "version": 1, "content": paragraphs}


def _adf_comment(alert: Alert) -> dict:
    lines = [
        f"[Dedup append] {alert.siem} · {alert.rule_id}",
        f"Primary entity: {alert.primary_entity}",
        f"Seen at: {alert.timestamp}",
    ]
    if alert.entities:
        lines.append(f"Entities: {', '.join(alert.entities)}")
    return {"type": "doc", "version": 1, "content": [_adf_para(line) for line in lines]}


def _adf_para(text: str) -> dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _adf_doc(text: str) -> dict:
    """Wrap a plain string as a single-paragraph ADF document.
    Required for textarea custom fields in Jira Cloud (post-2024 — they no
    longer accept plain string values; the API rejects with 400 otherwise)."""
    return {"type": "doc", "version": 1, "content": [_adf_para(text or "")]}
