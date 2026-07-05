"""
Jira helpers owned by the L2 dashboard.

Deliberately a separate module from tools/jira_client.py: that module is
imported by the live L1 webhook path (routes/webhook.py, tools/triage.py,
tools/mitre_mapper.py), so the dashboard must not modify it. This module
IMPORTS the shared auth/parsing helpers from jira_client instead — the same
cross-module private-helper reuse the webhook and triage already practice.

Contents:
  - jira_search_with_comments(): like jira_client.jira_search() but with an
    explicit field list that includes ``comment``, so the dashboard sync can
    read the L1 enrichment comment in the SAME search call (one request per
    project page instead of one per ticket — matters at ~60 customers).
  - close_ticket(): generic close-transition helper (Stage 4 write-back).
    SCDM's Close is a workflow transition that requires Close Justification /
    Resolution Summary / Resolution Category custom fields set BEFORE firing.
    tools/dedup_jira.py has a closer but it hardcodes Category=Duplicate, so
    it cannot be reused here.
"""
from __future__ import annotations

import logging
import os

import httpx

from tools.jira_client import _resolve_jira_auth

logger = logging.getLogger(__name__)

# jira_client._FIELDS plus comment + resolutiondate. Kept as our own constant
# so a change to the L1 field list can never silently change dashboard sync.
_SYNC_FIELDS = (
    "summary,status,priority,labels,created,updated,resolved,assignee,"
    "resolution,resolutiondate,comment,"
    "customfield_10038,"   # Severity
    "customfield_10488"    # Incident Type (dashboard "source" column)
)

# SCDM close-transition config — same env names/defaults tools/dedup_jira.py
# uses, so both closers follow the one workflow configuration.
_CLOSE_TRANSITION_ID = os.environ.get("JIRA_CLOSE_TRANSITION_ID", "181")
_FIELD_CLOSE_JUSTIFICATION = os.environ.get("JIRA_FIELD_CLOSE_JUSTIFICATION", "customfield_10057")
_FIELD_RESOLUTION_SUMMARY = os.environ.get("JIRA_FIELD_RESOLUTION_SUMMARY", "customfield_10127")
_FIELD_RESOLUTION_CATEGORY = os.environ.get("JIRA_FIELD_RESOLUTION_CATEGORY", "customfield_10521")


def jira_search_with_comments(jql: str, max_results: int = 100,
                              next_page_token: str | None = None,
                              project_spec: dict | None = None) -> dict:
    """Search issues with comments included in the response.

    Same request shape as jira_client.jira_search() (GET /search/jql) but with
    _SYNC_FIELDS. Returns the parsed JSON, or {"error": ...} on HTTP failure.
    The caller treats an error dict as "skip this project this cycle".
    """
    params = {
        "jql": jql,
        "maxResults": max_results,
        "fields": _SYNC_FIELDS,
    }
    if next_page_token:
        params["nextPageToken"] = next_page_token

    base_url, headers = _resolve_jira_auth(project_spec)
    try:
        r = httpx.get(
            f"{base_url}/rest/api/3/search/jql",
            headers=headers,
            params=params,
            timeout=30,
        )
    except Exception as e:
        logger.error("jira_search_with_comments exception: %s", e)
        return {"error": str(e)}
    if r.status_code >= 400:
        logger.error("jira_search_with_comments HTTP %s: %s",
                     r.status_code, r.text[:500])
        return {"error": f"HTTP {r.status_code}", "status_code": r.status_code,
                "detail": r.text[:500]}
    return r.json()


def search_jira_text(q: str, project_keys: list[str],
                     max_results: int = 20) -> list[dict]:
    """Live Jira full-text search, scoped to the given project keys. Used by
    the dashboard search bar to reach past the read-model's sync window.
    Returns compact feed-shaped dicts (source='jira'); [] on any failure."""
    from tools.jira_client import jira_search, _normalize_severity

    q = (q or "").replace('"', " ").replace("\\", " ").strip()
    keys = [k for k in (project_keys or []) if k]
    if not q or len(q) < 3 or not keys:
        return []
    scope = ", ".join(f'"{k}"' for k in keys[:60])
    jql = f'project in ({scope}) AND text ~ "{q}" ORDER BY created DESC'
    try:
        result = jira_search(jql, max_results=max_results)
    except Exception:
        logger.exception("search_jira_text failed")
        return []
    if not isinstance(result, dict) or result.get("error"):
        return []

    out = []
    for issue in result.get("issues", []):
        f = issue.get("fields", {}) or {}
        labels_lower = {str(l).lower() for l in (f.get("labels") or [])}
        verdict = ("TRUE-POSITIVE" if "true-positive" in labels_lower
                   else "BENIGN-POSITIVE" if "benign-positive" in labels_lower
                   else "UNKNOWN" if "unknown" in labels_lower else "")
        sev = (f.get("customfield_10038") or {}).get("value", "")
        out.append({
            "ticket_key": issue.get("key", ""),
            "summary": f.get("summary", "") or "",
            "severity": _normalize_severity(sev),
            "verdict_label": verdict,
            "raw_status": (f.get("status") or {}).get("name", ""),
            "source": "Jira archive",
            "ai_explanation": "",
            "created_at": f.get("created", ""),
            "from_jira": True,
        })
    return out


def close_ticket(ticket_key: str, justification: str, resolution_summary: str,
                 resolution_category: str,
                 project_spec: dict | None = None) -> tuple[bool, str]:
    """Close a ticket via the workflow transition. Returns (ok, error_message).

    Two steps, matching what the SCDM workflow validates:
      1. PUT the required close custom fields.
      2. POST the Close transition.
    Justification/summary/category are caller-supplied (UI inputs) — never
    hardcoded here, so the open FP/Benign-Positive taxonomy decision stays
    with the analyst.
    """
    if not ticket_key:
        return False, "no ticket key"
    base_url, headers = _resolve_jira_auth(project_spec)

    # Field shapes copied from the proven closer in tools/dedup_jira.py:
    # justification/category are option fields ({"value": ...}), Resolution
    # Summary is an ADF rich-text doc, and the Close transition validator
    # requires non-empty Labels — so read current labels first and add a
    # fallback marker if the ticket has none.
    try:
        r = httpx.get(
            f"{base_url}/rest/api/3/issue/{ticket_key}?fields=labels",
            headers=headers, timeout=30,
        )
        if r.status_code >= 400:
            msg = f"close labels GET HTTP {r.status_code}: {r.text[:300]}"
            logger.error("close_ticket %s: %s", ticket_key, msg)
            return False, msg
        labels = (r.json().get("fields", {}) or {}).get("labels") or []
    except Exception as e:
        logger.error("close_ticket %s labels GET exception: %s", ticket_key, e)
        return False, str(e)
    if not labels:
        labels = ["analyst-closed"]

    fields_payload = {
        "labels": labels,
        _FIELD_CLOSE_JUSTIFICATION: {"value": justification},
        _FIELD_RESOLUTION_SUMMARY: {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": resolution_summary or justification}
            ]}],
        },
        _FIELD_RESOLUTION_CATEGORY: {"value": resolution_category},
    }
    try:
        r = httpx.put(
            f"{base_url}/rest/api/3/issue/{ticket_key}",
            headers=headers,
            json={"fields": fields_payload},
            timeout=30,
        )
        if r.status_code >= 400:
            msg = f"close fields PUT HTTP {r.status_code}: {r.text[:300]}"
            logger.error("close_ticket %s: %s", ticket_key, msg)
            return False, msg

        r = httpx.post(
            f"{base_url}/rest/api/3/issue/{ticket_key}/transitions",
            headers=headers,
            json={"transition": {"id": _CLOSE_TRANSITION_ID}},
            timeout=30,
        )
        if r.status_code >= 400:
            msg = f"close transition HTTP {r.status_code}: {r.text[:300]}"
            logger.error("close_ticket %s: %s", ticket_key, msg)
            return False, msg
    except Exception as e:
        logger.error("close_ticket %s exception: %s", ticket_key, e)
        return False, str(e)

    logger.info("close_ticket %s: closed (category=%s)", ticket_key, resolution_category)
    return True, ""
