import os
import csv
import json
import base64
import logging
from datetime import datetime, timedelta
from collections import Counter

import httpx

logger = logging.getLogger(__name__)

JIRA_URL = os.environ.get("JIRA_URL", "").rstrip("/")
USE_SAMPLE_DATA = os.environ.get("USE_SAMPLE_DATA", "false").lower() == "true"


def _jira_headers() -> dict:
    """Build the Jira REST auth header at call time.

    Resolves email + token via tools.secrets.get_secret so KV-backed
    deployments work without the credentials being smuggled into the image
    via .env. Falls back to os.environ for dev/CI where load_dotenv() has
    populated the process env."""
    from tools.secrets import get_secret
    email = get_secret("JIRA_EMAIL") or os.environ.get("JIRA_EMAIL", "")
    token = get_secret("JIRA_API_TOKEN") or os.environ.get("JIRA_API_TOKEN", "")
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {"Authorization": f"Basic {creds}", "Accept": "application/json"}


_FIELDS = (
    "summary,status,priority,labels,created,updated,resolved,assignee,"
    "resolution,description,"
    "customfield_10038,"   # Severity
    "customfield_10488,"   # Incident Type
    "customfield_10057,"   # Close Justification
    "customfield_10127,"   # Resolution Summary
    "customfield_10072"    # Tactics List
)


def fetch_issue_by_key(issue_key: str, fields: str = "*all") -> dict | None:
    """Fetch a single Jira issue by key. Returns the parsed JSON (with `fields`
    populated) or None on any error. Used by the L1 Triage webhook handler to
    re-read an issue after a short delay, since Service Desk request forms can
    populate custom fields after the initial issue_created webhook fires."""
    if not JIRA_URL:
        logger.error("fetch_issue_by_key: JIRA_URL not configured")
        return None
    try:
        r = httpx.get(
            f"{JIRA_URL}/rest/api/3/issue/{issue_key}",
            headers=_jira_headers(),
            params={"fields": fields},
            timeout=30,
        )
        if r.status_code >= 400:
            logger.error("fetch_issue_by_key %s HTTP %s: %s",
                         issue_key, r.status_code, r.text[:300])
            return None
        return r.json()
    except Exception as e:
        logger.error("fetch_issue_by_key %s exception: %s", issue_key, e)
        return None


def jira_search(jql: str, max_results: int = 100, next_page_token: str | None = None) -> dict:
    params = {
        "jql": jql,
        "maxResults": max_results,
        "fields": _FIELDS,
    }
    if next_page_token:
        params["nextPageToken"] = next_page_token

    r = httpx.get(
        f"{JIRA_URL}/rest/api/3/search/jql",
        headers=_jira_headers(),
        params=params,
        timeout=30,
    )
    if r.status_code >= 400:
        logger.error(f"jira_search HTTP {r.status_code}: {r.text[:500]}")
        return {"error": f"HTTP {r.status_code}", "detail": r.text[:500]}
    return r.json()


# Centralised filter used by every code path that counts incidents. Keeping it
# in one place guarantees the verifier in tools/jira_verifier.py applies the
# exact same project + issue-type predicate as the primary fetch — otherwise
# they could disagree purely from drift in two copies of the same string.
DEFAULT_INCIDENT_ISSUE_TYPE = "[System] Incident"


def _incident_jql_filter(project_key: str, issue_type: str) -> str:
    return f'project = "{project_key}" AND issuetype = "{issue_type or DEFAULT_INCIDENT_ISSUE_TYPE}"'


def _parse_jira_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


def _extract_adf_text(field_value) -> str:
    """Extract plain text from an Atlassian Document Format (ADF) rich text field."""
    if not field_value:
        return ""
    if isinstance(field_value, str):
        return field_value
    if not isinstance(field_value, dict):
        return str(field_value)

    parts = []

    def _walk(node):
        if isinstance(node, dict):
            if node.get("type") == "text":
                parts.append(node.get("text", ""))
            for child in node.get("content", []):
                _walk(child)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(field_value)
    return " ".join(parts).strip()


def _normalize_issue(issue: dict) -> dict:
    fields = issue.get("fields", {})
    status = fields.get("status", {})
    priority = fields.get("priority", {})
    assignee = fields.get("assignee", {})

    # Extract tactics text and take the first tactic as category
    tactics_raw = _extract_adf_text(fields.get("customfield_10072"))
    category = tactics_raw.split()[0].strip() if tactics_raw else ""

    return {
        "key": issue.get("key", ""),
        "summary": fields.get("summary", ""),
        "status": status.get("name", "") if status else "",
        "priority": priority.get("name", "") if priority else "",
        "severity": (fields.get("customfield_10038") or {}).get("value", "") or (priority.get("name", "") if priority else ""),
        "incident_type": category,
        "labels": fields.get("labels", []),
        "created": fields.get("created", ""),
        "updated": fields.get("updated", ""),
        "resolved": fields.get("resolved", ""),
        "assignee": (assignee.get("displayName", "") if assignee else ""),
        "close_justification": (fields.get("customfield_10057") or {}).get("value", ""),
        "resolution_summary": _extract_adf_text(fields.get("customfield_10127")),
        "tactics_list": tactics_raw,
    }


def _fetch_all_pages(jql: str) -> list:
    """Fetch all pages for a JQL query using cursor pagination."""
    all_issues = []
    next_token = None
    while len(all_issues) < 5000:
        result = jira_search(jql, max_results=100, next_page_token=next_token)
        if "error" in result:
            logger.error(f"Jira fetch error: {result}")
            break
        issues = result.get("issues", [])
        all_issues.extend(issues)
        next_token = result.get("nextPageToken")
        if not issues or not next_token or result.get("isLast") is True:
            break
    return all_issues


def _date_chunks(start_date: str, end_date: str):
    """Yield (chunk_start, chunk_end_exclusive) tuples for each day in the range.
    Uses next-day exclusive end to avoid Jira's zero-width window when >= and <= share the same date."""
    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    current = start
    while current <= end:
        next_day = current + timedelta(days=1)
        yield current.strftime("%Y-%m-%d"), next_day.strftime("%Y-%m-%d")
        current = next_day


def fetch_incidents_for_report(project_key: str, start_date: str, end_date: str,
                               incident_issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE) -> dict:
    if USE_SAMPLE_DATA:
        return fetch_incidents_from_csv(project_key, start_date, end_date)

    seen_keys = set()
    all_issues = []

    for chunk_start, chunk_end in _date_chunks(start_date, end_date):
        jql = (
            f'{_incident_jql_filter(project_key, incident_issue_type)} '
            f'AND created >= "{chunk_start}" '
            f'AND created < "{chunk_end}" '
            f'ORDER BY created DESC'
        )
        issues = _fetch_all_pages(jql)
        for issue in issues:
            key = issue.get("key")
            if key and key not in seen_keys:
                seen_keys.add(key)
                all_issues.append(issue)

    logger.info("fetch_incidents_for_report: total=%d", len(all_issues))
    incidents = [_normalize_issue(i) for i in all_issues]
    stats = _compute_stats(incidents)
    return {"incidents": incidents, "stats": stats}


def _compute_stats(incidents: list[dict]) -> dict:
    total = len(incidents)
    by_severity = dict(Counter(i["severity"] or "Unspecified" for i in incidents))
    by_status = dict(Counter(i["status"] for i in incidents))
    by_priority = dict(Counter(i["priority"] or "Unspecified" for i in incidents))
    by_close_justification = dict(Counter(
        i["close_justification"] or "Unspecified" for i in incidents if i["close_justification"]
    ))

    label_counts = Counter()
    for i in incidents:
        for label in i["labels"]:
            label_counts[label] += 1
    top_alerts = dict(label_counts.most_common(10))

    monthly_trend = Counter()
    for i in incidents:
        created = i["created"]
        if created:
            try:
                dt = _parse_jira_date(created) or _parse_csv_date(created)
                if dt:
                    monthly_trend[dt.strftime("%Y-%m")] += 1
            except Exception:
                pass
    monthly_trend = dict(sorted(monthly_trend.items()))

    assignee_counts = dict(Counter(i["assignee"] or "Unassigned" for i in incidents))

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_priority": by_priority,
        "by_close_justification": by_close_justification,
        "top_alerts": top_alerts,
        "monthly_trend": monthly_trend,
        "assignee_distribution": assignee_counts,
    }


def _parse_csv_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    for fmt in ("%d/%m/%Y %H:%M", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    return None


def fetch_incidents_from_csv(project_key: str, start_date: str, end_date: str,
                             csv_path: str | None = None) -> dict:
    if not csv_path:
        csv_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "samples", "sample-CAM Jira Dump.csv"
        )
    if not os.path.exists(csv_path):
        logger.error(f"Sample CSV not found at {csv_path}")
        return {"incidents": [], "stats": {}, "error": "Sample CSV not found"}

    try:
        start_dt = _parse_csv_date(start_date) or datetime(2000, 1, 1)
        end_dt = _parse_csv_date(end_date) or datetime(2099, 12, 31)
    except Exception:
        start_dt = datetime(2000, 1, 1)
        end_dt = datetime(2099, 12, 31)

    incidents = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("Project key", "") != project_key and project_key:
                continue

            created_dt = _parse_csv_date(row.get("Created", ""))
            if created_dt and not (start_dt <= created_dt <= end_dt):
                continue

            # Use Tactics List as primary category (matches sample report's Category column)
            tactics = row.get("Custom field (Tactics List)", "").strip()
            # Clean up multi-tactic entries: take the first one
            category = tactics.split("  ")[0].strip() if tactics else ""

            incidents.append({
                "key": row.get("Issue key", ""),
                "summary": row.get("Summary", ""),
                "status": row.get("Status", ""),
                "priority": row.get("Priority", ""),
                "severity": row.get("Custom field (Severity)", "").strip() or row.get("Priority", "").strip(),
                "incident_type": category,
                "labels": [l.strip() for l in row.get("Labels", "").split(",") if l.strip()],
                "created": row.get("Created", ""),
                "updated": row.get("Updated", ""),
                "resolved": row.get("Resolved", ""),
                "assignee": row.get("Assignee", ""),
                "close_justification": row.get("Custom field (Close Justification)", ""),
                "resolution_summary": row.get("Custom field (Resolution Summary)", ""),
                "tactics_list": tactics,
            })

    stats = _compute_stats(incidents)
    return {"incidents": incidents, "stats": stats}


def _fetch_jira_by_type(issue_type: str, project_key: str,
                        start_date: str, end_date: str) -> dict:
    """Generic Jira fetch by issue type. Returns {items, stats, unavailable}."""
    seen_keys = set()
    all_issues = []

    for chunk_start, chunk_end in _date_chunks(start_date, end_date):
        jql = (
            f'project = "{project_key}" '
            f'AND issuetype = "{issue_type}" '
            f'AND created >= "{chunk_start}" '
            f'AND created < "{chunk_end}" '
            f'ORDER BY created DESC'
        )
        result = jira_search(jql, max_results=100, next_page_token=None)
        if "error" in result:
            if "HTTP 400" in result.get("error", "") or "HTTP 404" in result.get("error", ""):
                logger.warning(f"Issue type '{issue_type}' not found in project {project_key}")
                return {"items": [], "stats": {}, "unavailable": True}
            logger.error(f"Jira fetch failed for {issue_type}: {result}")
            return {"items": [], "stats": {}, "error": result["error"], "unavailable": False}

        for issue in result.get("issues", []):
            key = issue.get("key")
            if key and key not in seen_keys:
                seen_keys.add(key)
                all_issues.append(issue)

    logger.info("_fetch_jira_by_type(%s): total=%d", issue_type, len(all_issues))
    items = [_normalize_issue(i) for i in all_issues]
    stats = _compute_stats(items)
    return {"items": items, "stats": stats, "unavailable": False}


def fetch_service_requests(project_key: str, start_date: str, end_date: str,
                           issue_type: str = "Service Request") -> dict:
    """Fetch Service Request tickets from Jira for the given project and date range.

    The issue_type defaults to the canonical Atlassian/JSM name "Service Request",
    but customers whose Jira project uses a different label (e.g.
    "Service Desk Request") can override this per customer in the admin UI."""
    try:
        return _fetch_jira_by_type(issue_type or "Service Request", project_key,
                                   start_date, end_date)
    except Exception as e:
        logger.warning(f"fetch_service_requests exception: {e}")
        return {"items": [], "stats": {}, "unavailable": True}


def fetch_change_requests(project_key: str, start_date: str, end_date: str,
                          issue_type: str = "Change") -> dict:
    """Fetch Change Request tickets from Jira for the given project and date range.

    The issue_type defaults to "Change" (the JSM canonical name); per-customer
    overrides are supported for projects using alternatives like "RFC" or
    "Change Management"."""
    try:
        return _fetch_jira_by_type(issue_type or "Change", project_key,
                                   start_date, end_date)
    except Exception as e:
        logger.warning(f"fetch_change_requests exception: {e}")
        return {"items": [], "stats": {}, "unavailable": True}


# Sanity bound on the per-month pagination loop. Far above any plausible
# incident volume — its only job is to prevent a runaway loop if Jira ever
# misbehaves. NOT a truncation cap on real data.
_MONTHLY_FETCH_SAFETY_BOUND = 200_000


def _fetch_month_count(project_key: str, month_start: str, month_end: str,
                       issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE) -> int:
    """Return the count of incidents for a single month window using cursor pagination.

    Uses full pagination — the loop terminates naturally on `isLast` /
    missing nextPageToken / empty page. The safety bound only protects
    against an upstream API bug that would otherwise spin forever; if it is
    ever hit on real data, that is a data-integrity incident, not a normal
    truncation, and is logged at WARNING.
    """
    jql = (
        f'{_incident_jql_filter(project_key, issue_type)} '
        f'AND created >= "{month_start}" '
        f'AND created < "{month_end}" '
        f'ORDER BY created ASC'
    )
    logger.info("_fetch_month_count JQL: %s", jql)
    count = 0
    next_token = None
    while count < _MONTHLY_FETCH_SAFETY_BOUND:
        params: dict = {"jql": jql, "maxResults": 100, "fields": "created"}
        if next_token:
            params["nextPageToken"] = next_token
        r = httpx.get(
            f"{JIRA_URL}/rest/api/3/search/jql",
            headers=_jira_headers(),
            params=params,
            timeout=30,
        )
        if r.status_code >= 400:
            logger.warning("_fetch_month_count HTTP %s for %s — JQL: %s — response: %s",
                           r.status_code, month_start, jql, r.text[:500])
            break
        data = r.json()
        issues = data.get("issues", [])
        count += len(issues)
        next_token = data.get("nextPageToken")
        if not issues or not next_token or data.get("isLast") is True:
            break
    if count >= _MONTHLY_FETCH_SAFETY_BOUND:
        logger.warning(
            "_fetch_month_count hit safety bound %d for %s — month count may be truncated. "
            "This is unexpected; investigate JIRA volume or pagination behaviour.",
            _MONTHLY_FETCH_SAFETY_BOUND, month_start,
        )
    logger.info("_fetch_month_count %s: %d issues", month_start, count)
    return count


def fetch_monthly_counts_12m(project_key: str, end_date: str,
                             incident_issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE) -> dict:
    """Fetch incident counts per month for the 12 months ending at end_date.

    Queries one month at a time so that months with large issue counts (e.g. 700+)
    cannot cause the cursor to exhaust the page budget and starve earlier months.
    Each month is an independent paginated query — the same JQL filter used by
    fetch_incidents_for_report ensures consistency with the report data.
    """
    from dateutil.relativedelta import relativedelta

    try:
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        logger.warning("fetch_monthly_counts_12m: invalid end_date %s", end_date)
        return {}

    end_month = end_dt.replace(day=1)

    monthly_counts: dict[str, int] = {}
    for i in range(11, -1, -1):
        m = end_month - relativedelta(months=i)
        month_key = m.strftime("%Y-%m")
        month_start = m.strftime("%Y-%m-%d")
        month_end = (m + relativedelta(months=1)).strftime("%Y-%m-%d")
        count = _fetch_month_count(project_key, month_start, month_end, issue_type=incident_issue_type)
        monthly_counts[month_key] = count
        logger.info("fetch_monthly_counts_12m(%s): %s = %d", project_key, month_key, count)

    return monthly_counts
