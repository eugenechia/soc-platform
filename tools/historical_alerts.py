"""
Phase 3 L1 Triage redesign — historical alert correlation.

Looks up "similar alerts in the past 24h" for a freshly-created Jira ticket
and returns counts grouped by Phase 1 verdict label (True-Positive /
Benign-Positive / Unknown / Untriaged). The result feeds two consumers:

  1. tools.triage.triage_priority() — historical FP rate is a strong
     de-escalation signal for the LLM Triage call.
  2. tools.enrichment._build_comment() — surfaces the "Similar Alerts" block
     in the Jira enrichment comment for the analyst.

Match signal: Jira summary prefix (first N chars after stripping leading
bracket prefixes like "[DUPLICATE]"). Universal across Sentinel-Logic-App
and soc-ticket-gateway ticket sources — neither exposes the SIEM rule_id
in a consistent custom field today.

Failure mode: any exception → log and return None. The caller stays
graceful (no Historical section in the comment, no historical block in
the LLM prompt). Pipeline never blocks on a JQL hiccup.
"""
import logging
import os
import re

import httpx

logger = logging.getLogger(__name__)

JIRA_URL = os.environ.get("JIRA_URL", "").rstrip("/")

# Default tuning. All three can be overridden via env without a code change.
_DEFAULT_WINDOW_HOURS = 24
_DEFAULT_PREFIX_LEN = 50

# Leading bracket prefixes Jira / our dedup pipeline / analysts sometimes add
# to a summary that have NOTHING to do with the underlying alert (they signal
# ticket state, not rule identity). Strip these before extracting the prefix.
_BRACKET_NOISE_RE = re.compile(r"^\s*(\[[^\]]+\]\s*)+")


def _enabled() -> bool:
    return os.environ.get("HISTORICAL_LOOKUP_ENABLED", "true").lower() != "false"


def _window_hours() -> int:
    try:
        return int(os.environ.get("HISTORICAL_LOOKUP_WINDOW_HOURS", str(_DEFAULT_WINDOW_HOURS)))
    except (TypeError, ValueError):
        return _DEFAULT_WINDOW_HOURS


def _prefix_len() -> int:
    try:
        return int(os.environ.get("HISTORICAL_LOOKUP_SUMMARY_PREFIX_LEN", str(_DEFAULT_PREFIX_LEN)))
    except (TypeError, ValueError):
        return _DEFAULT_PREFIX_LEN


def _label_names() -> dict[str, str]:
    """Read the three verdict label names from env (same env vars Phase 1 uses).
    Returns lower-cased values for case-insensitive comparison against the
    `labels` list on each candidate ticket."""
    return {
        "tp":      (os.environ.get("JIRA_TRIAGE_MALICIOUS_LABEL", "True-Positive") or "").strip().lower(),
        "fp":      (os.environ.get("JIRA_TRIAGE_CLEAN_LABEL",     "Benign-Positive") or "").strip().lower(),
        "unknown": (os.environ.get("JIRA_TRIAGE_UNKNOWN_LABEL",   "Unknown") or "").strip().lower(),
    }


def _normalize_summary_prefix(summary: str) -> str:
    """Strip leading bracket prefixes, trim whitespace, return the first N
    chars (env-configurable). The result is what we pass to JQL `summary ~`.

    Bracket prefixes carry ticket-state semantics, not rule identity:
      "[DUPLICATE] Brute force on srv-01"      → "Brute force on srv-01"
      "[Resolved] [URGENT] Brute force..."      → "Brute force..."
    """
    if not summary:
        return ""
    cleaned = _BRACKET_NOISE_RE.sub("", summary).strip()
    return cleaned[:_prefix_len()]


def _jql_escape(s: str) -> str:
    """Escape backslashes and double quotes so the prefix lives safely inside
    a JQL phrase literal. We don't need to escape quotes-inside-phrases for
    real, but defensive escaping keeps things safe if a summary contains
    unusual characters."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _jira_headers() -> dict:
    """Same Basic Auth headers as tools.enrichment._jira_headers(). Duplicated
    here to keep this module independently importable for testing without
    pulling in the whole enrichment surface."""
    import base64
    from tools.secrets import get_secret
    email = get_secret("JIRA_EMAIL")
    token = get_secret("JIRA_API_TOKEN")
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _categorise(labels: list[str], label_map: dict[str, str]) -> str:
    """Return 'tp' | 'fp' | 'unknown' | 'untriaged' based on which Phase 1
    verdict label the candidate carries. Case-insensitive. Precedence:
    TP > FP > Unknown > untriaged — so a ticket with both TP and FP labels
    (shouldn't happen but defensive) reads as TP."""
    lc = {l.strip().lower() for l in (labels or []) if l}
    if label_map["tp"] and label_map["tp"] in lc:
        return "tp"
    if label_map["fp"] and label_map["fp"] in lc:
        return "fp"
    if label_map["unknown"] and label_map["unknown"] in lc:
        return "unknown"
    return "untriaged"


def query_similar_alerts(ticket_key: str, summary: str, project_key: str) -> dict | None:
    """Find Jira tickets in the same project whose summary shares the first N
    chars with this one, created within the past _window_hours(). Returns
    counts grouped by verdict label, or None on any error (caller stays
    graceful — no Historical section gets rendered).

    Important: the current ticket is excluded from the result so we don't
    self-count. We assume the caller has only just created the ticket and
    has the cleaned `summary` field already loaded.
    """
    if not _enabled():
        logger.info("Historical lookup disabled by env for %s", ticket_key)
        return None
    if not JIRA_URL:
        logger.warning("Historical lookup: JIRA_URL not set — skipping for %s", ticket_key)
        return None

    prefix = _normalize_summary_prefix(summary)
    if len(prefix) < 10:
        # Too short to be meaningful — would match almost anything. Skip
        # rather than return noisy data.
        logger.info("Historical lookup: summary prefix too short (%d chars) for %s — skipping",
                    len(prefix), ticket_key)
        return None

    hours = _window_hours()
    escaped = _jql_escape(prefix)
    jql = (
        f'project = "{project_key}" '
        f'AND key != "{ticket_key}" '
        f'AND created >= -{hours}h '
        f'AND summary ~ "\\"{escaped}\\"" '
        f'ORDER BY created DESC'
    )

    url = f"{JIRA_URL}/rest/api/3/search/jql"
    try:
        r = httpx.get(
            url,
            headers=_jira_headers(),
            params={"jql": jql, "fields": "summary,labels,created", "maxResults": 100},
            timeout=20,
        )
        if r.status_code >= 400:
            logger.warning("Historical lookup HTTP %s for %s: %s",
                           r.status_code, ticket_key, r.text[:200])
            return None
        data = r.json() or {}
    except Exception as e:
        logger.warning("Historical lookup failed (%s): %s for %s",
                       type(e).__name__, e, ticket_key)
        return None

    label_map = _label_names()
    counts = {"tp": 0, "fp": 0, "unknown": 0, "untriaged": 0}
    earliest_iso: str | None = None

    issues = data.get("issues") or []
    for issue in issues:
        fields = issue.get("fields") or {}
        labels = fields.get("labels") or []
        bucket = _categorise(labels, label_map)
        counts[bucket] += 1
        created = (fields.get("created") or "").strip()
        if created and (earliest_iso is None or created < earliest_iso):
            earliest_iso = created

    total = sum(counts.values())
    result = {
        "total": total,
        "true_positive": counts["tp"],
        "false_positive": counts["fp"],
        "unknown": counts["unknown"],
        "untriaged": counts["untriaged"],
        "first_seen_at": earliest_iso or "",
        "rule_prefix": prefix,
        "window_hours": hours,
    }
    logger.info(
        "Historical lookup: %d similar alerts in past %dh for %s "
        "(TP=%d FP=%d U=%d untriaged=%d)",
        total, hours, ticket_key,
        counts["tp"], counts["fp"], counts["unknown"], counts["untriaged"],
    )
    return result
