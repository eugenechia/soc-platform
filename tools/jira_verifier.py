"""Independent verification of JIRA incident monthly counts.

The primary fetch path (tools/jira_client._fetch_month_count, called once per
month by fetch_monthly_counts_12m) issues 12 separate JQL queries — one per
month — and counts the issues returned by each. Any latent bug in that loop
(stale cursor, accidental cap, silent HTTP failure mid-loop) would corrupt
the monthly counts in a way the report has no way to detect.

This module provides a deterministic cross-check using a deliberately
different code path:

  * One JQL covering the full 12-month window (not 12 separate queries).
  * Cursor pagination with `fields=["created"]` only (minimum bandwidth).
  * Local grouping by the issue's `created` timestamp into YYYY-MM buckets.

If the verifier's per-month totals disagree with the primary fetch, the
report generator refuses to produce a report rather than ship a chart with
unverified numbers.

Failure modes are explicitly fail-closed: any internal error (network, auth,
JQL rejection) sets `verified=False` with an `error` string. The caller is
responsible for raising on `verified=False`.
"""
import logging
from datetime import datetime

import httpx

from tools.jira_client import (
    JIRA_URL,
    _jira_headers,
    _incident_jql_filter,
    _parse_jira_date,
    DEFAULT_INCIDENT_ISSUE_TYPE,
)

logger = logging.getLogger(__name__)

# Independent safety bound. The verifier should never need to fetch this
# many issues across a 12-month window in normal operation; if it does,
# either the customer has extreme volume or the JQL filter is wrong.
_VERIFIER_SAFETY_BOUND = 500_000


def _empty_12m_buckets(end_date: str) -> dict:
    """Return a dict with all 12 month keys (YYYY-MM) initialised to 0,
    so the verifier reports zero-count months explicitly rather than
    omitting them and creating false discrepancies on the diff."""
    from dateutil.relativedelta import relativedelta

    try:
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        return {}
    end_month = end_dt.replace(day=1)
    return {
        (end_month - relativedelta(months=i)).strftime("%Y-%m"): 0
        for i in range(11, -1, -1)
    }


def verify_monthly_counts(
    project_key: str,
    end_date: str,
    primary_monthly_counts: dict,
    incident_issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE,
) -> dict:
    """Cross-check primary_monthly_counts via an independent JQL window.

    Returns a dict with this shape:
        {
          "verified":        bool,
          "by_month":        {"2025-06": 17, ...},  # all 12 months, 0 if none
          "total_verifier":  int,
          "total_primary":   int,
          "discrepancies":   [{"month": "2026-01", "primary": 47,
                               "verifier": 53, "delta": 6}, ...],
          "error":           str | None,
          "issue_type":      str,
        }

    `verified=True` requires both:
      1. No internal error.
      2. Every month's primary count equals the verifier's count.
    """
    from dateutil.relativedelta import relativedelta

    issue_type = (incident_issue_type or DEFAULT_INCIDENT_ISSUE_TYPE).strip() or DEFAULT_INCIDENT_ISSUE_TYPE
    by_month = _empty_12m_buckets(end_date)

    if not by_month:
        return {
            "verified": False,
            "by_month": {},
            "total_verifier": 0,
            "total_primary": sum(primary_monthly_counts.values()),
            "discrepancies": [],
            "error": f"verify_monthly_counts: invalid end_date {end_date!r}",
            "issue_type": issue_type,
        }

    # The full 12-month window. window_end is exclusive (`<`) — matches the
    # convention used by _fetch_month_count, so both code paths cover the
    # exact same calendar interval.
    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    end_month = end_dt.replace(day=1)
    window_start = (end_month - relativedelta(months=11)).strftime("%Y-%m-%d")
    window_end = (end_month + relativedelta(months=1)).strftime("%Y-%m-%d")

    jql = (
        f'{_incident_jql_filter(project_key, issue_type)} '
        f'AND created >= "{window_start}" '
        f'AND created < "{window_end}" '
        f'ORDER BY created ASC'
    )
    logger.info("verify_monthly_counts JQL: %s", jql)

    fetched = 0
    next_token: str | None = None
    while fetched < _VERIFIER_SAFETY_BOUND:
        params: dict = {"jql": jql, "maxResults": 100, "fields": "created"}
        if next_token:
            params["nextPageToken"] = next_token
        try:
            r = httpx.get(
                f"{JIRA_URL}/rest/api/3/search/jql",
                headers=_jira_headers(),
                params=params,
                timeout=30,
            )
        except Exception as e:
            return {
                "verified": False,
                "by_month": by_month,
                "total_verifier": fetched,
                "total_primary": sum(primary_monthly_counts.values()),
                "discrepancies": [],
                "error": f"verifier HTTP exception: {type(e).__name__}: {e}",
                "issue_type": issue_type,
            }
        if r.status_code >= 400:
            return {
                "verified": False,
                "by_month": by_month,
                "total_verifier": fetched,
                "total_primary": sum(primary_monthly_counts.values()),
                "discrepancies": [],
                "error": f"verifier HTTP {r.status_code}: {r.text[:300]}",
                "issue_type": issue_type,
            }
        data = r.json()
        issues = data.get("issues", [])
        for issue in issues:
            created_raw = (issue.get("fields") or {}).get("created", "")
            dt = _parse_jira_date(created_raw)
            if not dt:
                # Cannot bucket without a valid timestamp. Skipping silently
                # would let unverifiable issues through, so this is an error.
                return {
                    "verified": False,
                    "by_month": by_month,
                    "total_verifier": fetched,
                    "total_primary": sum(primary_monthly_counts.values()),
                    "discrepancies": [],
                    "error": (f"verifier could not parse 'created' for issue "
                              f"{issue.get('key', '?')}: {created_raw!r}"),
                    "issue_type": issue_type,
                }
            key = dt.strftime("%Y-%m")
            if key in by_month:
                by_month[key] += 1
            # Issues outside the 12-month bucket window are silently dropped
            # (shouldn't happen given the JQL filter, but if Jira returns
            # boundary creates due to timezone, we don't want to false-fail).
            fetched += 1
        next_token = data.get("nextPageToken")
        if not issues or not next_token or data.get("isLast") is True:
            break

    if fetched >= _VERIFIER_SAFETY_BOUND:
        logger.warning(
            "verify_monthly_counts hit safety bound %d for project %s — counts may be incomplete.",
            _VERIFIER_SAFETY_BOUND, project_key,
        )

    # Diff every month present in either source (don't trust the input dict
    # to have all 12 keys).
    all_months = set(by_month.keys()) | set(primary_monthly_counts.keys())
    discrepancies = []
    for k in sorted(all_months):
        primary = int(primary_monthly_counts.get(k, 0) or 0)
        verifier = int(by_month.get(k, 0) or 0)
        if primary != verifier:
            discrepancies.append({
                "month": k,
                "primary": primary,
                "verifier": verifier,
                "delta": verifier - primary,
            })

    return {
        "verified": len(discrepancies) == 0,
        "by_month": by_month,
        "total_verifier": sum(by_month.values()),
        "total_primary": sum(primary_monthly_counts.values()),
        "discrepancies": discrepancies,
        "error": None,
        "issue_type": issue_type,
    }


def format_verification_error(verification: dict) -> str:
    """Render a verification result into an operator-friendly message.

    Used when raising on verified=False so the report wizard's error panel
    shows enough detail for an operator to investigate without combing logs.
    """
    if verification.get("error"):
        return f"Verifier internal error: {verification['error']}"

    lines = [
        f"JIRA monthly count discrepancy detected for issue type "
        f"'{verification.get('issue_type', '?')}'.",
        f"  Primary fetch total:  {verification.get('total_primary', 0)} incidents",
        f"  Verifier total:       {verification.get('total_verifier', 0)} incidents",
        "",
        "Per-month differences (primary → verifier):",
    ]
    for d in verification.get("discrepancies", []):
        sign = "+" if d["delta"] > 0 else ""
        lines.append(
            f"  {d['month']}:  {d['primary']:>5}  →  {d['verifier']:>5}  "
            f"(delta: {sign}{d['delta']})"
        )
    return "\n".join(lines)
