"""Historical Sentinel data sourced from previously-saved reports.

Sentinel's Log Analytics workspace retains data for 90 days by default, so any
query covering a date range older than that returns nothing. To make the
report generator robust against this — both for showing N months of history
in current reports and for regenerating reports from 4+ months ago — we
treat the per-month saved report JSONs at ``data/reports/*.json`` as a
durable archive of each month's Sentinel snapshot.

Two helpers are exposed:

- :func:`load_historical_sentinel_data` — for the *current* month's report.
  Walks saved reports for the customer, extracts each month's utilization
  total + incident total, returns 11 months of monthly aggregates the chart
  code can stitch together with the live current month.

- :func:`load_sentinel_data_from_saved_report` — for *regenerating an old
  month's report*. Pulls the previously-saved Sentinel snapshot for a
  specific (customer, start_date) pair so the report can be re-rendered
  without re-querying Sentinel (which would return empty past 90 days).

Both functions are read-only. They never mutate saved reports.
"""
import json
import logging
import os
from datetime import datetime
from typing import Optional

from dateutil.relativedelta import relativedelta

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")

# Sentinel's standard retention. Used to decide whether to skip live KQL and
# fall back to a saved snapshot for the requested month.
SENTINEL_RETENTION_DAYS = 90


def _month_key(date_str: str) -> str:
    """Map a YYYY-MM-DD (or YYYY-MM) string to its YYYY-MM canonical form.

    Tolerant of partial/malformed inputs — returns "" rather than raising so
    a single bad saved report doesn't kill history loading.
    """
    if not date_str:
        return ""
    s = date_str.strip()[:7]
    if len(s) == 7 and s[4] == "-" and s[:4].isdigit() and s[5:].isdigit():
        return s
    return ""


def _iter_customer_reports(customer_id: str):
    """Yield (start_month, report_dict) for every saved report belonging to
    the given customer, newest-month first.

    Each entry is sorted by the report's ``start_date`` month, descending.
    Reports without a matching ``customer_id`` field are skipped silently.
    Corrupt or unreadable JSON files are logged once and skipped.
    """
    if not customer_id or not os.path.isdir(REPORTS_DIR):
        return
    records: list[tuple[str, dict]] = []
    for fname in os.listdir(REPORTS_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(REPORTS_DIR, fname)
        try:
            with open(path) as f:
                r = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Skipping unreadable report %s: %s", fname, exc)
            continue
        if r.get("customer_id") != customer_id:
            continue
        month = _month_key(r.get("start_date", ""))
        if not month:
            continue
        records.append((month, r))
    records.sort(key=lambda x: x[0], reverse=True)
    yield from records


def load_historical_sentinel_data(customer_id: str, end_date_str: str,
                                  months_back: int = 11) -> dict:
    """Return monthly Sentinel aggregates for the N months preceding ``end_date``.

    The current month (the one ``end_date`` belongs to) is **excluded** — that
    comes from live Sentinel. Older months are taken from saved reports.

    Args:
        customer_id: customer record id (matches the field stored at save time).
        end_date_str: YYYY-MM-DD; defines the month we're stitching history onto.
        months_back: how many months of history to look back (default 11, so
            with the live current month the caller has a 12-month series).

    Returns:
        ``{"utilization_monthly": {"YYYY-MM": float_gb, ...},
           "missing_months": ["YYYY-MM", ...]}``

        The dict is always populated — empty maps mean no history was found
        rather than an error. Callers treat missing months as zero or as a
        rendering hint depending on context.
    """
    out_util: dict[str, float] = {}
    expected_months: list[str] = []

    try:
        end_dt = datetime.strptime(end_date_str, "%Y-%m-%d")
    except (ValueError, TypeError):
        return {"utilization_monthly": {}, "missing_months": []}

    current_month = end_dt.replace(day=1)
    for i in range(1, months_back + 1):
        m = current_month - relativedelta(months=i)
        expected_months.append(m.strftime("%Y-%m"))

    # Walk newest-first; stop early once we've collected every needed month.
    needed = set(expected_months)
    for month, report in _iter_customer_reports(customer_id):
        if month not in needed:
            continue
        sentinel = (report.get("data") or {}).get("sentinel") or {}
        util = sentinel.get("utilization") or {}
        gb = util.get("total_gb")
        if isinstance(gb, (int, float)):
            out_util[month] = round(float(gb), 2)
        needed.discard(month)
        if not needed:
            break

    missing = sorted(needed)
    if missing:
        logger.info(
            "Sentinel history for customer=%s: %d/%d months loaded, missing=%s",
            customer_id, len(out_util), len(expected_months), missing,
        )

    return {
        "utilization_monthly": out_util,
        "missing_months": missing,
    }


def load_sentinel_data_from_saved_report(customer_id: str,
                                         start_date: str) -> Optional[dict]:
    """Return the full saved ``data["sentinel"]`` snapshot for a specific
    customer + month, or None if no matching saved report exists.

    Match key is ``customer_id`` + the YYYY-MM prefix of ``start_date`` — we
    don't require an exact day match because reports use month boundaries.

    Used when the requested report end_date is older than
    ``SENTINEL_RETENTION_DAYS``: live KQL would return empty, so we resurrect
    the previously-captured snapshot instead.
    """
    target_month = _month_key(start_date)
    if not target_month:
        return None
    for month, report in _iter_customer_reports(customer_id):
        if month == target_month:
            sentinel = (report.get("data") or {}).get("sentinel")
            return sentinel
    return None


def is_outside_sentinel_retention(end_date_str: str,
                                  retention_days: int = SENTINEL_RETENTION_DAYS,
                                  *, now: Optional[datetime] = None) -> bool:
    """Return True if ``end_date`` is older than Sentinel's retention window.

    When this is True, ``_collect_report_data`` should skip the live Sentinel
    call and substitute ``load_sentinel_data_from_saved_report`` instead. The
    ``now`` parameter is overridable for testing.
    """
    try:
        end_dt = datetime.strptime(end_date_str, "%Y-%m-%d")
    except (ValueError, TypeError):
        return False
    reference = now or datetime.now()
    age_days = (reference - end_dt).days
    return age_days > retention_days
