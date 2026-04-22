import os
import json
import logging

import httpx

logger = logging.getLogger(__name__)

SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "").rstrip("/")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")
SPLUNK_VERIFY_SSL = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() != "false"


def _headers() -> dict:
    return {"Authorization": f"Bearer {SPLUNK_TOKEN}"}


def _run_search(spl: str, earliest: str, latest: str, count: int = 200) -> list[dict]:
    """
    Execute a one-shot Splunk export search and return result rows as list of dicts.
    Uses the /services/search/jobs/export endpoint which streams NDJSON results.
    """
    url = f"{SPLUNK_HOST}/services/search/jobs/export"
    r = httpx.post(
        url,
        headers=_headers(),
        data={
            "search": f"search {spl}",
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
            "count": count,
        },
        verify=SPLUNK_VERIFY_SSL,
        timeout=30,
    )
    r.raise_for_status()

    rows = []
    for line in r.text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            result = obj.get("result")
            if result:
                rows.append(result)
        except json.JSONDecodeError:
            continue
    return rows


def _safe_search(spl: str, earliest: str, latest: str, count: int = 200) -> list[dict]:
    try:
        return _run_search(spl, earliest, latest, count)
    except Exception as e:
        logger.warning(f"Splunk search skipped ({type(e).__name__}): {e}")
        return []


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """Fetch security data from Splunk."""
    if not SPLUNK_HOST or not SPLUNK_TOKEN:
        raise ValueError(
            "Splunk credentials incomplete. Check SPLUNK_HOST and SPLUNK_TOKEN env vars."
        )

    earliest = f"{start_date}T00:00:00"
    latest = f"{end_date}T23:59:59"

    # 1. Event volume by index
    volume_rows = _safe_search(
        "index=* | stats count by index | sort -count | head 10",
        earliest, latest,
    )
    total_events = sum(int(r.get("count", 0)) for r in volume_rows)

    # 2. Top notable events from Splunk ES correlation searches
    notable_rows = _safe_search(
        "index=notable | stats count by rule_name | sort -count | head 15",
        earliest, latest,
    )

    # Fallback: if notable index is empty/absent, show top sourcetypes instead
    if not notable_rows:
        notable_rows = _safe_search(
            "index=* | stats count by sourcetype | sort -count | head 15",
            earliest, latest,
        )

    # 3. Severity breakdown of notable events
    severity_rows = _safe_search(
        "index=notable | stats count by urgency | sort -count",
        earliest, latest,
    )

    # 4. Top source IPs generating events (threat hunting context)
    top_src_rows = _safe_search(
        "index=* | stats count by src_ip | sort -count | head 10",
        earliest, latest,
    )

    return {
        "event_volume": {
            "total_events": total_events,
            "by_index": volume_rows,
        },
        "top_alerts": notable_rows,
        "severity_breakdown": severity_rows,
        "top_source_ips": top_src_rows,
    }
