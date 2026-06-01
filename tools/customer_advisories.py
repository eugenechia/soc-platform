"""Per-customer advisory feeds for the GSOC monthly report.

Two artefact types live here, both manually maintained by GSOC analysts as
JSON files under `data/{customer_slug}/`:

  - `threat_analytics_advisories.json` — feeds §1.15 (Threat Analytics
    Hunting). Mirrors the Microsoft Defender XDR "Threat Analytics" article
    list with the hunt outcome recorded per article. Sample row:
        {"threat": "CVE-2025-54948 - Trend Micro Apex One",
         "report_type": "Vulnerability",
         "published": "2026-02-28",
         "hunting_result": "Nothing Found"}

  - `ioc_advisories.json` — feeds §1.17 (IOC Update). Tracks external
    advisories (e.g. MASNET MAS-Tx circulars) acted on. Sample row:
        {"advisory": "[MAS-Tx] New Circular Published: [FINTEL-2026-0227-01] ...",
         "date": "2026-02-02",
         "hunt_outcome": "No Hits for the IOCs in Customer Environment"}

Why files, not an API: MDE Threat Analytics articles aren't reliably exposed
via the public Defender / Graph Security APIs; advisory sources like MASNET
are customer-specific. A manual feed always works and never blocks the
report. An API-backed fetcher can be layered on top later without changing
the rendering side.
"""
import json
import logging
import os
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def customer_slug(name: str) -> str:
    """Normalise a display name into a filesystem-safe slug.

    "Chartered Asset Management (CAM)" → "chartered-asset-management-cam"
    "Logicalis"                        → "logicalis"
    """
    if not name:
        return ""
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


def _within_window(date_str: str, start: str, end: str) -> bool:
    """Return True if date_str ∈ [start, end] inclusive. All dates YYYY-MM-DD.

    Empty bounds mean "no filter on that side". Malformed dates are treated
    as out-of-window so we never crash the whole report on one bad row.
    """
    if not date_str:
        return False
    try:
        d = datetime.strptime(date_str[:10], "%Y-%m-%d")
    except ValueError:
        return False
    if start:
        try:
            if d < datetime.strptime(start, "%Y-%m-%d"):
                return False
        except ValueError:
            pass
    if end:
        try:
            if d > datetime.strptime(end, "%Y-%m-%d"):
                return False
        except ValueError:
            pass
    return True


def _read_json_list(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        logger.warning("Advisory file %s is not a JSON list — ignoring.", path)
        return []
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load %s: %s", path, exc)
        return []


def load_threat_analytics_advisories(customer_name: str,
                                     start_date: str = "",
                                     end_date: str = "") -> list:
    """Load §1.15 advisory rows for the customer, filtered to the report window."""
    slug = customer_slug(customer_name)
    if not slug:
        return []
    path = os.path.join(DATA_DIR, slug, "threat_analytics_advisories.json")
    rows = _read_json_list(path)
    return [
        r for r in rows
        if isinstance(r, dict) and _within_window(r.get("published", ""),
                                                  start_date, end_date)
    ]


def load_ioc_advisories(customer_name: str,
                        start_date: str = "",
                        end_date: str = "") -> list:
    """Load §1.17 advisory rows for the customer, filtered to the report window."""
    slug = customer_slug(customer_name)
    if not slug:
        return []
    path = os.path.join(DATA_DIR, slug, "ioc_advisories.json")
    rows = _read_json_list(path)
    return [
        r for r in rows
        if isinstance(r, dict) and _within_window(r.get("date", ""),
                                                  start_date, end_date)
    ]
