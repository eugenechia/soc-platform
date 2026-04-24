"""
SOCRadar threat intelligence client for SOC-Report.

Uses the SOCRadar REST API (direct API key auth) to pull:
  - Company alarms / incidents
  - Threat actors targeting the customer's industry
  - Recent high-severity CVEs

Required env vars:
  SOCRADAR_API_KEY     — SOCRadar API key
  SOCRADAR_COMPANY_ID  — Default company ID (can be overridden per-customer via config)

API reference: https://platform.socradar.com/docs/api/
"""

import os
import logging
from datetime import datetime, timedelta

import httpx

logger = logging.getLogger(__name__)

SOCRADAR_API_KEY = os.environ.get("SOCRADAR_API_KEY", "")
SOCRADAR_COMPANY_ID = os.environ.get("SOCRADAR_COMPANY_ID", "")
_BASE = "https://platform.socradar.com/api"


def _headers() -> dict:
    return {
        "API-Key": SOCRADAR_API_KEY,
        "Accept": "application/json",
    }


def _get(path: str, params: dict | None = None) -> dict | list | None:
    """Make a GET request to the SOCRadar API. Returns parsed JSON or None on failure."""
    if not SOCRADAR_API_KEY:
        logger.warning("SOCRADAR_API_KEY not configured — skipping API call.")
        return None
    url = f"{_BASE}/{path.lstrip('/')}"
    try:
        r = httpx.get(url, headers=_headers(), params=params or {}, timeout=30)
        if r.status_code == 401:
            logger.error("SOCRadar API: Unauthorized (check SOCRADAR_API_KEY).")
            return None
        if r.status_code == 404:
            logger.warning("SOCRadar API 404: %s", url)
            return None
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        logger.warning("SOCRadar API HTTP error %s: %s", e.response.status_code, url)
        return None
    except Exception as e:
        logger.warning("SOCRadar API request failed (%s): %s", type(e).__name__, e)
        return None


def _fetch_company_alarms(company_id: str, start_date: str, end_date: str) -> list[dict]:
    """Fetch company-specific alarms (incidents/detections) for the period."""
    data = _get(f"company/{company_id}/alarms", params={
        "start_date": start_date,
        "end_date": end_date,
        "limit": 20,
    })
    if not data:
        return []
    # Handle both list and {data: [...]} shapes
    if isinstance(data, list):
        return data[:20]
    if isinstance(data, dict):
        return (data.get("data") or data.get("alarms") or data.get("results") or [])[:20]
    return []


def _fetch_threat_actors(company_id: str) -> list[dict]:
    """Fetch threat actors targeting the customer's company or industry."""
    data = _get(f"company/{company_id}/threat-actors", params={"limit": 10})
    if not data:
        # Fallback: generic threat actor endpoint
        data = _get("threat/actors", params={"limit": 10})
    if not data:
        return []
    if isinstance(data, list):
        return data[:10]
    if isinstance(data, dict):
        return (data.get("data") or data.get("threat_actors") or data.get("results") or [])[:10]
    return []


def _fetch_cve_intel(start_date: str, end_date: str) -> list[dict]:
    """Fetch recent high-severity CVEs published in the report period."""
    data = _get("vulnerability/monitor", params={
        "start_date": start_date,
        "end_date": end_date,
        "severity": "critical,high",
        "limit": 10,
    })
    if not data:
        return []
    if isinstance(data, list):
        return data[:10]
    if isinstance(data, dict):
        return (data.get("data") or data.get("cves") or data.get("results") or [])[:10]
    return []


def _fetch_dark_web_alarms(company_id: str, start_date: str, end_date: str) -> list[dict]:
    """Fetch dark web mentions / leaked credential alerts for the company."""
    data = _get(f"company/{company_id}/dark-web", params={
        "start_date": start_date,
        "end_date": end_date,
        "limit": 10,
    })
    if not data:
        return []
    if isinstance(data, list):
        return data[:10]
    if isinstance(data, dict):
        return (data.get("data") or data.get("results") or [])[:10]
    return []


def check_ioc(value: str, ioc_type: str) -> dict | None:
    """Look up IOC reputation from SOCRadar.

    ioc_type: "ip" | "domain" | "hash"
    Returns {"score": int, "verdict": str, "raw": dict} or None on failure.

    Endpoint paths follow SOCRadar REST API conventions — verify against
    https://platform.socradar.com/docs/api/ if responses are empty.
    """
    endpoint_map = {
        "ip":     f"threat/ip/{value}/report",
        "domain": f"threat/domain/{value}/report",
        "hash":   f"threat/hash/{value}/report",
    }
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        logger.warning("check_ioc: unsupported ioc_type=%s", ioc_type)
        return None

    data = _get(endpoint)
    if not data:
        return None

    try:
        raw_score = data.get("score") or data.get("risk_score") or data.get("threat_score") or 0
        score = int(float(raw_score))
    except (TypeError, ValueError):
        score = 0

    threshold = int(os.environ.get("MALICIOUS_SCORE_THRESHOLD", "70"))
    verdict = "malicious" if score >= threshold else "clean"

    logger.info("SOCRadar IOC check: %s (%s) → score=%d verdict=%s", value, ioc_type, score, verdict)
    return {"score": score, "verdict": verdict, "raw": data}


def fetch_industry_data(industry: str, start_date: str, end_date: str) -> dict:
    """Fetch SOCRadar threat actors targeting a specific industry sector."""
    if not SOCRADAR_API_KEY:
        return {"threat_actors": []}

    data = _get("threat/actors", params={"industry": industry, "limit": 15})
    threat_actors: list = []
    if data:
        if isinstance(data, list):
            threat_actors = data[:15]
        elif isinstance(data, dict):
            threat_actors = (
                data.get("data") or data.get("threat_actors") or data.get("results") or []
            )[:15]

    logger.info("SOCRadar industry fetch (%s): %d threat actors", industry, len(threat_actors))
    return {"threat_actors": threat_actors}


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """
    Fetch SOCRadar threat intelligence for the report period.

    Returns:
        {
            "company_alarms": [...],
            "threat_actors": [...],
            "cve_intel": [...],
            "dark_web_alarms": [...],
        }
    All sub-lists may be empty if the API is unreachable or returns no data.
    """
    if not SOCRADAR_API_KEY:
        raise ValueError(
            "SOCRADAR_API_KEY not set. Add it to .env to enable SOCRadar integration."
        )

    company_id = (
        config.get("socradar_company_id")
        or SOCRADAR_COMPANY_ID
        or ""
    )

    if not company_id:
        logger.warning(
            "SOCRADAR_COMPANY_ID not set — company-specific endpoints will be skipped."
        )

    result: dict = {
        "company_alarms": [],
        "threat_actors": [],
        "cve_intel": [],
        "dark_web_alarms": [],
    }

    if company_id:
        result["company_alarms"] = _fetch_company_alarms(company_id, start_date, end_date)
        result["threat_actors"] = _fetch_threat_actors(company_id)
        result["dark_web_alarms"] = _fetch_dark_web_alarms(company_id, start_date, end_date)
    else:
        result["threat_actors"] = _fetch_threat_actors("")

    result["cve_intel"] = _fetch_cve_intel(start_date, end_date)

    logger.info(
        "SOCRadar fetch complete: %d alarms, %d actors, %d CVEs, %d dark-web",
        len(result["company_alarms"]),
        len(result["threat_actors"]),
        len(result["cve_intel"]),
        len(result["dark_web_alarms"]),
    )
    return result
