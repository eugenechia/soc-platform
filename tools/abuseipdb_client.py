"""
AbuseIPDB IP reputation stub.

Add ABUSEIPDB_API_KEY to .env (or Azure Key Vault) to activate.
Until then, all lookups return None and are skipped by the enrichment pipeline.
Only applies to IP-type IOCs.

API reference: https://docs.abuseipdb.com/#check-endpoint
"""
import logging

import httpx

logger = logging.getLogger(__name__)

_BASE = "https://api.abuseipdb.com/api/v2"


def _headers() -> dict | None:
    from tools.secrets import get_secret
    key = get_secret("ABUSEIPDB_API_KEY")
    if not key:
        return None
    return {"Key": key, "Accept": "application/json"}


def check_ip(ip: str) -> dict | None:
    """Look up IP reputation from AbuseIPDB.

    Returns {"confidence_score": int, "total_reports": int, "raw": dict} or None.
    """
    headers = _headers()
    if not headers:
        logger.debug("ABUSEIPDB_API_KEY not configured — skipping AbuseIPDB check for %s", ip)
        return None

    try:
        r = httpx.get(
            f"{_BASE}/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=30,
        )
        if r.status_code >= 400:
            logger.warning("AbuseIPDB %s HTTP %s: %s", ip, r.status_code, r.text[:200])
            return None
        data = r.json().get("data", {})
        return {
            "confidence_score": int(data.get("abuseConfidenceScore", 0)),
            "total_reports": int(data.get("totalReports", 0)),
            "raw": data,
        }
    except Exception as e:
        logger.warning("AbuseIPDB check failed (%s): %s", type(e).__name__, e)
        return None
