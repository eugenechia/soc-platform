"""
VirusTotal IOC reputation stub.

Add VT_API_KEY to .env (or Azure Key Vault) to activate.
Until then, all lookups return None and are skipped by the enrichment pipeline.

API reference: https://developers.virustotal.com/reference/overview
"""
import logging
import os

import httpx

logger = logging.getLogger(__name__)

_BASE = "https://www.virustotal.com/api/v3"


def _headers() -> dict | None:
    from tools.secrets import get_secret
    key = get_secret("VT_API_KEY")
    if not key:
        return None
    return {"x-apikey": key, "Accept": "application/json"}


def check_ioc(value: str, ioc_type: str) -> dict | None:
    """Look up IOC reputation from VirusTotal.

    ioc_type: "ip" | "domain" | "hash"
    Returns {"malicious_count": int, "total_engines": int, "reputation": int, "raw": dict} or None.
    `reputation` is VT's community-voted signed integer (negative = bad, positive = good); 0 when absent.
    """
    headers = _headers()
    if not headers:
        logger.debug("VT_API_KEY not configured — skipping VirusTotal check for %s", value)
        return None

    endpoint_map = {
        "ip":     f"ip_addresses/{value}",
        "domain": f"domains/{value}",
        "hash":   f"files/{value}",
    }
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return None

    try:
        r = httpx.get(f"{_BASE}/{endpoint}", headers=headers, timeout=30)
        if r.status_code == 404:
            return {"malicious_count": 0, "total_engines": 0, "reputation": 0, "raw": {}}
        if r.status_code >= 400:
            logger.warning("VirusTotal %s HTTP %s: %s", endpoint, r.status_code, r.text[:200])
            return None
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        total = sum(stats.values()) if stats else 0
        reputation = int(attrs.get("reputation", 0) or 0)
        return {
            "malicious_count": malicious,
            "total_engines": total,
            "reputation": reputation,
            "raw": data,
        }
    except Exception as e:
        logger.warning("VirusTotal check failed (%s): %s", type(e).__name__, e)
        return None
