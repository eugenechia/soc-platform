"""
SOCRadar REST client — covers two distinct paths:

(1) Per-IOC reputation enrichment for L1 Triage
    Endpoint:  GET /api/threat/analysis?key=<KEY>&entity=<value>
               (302-redirects to /api/threat/analysis/result?analysis_uid=…)
    Auth:      api key passed as query parameter `?key=`
    Key name:  SOCRadar product label "Threat Analysis API" — wired here
               via the env var SOCRADAR_THREAT_ANALYSIS_KEY.
    Confirmed working end-to-end 2026-05-08 against 185.156.73.62 — returned
    findings from Kaspersky, Blocklist.de, Maltiverse, Binary Defense, etc.

(2) Report generation — company-scoped data
    a. Company alarms:      GET /api/company/{id}/incidents/v4
       Auth: `Api-Key` header. Env: SOCRADAR_COMPANY_KEY.
       (Was historically misnamed SOCRADAR_IOC_ENRICHMENT_KEY — the new
        var is the canonical name. The old var is still read as a fallback
        so a deployment with only the legacy var keeps working through one
        rev cycle.)
    b. Dark web monitoring: GET /api/company/{id}/dark-web-monitoring/{sub}/v2
       Auth: `Api-Key` header. Env: SOCRADAR_IDENTITY_INTELLIGENCE_KEY.
    c. Threat actor / CVE / threat-feed:
       Endpoints not yet publicly documented. Keys staged in env
       (SOCRADAR_THREAT_ACTOR_KEY, SOCRADAR_CTI_VULNERABILITY_KEY,
       SOCRADAR_THREAT_FEED_KEY) for future wiring once SOCRadar support
       confirms the paths.

Required env (resolved at call-time via tools.secrets.get_secret):
  SOCRADAR_COMPANY_ID                  — non-secret, fine on the container
  SOCRADAR_THREAT_ANALYSIS_KEY         — for L1 Triage IOC reputation
  SOCRADAR_COMPANY_KEY                 — for /incidents/v4 (legacy alias:
                                         SOCRADAR_IOC_ENRICHMENT_KEY)
  SOCRADAR_IDENTITY_INTELLIGENCE_KEY   — for /dark-web-monitoring/*
  SOCRADAR_THREAT_ACTOR_KEY            — staged, endpoint TBD
  SOCRADAR_CTI_VULNERABILITY_KEY       — staged, endpoint TBD
  SOCRADAR_THREAT_FEED_KEY             — staged, endpoint TBD
"""

import os
import time
import logging
import threading
from collections import deque

import httpx

logger = logging.getLogger(__name__)


# ── /threat/analysis rate-limit pacer ────────────────────────────────────────
# SOCRadar enforces ~5 requests per 60-second window on /threat/analysis
# (verified empirically 2026-05-08 — first 5 calls succeed, 6th returns 429
# with Retry-After ~50s). With 10-20 IOCs/ticket common in L1 Triage, we'd
# 429 on most tickets without throttling. The pacer keeps us strictly below
# the limit by sleeping inside check_ioc() before each call.
#
# Single-replica deploy means a process-local deque is sufficient. If we ever
# split workers, swap this for a Redis-backed limiter.
_RATE_LIMIT_CALLS = 5
_RATE_LIMIT_WINDOW_S = 65  # 60s + 5s safety margin
_recent_calls: deque = deque(maxlen=_RATE_LIMIT_CALLS)
_pacer_lock = threading.Lock()


def _pace_threat_analysis_call() -> None:
    """Block until a /threat/analysis call is allowed under the rate limit.
    Called inside check_ioc() before the HTTP request."""
    with _pacer_lock:
        if len(_recent_calls) < _RATE_LIMIT_CALLS:
            _recent_calls.append(time.monotonic())
            return
        oldest = _recent_calls[0]
        wait = (_RATE_LIMIT_WINDOW_S - (time.monotonic() - oldest))
        if wait > 0:
            logger.info("SOCRadar pacer: sleeping %.1fs to stay under %d/min",
                        wait, _RATE_LIMIT_CALLS)
            time.sleep(wait)
        _recent_calls.append(time.monotonic())

_BASE = "https://platform.socradar.com/api"


# ── Per-product key resolvers ────────────────────────────────────────────────
# Each function returns the key for the SOCRadar product it's named after.
# Resolved at call time (NOT at import) so KV-backed deployments work without
# the secret being smuggled into the image via .env. Falls back to os.environ
# for dev/CI where load_dotenv() has populated the process env.

def _api_key_threat_analysis() -> str:
    """Key for /threat/analysis — the L1 Triage IOC reputation endpoint.
    SOCRadar product: 'Threat Analysis API' (also referred to as ThreatFusion)."""
    from tools.secrets import get_secret
    return (get_secret("SOCRADAR_THREAT_ANALYSIS_KEY")
            or os.environ.get("SOCRADAR_THREAT_ANALYSIS_KEY", ""))


def _api_key_company() -> str:
    """Key for /company/{id}/incidents/v4 (company alarms).
    SOCRadar product: 'Company API'. The legacy env name was
    SOCRADAR_IOC_ENRICHMENT_KEY (a misnomer — that key never authorised IOC
    enrichment). New deployments should set SOCRADAR_COMPANY_KEY; the legacy
    name is still consulted as a fallback so existing manifests keep working
    until they're updated."""
    from tools.secrets import get_secret
    return (get_secret("SOCRADAR_COMPANY_KEY")
            or get_secret("SOCRADAR_IOC_ENRICHMENT_KEY")
            or os.environ.get("SOCRADAR_COMPANY_KEY")
            or os.environ.get("SOCRADAR_IOC_ENRICHMENT_KEY", ""))


def _api_key_dark_web() -> str:
    """Key for /company/{id}/dark-web-monitoring/* — labelled `Identity Intelligence API`."""
    from tools.secrets import get_secret
    return (get_secret("SOCRADAR_IDENTITY_INTELLIGENCE_KEY")
            or os.environ.get("SOCRADAR_IDENTITY_INTELLIGENCE_KEY", ""))


def _company_id() -> str:
    """SOCRadar company ID. Non-secret — usually a plain env var on the
    Container App."""
    from tools.secrets import get_secret
    return get_secret("SOCRADAR_COMPANY_ID") or os.environ.get("SOCRADAR_COMPANY_ID", "")


def _get(path: str, api_key: str, params: dict | None = None) -> dict | list | None:
    """GET with the SOCRadar Api-Key header. Used for company-scoped endpoints
    (alarms, dark-web). Returns parsed JSON or None on any failure."""
    if not api_key:
        return None
    url = f"{_BASE}/{path.lstrip('/')}"
    headers = {"Api-Key": api_key, "Accept": "application/json"}
    try:
        r = httpx.get(url, headers=headers, params=params or {}, timeout=30)
        if r.status_code == 401:
            logger.error("SOCRadar API: Unauthorized for %s — wrong key for this endpoint?", path)
            return None
        if r.status_code == 404:
            logger.warning("SOCRadar API 404: %s", url)
            return None
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning("SOCRadar API GET %s failed (%s): %s", path, type(e).__name__, e)
        return None


def _extract_data_list(envelope) -> list:
    """SOCRadar v4-style envelope:
        {"data": {"data": [...], "total_data_count": N},
         "is_success": true, "message": "Success", "response_code": 200}
    Some endpoints return is_success=false with HTTP 200 (e.g. blackmarket
    when the customer has no botnet-data findings) — those resolve to []."""
    if not envelope:
        return []
    if isinstance(envelope, list):
        return envelope
    if isinstance(envelope, dict):
        if envelope.get("is_success") is False:
            return []
        inner = envelope.get("data")
        if isinstance(inner, list):
            return inner
        if isinstance(inner, dict):
            return inner.get("data") or []
    return []


# ── Per-section fetchers ─────────────────────────────────────────────────────

def _fetch_company_alarms(company_id: str, start_date: str, end_date: str) -> list[dict]:
    """Fetch the company's alarms (incidents/detections) for the period.
    Endpoint:  GET /api/company/{id}/incidents/v4
    Auth:      Api-Key header — Company API key."""
    raw = _get(
        f"company/{company_id}/incidents/v4",
        api_key=_api_key_company(),
        params={"start_date": start_date, "end_date": end_date, "limit": 50},
    )
    return _extract_data_list(raw)[:20]


def _fetch_threat_actors(company_id: str) -> list[dict]:
    """Threat actor intelligence. NOT YET WIRED — the endpoint path for the
    SOCRadar `Threat Actor Malware Ransomware API` key is not publicly
    documented and probes against the company-scoped patterns returned no
    matches. The key is staged in env (SOCRADAR_THREAT_ACTOR_KEY) ready to
    use once SOCRadar support confirms the path.

    Returns an empty list so the report's threat-actor table renders as
    'no data available' rather than failing."""
    logger.info("SOCRadar threat_actors: endpoint not yet confirmed — returning []")
    return []


def _fetch_cve_intel(start_date: str, end_date: str) -> list[dict]:
    """CVE / vulnerability intel. NOT YET WIRED — same gap as
    `_fetch_threat_actors`. Key staged as SOCRADAR_CTI_VULNERABILITY_KEY."""
    logger.info("SOCRadar cve_intel: endpoint not yet confirmed — returning []")
    return []


def _fetch_dark_web_alarms(company_id: str, start_date: str, end_date: str) -> list[dict]:
    """Fetch dark-web mentions across the 5 SOCRadar dark-web sub-categories.

    Endpoints: GET /api/company/{id}/dark-web-monitoring/{sub}/v2
                where sub ∈ botnet-data | blackmarket | suspicious-content
                            | pii-exposure | im-content
    Auth:      Api-Key header — Identity Intelligence key.

    Each item returned is annotated with `source_category` so downstream
    rendering can group / filter. We cap at 5 per sub-category and 20 total
    to keep the LLM-fed data within budget."""
    api_key = _api_key_dark_web()
    if not api_key:
        return []
    out: list[dict] = []
    for sub in ("botnet-data", "blackmarket", "suspicious-content",
                "pii-exposure", "im-content"):
        raw = _get(
            f"company/{company_id}/dark-web-monitoring/{sub}/v2",
            api_key=api_key,
            params={"start_date": start_date, "end_date": end_date, "limit": 10},
        )
        items = _extract_data_list(raw)
        for item in items[:5]:
            if isinstance(item, dict):
                item.setdefault("source_category", sub)
                out.append(item)
        if len(out) >= 20:
            break
    return out[:20]


# ── L1 Triage IOC reputation ────────────────────────────────────────────────
# Different endpoint family from the company-scoped ones above. Different
# auth method too (query param vs header). Confirmed working 2026-05-08 with
# the SOCRadar 'Threat Analysis API' key.

# Categories that score as "malicious" when present in the findings list.
# Anything else (e.g. "Whitelisted", "Reputation", an empty findings list) is
# treated as benign / unknown.
_MALICIOUS_CATEGORIES = {
    "Attackers", "Phishing", "Botnet & Malware",
    "Malware", "Bad Reputation", "Brute Force",
    "Spam", "Anonymizers", "C2",
}

# SOCRadar's `entity_type` parameter for /threat/analysis. We let SOCRadar
# infer the type from the value, but keeping this map lets the report show
# what was queried.
_IOC_TYPE_TO_LABEL = {
    "ip": "IP",
    "domain": "Domain",
    "hash": "File Hash",
}


def _ioc_score_from_findings(findings: list) -> tuple[int, list[str]]:
    """Reduce SOCRadar findings into a malicious score (0-100) + matched
    categories. Score is the max `reliability` across findings whose
    `main_category` is malicious. No malicious findings → score 0."""
    if not findings:
        return 0, []
    score = 0
    matched: list[str] = []
    seen_cats: set[str] = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        cat = (f.get("extra_info") or {}).get("main_category") or f.get("main_category")
        if not cat or cat not in _MALICIOUS_CATEGORIES:
            continue
        if cat not in seen_cats:
            matched.append(cat)
            seen_cats.add(cat)
        try:
            r = int(f.get("reliability") or 0)
        except (TypeError, ValueError):
            r = 0
        if r > score:
            score = r
    return score, matched


def check_ioc(value: str, ioc_type: str) -> dict | None:
    """Per-IOC reputation lookup via SOCRadar Threat Analysis API.

    Endpoint: GET /api/threat/analysis?key=<KEY>&entity=<value>
              The endpoint 302-redirects to
              /api/threat/analysis/result?analysis_uid=…  — httpx follows it.
    Auth:     query param `?key=`. Api-Key header is NOT used here.

    Returns:
        None if not configured / network error.
        Otherwise a dict shaped like the other reputation engines:
            {
              "source": "socradar",
              "score": int (0..100),                # max reliability across malicious findings
              "verdict": "malicious"|"clean",
              "categories": [str],                  # de-duped main_category list
              "top_findings": [{...}, ...],         # up to 3, sorted by reliability desc
              "remaining_daily_credit": int|None,   # log + warn if low
              "queried_as": str,                    # "IP" / "Domain" / "File Hash"
            }

    The function never raises — failures degrade to None so the rest of the
    L1 Triage chain (VirusTotal + AbuseIPDB) carries the verdict."""
    api_key = _api_key_threat_analysis()
    if not api_key:
        return None
    if not value:
        return None

    url = f"{_BASE}/threat/analysis"

    def _do_call() -> httpx.Response | None:
        _pace_threat_analysis_call()
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as c:
                return c.get(url, params={"key": api_key, "entity": value})
        except Exception as e:
            logger.warning("SOCRadar IOC lookup network error for %s (%s): %s",
                           value, type(e).__name__, e)
            return None

    r = _do_call()
    if r is None:
        return None

    # 429 → honour Retry-After, retry once. After that, give up so the rest
    # of the L1 Triage chain (VT + AbuseIPDB) carries the verdict.
    if r.status_code == 429:
        try:
            retry_after = int(r.headers.get("retry-after", "30"))
        except ValueError:
            retry_after = 30
        retry_after = min(max(retry_after, 5), 65)
        logger.warning("SOCRadar /threat/analysis: 429 (entity=%s) — sleeping %ds before retry",
                       value, retry_after)
        time.sleep(retry_after)
        # Drain pacer history — after the forced wait the window has reset.
        with _pacer_lock:
            _recent_calls.clear()
        r = _do_call()
        if r is None or r.status_code == 429:
            logger.warning("SOCRadar /threat/analysis: 429 again after retry (entity=%s) — giving up",
                           value)
            return None

    if r.status_code == 401:
        logger.error("SOCRadar /threat/analysis: 401 Unauthorized — key invalid for this product")
        return None
    try:
        r.raise_for_status()
        envelope = r.json()
    except Exception as e:
        logger.warning("SOCRadar IOC lookup parse error for %s (%s): %s",
                       value, type(e).__name__, e)
        return None

    if not isinstance(envelope, dict):
        return None

    data = envelope.get("data") or {}
    findings = data.get("findings") or []

    score, categories = _ioc_score_from_findings(findings)
    verdict = "malicious" if score > 0 else "clean"

    # Capture top-3 findings for the Jira comment.
    sortable = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        try:
            r_val = int(f.get("reliability") or 0)
        except (TypeError, ValueError):
            r_val = 0
        sortable.append((r_val, f))
    sortable.sort(key=lambda pair: pair[0], reverse=True)
    top_findings = []
    for r_val, f in sortable[:3]:
        extra = f.get("extra_info") or {}
        top_findings.append({
            "category": extra.get("main_category") or f.get("main_category"),
            "source": f.get("source_name") or extra.get("maintainer_name"),
            "reliability": r_val,
            "first_seen": extra.get("first_seen_date"),
            "last_seen": extra.get("last_seen_date"),
        })

    credit = data.get("credit_details") or {}
    remaining_daily = credit.get("remaining_daily_credit")
    if isinstance(remaining_daily, int) and remaining_daily < 20:
        logger.warning("SOCRadar /threat/analysis daily credit low: %d remaining", remaining_daily)

    return {
        "source": "socradar",
        "score": int(score),
        "verdict": verdict,
        "categories": categories,
        "top_findings": top_findings,
        "remaining_daily_credit": remaining_daily,
        "queried_as": _IOC_TYPE_TO_LABEL.get(ioc_type, ioc_type),
    }


def fetch_industry_data(industry: str, start_date: str, end_date: str) -> dict:
    """Industry-scoped threat-actor feed. NOT YET WIRED (same gap as
    `_fetch_threat_actors`). Returns {"threat_actors": []} so the
    Industry Threat Landscape section renders the no-data fallback."""
    logger.info("SOCRadar industry_data (%s): endpoint not yet known — returning empty", industry)
    return {"threat_actors": []}


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """Fetch SOCRadar threat intelligence for a customer's report period.

    Returns:
        {
            "company_alarms": [...],     # populated when Company key is set
            "threat_actors": [],          # endpoint not yet confirmed
            "cve_intel": [],              # endpoint not yet confirmed
            "dark_web_alarms": [...],     # populated when Identity Intelligence key is set
        }
    """
    company_id = (
        config.get("socradar_company_id")
        or _company_id()
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
        "SOCRadar fetch complete: %d alarms, %d actors, %d CVEs, %d dark-web (company_id=%s)",
        len(result["company_alarms"]),
        len(result["threat_actors"]),
        len(result["cve_intel"]),
        len(result["dark_web_alarms"]),
        company_id or "<unset>",
    )
    return result
