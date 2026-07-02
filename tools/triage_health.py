"""L1 Triage dependency health check — powers the home-page status tile.

L1 Triage runs as a background pipeline off Jira webhooks; there is no
"triage page" and no persisted run-state. "Working or not" is therefore
defined as: are L1 Triage's two critical live dependencies reachable right
now —

  * the Jira API   (the pipeline fetches + labels tickets through it), and
  * the triage LLM (the model that produces the verdict + recommendation).

Both green  -> "operational"
One green   -> "degraded"
Both down   -> "down"

Results are cached for a short TTL so loading the home page does not hammer
Jira or spend LLM tokens on every request. Every check is failure-isolated:
a raised exception becomes a failed check, never a 500.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import threading
import time

import httpx

from tools.secrets import get_secret

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 60
_cache: dict = {"ts": 0.0, "result": None}
_lock = threading.Lock()

# Fail-loud schema-mismatch signal (recorded by enrichment.enrich_ticket when a
# public IP / file hash is present but 0 IOCs were extracted — i.e. a customer's
# entity field mapping is likely wrong). Ephemeral + in-memory + bounded, mirroring
# the cache design. Keyed by project so ops can spot broken mappings per customer.
_MAX_MISMATCH_PROJECTS = 50
_schema_mismatches: dict = {}   # project_key -> {"detail": str, "count": int, "last_ts": float}
_mismatch_lock = threading.Lock()


def record_schema_mismatch(project_key: str, detail: str) -> None:
    """Record a schema-mismatch event. Never raises (best-effort telemetry)."""
    pk = (project_key or "?").strip().upper()
    try:
        with _mismatch_lock:
            rec = _schema_mismatches.get(pk) or {"count": 0}
            rec["detail"] = detail
            rec["count"] = rec.get("count", 0) + 1
            rec["last_ts"] = time.time()
            _schema_mismatches[pk] = rec
            if len(_schema_mismatches) > _MAX_MISMATCH_PROJECTS:
                oldest = min(_schema_mismatches, key=lambda k: _schema_mismatches[k]["last_ts"])
                _schema_mismatches.pop(oldest, None)
    except Exception:  # noqa: BLE001 — telemetry must never break enrichment
        pass


def schema_mismatches() -> list[dict]:
    """Recent schema-mismatch flags, most-recent first."""
    with _mismatch_lock:
        return [{"project": pk, **rec} for pk, rec in
                sorted(_schema_mismatches.items(), key=lambda kv: kv[1]["last_ts"], reverse=True)]


def _check_jira() -> tuple[bool, str]:
    """Authenticated reachability of the Jira API via GET /myself."""
    base = os.environ.get("JIRA_URL", "").rstrip("/")
    if not base:
        return False, "JIRA_URL not configured"
    try:
        email = get_secret("JIRA_EMAIL")
        token = get_secret("JIRA_API_TOKEN")
        if not email or not token:
            return False, "Jira credentials not configured"
        creds = base64.b64encode(f"{email}:{token}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"}
        r = httpx.get(f"{base}/rest/api/3/myself", headers=headers, timeout=6)
        if r.status_code == 200:
            return True, "reachable"
        return False, f"HTTP {r.status_code}"
    except Exception as e:  # noqa: BLE001 — health check must never raise
        logger.warning("triage_health Jira check failed: %s", e)
        return False, type(e).__name__


def _check_llm() -> tuple[bool, str]:
    """Reachability of the configured triage LLM via a minimal completion.

    Mirrors the asyncio.run + max_completion_tokens pattern used by
    tools.triage / tools.recommendation so it exercises the real path.
    """
    try:
        from tools.llm_client import make_chat_client

        async def _ping() -> None:
            client, model = make_chat_client()
            await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "ping"}],
                max_completion_tokens=16,
                timeout=8,
            )

        asyncio.run(_ping())
        return True, "reachable"
    except Exception as e:  # noqa: BLE001 — health check must never raise
        logger.warning("triage_health LLM check failed: %s", e)
        return False, type(e).__name__


def _customer_readiness() -> tuple[list[dict], dict]:
    """Per-customer L1 Triage readiness (config-only, no live calls).

    Tier per onboarded customer:
      * inactive — no Jira project key, or none of its keys is in the
                   JIRA_ENRICHMENT_PROJECT allowlist → L1 Triage will NOT
                   process this customer's tickets.
      * limited  — triage-enabled but missing an enrichment layer
                   (Sentinel KQL and/or Confluence RAG). Core triage runs;
                   the AI just has less context.
      * active   — triage-enabled with BOTH Sentinel + RAG configured.
    """
    try:
        from tools.customers import load_customers
        customers = load_customers()
    except Exception as e:  # noqa: BLE001 — health check must never raise
        logger.warning("triage_health customer scan failed: %s", e)
        return [], {"active": 0, "limited": 0, "inactive": 0, "total": 0}

    allow_raw = os.environ.get("JIRA_ENRICHMENT_PROJECT", "")
    allow = {p.strip().upper() for p in allow_raw.split(",") if p.strip()}

    rows: list[dict] = []
    counts = {"active": 0, "limited": 0, "inactive": 0}
    for c in customers:
        keys = [
            (jp.get("project_key") or "").strip().upper()
            for jp in (c.get("jira_projects") or [])
            if (jp.get("project_key") or "").strip()
        ]
        # allow empty allowlist == every project is in scope
        triaged = bool(keys) and (not allow or any(k in allow for k in keys))
        sentinel = len(c.get("sentinel_workspaces") or []) > 0
        rag = len(c.get("confluence_pages") or []) > 0

        if not triaged:
            tier = "inactive"
            detail = "no Jira project key" if not keys else "project not in triage scope"
        elif sentinel and rag:
            tier = "active"
            detail = "Sentinel + RAG"
        else:
            tier = "limited"
            missing = []
            if not sentinel:
                missing.append("Sentinel")
            if not rag:
                missing.append("RAG")
            detail = "no " + " / ".join(missing)

        counts[tier] += 1
        rows.append({
            "name": c.get("name") or c.get("id") or "(unnamed)",
            "tier": tier,
            "detail": detail,
            "projects": keys,
        })

    _order = {"active": 0, "limited": 1, "inactive": 2}
    rows.sort(key=lambda r: (_order[r["tier"]], r["name"].lower()))
    return rows, {**counts, "total": len(customers)}


def triage_health(force: bool = False) -> dict:
    """Return the cached (or freshly computed) L1 Triage health snapshot.

    Shape:
        {
          "status": "operational" | "degraded" | "down",
          "checks": {
             "jira": {"ok": bool, "detail": str},
             "llm":  {"ok": bool, "detail": str},
          },
          "customers": [
             {"name": str, "tier": "active"|"limited"|"inactive",
              "detail": str, "projects": [str]},
             ...
          ],
          "summary": {"active": int, "limited": int, "inactive": int, "total": int},
          "checked_at": <epoch seconds>,
          "cached": bool,
        }

    The top-level "status"/"checks" are GLOBAL live health (Jira API + LLM) —
    if those are down, triage fails for every customer regardless of tier.
    The per-customer "customers" list is config-only readiness.
    """
    now = time.time()
    with _lock:
        cached = _cache["result"]
        if not force and cached and (now - _cache["ts"]) < _CACHE_TTL_SECONDS:
            return {**cached, "cached": True}

    jira_ok, jira_detail = _check_jira()
    llm_ok, llm_detail = _check_llm()

    if jira_ok and llm_ok:
        status = "operational"
    elif jira_ok or llm_ok:
        status = "degraded"
    else:
        status = "down"

    customers, summary = _customer_readiness()

    result = {
        "status": status,
        "checks": {
            "jira": {"ok": jira_ok, "detail": jira_detail},
            "llm": {"ok": llm_ok, "detail": llm_detail},
        },
        "customers": customers,
        "summary": summary,
        "schema_mismatches": schema_mismatches(),
        "checked_at": now,
        "cached": False,
    }
    with _lock:
        _cache["ts"] = now
        _cache["result"] = result
    return result
