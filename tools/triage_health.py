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


def triage_health(force: bool = False) -> dict:
    """Return the cached (or freshly computed) L1 Triage health snapshot.

    Shape:
        {
          "status": "operational" | "degraded" | "down",
          "checks": {
             "jira": {"ok": bool, "detail": str},
             "llm":  {"ok": bool, "detail": str},
          },
          "checked_at": <epoch seconds>,
          "cached": bool,
        }
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

    result = {
        "status": status,
        "checks": {
            "jira": {"ok": jira_ok, "detail": jira_detail},
            "llm": {"ok": llm_ok, "detail": llm_detail},
        },
        "checked_at": now,
        "cached": False,
    }
    with _lock:
        _cache["ts"] = now
        _cache["result"] = result
    return result
