"""
Phase 5b — Per-IOC historical lookup (2026-06-15).

For each malicious IOC in the current ticket, search the customer's Jira
project for prior tickets that mention the same observable. Renders a
``Previously flagged: N times — SCDM-100, SCDM-150, ...`` line under the
IOC's reputation block in the enrichment comment.

Complements Phase 3 ``Similar Alerts (past 24h)`` — that block answers
"how often does this RULE fire", this answers "how often does this IOC
appear across any rule". Same dedup logic (24h strict-match) still
applies to whole-ticket dedup; this is a longer historical view.

Design constraints (Phase 4-pattern):
- Killswitch ``IOC_HISTORY_ENABLED=false`` by default — ships dark.
- Module-level cache (60s default TTL) — same IOC across back-to-back
  webhooks doesn't hit Jira twice.
- Per-IOC budget cap (default 10 per ticket) — bounds added latency.
- Function never raises; None return = skip the line.
- Renders ONLY in the analyst comment. Not fed into the LLM Triage
  prompt (same conservative ladder as Phase 4 → 4c).
"""
from __future__ import annotations

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

_DEFAULT_MAX_RESULTS = 50
_DEFAULT_CACHE_TTL_S = 60.0
_DEFAULT_BUDGET_PER_TICKET = 10
_DEFAULT_TIMEOUT_S = 8.0

# Module-level cache: cache_key → (timestamp_monotonic, result_dict_or_None)
_cache: dict[str, tuple[float, dict | None]] = {}
_cache_lock = threading.Lock()


# ── Config knobs ──────────────────────────────────────────────────────────

def _enabled() -> bool:
    return os.environ.get("IOC_HISTORY_ENABLED", "false").strip().lower() == "true"


def _max_results() -> int:
    try:
        return max(1, int(os.environ.get("IOC_HISTORY_MAX_RESULTS",
                                          str(_DEFAULT_MAX_RESULTS))))
    except (TypeError, ValueError):
        return _DEFAULT_MAX_RESULTS


def _cache_ttl() -> float:
    try:
        return float(os.environ.get("IOC_HISTORY_CACHE_TTL_S",
                                     str(_DEFAULT_CACHE_TTL_S)))
    except (TypeError, ValueError):
        return _DEFAULT_CACHE_TTL_S


def budget_per_ticket() -> int:
    try:
        return max(0, int(os.environ.get("IOC_HISTORY_BUDGET_PER_TICKET",
                                           str(_DEFAULT_BUDGET_PER_TICKET))))
    except (TypeError, ValueError):
        return _DEFAULT_BUDGET_PER_TICKET


def _timeout_s() -> float:
    try:
        return float(os.environ.get("IOC_HISTORY_TIMEOUT_S",
                                     str(_DEFAULT_TIMEOUT_S)))
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT_S


# ── JQL helpers ───────────────────────────────────────────────────────────

def _jql_escape(s: str) -> str:
    """Escape backslashes + double quotes so a value lives safely inside a
    JQL phrase literal. Same pattern as tools.historical_alerts._jql_escape."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _build_jql(ioc_value: str, project: str, exclude_ticket_key: str) -> str:
    parts = [f'project = "{project}"', f'text ~ "{_jql_escape(ioc_value)}"']
    if exclude_ticket_key:
        parts.append(f'key != "{_jql_escape(exclude_ticket_key)}"')
    return " AND ".join(parts) + " ORDER BY created DESC"


# ── Public entry ──────────────────────────────────────────────────────────

def lookup_ioc_history(ioc_value: str,
                       exclude_ticket_key: str = "",
                       project: str | None = None) -> dict | None:
    """Killswitch-gated wrapper around :func:`fetch_ioc_history` — Phase 5b
    comment rendering goes through here so ``IOC_HISTORY_ENABLED`` keeps its
    original meaning. Alert Pattern Analysis calls ``fetch_ioc_history``
    directly (it has its own killswitch)."""
    if not _enabled():
        return None
    return fetch_ioc_history(ioc_value, exclude_ticket_key, project)


def fetch_ioc_history(ioc_value: str,
                      exclude_ticket_key: str = "",
                      project: str | None = None) -> dict | None:
    """Return historical Jira ticket appearances of an IOC.

    Args:
        ioc_value: the observable (IP, hash, domain, URL, hostname). Whitespace-
            stripped; values shorter than 3 chars are skipped (too noisy).
        exclude_ticket_key: the current ticket key — excluded from results so
            we don't count the current occurrence.
        project: Jira project key to search in. Defaults to
            ``JIRA_PROJECT_KEY`` env var (or "SCDM" if unset).

    Returns:
        ``{"count": int, "tickets": list[str], "true_positive": int,
        "false_positive": int, "unknown": int, "untriaged": int,
        "historically_benign": bool}`` when at least one prior ticket is
        found. ``tickets`` is newest-first, capped at IOC_HISTORY_MAX_RESULTS.
        ``historically_benign`` is True when ≥2 decided outcomes and zero
        True-Positives. ``None`` when no matches or any error path. Caller
        treats None as "skip the line".

    Module-level cache (TTL 60s) keyed by (ioc_value, exclude_ticket_key, project)
    avoids duplicate JQL calls when the same observable appears across
    back-to-back webhooks. This function MUST NOT raise.
    """
    val = (ioc_value or "").strip()
    if not val or len(val) < 3:
        return None

    project = (project or os.environ.get("JIRA_PROJECT_KEY", "SCDM")).strip()
    if not project:
        return None

    cache_key = f"{val}|{exclude_ticket_key}|{project}"
    ttl = _cache_ttl()
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and (now - cached[0]) < ttl:
            return cached[1]

    jql = _build_jql(val, project, exclude_ticket_key)
    max_results = _max_results()
    timeout_s = _timeout_s()

    def _do_search():
        from tools.jira_client import jira_search
        return jira_search(jql, max_results=max_results)

    # daemon-thread timeout pattern (same as rag_retrieval / kql_expansion)
    result_box: dict = {"value": None, "exc": None, "done": False}

    def _target():
        try:
            result_box["value"] = _do_search()
        except Exception as e:
            result_box["exc"] = e
        finally:
            result_box["done"] = True

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=timeout_s)

    if not result_box["done"]:
        logger.warning("ioc_history: timeout (%.1fs) for %r", timeout_s, val)
        with _cache_lock:
            _cache[cache_key] = (now, None)
        return None
    if result_box["exc"]:
        logger.warning("ioc_history: jira_search failed for %r (%s): %s",
                       val, type(result_box["exc"]).__name__, result_box["exc"])
        with _cache_lock:
            _cache[cache_key] = (now, None)
        return None

    pages = result_box["value"] or {}
    issues = pages.get("issues") or []
    keys = [iss.get("key") for iss in issues if iss.get("key")]
    if not keys:
        with _cache_lock:
            _cache[cache_key] = (now, None)
        return None

    # Outcome breakdown — labels ride along free on every jira_search hit
    # (see tools.jira_client._FIELDS), so this costs zero extra API calls.
    from tools.historical_alerts import _categorise, _label_names
    label_map = _label_names()
    counts = {"tp": 0, "fp": 0, "unknown": 0, "untriaged": 0}
    for iss in issues:
        if not iss.get("key"):
            continue
        labels = (iss.get("fields") or {}).get("labels") or []
        counts[_categorise(labels, label_map)] += 1
    decided = counts["tp"] + counts["fp"]

    result = {
        "count": len(keys),
        "tickets": keys,
        "true_positive": counts["tp"],
        "false_positive": counts["fp"],
        "unknown": counts["unknown"],
        "untriaged": counts["untriaged"],
        "historically_benign": decided >= 2 and counts["tp"] == 0,
    }
    with _cache_lock:
        _cache[cache_key] = (now, result)
    return result


def render_line(history: dict | None, max_keys_inline: int = 5) -> str | None:
    """Format the history dict as a one-line ``Previously flagged: ...`` string
    suitable for inline rendering under an IOC reputation block. Returns None
    when there's nothing useful to show (caller skips the line)."""
    if not history:
        return None
    count = int(history.get("count") or 0)
    if count <= 0:
        return None
    keys = list(history.get("tickets") or [])
    if not keys:
        return None
    visible = keys[:max_keys_inline]
    suffix = ""
    if count > max_keys_inline:
        remaining = count - max_keys_inline
        suffix = f" (+{remaining} more)"
    times_word = "time" if count == 1 else "times"
    line = f"  Previously flagged: {count} {times_word} — {', '.join(visible)}{suffix}"

    # Outcome breakdown (present when fetch parsed labels; absent on old
    # cached shapes — render degrades gracefully to the bare count line).
    outcome_bits = []
    fp = int(history.get("false_positive") or 0)
    tp = int(history.get("true_positive") or 0)
    unknown = int(history.get("unknown") or 0)
    if fp:
        outcome_bits.append(f"{fp} Benign-Positive")
    if tp:
        outcome_bits.append(f"{tp} True-Positive")
    if unknown:
        outcome_bits.append(f"{unknown} Unknown")
    if outcome_bits:
        line += f" ({', '.join(outcome_bits)})"
    if history.get("historically_benign"):
        line += " — recurring benign pattern"
    return line
