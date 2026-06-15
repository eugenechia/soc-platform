"""
Phase 4 — Hot-path RAG retrieval.

The single point of contact between the webhook flow and the RAG store. The
function ``retrieve_customer_context`` is called once per ticket, with a
hard timeout and a single try/except so it can NEVER raise into the caller.

Design constraint (from prior failure): the previous RAG attempt let errors
propagate and killed the whole triage pipeline. Every entry point here must
return ``None`` on failure rather than raising. The webhook handler treats
``None`` as "skip the Customer Context section" and continues normally.
"""
from __future__ import annotations

import logging
import os
import threading

logger = logging.getLogger(__name__)

_DEFAULT_TOP_K = 3
_DEFAULT_MIN_SCORE = 0.5
_DEFAULT_TIMEOUT_S = 5.0
_MIN_QUERY_LEN = 8  # below this, retrieval is pointless noise


def _enabled() -> bool:
    return os.environ.get("RAG_LOOKUP_ENABLED", "false").strip().lower() == "true"


def _timeout_s() -> float:
    try:
        return float(os.environ.get("RAG_TIMEOUT_SECONDS", str(_DEFAULT_TIMEOUT_S)))
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT_S


def _top_k() -> int:
    try:
        return int(os.environ.get("RAG_TOP_K", str(_DEFAULT_TOP_K)))
    except (TypeError, ValueError):
        return _DEFAULT_TOP_K


def _min_score() -> float:
    try:
        return float(os.environ.get("RAG_MIN_SCORE", str(_DEFAULT_MIN_SCORE)))
    except (TypeError, ValueError):
        return _DEFAULT_MIN_SCORE


def _run_with_timeout(fn, *, timeout_s: float):
    """Run a callable on a daemon thread with a hard timeout. Returns the
    callable's result, or None if it timed out or raised. We don't use
    signal.alarm because the webhook handler is already on a background
    thread (signal.alarm only works on the main thread)."""
    result: dict = {"value": None, "exc": None, "done": False}

    def _target():
        try:
            result["value"] = fn()
        except Exception as e:
            result["exc"] = e
        finally:
            result["done"] = True

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    if not result["done"]:
        return None, "timeout"
    if result["exc"] is not None:
        return None, f"{type(result['exc']).__name__}: {result['exc']}"
    return result["value"], None


def retrieve_customer_context(query: str,
                              customer_id: str | None = None) -> list[dict] | None:
    """Return up to RAG_TOP_K chunks above RAG_MIN_SCORE for the given query.

    Args:
        query: text concatenated from the Jira ticket summary + IOCs.
        customer_id: Phase 4b-rev (2026-06-15). When non-empty, retrieval is
            STRICTLY scoped to chunks whose ``customer_id`` metadata matches.
            When None or empty, retrieval is skipped — every webhook is
            expected to resolve a customer first. This prevents cross-
            customer context leakage and matches the per-customer model
            chosen in Phase 4b-rev.

    Returns:
        list of dicts with keys {text, source, file, position, customer_id,
        score} when at least one chunk clears the score threshold.
        None in every failure case (disabled, no customer, no provider,
        embed failure, store failure, timeout, no chunks above threshold).
        Caller treats None as "skip the Customer Context section".

    This function MUST NOT raise. Every exception is caught and logged.
    """
    if not _enabled():
        logger.info("RAG lookup disabled by env")
        return None

    if not query or len(query.strip()) < _MIN_QUERY_LEN:
        logger.info("RAG retrieval skipped: query too short (len=%d)",
                    len(query.strip()) if query else 0)
        return None

    cid = (customer_id or "").strip()
    if not cid:
        # Per-customer model: no customer → no retrieval. Logged so the
        # operator can spot orphan project keys quickly.
        logger.info("RAG retrieval skipped: no customer_id supplied "
                    "(ticket's project key didn't match any customer record)")
        return None

    timeout_s = _timeout_s()
    top_k = _top_k()
    min_score = _min_score()

    def _do_retrieval() -> list[dict]:
        from tools.rag_embed import embed_text
        from tools.rag_store import search

        vec = embed_text(query)
        if vec is None:
            return []
        hits = search(vec, top_k=top_k, where={"customer_id": cid})
        # Apply similarity threshold AFTER retrieval so the cutoff is
        # transparent in logs.
        return [h for h in hits if h.get("score", 0.0) >= min_score]

    try:
        result, err = _run_with_timeout(_do_retrieval, timeout_s=timeout_s)
    except Exception as e:
        logger.warning("RAG retrieval orchestrator failed (%s): %s",
                       type(e).__name__, e)
        return None

    if err:
        logger.warning("RAG retrieval failed: %s", err)
        return None
    if not result:
        logger.info("RAG retrieval: 0 chunks above threshold %.2f (top_k=%d)",
                    min_score, top_k)
        return None

    top_score = max((h.get("score", 0.0) for h in result), default=0.0)
    logger.info("RAG retrieval: %d chunks above threshold %.2f (top score %.2f)",
                len(result), min_score, top_score)
    return result
