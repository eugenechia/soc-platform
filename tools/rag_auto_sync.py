"""
Scheduled Confluence RAG re-sync (Phase 5d, 2026-06-16).

Iterates every customer that has Confluence pages configured on their record
and re-runs their sync against the live Confluence content. Triggered by
APScheduler at ``RAG_AUTO_SYNC_HOUR`` SGT daily, AND optionally at container
startup.

Why an immediate-on-startup sync matters: the Chroma vector store lives on
ephemeral ``/tmp/rag`` (see [[soc-platform-rag-ephemeral-chroma]] — SQLite +
SMB don't mix), so every container restart wipes the vectors but
``customers.json::confluence_pages[].chunk_count`` metadata stays. Without
an immediate sync, RAG retrieval returns 0 hits until either an analyst
clicks "Sync now" in the admin UI or the next 03:00 SGT cron fires.

Failure isolation: per-customer try/except. One customer's sync failure
never blocks the remaining customers.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

SGT = timezone(timedelta(hours=8))

_lock = threading.Lock()
_last_run_at: datetime | None = None
_last_run_summary: dict | None = None


def sync_all_customers(*, reason: str = "scheduled") -> dict:
    """Iterate every customer with Confluence pages and re-sync each.

    Returns a dict containing per-customer outcomes and aggregate stats.
    If another sync is already running, returns immediately with
    ``{"in_progress": True}`` rather than queuing.
    """
    global _last_run_at, _last_run_summary

    if not _lock.acquire(blocking=False):
        logger.info("RAG auto-sync: already in progress; ignoring %s trigger", reason)
        return {"in_progress": True, "reason": reason}

    try:
        started_at = datetime.now(SGT)
        logger.info("RAG auto-sync started (%s)", reason)

        # Imported here to avoid pulling chromadb at module-import time when
        # the killswitch may have disabled this codepath.
        from tools.customers import load_customers
        from tools.rag_confluence_ingest import sync_for_customer

        results: dict[str, dict] = {}
        ok = 0
        failed = 0
        skipped = 0

        for c in load_customers():
            cid = c.get("id", "")
            pages = c.get("confluence_pages") or []
            if not pages:
                results[cid] = {"status": "skipped", "reason": "no Confluence pages configured"}
                skipped += 1
                continue
            try:
                r = sync_for_customer(cid)
                results[cid] = {"status": "ok", **(r or {})}
                ok += 1
            except Exception as e:
                logger.exception("RAG auto-sync failed for customer %s", cid)
                results[cid] = {"status": "error", "error": str(e)[:200]}
                failed += 1

        finished_at = datetime.now(SGT)
        elapsed = (finished_at - started_at).total_seconds()

        summary = {
            "started_at": started_at.isoformat(timespec="seconds"),
            "finished_at": finished_at.isoformat(timespec="seconds"),
            "elapsed_seconds": elapsed,
            "reason": reason,
            "ok": ok,
            "failed": failed,
            "skipped": skipped,
            "per_customer": results,
        }

        _last_run_at = finished_at
        _last_run_summary = summary
        logger.info("RAG auto-sync done: ok=%d failed=%d skipped=%d elapsed=%.1fs",
                    ok, failed, skipped, elapsed)
        return summary
    finally:
        _lock.release()


def last_sync_at() -> str | None:
    """ISO8601 SGT timestamp of the last completed sync, or None."""
    if _last_run_at is None:
        return None
    return _last_run_at.isoformat(timespec="seconds")


def last_sync_summary() -> dict | None:
    """Full last-run summary dict, or None if no sync has completed yet."""
    return _last_run_summary
