"""
Phase 4b-rev (2026-06-15) — per-customer Confluence ingest.

Each customer record in ``data/customers.json`` carries its own list of
Confluence pages under ``confluence_pages``. The L1 Triage webhook resolves
a ticket to a customer (via Jira project key, see
``tools.customers.find_customer_by_jira_project``) and asks Chroma only for
chunks tagged with that ``customer_id``.

Why per-customer:
  * Single source of truth lives on the customer record alongside the
    customer's other configuration (Sentinel SP creds, Jira projects, etc.).
  * Retrieval can be strictly scoped so customer A's tickets never surface
    customer B's HRT/HVT list or escalation matrix.
  * UI lives on the customer onboarding/edit page — admins manage what their
    customer's L1 Triage sees from the same screen they edit credentials.

What was here before (Phase 4b global flat-file model) is gone. If anyone
re-runs an old client against the deprecated ``data/rag_confluence_pages.json``
file, they get a clear warning at startup and the file is otherwise ignored.

Hot retrieval path (``tools/rag_retrieval.py``) is unchanged in shape —
``customer_id`` is just one more parameter. The killswitch, the 5-second
timeout, and the "comment-only, never LLM Triage prompt" rule from Phase 4
still apply.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from bs4 import BeautifulSoup

from tools.confluence_client import extract_page_id, fetch_page
from tools.customers import get_customer, load_customers, save_customers
from tools.rag_chunking import chunk_text
from tools.rag_embed import embed_texts
from tools.rag_store import delete_by_file, upsert_chunks

logger = logging.getLogger(__name__)

_io_lock = threading.Lock()  # serialises customer-record reads/writes


# ─── Per-customer page-list accessors ────────────────────────────────────────

def load_pages_for_customer(cid: str) -> list[dict]:
    """Return the configured Confluence pages for a customer (empty list if
    the customer doesn't exist or has none)."""
    if not cid:
        return []
    c = get_customer(cid)
    if not c:
        return []
    return list(c.get("confluence_pages") or [])


def save_pages_for_customer(cid: str, pages: list[dict]) -> bool:
    """Replace the ``confluence_pages`` array on the given customer. Returns
    True on success."""
    if not cid:
        return False
    with _io_lock:
        customers = load_customers()
        idx = None
        for i, c in enumerate(customers):
            if c.get("id") == cid:
                idx = i
                break
        if idx is None:
            logger.warning("save_pages_for_customer: no customer %s", cid)
            return False
        customers[idx]["confluence_pages"] = list(pages or [])
        try:
            save_customers(customers)
            return True
        except Exception as e:
            logger.warning("save_pages_for_customer(%s) write failed (%s): %s",
                           cid, type(e).__name__, e)
            return False


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_key(page_id: str) -> str:
    """Chroma metadata.file value. Stable for the lifetime of the page so
    delete_by_file() cleanly purges the prior chunks before re-upsert."""
    return f"confluence:{page_id}"


def _source_tag(space_key: str) -> str:
    return f"Confluence:{space_key}" if space_key else "Confluence"


# ─── Page operations ──────────────────────────────────────────────────────────

def add_page(customer_id: str, url: str) -> dict:
    """Validate the URL, fetch page metadata from Confluence, persist a new
    entry on the customer record. Returns either the new entry or a dict
    with an ``error`` key for the HTTP route to map to a status code."""
    if not customer_id:
        return {"error": "customer_id is required"}
    if not get_customer(customer_id):
        return {"error": f"customer {customer_id} not found"}

    page_id = extract_page_id(url or "")
    if not page_id:
        return {"error": "Could not extract a Confluence page id from that URL. "
                          "URLs should look like https://<site>/wiki/spaces/<SPACE>/pages/<ID>/..."}

    fetched = fetch_page(page_id)
    if not fetched:
        return {"error": f"Could not fetch page {page_id} from Confluence — "
                          f"check the page exists and your credentials can read it."}

    with _io_lock:
        pages = load_pages_for_customer(customer_id)
        pages = [p for p in pages if str(p.get("page_id")) != page_id]
        entry = {
            "url": url.strip(),
            "page_id": page_id,
            "title": fetched.get("title") or f"(untitled page {page_id})",
            "space_key": fetched.get("space_key") or "",
            "last_synced_at": None,
            "chunk_count": 0,
            "last_error": None,
        }
        pages.append(entry)
        save_pages_for_customer(customer_id, pages)
    return entry


def remove_page(customer_id: str, page_id: str) -> bool:
    """Drop the entry from the customer record + purge its chunks from
    Chroma. Best-effort on both halves."""
    if not customer_id or not page_id:
        return False
    with _io_lock:
        pages = load_pages_for_customer(customer_id)
        before = len(pages)
        pages = [p for p in pages if str(p.get("page_id")) != str(page_id)]
        removed = len(pages) != before
        if removed:
            save_pages_for_customer(customer_id, pages)
    if removed:
        try:
            delete_by_file(_file_key(str(page_id)))
        except Exception as e:
            logger.warning("remove_page(%s, %s): Chroma delete failed: %s",
                           customer_id, page_id, e)
    return removed


# ─── Sync orchestration ───────────────────────────────────────────────────────

def _strip_xhtml(body_html: str) -> str:
    """Confluence storage format is XHTML. Strip tags to plain text, collapse
    whitespace, drop empties. BeautifulSoup handles malformed inputs without
    raising."""
    if not body_html:
        return ""
    try:
        soup = BeautifulSoup(body_html, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        lines = [ln.strip() for ln in text.splitlines()]
        cleaned: list[str] = []
        blank = False
        for ln in lines:
            if ln:
                cleaned.append(ln)
                blank = False
            elif not blank:
                cleaned.append("")
                blank = True
        return "\n".join(cleaned).strip()
    except Exception as e:
        logger.warning("Confluence _strip_xhtml failed (%s): %s — returning raw",
                       type(e).__name__, e)
        return body_html


def _chunk_id(customer_id: str, page_id: str, position: int) -> str:
    """Including the customer id in the chunk id keeps two customers from
    accidentally colliding if (improbably) they ever indexed the same
    public Confluence page."""
    return f"confluence-{customer_id}-{page_id}-{position}"


def _sync_one(customer_id: str, entry: dict) -> dict:
    """Refresh chunks for a single page entry on the given customer. Mutates
    `entry` in place with last_synced_at / chunk_count / last_error and
    returns it. Never raises."""
    page_id = str(entry.get("page_id") or "").strip()
    if not page_id:
        entry["last_error"] = "missing page_id"
        return entry

    fetched = fetch_page(page_id)
    if not fetched:
        entry["last_error"] = "Confluence fetch failed (see logs)"
        return entry

    if fetched.get("title"):
        entry["title"] = fetched["title"]
    if fetched.get("space_key") and not entry.get("space_key"):
        entry["space_key"] = fetched["space_key"]

    text = _strip_xhtml(fetched.get("body_html") or "")
    chunks = chunk_text(text)
    file_key = _file_key(page_id)

    if not chunks:
        delete_by_file(file_key)
        entry["last_synced_at"] = _now_iso()
        entry["chunk_count"] = 0
        entry["last_error"] = None
        return entry

    vectors = embed_texts(chunks)
    items: list[dict] = []
    source = _source_tag(entry.get("space_key") or fetched.get("space_key") or "")
    for pos, (chunk, vec) in enumerate(zip(chunks, vectors)):
        if vec is None:
            continue
        items.append({
            "id": _chunk_id(customer_id, page_id, pos),
            "text": chunk,
            "embedding": vec,
            "source": source,
            "file": file_key,
            "position": pos,
            "customer_id": customer_id,
        })

    if not items:
        entry["last_error"] = "every chunk failed to embed"
        return entry

    delete_by_file(file_key)
    written = upsert_chunks(items)

    entry["last_synced_at"] = _now_iso()
    entry["chunk_count"] = int(written)
    entry["last_error"] = None
    logger.info("Confluence sync: customer=%s page=%s (%s) — %d chunks",
                customer_id, page_id, entry.get("title", ""), written)
    return entry


def sync_for_customer(customer_id: str) -> dict:
    """Refresh every page registered against this customer. Returns:
        {customer_id, pages, chunks_total, succeeded, failed, pages_state}
    Per-page failures isolated. The whole function never raises."""
    if not customer_id:
        return {"error": "customer_id is required"}
    if not get_customer(customer_id):
        return {"error": f"customer {customer_id} not found"}

    with _io_lock:
        pages = load_pages_for_customer(customer_id)
    if not pages:
        return {"customer_id": customer_id, "pages": 0, "chunks_total": 0,
                "succeeded": 0, "failed": 0, "pages_state": []}

    succeeded = 0
    failed = 0
    chunks_total = 0
    for entry in pages:
        try:
            updated = _sync_one(customer_id, entry)
        except Exception as e:
            logger.exception("Confluence sync_one for customer=%s page=%s raised: %s",
                             customer_id, entry.get("page_id"), e)
            entry["last_error"] = f"{type(e).__name__}: {e}"
            updated = entry
        if updated.get("last_error"):
            failed += 1
        else:
            succeeded += 1
            chunks_total += int(updated.get("chunk_count") or 0)

    with _io_lock:
        save_pages_for_customer(customer_id, pages)

    summary = {
        "customer_id": customer_id,
        "pages": len(pages),
        "chunks_total": chunks_total,
        "succeeded": succeeded,
        "failed": failed,
        "pages_state": pages,
    }
    logger.info("Confluence sync summary for customer=%s: %d pages, %d chunks, %d failed",
                customer_id, summary["pages"], summary["chunks_total"], summary["failed"])
    return summary


# ─── Deprecated global flat-file warning (one-shot at first import) ───────────

def _warn_deprecated_global_file() -> None:
    """Phase 4b shipped on 2026-06-15 used data/rag_confluence_pages.json as a
    global flat list. Phase 4b-rev (same day, later) moved everything to
    per-customer storage. If the old file still exists with content, log a
    single WARNING listing the entries so the operator can manually re-add
    them on the appropriate customer record."""
    import os, json
    from tools.customers import BASE_DIR
    legacy = os.path.join(BASE_DIR, "data", "rag_confluence_pages.json")
    if not os.path.exists(legacy):
        return
    try:
        with open(legacy) as f:
            data = json.load(f)
        if not data:
            return
        logger.warning(
            "DEPRECATED: %s contains %d entries from the old global Confluence model. "
            "Per Phase 4b-rev, manage Confluence pages on each customer record at "
            "/admin/customers. These entries are NOT used: %s",
            legacy, len(data), [d.get("url") for d in data],
        )
    except Exception:
        # Don't crash at import; this warning is best-effort.
        pass


_warn_deprecated_global_file()


# ─── CLI passthrough ──────────────────────────────────────────────────────────

def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Sync Confluence RAG pages for a customer.")
    parser.add_argument("--customer", required=True, help="Customer id.")
    parser.add_argument("--add", help="Register a Confluence page URL.")
    parser.add_argument("--remove", help="Remove a registered page id.")
    parser.add_argument("--sync", action="store_true", help="Sync the customer's pages.")
    parser.add_argument("--list", action="store_true", help="Dump the customer's registered pages.")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.add:
        print(add_page(args.customer, args.add))
    if args.remove:
        print({"removed": remove_page(args.customer, args.remove)})
    if args.list:
        for p in load_pages_for_customer(args.customer):
            print(p)
    if args.sync:
        s = sync_for_customer(args.customer)
        s.pop("pages_state", None)
        print(s)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
