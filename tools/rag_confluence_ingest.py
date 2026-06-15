"""
Phase 4b — Confluence source ingest for the L1 Triage RAG store.

Maintains a small JSON file (``data/rag_confluence_pages.json``) listing the
Confluence pages the team has chosen to index. Provides three operations
backed by the existing Phase 4 RAG plumbing (Chroma + Azure OpenAI embed):

  * ``add_page(url)``    — register a page, fetch its metadata.
  * ``remove_page(id)``  — drop from list + delete its chunks from Chroma.
  * ``sync_all()``       — refresh every registered page (fetch + chunk +
                           embed + upsert). Per-page errors are isolated.

Hot retrieval path (tools/rag_retrieval.py) is NOT touched — Confluence
chunks land in the same Chroma collection as local-folder chunks, just
with a different ``source`` metadata tag. The killswitch and timeout still
apply unchanged.

Persisted state lives on the Azure Files share alongside data/customers.json
etc., written atomically via tempfile + rename so a crash mid-write can't
corrupt the list.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from typing import Optional

from bs4 import BeautifulSoup

from tools.confluence_client import extract_page_id, fetch_page
from tools.rag_chunking import chunk_text
from tools.rag_embed import embed_texts
from tools.rag_store import delete_by_file, upsert_chunks

logger = logging.getLogger(__name__)

_DEFAULT_DATA_DIR = "/app/data"
_PAGES_FILENAME = "rag_confluence_pages.json"

_io_lock = threading.Lock()  # serialises list reads/writes within a process


# ─── Persisted page list ──────────────────────────────────────────────────────

def _pages_file() -> str:
    base = os.environ.get("DATA_DIR", "").strip() or _DEFAULT_DATA_DIR
    return os.path.join(base, _PAGES_FILENAME)


def load_pages() -> list[dict]:
    """Load the persisted list. Returns []  if the file doesn't exist (first
    use) or can't be parsed."""
    path = _pages_file()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        logger.warning("Confluence pages file at %s is not a list — treating as empty", path)
        return []
    except Exception as e:
        logger.warning("Confluence pages load failed (%s): %s", type(e).__name__, e)
        return []


def save_pages(pages: list[dict]) -> bool:
    """Atomic write: tmpfile in the same dir, then rename. Returns True on
    success."""
    path = _pages_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        tmp_dir = os.path.dirname(path)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=tmp_dir,
                                          delete=False, suffix=".tmp") as tmp:
            json.dump(pages, tmp, indent=2, ensure_ascii=False)
            tmp_path = tmp.name
        os.replace(tmp_path, path)
        return True
    except Exception as e:
        logger.warning("Confluence pages save failed (%s): %s", type(e).__name__, e)
        return False


# ─── Page operations ──────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_key(page_id: str) -> str:
    """Chroma metadata.file value. Stable for the lifetime of the page; used
    by delete_by_file() to clean prior chunks before re-upsert."""
    return f"confluence:{page_id}"


def _source_tag(space_key: str) -> str:
    """Rendered as `[bracketed tag]` in the Jira comment."""
    return f"Confluence:{space_key}" if space_key else "Confluence"


def add_page(url: str) -> dict:
    """Validate the URL, fetch the page metadata from Confluence, persist a
    new entry. Returns either the new entry or a dict with an ``error``
    key (so the HTTP route can map to the right status code).
    """
    page_id = extract_page_id(url or "")
    if not page_id:
        return {"error": "Could not extract a Confluence page id from that URL. "
                          "URLs should look like https://<site>/wiki/spaces/<SPACE>/pages/<ID>/..."}

    fetched = fetch_page(page_id)
    if not fetched:
        return {"error": f"Could not fetch page {page_id} from Confluence — "
                          f"check the page exists and your credentials can read it."}

    with _io_lock:
        pages = load_pages()
        # Replace existing entry if the same id is already in the list (user
        # re-pasted to update the URL field, say).
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
        save_pages(pages)
    return entry


def remove_page(page_id: str) -> bool:
    """Drop the entry + purge its chunks from Chroma. Best-effort on both
    halves — the entry is removed even if the Chroma delete fails (the
    user can re-trigger by removing again)."""
    if not page_id:
        return False
    with _io_lock:
        pages = load_pages()
        before = len(pages)
        pages = [p for p in pages if str(p.get("page_id")) != str(page_id)]
        removed = len(pages) != before
        if removed:
            save_pages(pages)
    if removed:
        try:
            delete_by_file(_file_key(str(page_id)))
        except Exception as e:
            logger.warning("Confluence remove_page(%s): Chroma delete failed: %s",
                           page_id, e)
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
        # Confluence-specific noise: structured-macro params often produce
        # `ac:parameter` etc; remove script/style entirely.
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        # Collapse runs of blank lines so chunk_text's paragraph splitter
        # behaves naturally.
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


def _chunk_id(page_id: str, position: int) -> str:
    return f"confluence-{page_id}-{position}"


def _sync_one(entry: dict) -> dict:
    """Refresh chunks for a single page entry. Mutates `entry` in place
    with last_synced_at / chunk_count / last_error and returns it.
    Never raises — per-page failures are recorded into last_error and the
    outer sync_all moves on to the next page.
    """
    page_id = str(entry.get("page_id") or "").strip()
    if not page_id:
        entry["last_error"] = "missing page_id"
        return entry

    fetched = fetch_page(page_id)
    if not fetched:
        entry["last_error"] = "Confluence fetch failed (see logs)"
        return entry

    # Refresh display-y fields from the live page in case it was renamed.
    if fetched.get("title"):
        entry["title"] = fetched["title"]
    if fetched.get("space_key") and not entry.get("space_key"):
        entry["space_key"] = fetched["space_key"]

    text = _strip_xhtml(fetched.get("body_html") or "")
    chunks = chunk_text(text)
    if not chunks:
        # Empty page — wipe any old chunks and record state.
        delete_by_file(_file_key(page_id))
        entry["last_synced_at"] = _now_iso()
        entry["chunk_count"] = 0
        entry["last_error"] = None
        return entry

    vectors = embed_texts(chunks)
    items: list[dict] = []
    file_key = _file_key(page_id)
    source = _source_tag(entry.get("space_key") or fetched.get("space_key") or "")
    for pos, (chunk, vec) in enumerate(zip(chunks, vectors)):
        if vec is None:
            continue
        items.append({
            "id": _chunk_id(page_id, pos),
            "text": chunk,
            "embedding": vec,
            "source": source,
            "file": file_key,
            "position": pos,
        })

    if not items:
        entry["last_error"] = "every chunk failed to embed"
        return entry

    # Idempotent replace: drop prior chunks first.
    delete_by_file(file_key)
    written = upsert_chunks(items)

    entry["last_synced_at"] = _now_iso()
    entry["chunk_count"] = int(written)
    entry["last_error"] = None
    logger.info("Confluence sync: page %s (%s) — %d chunks written",
                page_id, entry.get("title", ""), written)
    return entry


def sync_all() -> dict:
    """Refresh every registered Confluence page. Per-page failures are
    isolated. Returns:
        {pages: int, chunks_total: int, succeeded: int, failed: int,
         pages_state: <updated entries>}
    """
    with _io_lock:
        pages = load_pages()
    if not pages:
        return {"pages": 0, "chunks_total": 0, "succeeded": 0, "failed": 0,
                "pages_state": []}

    succeeded = 0
    failed = 0
    chunks_total = 0
    for entry in pages:
        try:
            updated = _sync_one(entry)
        except Exception as e:
            # Defence in depth — _sync_one is meant not to raise, but this
            # is the failure-isolation boundary the user explicitly asked
            # for. Log + record + carry on.
            logger.exception("Confluence sync_one for %s raised: %s",
                             entry.get("page_id"), e)
            entry["last_error"] = f"{type(e).__name__}: {e}"
            updated = entry
        if updated.get("last_error"):
            failed += 1
        else:
            succeeded += 1
            chunks_total += int(updated.get("chunk_count") or 0)

    with _io_lock:
        save_pages(pages)

    summary = {
        "pages": len(pages),
        "chunks_total": chunks_total,
        "succeeded": succeeded,
        "failed": failed,
        "pages_state": pages,
    }
    logger.info("Confluence sync summary: %d pages, %d chunks, %d failed",
                summary["pages"], summary["chunks_total"], summary["failed"])
    return summary


# ─── CLI passthrough (handy from `python -m`) ────────────────────────────────

def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Sync Confluence RAG pages.")
    parser.add_argument("--add", help="Register a Confluence page URL.")
    parser.add_argument("--remove", help="Remove a registered page id.")
    parser.add_argument("--sync", action="store_true", help="Sync all registered pages.")
    parser.add_argument("--list", action="store_true", help="Dump the registered pages.")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.add:
        print(add_page(args.add))
    if args.remove:
        print({"removed": remove_page(args.remove)})
    if args.list:
        for p in load_pages():
            print(p)
    if args.sync:
        s = sync_all()
        s.pop("pages_state", None)
        print(s)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
