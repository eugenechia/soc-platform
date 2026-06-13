"""
Phase 4 — RAG ingest CLI.

Walks ``RAG_DOCS_DIR`` (default ``/app/data/rag_docs``), chunks each
Markdown or text file by paragraph (with a 500-char cap), embeds each
chunk via tools.rag_embed.embed_texts, and upserts to the Chroma store
via tools.rag_store.upsert_chunks.

Usage:
    python -m tools.rag_ingest [--dry-run] [--source <subdir>]

Subdirectory under RAG_DOCS_DIR becomes the chunk's ``source`` metadata
field (the tag rendered in `[brackets]` in the Jira comment). Example:

    /app/data/rag_docs/HRT-HVT/customer-acme.md   → source="HRT-HVT"
    /app/data/rag_docs/Whitelist/azure-infra.md   → source="Whitelist"

Idempotent — re-running on a file replaces its existing chunks. Files
removed from the source directory are NOT removed from the store; pass
``--prune`` to remove stale chunks (chunks whose file no longer exists).
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_DOCS_DIR = "/app/data/rag_docs"
_MAX_CHUNK_CHARS = 500
_VALID_EXTENSIONS = {".md", ".markdown", ".txt"}


def _docs_dir() -> Path:
    return Path(os.environ.get("RAG_DOCS_DIR", _DEFAULT_DOCS_DIR).strip() or _DEFAULT_DOCS_DIR)


def _chunk_id(file_path: str, position: int) -> str:
    """Stable id so re-ingest replaces a chunk in place rather than appending."""
    h = hashlib.sha1(f"{file_path}|{position}".encode()).hexdigest()[:16]
    return f"chunk-{h}"


def _chunk_text(text: str, max_chars: int = _MAX_CHUNK_CHARS) -> list[str]:
    """Paragraph-based chunking with a hard size cap. Splits on blank lines
    first, then further splits any oversize paragraph by sentence breaks
    (period + space) or, as a last resort, raw character cap."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    for p in paragraphs:
        if len(p) <= max_chars:
            chunks.append(p)
            continue
        # Soft-split on sentence-ish boundaries first.
        remaining = p
        while remaining:
            if len(remaining) <= max_chars:
                chunks.append(remaining)
                break
            # Find the last period+space within max_chars.
            cut = remaining.rfind(". ", 0, max_chars)
            if cut == -1 or cut < max_chars // 2:
                # No good sentence break — hard cut at max_chars.
                cut = max_chars
            else:
                cut += 1  # include the period
            chunks.append(remaining[:cut].strip())
            remaining = remaining[cut:].strip()
    return [c for c in chunks if c]


def _iter_source_files(root: Path, source_filter: str | None = None):
    """Yield (file_path, source_tag) pairs. source_tag is the first directory
    under root (or "" if file lives directly in root)."""
    if not root.exists():
        logger.warning("RAG ingest: docs dir does not exist: %s", root)
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _VALID_EXTENSIONS:
            continue
        rel = path.relative_to(root)
        parts = rel.parts
        source = parts[0] if len(parts) > 1 else ""
        if source_filter and source != source_filter:
            continue
        yield path, source


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.warning("RAG ingest: failed to read %s (%s): %s", path, type(e).__name__, e)
        return ""


def ingest(source_filter: str | None = None, dry_run: bool = False) -> dict:
    """Ingest the docs tree. Returns a summary dict suitable for the admin
    UI response.

    dry_run=True skips both embedding API calls and store writes — useful
    for sanity-checking what would be ingested without spending tokens.
    """
    from tools.rag_embed import embed_texts
    from tools.rag_store import delete_by_file, upsert_chunks

    root = _docs_dir()
    files_processed = 0
    chunks_total = 0
    chunks_embedded = 0
    chunks_skipped = 0

    for path, source in _iter_source_files(root, source_filter):
        text = _read_file(path)
        if not text.strip():
            continue
        chunks = _chunk_text(text)
        if not chunks:
            continue
        files_processed += 1
        chunks_total += len(chunks)
        file_path_str = str(path)

        if dry_run:
            logger.info("RAG ingest dry-run: %s — %d chunks (source=%s)",
                        file_path_str, len(chunks), source or "(root)")
            continue

        # Embed first so a partial-failure batch can be rejected before we
        # mutate the store.
        vectors = embed_texts(chunks)
        items = []
        for pos, (chunk, vec) in enumerate(zip(chunks, vectors)):
            if vec is None:
                chunks_skipped += 1
                continue
            items.append({
                "id": _chunk_id(file_path_str, pos),
                "text": chunk,
                "embedding": vec,
                "source": source,
                "file": file_path_str,
                "position": pos,
            })

        if not items:
            logger.warning("RAG ingest: every chunk failed embedding for %s — skipping write",
                           file_path_str)
            continue

        # Idempotent replace — drop any prior chunks for this file before
        # writing the new ones, so a shrunken file doesn't leave orphans.
        delete_by_file(file_path_str)
        written = upsert_chunks(items)
        chunks_embedded += written
        logger.info("RAG ingest: %s — %d chunks (source=%s)",
                    file_path_str, written, source or "(root)")

    summary = {
        "files_processed": files_processed,
        "chunks_total": chunks_total,
        "chunks_embedded": chunks_embedded,
        "chunks_skipped": chunks_skipped,
        "dry_run": dry_run,
        "docs_dir": str(root),
        "source_filter": source_filter or "",
    }
    logger.info("RAG ingest summary: %s", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-ingest RAG knowledge documents.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Walk the docs tree and chunk, but skip embedding API and store writes.")
    parser.add_argument("--source", default=None,
                        help="Limit ingest to a single source subdirectory (e.g. HRT-HVT).")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    summary = ingest(source_filter=args.source, dry_run=args.dry_run)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
