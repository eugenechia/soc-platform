"""
Phase 4 — shared chunking for the RAG ingest paths.

Originally lived as ``_chunk_text`` in ``tools/rag_ingest.py``. Promoted to
its own module in Phase 4b so the Confluence source can chunk consistently
with the local-folder source. Behaviour preserved exactly:

  * Split on blank-line paragraph breaks first.
  * Hard-cap each paragraph at ``max_chars`` (default 500). Oversize
    paragraphs are split on the nearest sentence-ish boundary (period +
    space) when that boundary is at least halfway through the window;
    otherwise a hard character cut.
  * Drop empty chunks.

No external dependencies. Pure text in, list of strings out.
"""
from __future__ import annotations

_DEFAULT_MAX_CHUNK_CHARS = 500


def chunk_text(text: str, max_chars: int = _DEFAULT_MAX_CHUNK_CHARS) -> list[str]:
    if not text:
        return []
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    for p in paragraphs:
        if len(p) <= max_chars:
            chunks.append(p)
            continue
        remaining = p
        while remaining:
            if len(remaining) <= max_chars:
                chunks.append(remaining)
                break
            cut = remaining.rfind(". ", 0, max_chars)
            if cut == -1 or cut < max_chars // 2:
                cut = max_chars
            else:
                cut += 1  # include the period
            chunks.append(remaining[:cut].strip())
            remaining = remaining[cut:].strip()
    return [c for c in chunks if c]
