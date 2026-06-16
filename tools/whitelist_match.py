"""
Direct whitelist match — literal IOC substring lookup in the customer's
already-indexed Confluence chunks.

Why this exists:
Vector RAG embeds tabular reference data (whitelist tables of IPs / domains /
hosts) poorly. The chunks score below the cosine-similarity threshold against
alert-shaped queries even when the alert's IOC is literally present in the
table. This helper sidesteps embedding similarity by doing a *substring*
search across the customer's already-indexed chunks. Matches surface as a
"Direct Whitelist Match" section in the enrichment comment, separate from
vector RAG.

Reuses the Chroma store that ``rag_confluence_ingest`` already populates —
no extra Confluence API call, no extra embedding cost. Just a metadata-
filtered ``collection.get(...)`` plus an in-memory substring scan.

Killswitch ``WHITELIST_MATCH_ENABLED`` defaults OFF — flip on after smoke
test. Failure isolation: returns [] on any error, never raises.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# Don't substring-match IOC values shorter than this; short strings ("10.0",
# "ip", "test") would generate noise without value.
MIN_VALUE_LEN = int(os.environ.get("WHITELIST_MATCH_MIN_VALUE_LEN", "5"))


def find_direct_matches(customer_id: str, iocs: list[dict]) -> list[dict]:
    """Substring-search the customer's Confluence chunks for each IOC value.

    Returns list of matches: ``[{ioc, ioc_type, source, page_id, snippet}]``.
    Empty list when:
      - killswitch off
      - no customer_id
      - no iocs
      - Chroma store unavailable
      - no customer chunks indexed
      - no IOC value is long enough to substring-search safely
      - any unexpected error

    One match per IOC value max (de-duplicated by lowercase value).
    """
    if os.environ.get("WHITELIST_MATCH_ENABLED", "false").lower() != "true":
        return []
    if not customer_id or not iocs:
        return []

    try:
        from tools.rag_store import _get_collection
        col = _get_collection()
        if col is None:
            return []
        result = col.get(
            where={"customer_id": customer_id},
            include=["documents", "metadatas"],
        )
        documents = result.get("documents") or []
        metadatas = result.get("metadatas") or []
    except Exception:
        logger.exception("whitelist_match: Chroma fetch failed for customer %s", customer_id)
        return []

    if not documents:
        return []

    matches: list[dict] = []
    seen: set[str] = set()
    for ioc in iocs:
        value = (ioc.get("value") or "").strip()
        if not value or len(value) < MIN_VALUE_LEN:
            continue
        key = value.lower()
        if key in seen:
            continue
        for doc, meta in zip(documents, metadatas):
            doc_text = doc or ""
            if key not in doc_text.lower():
                continue
            # Snippet window around the match
            idx = doc_text.lower().find(key)
            start = max(0, idx - 80)
            end = min(len(doc_text), idx + len(value) + 80)
            snippet = " ".join(doc_text[start:end].split()).strip()
            source = (meta or {}).get("source") or "Confluence"
            file = (meta or {}).get("file") or ""
            page_id = ""
            if isinstance(file, str) and file.startswith("confluence:"):
                page_id = file.split(":", 1)[1]
            matches.append({
                "ioc": value,
                "ioc_type": (ioc.get("type") or "").lower(),
                "source": source,
                "page_id": page_id,
                "snippet": snippet,
            })
            seen.add(key)
            break  # one match per IOC value

    if matches:
        logger.info("whitelist_match: %d direct match(es) for customer %s",
                    len(matches), customer_id)
    return matches
