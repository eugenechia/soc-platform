"""
Asset-inventory match (2026-06-19) — does the ticket's affected host/IP appear
in the customer's documented Inventory Assets, and how critical is it?

Same rationale as ``whitelist_match``: an asset inventory is TABULAR data that
vector RAG embeds poorly, so a ticket-summary query won't reliably retrieve the
right row even when the affected host is literally in the table. We sidestep
embeddings with a substring scan over the customer's already-indexed Confluence
chunks, capture the matched row, and heuristically read off a criticality
signal.

Distinct from whitelist_match by PURPOSE:
  - whitelist_match → "is this IOC explicitly benign/allow-listed?" (suppression)
  - asset_inventory → "is this a known / crown-jewel asset?"          (escalation)

The result feeds the Phase 6 recommendation as ASSET CONTEXT so the AI can say
"...the affected host is a documented production database (criticality: HIGH)".

Killswitch ``ASSET_INVENTORY_ENABLED`` defaults OFF. Failure isolation: returns
[] on any error, never raises. No extra Confluence API call or embedding cost —
reuses the Chroma store ``rag_confluence_ingest`` already populated.
"""
from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

MIN_VALUE_LEN = int(os.environ.get("ASSET_INVENTORY_MIN_VALUE_LEN", "5"))

# Pages whose title/source hint they are the inventory; we PREFER these chunks
# but fall back to all customer chunks if none are tagged this way.
_INVENTORY_HINTS = ("asset", "inventory", "cmdb")

# Heuristic criticality read-off from the matched row text. Ordered high→low;
# first hit wins. Word-boundary matched to avoid e.g. "production" matching
# inside unrelated prose is acceptable — these are deliberately broad.
_CRITICALITY_PATTERNS: list[tuple[str, str]] = [
    ("CRITICAL", r"crown[\s-]?jewel|critical|\bhvt\b|tier[\s-]?0|business[\s-]?critical"),
    ("HIGH",     r"\bhigh\b|sensitive|\bpii\b|\bphi\b|production|\bprod\b|tier[\s-]?1"),
    ("MEDIUM",   r"\bmedium\b|internal|staging|tier[\s-]?2"),
    ("LOW",      r"\blow\b|\bdev\b|test|sandbox|non[\s-]?prod"),
]


def _detect_criticality(text: str) -> str:
    low = text.lower()
    for label, pat in _CRITICALITY_PATTERNS:
        if re.search(pat, low):
            return label
    return "UNSPECIFIED"


def find_asset_matches(customer_id: str, iocs: list[dict]) -> list[dict]:
    """Substring-search the customer's Confluence chunks for each IOC value,
    preferring inventory-tagged pages, and read off a criticality heuristic.

    Returns ``[{value, type, criticality, source, page_id, snippet}]`` — one
    entry per matched IOC value. Empty list on killswitch off / no customer /
    no iocs / store unavailable / no chunks / any error.
    """
    if os.environ.get("ASSET_INVENTORY_ENABLED", "false").lower() != "true":
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
        logger.exception("asset_inventory: Chroma fetch failed for customer %s", customer_id)
        return []

    if not documents:
        return []

    pairs = list(zip(documents, metadatas))

    # Prefer chunks that look like an inventory page; fall back to all chunks.
    def _is_inventory(meta: dict) -> bool:
        hay = " ".join(str((meta or {}).get(k, "")) for k in ("source", "title", "file")).lower()
        return any(h in hay for h in _INVENTORY_HINTS)

    inventory_pairs = [(d, m) for d, m in pairs if _is_inventory(m or {})]
    scan_pairs = inventory_pairs or pairs

    matches: list[dict] = []
    seen: set[str] = set()
    for ioc in iocs:
        value = (ioc.get("value") or "").strip()
        if not value or len(value) < MIN_VALUE_LEN:
            continue
        key = value.lower()
        if key in seen:
            continue
        for doc, meta in scan_pairs:
            doc_text = doc or ""
            if key not in doc_text.lower():
                continue
            idx = doc_text.lower().find(key)
            # Wider window than whitelist_match: capture the whole row so the
            # criticality/owner columns land in the snippet.
            start = max(0, idx - 60)
            end = min(len(doc_text), idx + len(value) + 220)
            snippet = " ".join(doc_text[start:end].split()).strip()
            source = (meta or {}).get("source") or "Confluence"
            file = (meta or {}).get("file") or ""
            page_id = ""
            if isinstance(file, str) and file.startswith("confluence:"):
                page_id = file.split(":", 1)[1]
            matches.append({
                "value": value,
                "type": (ioc.get("type") or "").lower(),
                "criticality": _detect_criticality(snippet),
                "source": source,
                "page_id": page_id,
                "snippet": snippet,
            })
            seen.add(key)
            break  # one match per IOC value

    if matches:
        logger.info("asset_inventory: %d asset match(es) for customer %s",
                    len(matches), customer_id)
    return matches
