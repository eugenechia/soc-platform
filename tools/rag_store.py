"""
Phase 4 — Chroma vector store wrapper.

Provides a thin abstraction over a persistent Chroma client so the rest of
the codebase doesn't have to know about Chroma's API. Chroma runs in-process
(embedded SQLite + custom vector index files), persists to a directory on
the Azure Files share so the index survives container restarts, and needs
no managed service.

Module-level client cached after first call. All errors are caught and
either logged + re-raised (for explicit error visibility in the ingest CLI)
or swallowed (for the hot path — see tools.rag_retrieval).
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "soc_platform_rag"
_DEFAULT_CHROMA_DIR = "/app/data/rag"

_client_lock = threading.Lock()
_cached_collection: Any | None = None  # chromadb Collection type, lazy-imported


def _chroma_dir() -> str:
    return os.environ.get("RAG_CHROMA_DIR", _DEFAULT_CHROMA_DIR).strip() or _DEFAULT_CHROMA_DIR


def _get_collection() -> Any | None:
    """Returns the cached Chroma collection. Builds it (and parent dir) on
    first call. Returns None if chromadb itself fails to import or the
    persistence dir can't be created — both are catastrophic enough to
    bypass RAG entirely."""
    global _cached_collection
    if _cached_collection is not None:
        return _cached_collection
    with _client_lock:
        if _cached_collection is not None:
            return _cached_collection
        try:
            import chromadb
            persist_dir = _chroma_dir()
            os.makedirs(persist_dir, exist_ok=True)
            client = chromadb.PersistentClient(path=persist_dir)
            collection = client.get_or_create_collection(
                name=_COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            _cached_collection = collection
            logger.info("RAG store ready: chroma at %s, collection=%s",
                        persist_dir, _COLLECTION_NAME)
            return _cached_collection
        except Exception as e:
            logger.warning("RAG store init failed (%s): %s", type(e).__name__, e)
            return None


def upsert_chunks(items: list[dict]) -> int:
    """Upsert a batch of chunks. Each item must have keys:
        id, text, embedding, source, file, position
    Returns the count of items actually written (0 on failure). Used by
    tools.rag_ingest; the hot retrieval path never writes.
    """
    if not items:
        return 0
    collection = _get_collection()
    if collection is None:
        return 0
    try:
        collection.upsert(
            ids=[i["id"] for i in items],
            embeddings=[i["embedding"] for i in items],
            documents=[i["text"] for i in items],
            metadatas=[
                {"source": i.get("source", ""), "file": i.get("file", ""), "position": i.get("position", 0)}
                for i in items
            ],
        )
        return len(items)
    except Exception as e:
        logger.warning("RAG store upsert failed (%s): %s", type(e).__name__, e)
        return 0


def delete_by_file(file_path: str) -> int:
    """Delete every chunk whose metadata.file matches. Lets the ingest CLI
    cleanly replace a single source file without touching the rest. Returns
    chunk count deleted (best-effort; Chroma's API doesn't return a count
    directly, so we count via a prior query)."""
    collection = _get_collection()
    if collection is None:
        return 0
    try:
        existing = collection.get(where={"file": file_path})
        ids = existing.get("ids") or []
        if not ids:
            return 0
        collection.delete(ids=ids)
        return len(ids)
    except Exception as e:
        logger.warning("RAG store delete_by_file(%s) failed (%s): %s",
                       file_path, type(e).__name__, e)
        return 0


def search(query_embedding: list[float], top_k: int = 3) -> list[dict]:
    """Vector search. Returns a list of dicts shaped:
        {"text": str, "source": str, "file": str, "position": int, "score": float}
    where `score` is 1 - distance (Chroma returns cosine distance, we
    convert to similarity for analyst-friendly display). Returns [] on any
    failure — the hot path must stay graceful."""
    if not query_embedding:
        return []
    collection = _get_collection()
    if collection is None:
        return []
    try:
        res = collection.query(
            query_embeddings=[query_embedding],
            n_results=max(1, int(top_k)),
        )
        # Chroma returns lists-of-lists keyed by query index; we only sent 1 query.
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        out: list[dict] = []
        for doc, meta, dist in zip(docs, metas, dists):
            meta = meta or {}
            score = max(0.0, 1.0 - float(dist))  # cosine: 0 distance = identical
            out.append({
                "text": doc or "",
                "source": meta.get("source", "") or "",
                "file": meta.get("file", "") or "",
                "position": int(meta.get("position", 0) or 0),
                "score": score,
            })
        return out
    except Exception as e:
        logger.warning("RAG store search failed (%s): %s", type(e).__name__, e)
        return []


def collection_stats() -> dict:
    """Cheap summary for the admin UI."""
    collection = _get_collection()
    if collection is None:
        return {"ready": False, "chunk_count": 0, "persist_dir": _chroma_dir()}
    try:
        return {
            "ready": True,
            "chunk_count": int(collection.count()),
            "persist_dir": _chroma_dir(),
        }
    except Exception as e:
        logger.warning("RAG store stats failed (%s): %s", type(e).__name__, e)
        return {"ready": False, "chunk_count": 0, "persist_dir": _chroma_dir(),
                "error": f"{type(e).__name__}: {e}"}
