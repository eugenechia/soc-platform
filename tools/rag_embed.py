"""
Phase 4 — RAG embedding helper.

Wraps the Azure OpenAI embeddings endpoint behind a single function:

    embed_text(text: str) -> list[float] | None

Returns None on any failure so every caller can stay graceful. Uses the same
credentials and provider-detection pattern as tools.llm_client.make_chat_client
so we don't introduce a second auth surface. Provider order is intentionally
narrower than chat — only Azure OpenAI and public OpenAI are supported here
because Ollama / vLLM embedding shapes vary too much to abstract cleanly for
an MVP.

Module-level client cached after first call so we don't repeat the provider
detection per ticket.
"""
from __future__ import annotations

import logging
import os
import threading

from openai import AzureOpenAI, OpenAI

from tools.secrets import get_secret

logger = logging.getLogger(__name__)

_EMBED_DIM_DEFAULT = 1536  # text-embedding-3-small
_DEFAULT_MODEL = "text-embedding-3-small"

_client_lock = threading.Lock()
_cached_client: AzureOpenAI | OpenAI | None = None
_cached_model: str | None = None


def _build_client() -> tuple[AzureOpenAI | OpenAI, str] | None:
    """Detect provider and construct a sync client + model name. Returns None
    if no provider is configured — caller should treat that as "RAG
    embedding unavailable, skip retrieval"."""
    azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
    if azure_endpoint:
        try:
            client = AzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=get_secret("AZURE_OPENAI_API_KEY"),
                api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
            )
            model = (
                os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "").strip()
                or _DEFAULT_MODEL
            )
            logger.info("RAG embed provider: azure-openai endpoint=%s, deployment=%s",
                        azure_endpoint, model)
            return client, model
        except Exception as e:
            logger.warning("RAG embed: failed to build Azure client (%s): %s",
                           type(e).__name__, e)
            return None

    api_key = get_secret("OPENAI_API_KEY")
    if api_key:
        try:
            client = OpenAI(api_key=api_key)
            model = os.environ.get("OPENAI_EMBEDDING_MODEL", "").strip() or _DEFAULT_MODEL
            logger.info("RAG embed provider: public openai, model=%s", model)
            return client, model
        except Exception as e:
            logger.warning("RAG embed: failed to build OpenAI client (%s): %s",
                           type(e).__name__, e)
            return None

    logger.warning("RAG embed: no provider configured "
                   "(AZURE_OPENAI_ENDPOINT or OPENAI_API_KEY required)")
    return None


def _get_client() -> tuple[AzureOpenAI | OpenAI, str] | None:
    global _cached_client, _cached_model
    if _cached_client is not None and _cached_model is not None:
        return _cached_client, _cached_model
    with _client_lock:
        if _cached_client is not None and _cached_model is not None:
            return _cached_client, _cached_model
        built = _build_client()
        if not built:
            return None
        _cached_client, _cached_model = built
        return _cached_client, _cached_model


def embed_text(text: str) -> list[float] | None:
    """Embed a single text. Returns the vector or None on any failure."""
    if not text or not text.strip():
        return None
    pair = _get_client()
    if not pair:
        return None
    client, model = pair
    try:
        resp = client.embeddings.create(model=model, input=text[:8000])
        return list(resp.data[0].embedding)
    except Exception as e:
        logger.warning("RAG embed_text failed (%s): %s", type(e).__name__, e)
        return None


def embed_texts(texts: list[str]) -> list[list[float] | None]:
    """Embed multiple texts in a single API call. Ingest-path helper. If
    the batch call fails, falls back to per-text embedding so a single bad
    string can't kill the whole ingest."""
    if not texts:
        return []
    cleaned = [(i, t[:8000]) for i, t in enumerate(texts) if t and t.strip()]
    if not cleaned:
        return [None] * len(texts)

    pair = _get_client()
    if not pair:
        return [None] * len(texts)
    client, model = pair

    out: list[list[float] | None] = [None] * len(texts)
    try:
        resp = client.embeddings.create(
            model=model,
            input=[t for _, t in cleaned],
        )
        for (orig_idx, _), data in zip(cleaned, resp.data):
            out[orig_idx] = list(data.embedding)
        return out
    except Exception as e:
        logger.warning("RAG embed_texts batch failed (%s): %s — falling back to per-text",
                       type(e).__name__, e)
        for orig_idx, t in cleaned:
            v = embed_text(t)
            if v is not None:
                out[orig_idx] = v
        return out
