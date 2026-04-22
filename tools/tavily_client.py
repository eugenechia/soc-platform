"""
Tavily web search — supplementary open-source intelligence for free-form queries.

Used only by routes/investigate.py. When a user runs a free-form query (not a
template-driven entity lookup), we pull 5 recent web results and prepend them to
the LLM prompt so the model can synthesise broad threat-landscape questions
from current reporting rather than hallucinating from training data alone.
"""
import logging

from tools.secrets import get_secret

log = logging.getLogger(__name__)


def fetch_web_context(query: str) -> str | None:
    """Return formatted web-search context, or None on failure / empty results."""
    api_key = get_secret("TAVILY_API_KEY")
    if not api_key:
        log.info("TAVILY_API_KEY not configured — skipping web context.")
        return None

    try:
        from tavily import TavilyClient
    except ImportError:
        log.warning("tavily-python not installed — skipping web context.")
        return None

    try:
        tavily = TavilyClient(api_key=api_key)
        results = tavily.search(query=query, search_depth="advanced", max_results=5)
    except Exception as e:
        log.warning("Tavily query failed: %s", e)
        return None

    hits = results.get("results") or []
    if not hits:
        return None

    log.info("Tavily returned %d results for query", len(hits))

    lines = [
        "[Web Intelligence Context]",
        "The following recent open-source intelligence was gathered to assist your analysis:",
        "",
    ]
    for i, r in enumerate(hits, 1):
        lines.append(f"Source {i}: {r.get('title', 'Untitled')} ({r.get('url', '')})")
        lines.append((r.get("content") or "").strip())
        lines.append("")
    lines.append("---")
    return "\n".join(lines)
