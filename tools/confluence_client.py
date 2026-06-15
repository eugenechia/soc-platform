"""
Phase 4b — minimal Confluence Cloud REST v2 client.

Wraps just enough of the API to fetch a single page by id and return
``{id, title, space_key, body_html}`` for the RAG ingest path. All other
Confluence functionality is out of scope.

Credentials reuse the existing JIRA_EMAIL + JIRA_API_TOKEN by default —
Atlassian tokens work for both Jira REST and Confluence Cloud REST on the
same site (logicalisasia.atlassian.net). Override with CONFLUENCE_EMAIL /
CONFLUENCE_API_TOKEN / CONFLUENCE_BASE_URL when needed.

Failure-isolation invariant: ``fetch_page`` returns None on any error and
NEVER raises. The caller (rag_confluence_ingest.sync_all) records the
failure per page and continues with the rest. Same pattern as Phase 4
``tools/rag_retrieval``.
"""
from __future__ import annotations

import base64
import logging
import os
import re
from typing import Optional

import httpx

from tools.secrets import get_secret

logger = logging.getLogger(__name__)

# Default endpoints. Override via env if Confluence lives on a different site.
_DEFAULT_BASE_URL_SUFFIX = "/wiki"
_PAGE_ID_REGEX = re.compile(r"/pages/(\d+)")


def _base_url() -> str:
    """Derived Confluence base URL. Examples:
      JIRA_URL=https://logicalisasia.atlassian.net    →  https://logicalisasia.atlassian.net/wiki
      CONFLUENCE_BASE_URL=https://other.example/wiki  →  https://other.example/wiki
    """
    explicit = os.environ.get("CONFLUENCE_BASE_URL", "").strip().rstrip("/")
    if explicit:
        return explicit
    jira_url = os.environ.get("JIRA_URL", "").strip().rstrip("/")
    if not jira_url:
        return ""
    return f"{jira_url}{_DEFAULT_BASE_URL_SUFFIX}"


def _email() -> str:
    return (os.environ.get("CONFLUENCE_EMAIL", "").strip()
            or get_secret("JIRA_EMAIL"))


def _api_token() -> str:
    # Read via get_secret in BOTH cases so KV-backed deployments work.
    return (get_secret("CONFLUENCE_API_TOKEN") or get_secret("JIRA_API_TOKEN"))


def _headers() -> dict:
    creds = base64.b64encode(f"{_email()}:{_api_token()}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Accept": "application/json",
    }


def extract_page_id(url: str) -> Optional[str]:
    """Pull the numeric page id out of a standard Confluence URL:
      https://<site>/wiki/spaces/<SPACE>/pages/<PAGE_ID>/<title-slug>
    Returns None for any URL where the regex doesn't match — caller treats
    that as "user pasted something that isn't a Confluence page URL".
    """
    if not url:
        return None
    m = _PAGE_ID_REGEX.search(url.strip())
    return m.group(1) if m else None


def fetch_page(page_id: str) -> Optional[dict]:
    """Fetch a Confluence page by numeric id. Returns:
        {"id": str, "title": str, "space_key": str, "body_html": str}
    or None on any error (network, auth, 4xx, malformed response). The
    caller stays graceful — a single bad page must never break a multi-
    page sync.

    Uses Confluence Cloud REST v2:
      GET /wiki/api/v2/pages/{id}?body-format=storage
    The "storage" body format is Atlassian's XHTML; the caller strips it
    to plain text with BeautifulSoup before chunking.
    """
    if not page_id:
        return None
    base = _base_url()
    if not base:
        logger.warning("Confluence fetch_page(%s): no base URL configured", page_id)
        return None

    url = f"{base}/api/v2/pages/{page_id}"
    try:
        r = httpx.get(url,
                      headers=_headers(),
                      params={"body-format": "storage"},
                      timeout=20)
    except Exception as e:
        logger.warning("Confluence fetch_page(%s) network error (%s): %s",
                       page_id, type(e).__name__, e)
        return None

    if r.status_code >= 400:
        # 401/403/404 all common enough that we want the body for diagnostics.
        snippet = (r.text or "")[:200].replace("\n", " ")
        logger.warning("Confluence fetch_page(%s) HTTP %s: %s",
                       page_id, r.status_code, snippet)
        return None

    try:
        data = r.json() or {}
    except Exception as e:
        logger.warning("Confluence fetch_page(%s) JSON parse failed: %s", page_id, e)
        return None

    body_html = (((data.get("body") or {}).get("storage") or {}).get("value")) or ""

    # space_key isn't returned at the top level by v2 — they expose space.id.
    # Fall back to GET /api/v2/spaces/{id} only if we genuinely need it. For
    # now derive a best-effort tag from spaceId if present; UI shows it.
    space_id = str(data.get("spaceId") or "").strip()
    space_key = data.get("spaceKey") or ""  # not actually present in v2 — defensive
    if not space_key and space_id:
        space_key = _lookup_space_key(space_id) or space_id

    return {
        "id": str(data.get("id") or page_id),
        "title": data.get("title") or f"(untitled page {page_id})",
        "space_key": space_key or "",
        "body_html": body_html,
    }


# Cheap module-level cache for space-id → space-key. Spaces don't get renamed
# often and the dataset is small (one entry per added page).
_space_key_cache: dict[str, str] = {}


def _lookup_space_key(space_id: str) -> Optional[str]:
    """Resolve a Confluence v2 space id to its human-readable key. Returns
    None on any error; cache the result so we don't re-hit the API."""
    if not space_id:
        return None
    if space_id in _space_key_cache:
        return _space_key_cache[space_id]
    base = _base_url()
    if not base:
        return None
    try:
        r = httpx.get(f"{base}/api/v2/spaces/{space_id}",
                      headers=_headers(), timeout=15)
        if r.status_code >= 400:
            return None
        key = (r.json() or {}).get("key") or ""
        if key:
            _space_key_cache[space_id] = key
        return key or None
    except Exception as e:
        logger.warning("Confluence space lookup(%s) failed (%s): %s",
                       space_id, type(e).__name__, e)
        return None
