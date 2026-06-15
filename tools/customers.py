"""
Customer record helpers — single source of truth for reading customers.json.

Used by routes/admin.py (customer CRUD) and tools/sentinel_client.py (per-customer
Sentinel SP credential lookup). Kept in tools/ so that tools/ never has to import
from routes/.

## Multi-workspace schema (Phase C, 2026-06)

A customer record now carries a list of Sentinel workspaces under the
``sentinel_workspaces`` key:

```json
{
  "id": "logicalis-asia",
  "sentinel_workspaces": [
    {"name": "Malaysia",  "workspace_id": "...",
     "tenant_id": "...", "client_id": "...",
     "client_secret_kv_name": "customer-logicalis-asia-my-sentinel-secret"},
    {"name": "Singapore", ...}
  ],
  "defender_workspaces": [
    {"name": "Malaysia",  "tenant_id": "...", "client_id": "...",
     "client_secret_kv_name": "..."}
  ]
}
```

Legacy single-workspace records (with flat ``sentinel_workspace_id`` /
``sentinel_tenant_id`` / ``sentinel_client_id`` / ``sentinel_client_secret_kv_name``
fields) are auto-wrapped by :func:`_normalize_customer` at load time. The
normalization is idempotent and read-only — the on-disk file is never rewritten
just because someone read it. The admin UI rewrites the record in the new
shape the next time the customer is saved.

## Multi-Jira-project schema (2026-06)

A customer record can also describe multiple Jira projects (potentially across
different Jira Cloud instances) under ``jira_projects``:

```json
{
  "jira_projects": [
    {"name": "Logicalis MY", "project_key": "CAM",
     "base_url": "https://logicalis-my.atlassian.net",
     "email": "soc-my@logicalis.com",
     "api_token_kv_name": "customer-logicalis-asia-jira-logicalis-my-token"},
    {"name": "Logicalis SG", "project_key": "CAMSG", ...}
  ]
}
```

Legacy records with a flat ``jira_project_key`` are auto-wrapped into a
single-element ``jira_projects`` list by :func:`_normalize_customer`. Empty
``base_url`` / ``email`` / ``api_token_kv_name`` means "fall back to the
global ``JIRA_URL`` / ``JIRA_EMAIL`` / ``JIRA_API_TOKEN`` env vars" — the
current single-instance production setup. The 4 customer-level Jira issue
type fields (``jira_incident_issuetype`` etc.) apply to ALL projects on the
record; per-project issue type overrides are intentionally NOT supported.
"""
import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CUSTOMERS_FILE = os.path.join(BASE_DIR, "data", "customers.json")

# Legacy field names that wrap into a single-element sentinel_workspaces list
# if no sentinel_workspaces array is present on the record.
_LEGACY_SENTINEL_FIELDS = (
    "sentinel_workspace_id",
    "sentinel_tenant_id",
    "sentinel_client_id",
    "sentinel_client_secret_kv_name",
)


def _normalize_customer(record: dict) -> dict:
    """Return a copy of ``record`` with multi-source fields normalised.

    - If ``sentinel_workspaces`` is already a non-empty list, leave it alone.
    - Else, if any of the legacy flat ``sentinel_*`` fields is set, wrap them
      into a single-element list under ``sentinel_workspaces``.
    - Else, set ``sentinel_workspaces = []`` so callers can iterate safely.

    The same logic applies to ``defender_workspaces`` based on legacy
    ``DEFENDER_*`` env vars (no legacy per-customer Defender fields existed).

    Multi-Jira-project (2026-06): if ``jira_projects`` is absent but the legacy
    flat ``jira_project_key`` is set, wrap it into a single-element list with
    empty ``base_url`` / ``email`` / ``api_token_kv_name`` so the jira client
    falls back to ``JIRA_URL`` / ``JIRA_EMAIL`` / ``JIRA_API_TOKEN`` env vars
    (single-instance install, the current production setup).

    Idempotent: normalising an already-normalised record is a no-op.
    Read-only: the input dict is not mutated; a shallow copy is returned.
    """
    if not isinstance(record, dict):
        return record
    out = dict(record)

    workspaces = out.get("sentinel_workspaces")
    if not (isinstance(workspaces, list) and workspaces):
        legacy_present = any(out.get(k) for k in _LEGACY_SENTINEL_FIELDS)
        if legacy_present:
            out["sentinel_workspaces"] = [{
                "name":                  out.get("name", "") or "Primary",
                "workspace_id":          out.get("sentinel_workspace_id", ""),
                "tenant_id":             out.get("sentinel_tenant_id", ""),
                "client_id":             out.get("sentinel_client_id", ""),
                "client_secret_kv_name": out.get("sentinel_client_secret_kv_name", ""),
            }]
        else:
            out["sentinel_workspaces"] = []

    # Defender XDR — no legacy per-customer fields existed; the env-var
    # fallback in defender_client.py handles those installs. Just ensure
    # the key is present as a list for downstream iteration.
    if not isinstance(out.get("defender_workspaces"), list):
        out["defender_workspaces"] = []

    projects = out.get("jira_projects")
    if not (isinstance(projects, list) and projects):
        legacy_key = (out.get("jira_project_key") or "").strip()
        if legacy_key:
            out["jira_projects"] = [{
                "name":              out.get("name", "") or legacy_key or "Primary",
                "project_key":       legacy_key,
                "base_url":          "",
                "email":             "",
                "api_token_kv_name": "",
            }]
        else:
            out["jira_projects"] = []

    # Phase 4b-rev (2026-06-15): per-customer Confluence pages. Each entry has
    # {url, page_id, title, space_key, last_synced_at, chunk_count, last_error}.
    # Empty list when the customer hasn't been configured for RAG yet.
    if not isinstance(out.get("confluence_pages"), list):
        out["confluence_pages"] = []

    return out


def find_customer_by_jira_project(project_key: str) -> Optional[dict]:
    """Reverse-lookup a customer by Jira project key.

    Scans every customer's ``jira_projects[].project_key`` (and the legacy flat
    ``jira_project_key`` field). Returns the FIRST customer whose record claims
    the given project key, or None if no customer matches.

    Used by the L1 Triage webhook (Phase 4b-rev) to derive which customer a
    ticket belongs to so RAG retrieval can be scoped. Logs a WARNING when
    multiple customers claim the same project key — that's a config bug the
    operator should fix (a long-term solution is a customer-slug custom field
    on Jira tickets; see Phase 4c roadmap).
    """
    if not project_key:
        return None
    key = project_key.strip().upper()
    matches = []
    for c in load_customers():
        # Normalised customer always carries jira_projects as a list.
        for jp in (c.get("jira_projects") or []):
            if (jp.get("project_key") or "").strip().upper() == key:
                matches.append(c)
                break
    if not matches:
        return None
    if len(matches) > 1:
        logger.warning(
            "Multiple customers (%s) claim Jira project key %s — using the first match (%s). "
            "This is a config bug; each project should map to a single customer.",
            [m.get("id") for m in matches], key, matches[0].get("id"),
        )
    return matches[0]


def load_customers() -> list:
    """Read all customer records, normalised. Returns [] if file is absent."""
    if not os.path.exists(CUSTOMERS_FILE):
        return []
    with open(CUSTOMERS_FILE) as f:
        records = json.load(f)
    return [_normalize_customer(c) for c in records]


def save_customers(customers: list) -> None:
    """Persist the full customer list. Caller is responsible for shape."""
    os.makedirs(os.path.dirname(CUSTOMERS_FILE), exist_ok=True)
    with open(CUSTOMERS_FILE, "w") as f:
        json.dump(customers, f, indent=2)


def get_customer(customer_id: str) -> Optional[dict]:
    """Return the customer record for the given id (normalised), or None."""
    if not customer_id:
        return None
    for c in load_customers():
        if c.get("id") == customer_id:
            return c
    return None
