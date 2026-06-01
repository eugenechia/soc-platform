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
"""
import json
import os
from typing import Optional

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
    """Return a copy of ``record`` with multi-workspace fields normalised.

    - If ``sentinel_workspaces`` is already a non-empty list, leave it alone.
    - Else, if any of the legacy flat ``sentinel_*`` fields is set, wrap them
      into a single-element list under ``sentinel_workspaces``.
    - Else, set ``sentinel_workspaces = []`` so callers can iterate safely.

    The same logic applies to ``defender_workspaces`` based on legacy
    ``DEFENDER_*`` env vars (no legacy per-customer Defender fields existed).

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

    return out


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
