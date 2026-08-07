"""Resolve the Jira "Escalated Incident" custom field for a project.

The SOC monthly report breaks its incident statistics down a second time over
escalated incidents only. Which `customfield_*` carries that flag is a property
of the customer's Jira instance — every tenant renumbers custom fields
independently — so it cannot be hardcoded the way the report's other stats are.

Resolution order (first hit wins):

  1. ``jira_projects[].schema.escalation_field`` on the customer record — the
     same per-project override block already used by tools/jira_schema.py.
  2. The ``JIRA_FIELD_ESCALATED`` env var (global default, mirrors the other
     ``JIRA_FIELD_*`` vars).
  3. Auto-discovery against ``GET /rest/api/3/field``.

Auto-discovery deliberately REFUSES to guess. A wrong field would silently
publish a wrong number in a customer-facing report, which is worse than
publishing nothing: when the name match is ambiguous, this module returns None
and the report renders section 1.5 as "not configured" instead. The resolved
field is logged at INFO and surfaced on the Stats page so a bad match is
visible rather than silent.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time

import httpx

logger = logging.getLogger(__name__)

# Values (case-insensitive) that mean "this incident was escalated". Jira
# select-list options vary by tenant — "Yes" is the documented convention, the
# others are defensive. Overridable per project via
# ``schema.escalation_positive_values``.
_DEFAULT_POSITIVE_VALUES = ("yes", "true", "escalated", "y")

# A custom field is a candidate when its name mentions escalation. Anchored on
# the word stem so "Escalated", "Escalation", "Escalated Incident" and
# "Incident Escalated" all match. The `de-` lookbehinds exclude
# "De-escalation Notes" / "Deescalation", which mean the OPPOSITE of the flag
# we are looking for and would be a catastrophic auto-discovery match.
_NAME_RE = re.compile(r"(?<!de-)(?<![a-z])escalat(?:ed|ion)(?![a-z])",
                      re.IGNORECASE)

# Preferred exact names, checked in order before falling back to a single
# fuzzy match. Lower-cased for comparison.
_PREFERRED_NAMES = ("escalated incident", "escalated", "incident escalated",
                    "escalation")

# Jira schema types that can carry a yes/no flag. Anything else (a date, a
# user picker, a paragraph field) is not a usable escalation flag even if its
# name matches.
_USABLE_TYPES = {"option", "string", "any"}

_DEFAULT_CACHE_TTL_S = 900.0   # 15 min — field definitions change rarely
_DEFAULT_TIMEOUT_S = 15.0

# cache_key → (timestamp_monotonic, resolution_dict_or_None)
_cache: dict[str, tuple[float, dict | None]] = {}
_cache_lock = threading.Lock()


def _cache_ttl() -> float:
    try:
        return float(os.environ.get("JIRA_ESCALATION_CACHE_TTL_S",
                                    str(_DEFAULT_CACHE_TTL_S)))
    except (TypeError, ValueError):
        return _DEFAULT_CACHE_TTL_S


def reset_cache() -> None:
    """Drop the resolution cache. For tests and for the admin re-sync path."""
    with _cache_lock:
        _cache.clear()


def _positive_values(schema_block: dict) -> tuple[str, ...]:
    raw = schema_block.get("escalation_positive_values")
    if isinstance(raw, (list, tuple)) and raw:
        vals = tuple(str(v).strip().lower() for v in raw if str(v).strip())
        if vals:
            return vals
    return _DEFAULT_POSITIVE_VALUES


def _schema_block(project_spec: dict | None) -> dict:
    blk = (project_spec or {}).get("schema")
    return blk if isinstance(blk, dict) else {}


def _result(field_id: str, field_name: str, source: str,
            schema_block: dict) -> dict:
    return {
        "field_id": field_id,
        "field_name": field_name,
        "positive_values": _positive_values(schema_block),
        "source": source,
    }


# ── Discovery ────────────────────────────────────────────────────────────────

def _fetch_field_catalogue(project_spec: dict | None) -> list[dict]:
    """All field definitions visible to the configured Jira credentials.

    Returns [] on any failure — a discovery outage degrades the escalated
    section to "not configured", it never raises into report generation.
    """
    from tools.jira_client import _resolve_jira_auth

    base_url, headers = _resolve_jira_auth(project_spec)
    if not base_url:
        logger.warning("escalation discovery: no Jira base_url configured")
        return []
    try:
        r = httpx.get(f"{base_url}/rest/api/3/field", headers=headers,
                      timeout=_DEFAULT_TIMEOUT_S)
    except Exception as e:
        logger.warning("escalation discovery: /field request failed: %s", e)
        return []
    if r.status_code >= 400:
        logger.warning("escalation discovery: /field HTTP %s: %s",
                       r.status_code, r.text[:300])
        return []
    try:
        data = r.json()
    except Exception:
        logger.warning("escalation discovery: /field returned non-JSON")
        return []
    return data if isinstance(data, list) else []


def _candidates(catalogue: list[dict]) -> list[dict]:
    """Custom fields whose name mentions escalation and whose type can hold a
    yes/no value."""
    out = []
    for f in catalogue:
        if not isinstance(f, dict) or not f.get("custom"):
            continue
        name = str(f.get("name") or "").strip()
        fid = str(f.get("id") or "").strip()
        if not name or not fid or not _NAME_RE.search(name):
            continue
        ftype = str((f.get("schema") or {}).get("type") or "").strip().lower()
        if ftype and ftype not in _USABLE_TYPES:
            logger.debug("escalation discovery: skipping %r (%s) — type %r",
                         name, fid, ftype)
            continue
        out.append({"id": fid, "name": name})
    return out


def _discover(project_spec: dict | None, project_key: str) -> tuple[str, str] | None:
    """Return (field_id, field_name) or None when it cannot be determined
    unambiguously."""
    candidates = _candidates(_fetch_field_catalogue(project_spec))
    if not candidates:
        logger.info("escalation discovery (%s): no matching custom field found",
                    project_key)
        return None

    if len(candidates) == 1:
        c = candidates[0]
        logger.info("escalation discovery (%s): resolved %r -> %s",
                    project_key, c["name"], c["id"])
        return c["id"], c["name"]

    # More than one match — only accept a preferred exact name, and only when
    # exactly one candidate carries it. Anything else is ambiguous.
    by_lower = {}
    for c in candidates:
        by_lower.setdefault(c["name"].strip().lower(), []).append(c)
    for preferred in _PREFERRED_NAMES:
        hits = by_lower.get(preferred, [])
        if len(hits) == 1:
            logger.info("escalation discovery (%s): %d candidates, resolved on "
                        "exact name %r -> %s", project_key, len(candidates),
                        hits[0]["name"], hits[0]["id"])
            return hits[0]["id"], hits[0]["name"]

    logger.warning(
        "escalation discovery (%s): AMBIGUOUS — %d fields match and none has a "
        "preferred exact name: %s. Section 1.5 will render as not configured. "
        "Set JIRA_FIELD_ESCALATED or jira_projects[].schema.escalation_field to "
        "resolve this.",
        project_key, len(candidates),
        ", ".join(f"{c['name']} ({c['id']})" for c in candidates),
    )
    return None


# ── Public entry ─────────────────────────────────────────────────────────────

def resolve_escalation_field(project_key: str,
                             project_spec: dict | None = None) -> dict | None:
    """The escalation field for ``project_key``, or None when unresolvable.

    Result shape::

        {"field_id": "customfield_11742", "field_name": "Escalated Incident",
         "positive_values": ("yes", "true", ...), "source": "schema"|"env"|"discovered"}

    Cached per (base_url, project_key) for ``JIRA_ESCALATION_CACHE_TTL_S``
    seconds. Never raises.
    """
    schema_block = _schema_block(project_spec)

    explicit = str(schema_block.get("escalation_field") or "").strip()
    if explicit:
        return _result(explicit, schema_block.get("escalation_field_name")
                       or explicit, "schema", schema_block)

    env_field = os.environ.get("JIRA_FIELD_ESCALATED", "").strip()
    if env_field:
        return _result(env_field, env_field, "env", schema_block)

    if os.environ.get("JIRA_ESCALATION_DISCOVERY", "true").strip().lower() == "false":
        return None

    base_url = str((project_spec or {}).get("base_url") or "").strip() \
        or os.environ.get("JIRA_URL", "")
    cache_key = f"{base_url}|{project_key}"
    ttl = _cache_ttl()
    now = time.monotonic()

    with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and (now - cached[0]) < ttl:
            hit = cached[1]
            # Positive values come from the (uncached) schema block so a
            # customers.json edit takes effect without waiting out the TTL.
            return _result(hit["field_id"], hit["field_name"], "discovered",
                           schema_block) if hit else None

    try:
        found = _discover(project_spec, project_key)
    except Exception:
        logger.exception("escalation discovery (%s) failed", project_key)
        found = None

    entry = {"field_id": found[0], "field_name": found[1]} if found else None
    with _cache_lock:
        _cache[cache_key] = (time.monotonic(), entry)

    return _result(entry["field_id"], entry["field_name"], "discovered",
                   schema_block) if entry else None


def is_escalated(raw_value, positive_values=_DEFAULT_POSITIVE_VALUES) -> bool:
    """Whether a raw Jira field value means "escalated".

    Handles the shapes a Jira select/checkbox/text field can arrive in: a
    single-select ``{"value": "Yes"}``, a checkbox list ``[{"value": "Yes"}]``,
    a plain string, and a native bool.
    """
    if raw_value is None:
        return False
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, dict):
        raw_value = raw_value.get("value") or raw_value.get("name") or ""
    elif isinstance(raw_value, (list, tuple)):
        return any(is_escalated(v, positive_values) for v in raw_value)
    return str(raw_value).strip().lower() in tuple(positive_values)
