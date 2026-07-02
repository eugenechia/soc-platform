"""Per-customer Jira schema resolution for L1 triage.

Entity field IDs, the severity field, and the severity->priority map are
properties of a customer's Jira *instance/project* (each tenant renumbers its
`customfield_*` independently). This module is the single source of truth:

  * default_schema()   reproduces the historical GLOBAL SCDM defaults (read from
                       the same JIRA_FIELD_* env vars) -> SCDM stays byte-identical.
  * resolve_jira_schema(customer, project_key)
                       applies an optional per-project `schema` override that
                       merges key-by-key over the defaults, so an absent or
                       partial override leaves the default behaviour untouched.

The per-customer override lives on customers.json under
`jira_projects[].schema`:

    "schema": {
      "siem_source": "sentinel",
      "entity_fields": {"ip":"customfield_10079", "host":"customfield_10078",
                        "dns":"customfield_10080", "url":"customfield_10081",
                        "hash":"customfield_10082"},
      "severity_field": "customfield_10038",
      "severity_map": {"sev-0":"Highest", "sev-1":"High", ...}
    }

Import-time dependencies are stdlib-only (enrichment.py imports THIS module for
default_schema(); detect_schema_mismatch() and discover_schema() late-import
enrichment's low-level parsers to avoid a circular import).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

_ENTITY_SLOTS = ("ip", "host", "dns", "url", "hash")

_DEFAULT_ENTITY_FIELDS = {
    "ip":   os.environ.get("JIRA_FIELD_IP_ENTITIES",   "customfield_10079"),
    "host": os.environ.get("JIRA_FIELD_HOST_ENTITIES", "customfield_10078"),
    "dns":  os.environ.get("JIRA_FIELD_DNS_ENTITIES",  "customfield_10080"),
    "url":  os.environ.get("JIRA_FIELD_URL_ENTITIES",  "customfield_10081"),
    "hash": os.environ.get("JIRA_FIELD_HASH_ENTITIES", "customfield_10082"),
}
_DEFAULT_SEVERITY_FIELD = os.environ.get("JIRA_FIELD_SEVERITY", "customfield_10038")

# Canonical severity-value -> Jira priority map. jira_client imports this so the
# map is defined in exactly one place.
_DEFAULT_SEVERITY_MAP = {
    "critical":      "Highest",
    "high":          "High",
    "medium":        "Medium",
    "low":           "Low",
    "informational": "Lowest",
    "lowest":        "Lowest",
    "sev-0":         "Highest",
    "sev-1":         "High",
    "sev-2":         "Medium",
    "sev-3":         "Low",
}


@dataclass(frozen=True)
class JiraSchema:
    entity_fields: dict   # slot -> customfield id, for slots in _ENTITY_SLOTS
    severity_field: str
    severity_map: dict    # lower-cased severity value -> Jira priority
    siem_source: str = ""
    source: str = "default"   # "default" | "customer"

    def entity_field_ids(self) -> tuple:
        """The five entity custom-field IDs, in canonical slot order."""
        return tuple(self.entity_fields[k] for k in _ENTITY_SLOTS)

    def severity_to_priority(self, severity: str) -> Optional[str]:
        if not severity:
            return None
        return self.severity_map.get(str(severity).strip().lower())


def default_schema() -> JiraSchema:
    """The global default schema (SCDM). Backed by the JIRA_FIELD_* env vars."""
    return JiraSchema(
        entity_fields=dict(_DEFAULT_ENTITY_FIELDS),
        severity_field=_DEFAULT_SEVERITY_FIELD,
        severity_map=dict(_DEFAULT_SEVERITY_MAP),
        siem_source="",
        source="default",
    )


def _project_schema_block(customer: Optional[dict], project_key: str) -> Optional[dict]:
    if not customer or not project_key:
        return None
    pk = str(project_key).strip().upper()
    for proj in customer.get("jira_projects") or []:
        if str(proj.get("project_key", "")).strip().upper() == pk:
            blk = proj.get("schema")
            return blk if isinstance(blk, dict) else None
    return None


def resolve_jira_schema(customer: Optional[dict], project_key: str) -> JiraSchema:
    """Effective schema for a ticket's project. A per-project override merges
    key-by-key over the global defaults; absent/partial override -> defaults."""
    base = default_schema()
    blk = _project_schema_block(customer, project_key)
    if not blk:
        return base

    entity_fields = dict(base.entity_fields)
    for slot, fid in (blk.get("entity_fields") or {}).items():
        if slot in entity_fields and fid:
            entity_fields[slot] = fid

    severity_field = blk.get("severity_field") or base.severity_field

    severity_map = dict(base.severity_map)
    for value, priority in (blk.get("severity_map") or {}).items():
        if priority:
            severity_map[str(value).strip().lower()] = priority

    return JiraSchema(
        entity_fields=entity_fields,
        severity_field=severity_field,
        severity_map=severity_map,
        siem_source=blk.get("siem_source", "") or "",
        source="customer",
    )


# ─── Fail-loud detection ──────────────────────────────────────────────────────

def detect_schema_mismatch(fields: dict, schema: JiraSchema, iocs: list) -> Optional[dict]:
    """Return a warning dict when the configured schema looks wrong for this
    ticket, else None. High-signal only — does NOT fire on genuinely empty
    tickets (no IOC-like content anywhere).

    Signal: IOC-looking content is present in some custom field, but structured
    extraction produced 0 IOCs -> the entity field IDs are probably mis-mapped
    (the PAPAC silent-failure class)."""
    if iocs:
        return None
    from tools.enrichment import (  # late import: avoids circular import
        _extract_adf_text, _is_private_ip, _RE_IPV4, _RE_SHA256,
    )

    # High-precision signals only, to avoid alert fatigue across many customers:
    # a PUBLIC IPv4 or a 64-hex SHA256 present in a field while 0 IOCs were
    # extracted almost always means the entity mapping missed it. (SHA1/MD5 are
    # skipped — they collide with 40/32-hex device IDs; bare domains are too noisy.)
    def _has_real_ioc(text: str) -> bool:
        if not text:
            return False
        for m in _RE_IPV4.finditer(text):
            if not _is_private_ip(m.group()):
                return True
        for tok in re.split(r'[\s,;"{}\[\]:]+', text):
            if _RE_SHA256.fullmatch(tok):
                return True
        return False

    suspect = [fid for fid, val in (fields or {}).items()
               if str(fid).startswith("customfield_") and _has_real_ioc(_extract_adf_text(val))]
    if suspect:
        return {
            "kind": "entity_fields",
            "detail": "a public IP or file hash is present in the ticket but 0 IOCs were "
                      "extracted — entity field mapping is likely wrong for this customer",
            "suspect_fields": suspect,
        }
    return None


# ─── Schema discovery (onboarding aid) ────────────────────────────────────────

def discover_schema(fields: dict) -> dict:
    """Introspect a sample ticket's custom fields and SUGGEST a field mapping.
    Read-only; the operator confirms the suggestion into the customer record."""
    from tools.enrichment import (  # late import
        _extract_adf_text, _entity_json_objects,
        _RE_IPV4, _RE_DOMAIN, _RE_SHA256, _RE_SHA1, _RE_MD5,
    )

    evidence: dict = {}
    severity_candidates: list = []

    for fid, val in (fields or {}).items():
        if not str(fid).startswith("customfield_"):
            continue
        text = _extract_adf_text(val)
        if not text or not text.strip():
            continue

        kinds: set = set()
        objs = _entity_json_objects(text.strip())
        if objs:
            fmt = "json"
            keys = set()
            for o in objs:
                keys |= {str(k).lower() for k in o.keys()}
            if "hashvalue" in keys or "algorithm" in keys:
                kinds.add("hash")
            if "address" in keys:
                kinds.add("ip")
            if keys & {"dnsdomain", "domainname", "hostname", "fqdn"}:
                kinds.add("host")
            if "url" in keys:
                kinds.add("url")
        else:
            fmt = "plain"
            if _RE_SHA256.search(text) or _RE_SHA1.search(text) or _RE_MD5.search(text):
                kinds.add("hash")
            if _RE_IPV4.search(text):
                kinds.add("ip")
            if _RE_DOMAIN.search(text):
                kinds.add("host")

        low = text.strip().lower()
        if low in _DEFAULT_SEVERITY_MAP or low in ("p1", "p2", "p3", "p4"):
            severity_candidates.append({"field": fid, "value": text.strip()})

        if kinds:
            evidence[fid] = {"kinds": sorted(kinds), "format": fmt, "sample": text[:160]}

    suggested_entities: dict = {}
    for slot in _ENTITY_SLOTS:
        for fid, ev in evidence.items():
            if slot in ev["kinds"]:
                suggested_entities.setdefault(slot, fid)
                break

    siem = "defender" if any(e["format"] == "json" for e in evidence.values()) else "sentinel"

    return {
        "suggested": {
            "entity_fields": suggested_entities,
            "severity_field": severity_candidates[0]["field"] if severity_candidates else None,
            "siem_source": siem,
        },
        "evidence": evidence,
        "severity_candidates": severity_candidates,
    }
