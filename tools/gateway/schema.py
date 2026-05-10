"""Normalized alert payload — the contract between SIEMs and the Gateway.

Both Splunk (via webhook adapter) and Sentinel (via Logic App) must transform
their native alert shapes into this common format before POSTing to /api/ingest.
"""
from dataclasses import dataclass
from typing import List


class AlertValidationError(ValueError):
    """Raised when a payload fails schema validation. Returns HTTP 400 to caller."""
    pass


@dataclass
class Alert:
    """Normalized alert. Immutable after construction."""
    siem: str                # "splunk" | "sentinel" | "microsoft sentinel" | "devo" | "crowdstrike" | "microsoft xdr"
    rule_id: str             # e.g. "unusual_auth_geo"
    severity: str            # see _VALID_SEVERITIES below
    primary_entity: str      # e.g. "user:alice@corp.com" or "ip:185.220.x.x"
    entities: List[str]      # All entities seen in the alert (IPs, users, hashes, hosts)
    raw_link: str            # Deep link back to source SIEM event
    timestamp: str           # ISO-8601 UTC
    details: str = ""        # Raw alert payload (truncated; goes in description)


_REQUIRED_FIELDS = {"siem", "rule_id", "severity", "primary_entity"}
_VALID_SIEMS = {
    # Lowercased siem names. Whatever the caller sends gets .lower()'d before
    # this check, then .title()'d when written to Jira. Add new SIEM/EDR tools
    # here as needed; ensure they also exist as options on Jira's Incident
    # Source field.
    "splunk", "sentinel", "microsoft sentinel",
    "devo", "crowdstrike", "microsoft xdr",
}
# Severity values must match the destination Jira's Severity field options
# verbatim. The gateway is a passthrough — it does NOT translate between
# severity vocabularies. Two conventions are accepted by default; widen if
# your tenant uses a different scheme.
_VALID_SEVERITIES = {
    # English convention (legacy / cross-tenant default)
    "Critical", "High", "Medium", "Low", "Informational",
    # SCDM/Logicalis tenant convention
    "Sev-0", "Sev-1", "Sev-2", "Sev-3",
}


def parse_alert(payload: dict) -> Alert:
    """Validate + normalize an inbound payload. Raises AlertValidationError on failure."""
    if not isinstance(payload, dict):
        raise AlertValidationError("payload must be a JSON object")

    missing = _REQUIRED_FIELDS - set(payload.keys())
    if missing:
        raise AlertValidationError(f"missing required fields: {sorted(missing)}")

    siem = str(payload["siem"]).lower().strip()
    if siem not in _VALID_SIEMS:
        raise AlertValidationError(f"siem must be one of {sorted(_VALID_SIEMS)}")

    severity = str(payload["severity"]).strip()
    if severity not in _VALID_SEVERITIES:
        raise AlertValidationError(f"severity must be one of {sorted(_VALID_SEVERITIES)}")

    primary_entity = str(payload["primary_entity"]).strip()
    if not primary_entity:
        raise AlertValidationError("primary_entity must be non-empty")

    rule_id = str(payload["rule_id"]).strip()
    if not rule_id:
        raise AlertValidationError("rule_id must be non-empty")

    return Alert(
        siem=siem,
        rule_id=rule_id,
        severity=severity,
        primary_entity=primary_entity,
        entities=[str(e) for e in (payload.get("entities") or [])],
        raw_link=str(payload.get("raw_link", "")).strip(),
        timestamp=str(payload.get("timestamp", "")).strip(),
        details=str(payload.get("details", "")),
    )
