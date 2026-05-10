"""Deduplication key generation.

Two callers:

1. Gateway path (`/api/ingest`) — caller hands us a normalised `Alert`.
   Use `dedup_key(alert)`.

2. Webhook path (Jira `issue_created`) — caller hands us the ticket fields
   from a ticket created by the Sentinel Logic App or a future direct-to-Jira
   integration. Use `derive_key_from_ticket(fields)`.

Both paths produce a 16-hex-char SHA-256 prefix from the SAME hash function,
just with different inputs. Tickets created via the gateway already carry the
key in `customfield_10125`; tickets created via direct Jira REST do not, so
the webhook handler derives the key from the ticket's existing fields and
writes it to `customfield_10125` for future searches.

Key derivation priority (most-specific to least):
  Tier 1 — Sentinel Incident ID  (e.g. "LOGICALIS-25868")
  Tier 2 — Sentinel Alert ID     (e.g. "27706")
  Tier 3 — summary + first IP entity (fuzzy fallback)

Returns None when no reliable signal is available; the webhook handler
will then skip dedup and fall through to L1 Triage as today.
"""
import hashlib
import re

from tools.gateway.schema import Alert


def _hash(payload: str) -> str:
    """Canonical 16-hex-char SHA-256 prefix used for every dedup key."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def dedup_key(alert: Alert) -> str:
    """Compute the gateway-path dedup key from a normalised Alert."""
    return _hash(f"{alert.siem}:{alert.rule_id}|{alert.primary_entity}")


def _flatten_adf(node, out: list) -> None:
    """Walk an Atlassian Document Format tree and collect text nodes."""
    if isinstance(node, dict):
        if node.get("type") == "text":
            out.append(node.get("text", ""))
        for child in node.get("content", []):
            _flatten_adf(child, out)
    elif isinstance(node, list):
        for child in node:
            _flatten_adf(child, out)


def _description_text(description) -> str:
    """Extract plain text from a Jira description (ADF dict or plain string)."""
    if not description:
        return ""
    if isinstance(description, str):
        return description
    parts: list[str] = []
    _flatten_adf(description, parts)
    return "\n".join(parts)


_INCIDENT_ID_RE = re.compile(r"Incident ID\s*\n?\s*(\S+)")
_ALERT_ID_RE = re.compile(r"Alert ID\s*\n?\s*(\S+)")
_FIRST_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def derive_key_from_ticket(fields: dict) -> str | None:
    """Compute a dedup key from a Jira ticket's `fields` dict.

    Used by the webhook handler when `customfield_10125` is empty (i.e. ticket
    was created by something other than the gateway). Returns None if the
    ticket has no reliable signal — caller should fall through to L1 Triage.
    """
    desc_text = _description_text(fields.get("description"))

    # Tier 1: Sentinel Incident ID (groups multiple Alert IDs into one incident)
    m = _INCIDENT_ID_RE.search(desc_text)
    if m:
        return _hash(f"sentinel-incident:{m.group(1).strip()}")

    # Tier 2: Sentinel Alert ID (per-rule-fire identifier)
    m = _ALERT_ID_RE.search(desc_text)
    if m:
        return _hash(f"sentinel-alert:{m.group(1).strip()}")

    # Tier 3: summary + first IPv4 entity (fuzzy fallback)
    summary = (fields.get("summary") or "").strip()
    ip_field = str(fields.get("customfield_10079") or "")
    m = _FIRST_IPV4_RE.search(ip_field)
    if summary and m:
        return _hash(f"unknown:{summary}|{m.group(0)}")

    return None
