"""
Improvement #4 (2026-07-06) — command-line SOURCE for the reputation check.

The process / PowerShell command line an L1 analyst needs is NOT in the Jira
ticket (Sentinel/Defender only exports a canned narrative + typed entity fields).
It lives upstream in Microsoft Sentinel, inside ``SecurityAlert.Entities`` — every
Defender/MDATP process alert carries a Process entity with ``CommandLine`` and
``ImageFile.Name``. (``DeviceProcessEvents`` is the Advanced-Hunting table but is
frequently NOT streamed into the Log Analytics workspace, so we do not rely on it.)

This module fetches those command lines for a ticket from the customer's own
Sentinel workspace, using the SAME per-workspace service-principal auth as the
Phase 5 KQL expansion (tools.kql_expansion). Two lookup keys, both proven:
  1. PRIMARY  — the ticket's Sentinel incident number (Jira custom field) joined
     through ``SecurityIncident.AlertIds`` to ``SecurityAlert``. Precise.
  2. FALLBACK — the host/device name + a time window around the alert. Used when
     the incident number is absent or the incident join returns nothing.

Design constraints (mirror tools.kql_expansion / tools.ioc_insights):
- MUST NOT raise. Every failure path returns ``[]`` and logs. The caller renders
  nothing when the list is empty.
- No killswitch here — the analyzer (tools.cmdline_analysis) owns
  ``CMDLINE_ANALYSIS_ENABLED`` and only calls this when enabled.
- Bounded: caps alerts scanned and command lines returned so a noisy incident
  cannot blow the webhook latency budget.
"""
from __future__ import annotations

import json
import logging
import os
import re

logger = logging.getLogger(__name__)

_DEFAULT_LOOKBACK = os.environ.get("CMDLINE_SOURCE_LOOKBACK", "P7D")
_MAX_ALERTS = int(os.environ.get("CMDLINE_SOURCE_MAX_ALERTS", "25"))
_MAX_CMDLINES = int(os.environ.get("CMDLINE_SOURCE_MAX_CMDLINES", "5"))
_MAX_CMDLINE_LEN = 2000  # guard against a pathological command line

# Images that make a command line worth analysing first (LOLBins / shells /
# script hosts). Used only to PRIORITISE within the cap — never to exclude.
_INTERESTING_IMAGES = (
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "certutil.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe", "curl.exe", "wget.exe",
    "schtasks.exe", "at.exe", "psexec.exe", "net.exe", "reg.exe",
)


def _resolve_incident_number(fields: dict) -> str | None:
    """The Sentinel incident number lives in a Jira custom field. Configurable so
    a different customer's field id can override it, defaulting to the Logicalis
    ``customfield_10071`` seen on live tickets."""
    fid = os.environ.get("JIRA_FIELD_INCIDENT_NUMBER", "customfield_10071")
    val = (fields or {}).get(fid)
    if val is None:
        return None
    s = str(val).strip()
    # Must be a bare integer to be safely interpolated into KQL (no injection).
    return s if re.fullmatch(r"\d+", s) else None


def _resolve_device_name(fields: dict) -> str | None:
    """Best-effort host name from the Host Entities custom field. The field holds
    a Sentinel host-entity JSON object (sometimes ADF-wrapped); we only need the
    ``hostName``. Returns a KQL-safe token or None."""
    fid = os.environ.get("JIRA_FIELD_HOST_ENTITIES", "customfield_10078")
    raw = (fields or {}).get(fid)
    if not raw:
        return None
    text = json.dumps(raw) if not isinstance(raw, str) else raw
    m = re.search(r'"hostName"\s*:\s*"([^"]+)"', text)
    if not m:
        return None
    host = m.group(1).strip()
    # Only allow a safe hostname token (letters/digits/.-_) — reject anything that
    # could break out of the quoted KQL string literal.
    return host if re.fullmatch(r"[A-Za-z0-9._-]+", host) else None


def _parse_entities(entities_json: str) -> list[dict]:
    """Extract process command lines from a SecurityAlert ``Entities`` blob.

    Returns a list of ``{"command_line", "image", "parent_image",
    "parent_command_line"}`` — one per Process entity that carries a CommandLine.
    """
    out: list[dict] = []
    try:
        ents = json.loads(entities_json)
    except (TypeError, ValueError):
        return out
    if not isinstance(ents, list):
        return out
    for e in ents:
        if not isinstance(e, dict):
            continue
        cl = e.get("CommandLine") or e.get("commandLine")
        if not cl or not str(cl).strip():
            continue
        image = ""
        imgfile = e.get("ImageFile") or {}
        if isinstance(imgfile, dict):
            image = imgfile.get("Name") or imgfile.get("name") or ""
        parent_image, parent_cl = "", ""
        parent = e.get("ParentProcess") or {}
        if isinstance(parent, dict):
            parent_cl = parent.get("CommandLine") or ""
            pimg = parent.get("ImageFile") or {}
            if isinstance(pimg, dict):
                parent_image = pimg.get("Name") or ""
        out.append({
            "command_line": str(cl).strip()[:_MAX_CMDLINE_LEN],
            "image": image,
            "parent_image": parent_image,
            "parent_command_line": str(parent_cl).strip()[:_MAX_CMDLINE_LEN],
        })
    return out


def _dedupe_and_rank(rows: list[dict], parsed_per_row: list[list[dict]]) -> list[dict]:
    """Flatten, dedupe by command line, and rank LOLBin/script-host command lines
    first so the analyzer's per-ticket cap spends its budget on the lines most
    likely to matter."""
    seen: set[str] = set()
    merged: list[dict] = []
    for row, procs in zip(rows, parsed_per_row):
        for p in procs:
            key = p["command_line"]
            if key in seen:
                continue
            seen.add(key)
            merged.append({
                **p,
                "alert_name": row.get("AlertName", ""),
                "provider": row.get("ProviderName", ""),
            })

    def _rank(item: dict) -> int:
        img = (item.get("image") or "").lower()
        return 0 if img in _INTERESTING_IMAGES else 1

    merged.sort(key=_rank)
    return merged


def _run_query(token: str, workspace_id: str, query: str) -> list[dict]:
    from tools.sentinel_client import _safe_kql
    try:
        return _safe_kql(token, query, timespan=_DEFAULT_LOOKBACK, workspace_id=workspace_id) or []
    except PermissionError as e:
        logger.warning("cmdline_source: Sentinel auth denied — %s", e)
        return []


def _incident_query(incident_number: str) -> str:
    return (
        f"SecurityIncident "
        f"| where IncidentNumber == {incident_number} "
        f"| summarize arg_max(TimeGenerated, AlertIds) "
        f"| mv-expand AlertId = AlertIds to typeof(string) "
        f"| join kind=inner ("
        f"    SecurityAlert | where Entities has \"CommandLine\" "
        f"    | project SystemAlertId, AlertName, ProviderName, TimeGenerated, Entities"
        f"  ) on $left.AlertId == $right.SystemAlertId "
        f"| project AlertName, ProviderName, TimeGenerated, Entities "
        f"| take {_MAX_ALERTS}"
    )


def _device_query(device_name: str) -> str:
    return (
        f"SecurityAlert "
        f"| where Entities has \"{device_name}\" and Entities has \"CommandLine\" "
        f"| project AlertName, ProviderName, TimeGenerated, Entities "
        f"| order by TimeGenerated desc "
        f"| take {_MAX_ALERTS}"
    )


def fetch_command_lines(customer: dict | None, ticket_key: str, fields: dict) -> list[dict]:
    """Return the distinct process command lines for a ticket, newest-incident
    first, ranked with LOLBins/script-hosts ahead of the rest and capped at
    ``CMDLINE_SOURCE_MAX_CMDLINES``.

    Each item: ``{"command_line", "image", "parent_image",
    "parent_command_line", "alert_name", "provider"}``.

    Returns ``[]`` on every skip/failure mode (no workspace configured, no
    incident/device key, auth denied, empty result). Never raises.
    """
    from tools.kql_expansion import _resolve_workspace, _resolve_sentinel_token

    ws = _resolve_workspace(customer)
    if not ws:
        logger.info("cmdline_source %s: customer has no Sentinel workspace — skipping", ticket_key)
        return []

    incident_number = _resolve_incident_number(fields)
    device_name = _resolve_device_name(fields)
    if not incident_number and not device_name:
        logger.info("cmdline_source %s: no incident number or device name on ticket — skipping",
                    ticket_key)
        return []

    token = _resolve_sentinel_token(ws)
    if not token:
        logger.info("cmdline_source %s: could not acquire Sentinel token — skipping", ticket_key)
        return []

    workspace_id = ws["workspace_id"]
    rows: list[dict] = []

    if incident_number:
        rows = _run_query(token, workspace_id, _incident_query(incident_number))
        logger.info("cmdline_source %s: incident %s returned %d alert row(s)",
                    ticket_key, incident_number, len(rows))

    if not rows and device_name:
        rows = _run_query(token, workspace_id, _device_query(device_name))
        logger.info("cmdline_source %s: device fallback '%s' returned %d alert row(s)",
                    ticket_key, device_name, len(rows))

    if not rows:
        return []

    parsed = [_parse_entities(r.get("Entities", "")) for r in rows]
    merged = _dedupe_and_rank(rows, parsed)
    if len(merged) > _MAX_CMDLINES:
        logger.info("cmdline_source %s: %d distinct command lines, analysing first %d",
                    ticket_key, len(merged), _MAX_CMDLINES)
    return merged[:_MAX_CMDLINES]
