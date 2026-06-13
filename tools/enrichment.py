"""
IOC enrichment pipeline for Jira webhook processing.

Flow:
  1. extract_iocs_from_entity_fields() — read structured Sentinel-style entity custom fields (primary)
  2. extract_iocs() — regex fallback over summary + description text
  3. check_reputation()  — fan-out to SOCRadar (+ VT/AbuseIPDB when keys present)
  4. determine_verdict() — aggregate: any malicious → malicious
  5. post_jira_comment() — post enrichment summary as ADF comment
  6. assign_jira_ticket()— reassign based on verdict
  7. enrich_ticket()     — orchestrates all steps end-to-end
"""
import ipaddress
import logging
import os
import re
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

JIRA_URL = os.environ.get("JIRA_URL", "").rstrip("/")

# ─── L1 Triage labels ─────────────────────────────────────────────────────────
# Jira labels applied to triaged tickets based on the aggregated verdict.
# Phase 1 (2026-06-08): switched defaults from generic IOC_Detection /
# investigating to explicit True-Positive / False-Positive / Unknown so the
# label conveys the triage outcome directly. The label must already exist in
# the target Jira instance — the webhook handler only ADDS the label, it does
# not create it. Override via env if your Jira convention differs.
_TRIAGE_MALICIOUS_LABEL = os.environ.get("JIRA_TRIAGE_MALICIOUS_LABEL", "True-Positive")
_TRIAGE_CLEAN_LABEL     = os.environ.get("JIRA_TRIAGE_CLEAN_LABEL",     "False-Positive")
_TRIAGE_UNKNOWN_LABEL   = os.environ.get("JIRA_TRIAGE_UNKNOWN_LABEL",   "Unknown")

# ─── Custom field IDs for Sentinel-style structured entity fields ─────────────
# Override via env if Jira admin renumbers fields. Defaults are the SCDM project's
# current IDs (verified 2026-05-05 against SCDM-41).
_FIELD_IP_ENTITIES   = os.environ.get("JIRA_FIELD_IP_ENTITIES",   "customfield_10079")
_FIELD_HOST_ENTITIES = os.environ.get("JIRA_FIELD_HOST_ENTITIES", "customfield_10078")
_FIELD_DNS_ENTITIES  = os.environ.get("JIRA_FIELD_DNS_ENTITIES",  "customfield_10080")
_FIELD_URL_ENTITIES  = os.environ.get("JIRA_FIELD_URL_ENTITIES",  "customfield_10081")
_FIELD_HASH_ENTITIES = os.environ.get("JIRA_FIELD_HASH_ENTITIES", "customfield_10082")

ENTITY_FIELD_IDS = (
    _FIELD_IP_ENTITIES, _FIELD_HOST_ENTITIES, _FIELD_DNS_ENTITIES,
    _FIELD_URL_ENTITIES, _FIELD_HASH_ENTITIES,
)


def has_entity_data(fields: dict) -> bool:
    """Return True if any Sentinel-style entity custom field is non-empty.

    Used by the webhook poller to detect when a Service Desk request form has
    finished merging its entity fields into the issue (which can take 30+
    seconds after the issue_created event fires)."""
    if not fields:
        return False
    for fid in ENTITY_FIELD_IDS:
        val = fields.get(fid)
        if val is None:
            continue
        if isinstance(val, str) and val.strip():
            return True
        if isinstance(val, dict) and _extract_adf_text(val).strip():
            return True
        if isinstance(val, list) and any(val):
            return True
    return False

# ─── IOC regex patterns ───────────────────────────────────────────────────────

_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_IPV4   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|biz|info|xyz|ru|cn|tk|top|cc|pw|onion'
    r'|online|site|live|app|store|shop|tech|club|pro|co|me|us|uk|de|fr'
    r'|jp|au|nz|sg|my|id|ph|vn|in|br|za)\b',
    re.IGNORECASE,
)

_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    )
]

# Domains that appear in normal Jira/SIEM ticket bodies but are not IOCs
_DOMAIN_ALLOWLIST = {
    "atlassian.net", "jira.com", "microsoft.com", "windows.com",
    "office.com", "azure.com", "cloudflare.com", "github.com",
    "amazonaws.com", "google.com", "gmail.com", "outlook.com",
    "logicalis.com", "sharepoint.com", "teams.microsoft.com",
}


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


def _is_allowlisted_domain(domain: str) -> bool:
    domain = domain.lower()
    return any(
        domain == allowed or domain.endswith("." + allowed)
        for allowed in _DOMAIN_ALLOWLIST
    )


def _extract_adf_text(field_value) -> str:
    if not field_value:
        return ""
    if isinstance(field_value, str):
        return field_value
    parts = []

    def _walk(node):
        if isinstance(node, dict):
            if node.get("type") == "text":
                parts.append(node.get("text", ""))
            for child in node.get("content", []):
                _walk(child)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(field_value)
    return " ".join(parts).strip()


# ─── IOC Extraction ───────────────────────────────────────────────────────────

def extract_iocs(text: str) -> list[dict]:
    """Extract unique, public IOCs from plain text.

    Returns a list of {"type": "ip"|"domain"|"hash", "subtype": str, "value": str}.
    Hashes are checked longest-first to avoid MD5 matching inside SHA256.
    Private/loopback IPs and allowlisted domains are excluded.
    """
    seen: set[str] = set()
    iocs: list[dict] = []

    for m in _RE_SHA256.finditer(text):
        val = m.group().lower()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "hash", "subtype": "sha256", "value": val})

    for m in _RE_SHA1.finditer(text):
        val = m.group().lower()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "hash", "subtype": "sha1", "value": val})

    for m in _RE_MD5.finditer(text):
        val = m.group().lower()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "hash", "subtype": "md5", "value": val})

    for m in _RE_IPV4.finditer(text):
        val = m.group()
        if val not in seen and not _is_private_ip(val):
            seen.add(val)
            iocs.append({"type": "ip", "subtype": "ipv4", "value": val})

    for m in _RE_DOMAIN.finditer(text):
        val = m.group().lower()
        if val not in seen and not _is_allowlisted_domain(val):
            seen.add(val)
            iocs.append({"type": "domain", "subtype": "fqdn", "value": val})

    logger.info("extract_iocs: found %d IOCs", len(iocs))
    return iocs


# ─── Structured Entity Field Extraction ───────────────────────────────────────

def _split_entity_values(adf_field) -> list[str]:
    """Flatten an ADF custom field and split into individual entity values.
    Sentinel-populated entity fields can contain multiple values separated by
    whitespace, newlines, or commas."""
    text = _extract_adf_text(adf_field)
    if not text:
        return []
    parts = re.split(r"[\s,;]+", text)
    return [p.strip() for p in parts if p.strip()]


def extract_iocs_from_entity_fields(fields: dict) -> list[dict]:
    """Read Sentinel-style structured entity custom fields and produce typed IOCs.

    Returns the same shape as extract_iocs(): a list of
    {"type": "ip"|"domain"|"hash", "subtype": str, "value": str}.

    Field IDs are env-configurable via JIRA_FIELD_*_ENTITIES.
    """
    seen: set[str] = set()
    iocs: list[dict] = []

    # IP Address Entities
    for val in _split_entity_values(fields.get(_FIELD_IP_ENTITIES)):
        v = val.lower()
        if v in seen or _is_private_ip(val):
            continue
        try:
            ipaddress.ip_address(val)
        except ValueError:
            continue
        seen.add(v)
        iocs.append({"type": "ip", "subtype": "ipv4", "value": val})

    # Host Entities and DNS Entities → both treated as domains
    for field_id in (_FIELD_HOST_ENTITIES, _FIELD_DNS_ENTITIES):
        for val in _split_entity_values(fields.get(field_id)):
            v = val.lower()
            if v in seen or _is_allowlisted_domain(v):
                continue
            # Skip values that look like IPs or hashes (wrong field but defensive)
            if _RE_IPV4.fullmatch(val) or _RE_SHA256.fullmatch(val) or _RE_SHA1.fullmatch(val) or _RE_MD5.fullmatch(val):
                continue
            seen.add(v)
            iocs.append({"type": "domain", "subtype": "fqdn", "value": v})

    # URL Entities → extract host
    for val in _split_entity_values(fields.get(_FIELD_URL_ENTITIES)):
        try:
            host = urlparse(val if "://" in val else f"http://{val}").hostname
        except Exception:
            host = None
        if not host:
            continue
        h = host.lower()
        if h in seen or _is_allowlisted_domain(h):
            continue
        seen.add(h)
        iocs.append({"type": "domain", "subtype": "fqdn", "value": h})

    # FileHash Entities → classify by length
    for val in _split_entity_values(fields.get(_FIELD_HASH_ENTITIES)):
        v = val.lower()
        if v in seen:
            continue
        if _RE_SHA256.fullmatch(v):
            subtype = "sha256"
        elif _RE_SHA1.fullmatch(v):
            subtype = "sha1"
        elif _RE_MD5.fullmatch(v):
            subtype = "md5"
        else:
            continue
        seen.add(v)
        iocs.append({"type": "hash", "subtype": subtype, "value": v})

    logger.info("extract_iocs_from_entity_fields: found %d IOCs", len(iocs))
    return iocs


# ─── Reputation Checking ──────────────────────────────────────────────────────

def check_reputation(ioc: dict, socradar_enabled: bool = True) -> dict:
    """Fan out IOC to all configured reputation sources: SOCRadar, VirusTotal,
    and AbuseIPDB. Returns a merged result + an aggregated verdict.

    SOCRadar wires through tools.socradar_rest.check_ioc() against the
    `/api/threat/analysis` endpoint — this needs the SOCRadar 'Threat Analysis
    API' key (env: SOCRADAR_THREAT_ANALYSIS_KEY). If the key is unset OR
    socradar_enabled is False, SOCRadar is skipped and the verdict falls
    through to VT + AbuseIPDB only.

    The `socradar_enabled` flag exists so the orchestrator (enrich_ticket)
    can cap SOCRadar lookups per ticket — the API has a 100/day budget and
    a 5-per-minute rate limit, so calling it on every IOC of a 16-IOC
    ticket would (a) burn 16% of the daily quota in one go and (b) stretch
    webhook latency past 5 minutes. Tickets typically have 1-3 IOCs that
    matter; the rest are duplicates or known-noise.

    Verdict aggregation: ANY source flagging malicious → ticket is malicious.
    All sources None → verdict is 'unknown' (no engines reachable).
    """
    from tools import virustotal_client, abuseipdb_client, socradar_rest

    ioc_type = ioc["type"]
    value = ioc["value"]

    result: dict = {
        "ioc": ioc,
        "virustotal": None,
        "abuseipdb": None,
        "socradar": None,
        "verdict": "unknown",
    }

    result["virustotal"] = virustotal_client.check_ioc(value, ioc_type)
    if ioc_type == "ip":
        result["abuseipdb"] = abuseipdb_client.check_ip(value)
    if socradar_enabled:
        result["socradar"] = socradar_rest.check_ioc(value, ioc_type)

    malicious = False
    if result["virustotal"] and result["virustotal"].get("malicious_count", 0) > 0:
        malicious = True
    if result["abuseipdb"] and result["abuseipdb"].get("confidence_score", 0) > 50:
        malicious = True
    if result["socradar"] and result["socradar"].get("verdict") == "malicious":
        malicious = True

    all_none = all(result[k] is None for k in ("virustotal", "abuseipdb", "socradar"))
    result["verdict"] = "malicious" if malicious else ("unknown" if all_none else "clean")

    return result


def determine_verdict(results: list[dict]) -> str:
    """Aggregate per-IOC verdicts into a single ticket verdict."""
    if not results:
        return "unknown"
    if any(r["verdict"] == "malicious" for r in results):
        return "malicious"
    if all(r["verdict"] == "unknown" for r in results):
        return "unknown"
    return "clean"


# ─── Comment Builder ──────────────────────────────────────────────────────────

_VERDICT_LABEL = {
    "malicious": "TRUE-POSITIVE",
    "clean":     "FALSE-POSITIVE",
    "unknown":   "UNKNOWN",
}


def _format_sgt(raw: str) -> str:
    """Render an ISO 8601 timestamp in Asia/Singapore (UTC+8). Returns the raw
    string unchanged if parsing fails — analysts still see *some* time rather
    than nothing if a source emits an unusual format."""
    if not raw:
        return ""
    try:
        from datetime import datetime, timezone
        from zoneinfo import ZoneInfo
        s = str(raw).strip()
        if s.endswith("Z"):  # python<3.11 fromisoformat can't parse trailing Z
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(ZoneInfo("Asia/Singapore")).strftime("%Y-%m-%d %H:%M:%S SGT")
    except Exception:
        return str(raw)


def _ip_origin_lines(vt: dict | None, ab: dict | None) -> list[str]:
    """Build the per-IP Origin block for the L1 Triage comment. Combines
    AbuseIPDB and VirusTotal metadata so the analyst sees who owns the IP
    and where it sits without expanding raw payloads. Returns 0 lines if no
    origin data is available from either source."""
    ab = ab or {}
    vt = vt or {}

    country_name = ab.get("country_name") or ""
    country_code = ab.get("country_code") or vt.get("country") or ""
    # AbuseIPDB's ISP is more human-readable ("Microsoft Corporation");
    # VT's as_owner is more technical ("MICROSOFT-CORP-MSN-AS-BLOCK").
    # Prefer ISP, fall back to as_owner. Show both only when they say
    # genuinely different things.
    isp        = ab.get("isp") or ""
    as_owner   = vt.get("as_owner") or ""
    network    = vt.get("network") or ""
    usage_type = ab.get("usage_type") or ""
    domain     = ab.get("domain") or ""
    hostnames  = ab.get("hostnames") or []

    origin_parts: list[str] = []
    if country_name and country_code:
        origin_parts.append(f"{country_name} ({country_code})")
    elif country_name or country_code:
        origin_parts.append(country_name or country_code)
    if isp:
        origin_parts.append(f"ISP: {isp}")
    elif as_owner:
        origin_parts.append(f"AS: {as_owner}")
    if network:
        origin_parts.append(f"Network: {network}")
    if usage_type:
        origin_parts.append(f"Usage: {usage_type}")

    out: list[str] = []
    if origin_parts:
        out.append("  Origin: " + " • ".join(origin_parts))

    dns_parts: list[str] = []
    if domain:
        dns_parts.append(f"Domain: {domain}")
    if hostnames:
        # Show the first hostname; truncate the rest to a count to avoid a
        # noisy comment when an IP resolves to dozens of PTRs.
        first = hostnames[0]
        extra = f" (+{len(hostnames) - 1} more)" if len(hostnames) > 1 else ""
        dns_parts.append(f"Reverse: {first}{extra}")
    if dns_parts:
        out.append("  " + " • ".join(dns_parts))

    return out


def _append_mitre_section(lines: list[str], mitre_result: dict | None) -> None:
    """Inject MITRE ATT&CK section into lines in-place. No-op if result is absent."""
    if not mitre_result:
        return
    techniques = mitre_result.get("techniques") or []
    if not techniques:
        return
    lines.append("MITRE ATT&CK Mapping:")
    for t in techniques:
        pct = int(round(t.get("confidence", 0) * 100))
        lines.append(f"  [{t['id']}] {t['tactic']} — {t['name']} ({pct}% confidence)")
    lines.append("")


def _append_historical_section(lines: list[str], historical: dict | None) -> None:
    """Phase 3 (2026-06-13): inject the 'Similar Alerts (past 24h)' block
    into the enrichment comment. No-op when historical is None or total=0
    (first-time occurrence — adding a "Similar Alerts: 0" line would be
    noise, not signal)."""
    if not historical or historical.get("total", 0) <= 0:
        return
    window = historical.get("window_hours", 24)
    total = historical["total"]
    tp = historical.get("true_positive", 0)
    fp = historical.get("false_positive", 0)
    unk = historical.get("unknown", 0)
    unt = historical.get("untriaged", 0)
    prefix = historical.get("rule_prefix") or ""
    first_seen = _format_sgt(historical.get("first_seen_at") or "")

    lines.append(f"Similar Alerts (past {window}h): {total}")
    lines.append(f"  ├─ True-Positive:  {tp}")
    lines.append(f"  ├─ False-Positive: {fp}")
    lines.append(f"  ├─ Unknown:        {unk}")
    suffix = " (still in flight)" if unt else ""
    lines.append(f"  └─ Untriaged:      {unt}{suffix}")
    if prefix:
        lines.append(f"  Matched on: \"{prefix}\"")
    if first_seen:
        lines.append(f"  Earliest sibling: {first_seen}")
    lines.append("")


def _build_comment(ioc_results: list[dict], overall_verdict: str, action_taken: str,
                   mitre_result: dict | None = None,
                   historical: dict | None = None) -> str:
    lines = ["=== L1 Triage Report (Automated) ===", ""]
    verdict_display = _VERDICT_LABEL.get(overall_verdict, overall_verdict.upper())

    if not ioc_results:
        # No IOCs to actually query — produce reputation-engine-shaped output for
        # consistency with tickets that DO have IOCs. The triage outcome is
        # Unknown (we can't confirm or refute without observables); the ticket
        # is routed to L2 for analyst review.
        lines += [
            "Reputation engines (no extractable IOCs — no actual queries made):",
            "  - VirusTotal:  No detections",
            "  - AbuseIPDB:   No threat detected",
            "  - SOCRadar:    No detections",
            "",
        ]
        _append_historical_section(lines, historical)
        _append_mitre_section(lines, mitre_result)
        lines += [
            f"VERDICT: {verdict_display}",
            f"ACTION:  {action_taken}",
        ]
        return "\n".join(lines)

    # An "IOC" here means an observable that at least one reputation engine flagged
    # as malicious. Observables that all engines cleared (or returned no data for)
    # are still listed below for analyst visibility but don't bump the IOC count.
    ioc_count = sum(1 for r in ioc_results if r.get("verdict") == "malicious")
    lines.append(f"IOCs found: {ioc_count}")
    lines.append(f"(Extracted observables checked: {len(ioc_results)})")
    lines.append("")

    for i, result in enumerate(ioc_results, 1):
        ioc = result["ioc"]
        lines.append(f"[{i}] {ioc['value']} ({ioc['type'].upper()})")

        vt = result.get("virustotal")
        ab = result.get("abuseipdb")

        # Origin block (IPs only) — country + ISP/AS owner + reverse DNS.
        # Surfaces metadata both reputation engines already fetch but don't
        # historically display, so analysts see "Microsoft Azure IP from US"
        # at a glance instead of digging through raw payloads.
        if ioc["type"] == "ip":
            lines.extend(_ip_origin_lines(vt, ab))

        if vt:
            mal = vt.get("malicious_count", 0)
            tot = vt.get("total_engines", 0)
            rep = vt.get("reputation", 0)
            if tot > 0:
                confidence = (mal / tot) * 100
                lines.append(
                    f"  VirusTotal: {mal}/{tot} detections "
                    f"(Confidence {confidence:.1f}%, Reputation {rep})"
                )
            else:
                lines.append(f"  VirusTotal: {mal}/{tot} detections (Reputation {rep})")
        else:
            lines.append("  VirusTotal: Not configured")

        if ioc["type"] == "ip":
            if ab:
                lines.append(f"  AbuseIPDB: Confidence {ab.get('confidence_score', 0)}%")
            else:
                lines.append("  AbuseIPDB: Not configured")
        else:
            lines.append("  AbuseIPDB: N/A (IP only)")

        sr = result.get("socradar")
        if sr:
            verdict = sr.get("verdict", "unknown")
            score = sr.get("score", 0)
            cats = sr.get("categories") or []
            cats_str = (" — " + ", ".join(cats)) if cats else ""
            lines.append(f"  SOCRadar:  {verdict.title()} (score {score}/100){cats_str}")
            for f in (sr.get("top_findings") or [])[:3]:
                src = f.get("source") or "?"
                cat = f.get("category") or "?"
                rel = f.get("reliability") or 0
                last = _format_sgt(f.get("last_seen") or "")
                lines.append(f"    · {src} — {cat} (reliability {rel}, last seen {last})")
        else:
            lines.append("  SOCRadar:  Not configured")

        lines.append("")

    _append_historical_section(lines, historical)
    _append_mitre_section(lines, mitre_result)
    lines.append(f"VERDICT: {verdict_display}")
    lines.append(f"ACTION:  {action_taken}")
    return "\n".join(lines)


# ─── Jira Actions ─────────────────────────────────────────────────────────────

def _jira_headers() -> dict:
    import base64
    from tools.secrets import get_secret
    email = get_secret("JIRA_EMAIL")
    token = get_secret("JIRA_API_TOKEN")
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def post_jira_comment(ticket_key: str, text: str) -> bool:
    """Post a plain-text comment to a Jira issue using ADF format."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot post comment to %s", ticket_key)
        return False

    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}/comment"
    paragraphs = [
        {"type": "paragraph", "content": [{"type": "text", "text": line or " "}]}
        for line in text.split("\n")
    ]
    body = {"body": {"type": "doc", "version": 1, "content": paragraphs}}

    try:
        r = httpx.post(url, headers=_jira_headers(), json=body, timeout=30)
        if r.status_code >= 400:
            logger.error("post_jira_comment %s HTTP %s: %s", ticket_key, r.status_code, r.text[:300])
            return False
        logger.info("Posted enrichment comment to %s", ticket_key)
        return True
    except Exception as e:
        logger.error("post_jira_comment %s failed: %s", ticket_key, e)
        return False


def add_jira_label(ticket_key: str, label: str) -> bool:
    """Add a label to a Jira issue without removing existing labels."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot label %s", ticket_key)
        return False

    get_url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}"
    try:
        r = httpx.get(get_url, headers=_jira_headers(), timeout=30)
        if r.status_code >= 400:
            logger.error("add_jira_label GET %s HTTP %s", ticket_key, r.status_code)
            return False
        existing = r.json().get("fields", {}).get("labels", [])
        if label in existing:
            return True
        updated = existing + [label]
        put_url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}"
        r2 = httpx.put(put_url, headers=_jira_headers(),
                       json={"fields": {"labels": updated}}, timeout=30)
        if r2.status_code >= 400:
            logger.error("add_jira_label PUT %s HTTP %s: %s",
                         ticket_key, r2.status_code, r2.text[:200])
            return False
        logger.info("Added label '%s' to %s", label, ticket_key)
        return True
    except Exception as e:
        logger.error("add_jira_label %s failed: %s", ticket_key, e)
        return False


def assign_jira_ticket(ticket_key: str, account_id: str) -> bool:
    """Reassign a Jira ticket to the given Jira account ID."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot assign %s", ticket_key)
        return False

    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}/assignee"
    try:
        r = httpx.put(url, headers=_jira_headers(), json={"accountId": account_id}, timeout=30)
        if r.status_code >= 400:
            logger.error("assign_jira_ticket %s → %s HTTP %s: %s",
                         ticket_key, account_id, r.status_code, r.text[:300])
            return False
        logger.info("Assigned %s to account %s", ticket_key, account_id)
        return True
    except Exception as e:
        logger.error("assign_jira_ticket %s failed: %s", ticket_key, e)
        return False


def set_priority(ticket_key: str, priority_name: str) -> bool:
    """Set the Jira priority on a ticket. priority_name must match a Jira
    priority option exactly (e.g. "Highest", "High", "Medium", "Low",
    "Lowest"). Added in Phase 1 for severity-sync + LLM Triage override."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot set priority on %s", ticket_key)
        return False
    if not priority_name:
        return False

    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}"
    try:
        r = httpx.put(url, headers=_jira_headers(),
                      json={"fields": {"priority": {"name": priority_name}}},
                      timeout=30)
        if r.status_code >= 400:
            logger.error("set_priority %s → %s HTTP %s: %s",
                         ticket_key, priority_name, r.status_code, r.text[:300])
            return False
        logger.info("set_priority(%s) → %s", ticket_key, priority_name)
        return True
    except Exception as e:
        logger.error("set_priority %s failed: %s", ticket_key, e)
        return False


def remove_jira_label(ticket_key: str, label: str) -> bool:
    """Remove a label from a Jira issue. No-op if the label isn't present."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot remove label from %s", ticket_key)
        return False

    get_url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}"
    try:
        r = httpx.get(get_url, headers=_jira_headers(), timeout=30)
        if r.status_code >= 400:
            logger.error("remove_jira_label GET %s HTTP %s", ticket_key, r.status_code)
            return False
        existing = r.json().get("fields", {}).get("labels", [])
        if label not in existing:
            return True
        updated = [lbl for lbl in existing if lbl != label]
        r2 = httpx.put(get_url, headers=_jira_headers(),
                       json={"fields": {"labels": updated}}, timeout=30)
        if r2.status_code >= 400:
            logger.error("remove_jira_label PUT %s HTTP %s: %s",
                         ticket_key, r2.status_code, r2.text[:200])
            return False
        logger.info("Removed label '%s' from %s", label, ticket_key)
        return True
    except Exception as e:
        logger.error("remove_jira_label %s failed: %s", ticket_key, e)
        return False


# ─── Main Orchestrator ────────────────────────────────────────────────────────

def enrich_ticket(ticket_key: str, fields: dict,
                  historical: dict | None = None) -> dict:
    """Full enrichment pipeline for one Jira ticket.

    Reads typed Sentinel-style entity fields first (the canonical IOC source),
    then regexes summary + description as a belt-and-suspenders fallback for
    free-text mentions. Dedupes by value. Checks reputation across all
    configured sources, posts a comment with the findings, and reassigns the
    ticket based on verdict. Returns a summary dict for job status tracking.

    Phase 3 (2026-06-13): optional `historical` arg from
    tools.historical_alerts.query_similar_alerts(). When present and total>0,
    the comment renders a 'Similar Alerts (past 24h)' block between IOC
    reputations and the MITRE section.
    """
    from tools.secrets import get_secret

    summary = fields.get("summary") or ""
    desc_text = _extract_adf_text(fields.get("description"))

    # Primary source: typed entity fields (canonical, populated by Sentinel)
    entity_iocs = extract_iocs_from_entity_fields(fields)

    # Fallback source: regex over free text (catches analyst-pasted IOCs)
    regex_iocs = extract_iocs(f"{summary}\n{desc_text}")

    # Dedupe by value, prefer typed entries from entity fields
    seen_values: set[str] = {i["value"] for i in entity_iocs}
    iocs = list(entity_iocs)
    for i in regex_iocs:
        if i["value"] not in seen_values:
            seen_values.add(i["value"])
            iocs.append(i)

    logger.info(
        "enrich_ticket(%s): %d IOCs total (entity=%d, regex-fallback=%d)",
        ticket_key, len(iocs), len(entity_iocs), len(regex_iocs),
    )

    # Cap SOCRadar lookups per ticket (default 5). The API has a 100/day budget
    # and a 5-per-minute rate limit; calling it on every IOC of a 16-IOC ticket
    # would burn the daily quota fast and push webhook latency past 5 min.
    # Override via SOCRADAR_TRIAGE_BUDGET_PER_TICKET if you want different.
    socradar_budget = int(os.environ.get("SOCRADAR_TRIAGE_BUDGET_PER_TICKET", "5"))
    ioc_results = []
    socradar_used = 0
    for ioc in iocs:
        enabled = socradar_used < socradar_budget
        res = check_reputation(ioc, socradar_enabled=enabled)
        ioc_results.append(res)
        if res.get("socradar") is not None:
            socradar_used += 1
    if socradar_used >= socradar_budget and len(iocs) > socradar_budget:
        logger.info("enrich_ticket(%s): SOCRadar budget exhausted (%d/%d) — "
                    "remaining IOCs covered by VT + AbuseIPDB only",
                    ticket_key, socradar_used, len(iocs))
    overall_verdict = determine_verdict(ioc_results)

    # Phase 2 (2026-06-10): MITRE ATT&CK mapping — runs after full reputation
    # picture is available so SOCRadar categories can seed the LLM prompt.
    # Wrapped in try/except: any failure is logged and silently skipped.
    mitre_result = None
    if os.environ.get("MITRE_MAPPING_ENABLED", "true").lower() != "false":
        try:
            from tools import mitre_mapper
            mitre_result = mitre_mapper.map_mitre(ticket_key, fields, ioc_results)
        except Exception as _e:
            logger.warning("enrich_ticket(%s): MITRE mapping failed (%s) — skipping",
                           ticket_key, _e)

    l1_id = get_secret("JIRA_L1_ACCOUNT_ID")
    l2_id = get_secret("JIRA_L2_ACCOUNT_ID")

    # Phase 1 (2026-06-08): verdict-to-label mapping is now explicit across all
    # three outcomes (True-Positive / False-Positive / Unknown). The "unknown"
    # case previously fell through to clean; it now gets its own label so an
    # analyst can distinguish "we checked and it's benign" from "we couldn't
    # tell" at a glance. Assignment routing (L1 for TP, L2 for FP and Unknown)
    # is unchanged — auto-close for FP is deferred to Phase 7.
    if overall_verdict == "malicious":
        add_jira_label(ticket_key, _TRIAGE_MALICIOUS_LABEL)
        action_taken = (f"Ticket flagged as a True Positive — labelled "
                        f"'{_TRIAGE_MALICIOUS_LABEL}'.")
        if l1_id:
            assign_jira_ticket(ticket_key, l1_id)
            action_taken += " Assigned to L1 Lead."
        else:
            action_taken += " (JIRA_L1_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L1_ACCOUNT_ID not set — cannot assign %s to L1 lead", ticket_key)
    elif overall_verdict == "unknown":
        add_jira_label(ticket_key, _TRIAGE_UNKNOWN_LABEL)
        action_taken = (f"Verdict Unknown — labelled '{_TRIAGE_UNKNOWN_LABEL}'. "
                        f"Routed to L2 SOC Analyst for manual review.")
        if l2_id:
            assign_jira_ticket(ticket_key, l2_id)
        else:
            action_taken += " (JIRA_L2_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L2_ACCOUNT_ID not set — cannot assign %s to L2", ticket_key)
    else:
        add_jira_label(ticket_key, _TRIAGE_CLEAN_LABEL)
        action_taken = (f"Ticket judged a False Positive — labelled "
                        f"'{_TRIAGE_CLEAN_LABEL}'. Routed to L2 SOC Analyst for sign-off.")
        if l2_id:
            assign_jira_ticket(ticket_key, l2_id)
        else:
            action_taken += " (JIRA_L2_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L2_ACCOUNT_ID not set — cannot assign %s to L2", ticket_key)

    comment_text = _build_comment(ioc_results, overall_verdict, action_taken,
                                   mitre_result, historical)
    post_jira_comment(ticket_key, comment_text)

    return {
        "ticket": ticket_key,
        "iocs": ioc_results,
        "verdict": overall_verdict,
        "action": action_taken,
    }
