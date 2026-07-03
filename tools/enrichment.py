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
import json
import logging
import os
import re
from urllib.parse import urlparse

import httpx

from tools.jira_schema import default_schema

logger = logging.getLogger(__name__)

JIRA_URL = os.environ.get("JIRA_URL", "").rstrip("/")

# ─── L1 Triage labels ─────────────────────────────────────────────────────────
# Jira labels applied to triaged tickets based on the aggregated verdict.
# Phase 1 (2026-06-08): switched defaults from generic IOC_Detection /
# investigating to explicit True-Positive / Benign-Positive / Unknown so the
# label conveys the triage outcome directly. The label must already exist in
# the target Jira instance — the webhook handler only ADDS the label, it does
# not create it. Override via env if your Jira convention differs.
_TRIAGE_MALICIOUS_LABEL = os.environ.get("JIRA_TRIAGE_MALICIOUS_LABEL", "True-Positive")
_TRIAGE_CLEAN_LABEL     = os.environ.get("JIRA_TRIAGE_CLEAN_LABEL",     "Benign-Positive")
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


def has_entity_data(fields: dict, schema=None) -> bool:
    """Return True if any Sentinel-style entity custom field is non-empty.

    Used by the webhook poller to detect when a Service Desk request form has
    finished merging its entity fields into the issue (which can take 30+
    seconds after the issue_created event fires)."""
    if not fields:
        return False
    for fid in (schema or default_schema()).entity_field_ids():
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
    """True for any non-globally-routable address (skip from reputation checks).

    Handles IPv4 and IPv6, including IPv4-mapped IPv6 (``::ffff:a.b.c.d``) and
    link-local (``fe80::/10``). Reputation engines only make sense for public
    addresses, so private/loopback/link-local/reserved/multicast are all skipped."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


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

def _entity_json_objects(text: str) -> list[dict] | None:
    """Sentinel/Defender exports store entity fields as one or more
    whitespace-separated JSON objects, e.g. ``{"address":"1.2.3.4","Type":"ip"}``
    or ``{"hashValue":"ab..","algorithm":"SHA1"}``. Parse them with a raw_decode
    loop so nested/escaped JSON (Host entity ``additionalData``) is handled.

    Returns the parsed objects, or None if the text is not JSON — in which case
    the caller falls back to legacy plain-value splitting. If the text starts as
    JSON but is malformed, also returns None (fall back rather than raise)."""
    s = text.strip()
    if not s.startswith("{"):
        return None
    objs: list[dict] = []
    dec = json.JSONDecoder()
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i] in " \t\r\n,;":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(s, i)
        except json.JSONDecodeError:
            return None
        if isinstance(obj, dict):
            objs.append(obj)
        i = end
    return objs or None


def _values_from_entity_objects(objs: list[dict], kind: str) -> list[str]:
    """Pull the canonical IOC value(s) from parsed entity objects, per field kind.
    Bare host names are intentionally skipped (asset context, not a domain to
    check); only dotted domains / FQDNs are emitted for host/dns fields."""
    out: list[str] = []
    for o in objs:
        if kind == "ip":
            v = o.get("address") or o.get("Address")
            if v:
                out.append(str(v))
        elif kind == "hash":
            v = o.get("hashValue") or o.get("Value") or o.get("value")
            if v:
                out.append(str(v))
        elif kind == "url":
            v = o.get("url") or o.get("Url") or o.get("address") or o.get("Address")
            if v:
                out.append(str(v))
        else:  # host / dns → dotted domains + FQDN only
            for key in ("dnsDomain", "domainName"):
                v = o.get(key)
                if v:
                    out.append(str(v))
            ad = o.get("additionalData")
            if isinstance(ad, dict) and ad.get("FQDN"):
                out.append(str(ad["FQDN"]))
    return out


def _split_entity_values(adf_field, kind: str = "generic") -> list[str]:
    """Flatten an ADF entity custom field into individual values.

    Handles two formats:
      * Sentinel/Defender JSON objects (what SCDM/Defender tickets actually
        export) — parsed, with the canonical value pulled per ``kind``.
      * Legacy plain values separated by whitespace / comma / semicolon — split.
    """
    text = _extract_adf_text(adf_field)
    if not text:
        return []
    objs = _entity_json_objects(text)
    if objs is not None:
        return _values_from_entity_objects(objs, kind)
    parts = re.split(r"[\s,;]+", text)
    return [p.strip() for p in parts if p.strip()]


def extract_iocs_from_entity_fields(fields: dict, schema=None) -> list[dict]:
    """Read Sentinel-style structured entity custom fields and produce typed IOCs.

    Returns the same shape as extract_iocs(): a list of
    {"type": "ip"|"domain"|"hash", "subtype": str, "value": str}.

    Entity field IDs come from the resolved per-customer `schema`; when None the
    global defaults (SCDM) are used, so existing callers behave identically.
    """
    sch = schema or default_schema()
    seen: set[str] = set()
    iocs: list[dict] = []

    # IP Address Entities
    for val in _split_entity_values(fields.get(sch.entity_fields["ip"]), "ip"):
        v = val.lower()
        if v in seen or _is_private_ip(val):
            continue
        try:
            _ip = ipaddress.ip_address(val)
        except ValueError:
            continue
        seen.add(v)
        iocs.append({"type": "ip", "subtype": "ipv6" if _ip.version == 6 else "ipv4", "value": val})

    # Host Entities and DNS Entities → both treated as domains
    for field_id, _kind in ((sch.entity_fields["host"], "host"), (sch.entity_fields["dns"], "dns")):
        for val in _split_entity_values(fields.get(field_id), _kind):
            v = val.lower()
            if v in seen or _is_allowlisted_domain(v):
                continue
            # Skip values that look like IPs or hashes (wrong field but defensive)
            if _RE_IPV4.fullmatch(val) or _RE_SHA256.fullmatch(val) or _RE_SHA1.fullmatch(val) or _RE_MD5.fullmatch(val):
                continue
            seen.add(v)
            iocs.append({"type": "domain", "subtype": "fqdn", "value": v})

    # URL Entities → extract host
    for val in _split_entity_values(fields.get(sch.entity_fields["url"]), "url"):
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
    for val in _split_entity_values(fields.get(sch.entity_fields["hash"]), "hash"):
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


def _rep_empty_label(source: str) -> str:
    """Label for a reputation source that returned no result. Distinguishes a
    genuinely-absent API key ("Not configured") from a key that IS present but
    whose lookup returned nothing or errored ("No data") — so a working engine
    fed an invalid/clean IOC no longer reads as unconfigured."""
    from tools import virustotal_client, abuseipdb_client, socradar_rest
    checker = {
        "virustotal": virustotal_client.is_configured,
        "abuseipdb": abuseipdb_client.is_configured,
        "socradar": socradar_rest.is_configured,
    }.get(source)
    try:
        return "No data" if (checker and checker()) else "Not configured"
    except Exception:
        return "Not configured"


# ─── Comment Builder ──────────────────────────────────────────────────────────

_VERDICT_LABEL = {
    "malicious": "TRUE-POSITIVE",
    "clean":     "BENIGN-POSITIVE",
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


def _append_insights_section(lines: list[str], ioc_results: list[dict] | None) -> None:
    """Improvement #2 (2026-07-03): inject the AI web-research 'Additional Insights'
    section for malicious IOCs. No-op unless a malicious IOC carries an ``insights``
    note (only populated when IOC_INSIGHTS_ENABLED is on)."""
    items = [((r.get("ioc") or {}).get("value", ""), r.get("insights"))
             for r in (ioc_results or [])
             if r.get("verdict") == "malicious" and r.get("insights")]
    if not items:
        return
    lines.append("Additional Insights (Open-Source Web Research):")
    for value, text in items:
        lines.append(f"  [{value}]")
        lines.append(f"    {text}")
    lines.append("")


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


def _append_sentinel_evidence_section(lines: list[str], kql_result: dict | None) -> None:
    """Phase 5 (2026-06-15): inject the 'Sentinel Evidence' RAG-style block
    into the enrichment comment. No-op when kql_result is None or has no
    queries (KQL expansion disabled, customer has no Sentinel workspace,
    auth failure, timeout, or LLM returned nothing).

    Phase 5 MVP renders ONLY in the comment. NEVER fed into the LLM Triage
    prompt — same conservative ladder as Phase 4 → 4c (separate killswitch
    + threshold for prompt integration if/when we add Phase 5c)."""
    if not kql_result:
        return
    queries = kql_result.get("queries") or []
    if not queries:
        return

    workspace = kql_result.get("workspace_name") or "(unnamed)"
    iters = kql_result.get("iterations", len(queries))
    total = kql_result.get("total_rows", 0)
    iter_word = "iteration" if iters == 1 else "iterations"
    row_word = "row" if total == 1 else "rows"
    lines.append(f"Sentinel Evidence ({workspace} — {iters} {iter_word}, {total} {row_word} total):")

    for q in queries:
        i = q.get("iteration", 0)
        table = q.get("table") or "(unspecified table)"
        rationale = (q.get("rationale") or "").strip()
        row_count = q.get("row_count", 0)
        rc_word = "row" if row_count == 1 else "rows"
        # One-line summary per iteration. Full KQL is intentionally NOT
        # rendered in the comment to keep it scannable — pull it from the
        # logs if an analyst needs to reproduce.
        prefix = f"  [{i}] {table}: {row_count} {rc_word}"
        if rationale:
            if len(rationale) > 200:
                rationale = rationale[:197] + "..."
            prefix += f" — {rationale}"
        lines.append(prefix)
    lines.append("")


def _append_customer_knowledge_section(lines: list[str], rag_info: dict | None) -> None:
    """Phase 4 / 4b (2026-06-13 → 2026-06-15): inject the 'Customer Knowledge
    Base (Confluence)' block into the enrichment comment.

    rag_info shape (set by routes/webhook.py):
        {"pages_searched": int, "status": "matched"|"no_matches",
         "chunks": list[dict]}
    Caller passes None to suppress the section entirely — that's how the
    silent cases (RAG disabled, customer not resolved, customer has no
    Confluence pages, embed/store error) are filtered out *before* this
    function is invoked.

    Header always includes the page count so analysts can deduce that the
    AI consulted the customer's Confluence pages. When chunks is empty the
    block still renders (analyst signal that the lookup ran but didn't find
    anything above the similarity threshold).

    RAG content is rendered for the analyst only; it is NOT fed into the
    LLM Triage prompt (deliberate isolation against the prior failure mode
    where bad retrievals confused the LLM)."""
    if not rag_info:
        return
    pages = int(rag_info.get("pages_searched") or 0)
    if pages <= 0:
        return
    chunks = list(rag_info.get("chunks") or [])
    page_word = "page" if pages == 1 else "pages"
    lines.append(f"Customer Knowledge Base (Confluence) — searched {pages} {page_word}:")
    if not chunks:
        lines.append("  ► No relevant matches above similarity threshold.")
    else:
        for c in chunks:
            text = (c.get("text") or "").strip()
            if not text:
                continue
            source = c.get("source") or "doc"
            score = float(c.get("score") or 0.0)
            # Single-line render: collapse internal whitespace + trim
            # aggressively so the comment stays scannable. Full chunk is
            # in the vector store if an analyst needs the full context.
            oneline = " ".join(text.split())
            if len(oneline) > 240:
                oneline = oneline[:237] + "..."
            lines.append(f"  ► [{source}] {oneline} — {score:.2f}")
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
    lines.append(f"  ├─ Benign-Positive: {fp}")
    lines.append(f"  ├─ Unknown:        {unk}")
    suffix = " (still in flight)" if unt else ""
    lines.append(f"  └─ Untriaged:      {unt}{suffix}")
    if prefix:
        lines.append(f"  Matched on: \"{prefix}\"")
    if first_seen:
        lines.append(f"  Earliest sibling: {first_seen}")
    lines.append("")


def _append_whitelist_match_section(lines: list[str], matches: list[dict] | None) -> None:
    """Phase 5e (2026-06-16): direct (literal substring) IOC hits in the
    customer's Confluence chunks. Surfaces whitelist + reference-table
    matches that vector RAG misses because tabular data embeds poorly."""
    if not matches:
        return
    lines.append(f"Direct Whitelist Match ({len(matches)}):")
    for m in matches:
        ioc_type = (m.get("ioc_type") or "?").upper()
        lines.append(f"  ► [{ioc_type}] {m.get('ioc','')} — {m.get('source','')}")
        snippet = m.get("snippet", "")
        if snippet:
            lines.append(f"      « {snippet} »")
    lines.append("")


def _build_comment(ioc_results: list[dict], overall_verdict: str, action_taken: str,
                   mitre_result: dict | None = None,
                   historical: dict | None = None,
                   rag_info: dict | None = None,
                   kql_evidence: dict | None = None,
                   recommendation: str | None = None,
                   whitelist_matches: list[dict] | None = None,
                   ticket_key: str = "") -> str:
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
        _append_whitelist_match_section(lines, whitelist_matches)
        _append_customer_knowledge_section(lines, rag_info)
        _append_sentinel_evidence_section(lines, kql_evidence)
        _append_historical_section(lines, historical)
        _append_mitre_section(lines, mitre_result)
        lines += [
            f"VERDICT: {verdict_display}",
            f"AUTO-TRIAGE: {action_taken}",
        ]
        if recommendation:
            lines.append(f"RECOMMENDED ACTION: {recommendation}")
        return "\n".join(lines)

    # An "IOC" here means an observable that at least one reputation engine flagged
    # as malicious. Observables that all engines cleared (or returned no data for)
    # are still listed below for analyst visibility but don't bump the IOC count.
    ioc_count = sum(1 for r in ioc_results if r.get("verdict") == "malicious")
    lines.append(f"IOCs found: {ioc_count}")
    lines.append(f"(Extracted observables checked: {len(ioc_results)})")
    lines.append("")

    # Phase 5b (2026-06-15): per-IOC historical lookup budget. Each malicious
    # IOC may consume one JQL call; cap protects webhook latency. Same shape
    # as the existing SOCRADAR_TRIAGE_BUDGET_PER_TICKET pattern.
    try:
        from tools.ioc_history import budget_per_ticket as _ioc_history_budget
        ioc_history_budget_remaining = _ioc_history_budget()
    except Exception:
        ioc_history_budget_remaining = 0

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
            lines.append(f"  VirusTotal: {_rep_empty_label('virustotal')}")

        if ioc["type"] == "ip":
            if ab:
                lines.append(f"  AbuseIPDB: Confidence {ab.get('confidence_score', 0)}%")
            else:
                lines.append(f"  AbuseIPDB: {_rep_empty_label('abuseipdb')}")
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
            lines.append(f"  SOCRadar:  {_rep_empty_label('socradar')}")

        # Phase 5b (2026-06-15): per-IOC historical Jira appearances for any
        # IOC the reputation engines flagged as malicious. Killswitch-gated;
        # budgeted to IOC_HISTORY_BUDGET_PER_TICKET to bound webhook latency
        # (each call is one JQL search, ~1-2s on Jira Cloud). Failure-
        # isolated: never raises out of this block — a None return just
        # skips the line for that IOC.
        if result.get("verdict") == "malicious" and ioc_history_budget_remaining > 0:
            try:
                from tools.ioc_history import lookup_ioc_history, render_line
                hist = lookup_ioc_history(ioc.get("value", ""), exclude_ticket_key=ticket_key)
                hist_line = render_line(hist)
                if hist_line:
                    lines.append(hist_line)
            except Exception as _hist_err:
                logger.warning("ioc_history render failed for %s (%s); skipping line",
                               ioc.get("value", ""), _hist_err)
            ioc_history_budget_remaining -= 1

        lines.append("")

    _append_whitelist_match_section(lines, whitelist_matches)
    _append_customer_knowledge_section(lines, rag_info)
    _append_sentinel_evidence_section(lines, kql_evidence)
    _append_historical_section(lines, historical)
    _append_insights_section(lines, ioc_results)
    _append_mitre_section(lines, mitre_result)
    lines.append(f"VERDICT: {verdict_display}")
    lines.append(f"AUTO-TRIAGE: {action_taken}")
    if recommendation:
        lines.append(f"RECOMMENDED ACTION: {recommendation}")
    return "\n".join(lines)


# ─── Phase 5c (2026-06-16) — ADF table renderer ──────────────────────────────
#
# Mirrors _build_comment() but emits ADF (Atlassian Document Format) so the
# enrichment comment renders as panels, headings, and tables in Jira instead
# of dense paragraphs. Feature-flagged via COMMENT_ADF_ENABLED — default off
# until verified end-to-end on a synthetic webhook. On Jira HTTP 400 (any
# ADF validation failure), enrich_ticket() falls back to the plain-text
# _build_comment() path so an analyst never sees an empty comment.

_VERDICT_PANEL_TYPE = {
    "malicious":  "error",   # red
    "suspicious": "warning", # amber
    "benign":     "success", # green
    "unknown":    "note",    # grey
}


def _adf_ioc_block(ioc_results: list[dict], ticket_key: str) -> list[dict]:
    """Build the ADF nodes for the per-IOC details section.

    Each malicious IOC gets its own subheading + 2-col key/value Origin
    table (IPs only) + Reputation table + a 'Previously flagged' line if
    history is available. Same per-IOC budget rules as _build_comment.
    """
    from tools import adf

    if not ioc_results:
        return [
            adf.heading(3, "IOCs"),
            adf.paragraph(
                adf.text("No extractable IOCs in this ticket — reputation engines were not queried.", italic=True)
            ),
        ]

    ioc_count = sum(1 for r in ioc_results if r.get("verdict") == "malicious")
    out: list[dict] = [
        adf.heading(3, f"IOCs ({ioc_count} flagged · {len(ioc_results)} checked)")
    ]

    try:
        from tools.ioc_history import budget_per_ticket as _ioc_history_budget
        ioc_history_budget_remaining = _ioc_history_budget()
    except Exception:
        ioc_history_budget_remaining = 0

    for i, result in enumerate(ioc_results, 1):
        ioc = result["ioc"]
        # 2026-06-16: bumped from h4 → h3 + bold mark on the IOC value so the
        # IP/domain/hash is the visual centre of each per-IOC block. We do
        # NOT also apply the `code` (monospace) mark because Jira ADF rejects
        # the strong+code mark combination on text inside a heading with
        # INVALID_INPUT (HTTP 400). Bold + larger heading already gives
        # plenty of visual weight; the monospace look is nice-to-have rather
        # than essential here.
        out.append(adf.heading(3, adf.text(f"[{i}] ", italic=True),
                                    adf.text(ioc["value"], bold=True),
                                    adf.text(f" ({ioc['type'].upper()})")))

        vt = result.get("virustotal")
        ab = result.get("abuseipdb")

        if ioc["type"] == "ip":
            origin_rows = _adf_origin_rows(vt, ab)
            if origin_rows:
                out.append(adf.table(["Field", "Value"], origin_rows))

        rep_rows: list[list] = []
        # VirusTotal row
        if vt:
            mal = vt.get("malicious_count", 0)
            tot = vt.get("total_engines", 0)
            rep = vt.get("reputation", 0)
            det = f"{mal} / {tot}" if tot else "—"
            conf = f"{(mal/tot)*100:.1f}%" if tot else "—"
            notes = f"Reputation {rep}"
            rep_rows.append(["VirusTotal", det, conf, notes])
        else:
            rep_rows.append(["VirusTotal", _rep_empty_label('virustotal'), "—", "—"])

        # AbuseIPDB row
        if ioc["type"] == "ip":
            if ab:
                rep_rows.append(["AbuseIPDB", "—", f"{ab.get('confidence_score', 0)}%", "—"])
            else:
                rep_rows.append(["AbuseIPDB", _rep_empty_label('abuseipdb'), "—", "—"])
        else:
            rep_rows.append(["AbuseIPDB", "N/A (IP only)", "—", "—"])

        # SOCRadar row
        sr = result.get("socradar")
        if sr:
            verdict = sr.get("verdict", "unknown").title()
            score = sr.get("score", 0)
            cats = sr.get("categories") or []
            notes = ", ".join(cats) if cats else "—"
            rep_rows.append(["SOCRadar", verdict, f"{score} / 100", notes])
            for f in (sr.get("top_findings") or [])[:3]:
                src = f.get("source") or "?"
                cat = f.get("category") or "?"
                rel = f.get("reliability") or 0
                last = _format_sgt(f.get("last_seen") or "")
                rep_rows.append([
                    adf.paragraph(adf.text("  · ", italic=True), adf.text(src, italic=True)),
                    "—",
                    f"rel {rel}",
                    f"{cat} · last seen {last}",
                ])
        else:
            rep_rows.append(["SOCRadar", _rep_empty_label('socradar'), "—", "—"])

        out.append(adf.table(["Engine", "Detections", "Confidence", "Notes"], rep_rows))

        # Per-IOC historical
        if result.get("verdict") == "malicious" and ioc_history_budget_remaining > 0:
            try:
                from tools.ioc_history import lookup_ioc_history, render_line
                hist = lookup_ioc_history(ioc.get("value", ""), exclude_ticket_key=ticket_key)
                hist_line = render_line(hist)
                if hist_line:
                    out.append(adf.paragraph(adf.text(hist_line, italic=True)))
            except Exception as _hist_err:
                logger.warning("ioc_history ADF render failed for %s (%s)",
                               ioc.get("value", ""), _hist_err)
            ioc_history_budget_remaining -= 1

    return out


def _adf_origin_rows(vt: dict | None, ab: dict | None) -> list[list]:
    """Build origin key/value rows for the per-IOC Origin table. Drops empty
    fields so the table stays compact."""
    ab = ab or {}
    vt = vt or {}
    rows: list[list] = []

    country_name = ab.get("country_name") or ""
    country_code = ab.get("country_code") or vt.get("country") or ""
    if country_name and country_code:
        rows.append(["Country", f"{country_name} ({country_code})"])
    elif country_name or country_code:
        rows.append(["Country", country_name or country_code])

    isp = ab.get("isp") or ""
    as_owner = vt.get("as_owner") or ""
    if isp:
        rows.append(["ISP", isp])
    elif as_owner:
        rows.append(["AS Owner", as_owner])

    if vt.get("network"):
        rows.append(["Network", vt["network"]])
    if ab.get("usage_type"):
        rows.append(["Usage", ab["usage_type"]])
    if ab.get("domain"):
        rows.append(["Domain", ab["domain"]])

    hostnames = ab.get("hostnames") or []
    if hostnames:
        first = hostnames[0]
        suffix = f" (+{len(hostnames) - 1} more)" if len(hostnames) > 1 else ""
        rows.append(["Reverse DNS", f"{first}{suffix}"])

    return rows


def _adf_insights_block(ioc_results: list[dict] | None) -> list[dict]:
    """Improvement #2 (2026-07-03): ADF 'Additional Insights' section for malicious
    IOCs. Returns [] unless a malicious IOC carries an ``insights`` note."""
    from tools import adf
    items = [((r.get("ioc") or {}).get("value", ""), r.get("insights"))
             for r in (ioc_results or [])
             if r.get("verdict") == "malicious" and r.get("insights")]
    if not items:
        return []
    blocks = [adf.heading(3, "Additional Insights (Open-Source Web Research)")]
    for value, text in items:
        blocks.append(adf.paragraph(adf.text(f"{value} — ", bold=True), adf.text(text)))
    return blocks


def _adf_mitre_block(mitre_result: dict | None) -> list[dict]:
    from tools import adf
    if not mitre_result:
        return []
    techniques = mitre_result.get("techniques") or []
    if not techniques:
        return []
    rows = []
    for t in techniques:
        pct = int(round(t.get("confidence", 0) * 100))
        rows.append([t["id"], t.get("tactic", "—"), t.get("name", "—"), f"{pct}%"])
    return [
        adf.heading(3, "MITRE ATT&CK"),
        adf.table(["ID", "Tactic", "Name", "Confidence"], rows),
    ]


def _adf_whitelist_match_block(matches: list[dict] | None) -> list[dict]:
    """Phase 5e (2026-06-16): rendered as a 'success' panel with a 4-col
    table. Sits ABOVE Customer Knowledge Base because a literal whitelist
    hit is a stronger signal than a semantic similarity hit — analyst eye
    lands on it first within the comment body."""
    from tools import adf
    if not matches:
        return []
    rows = []
    for m in matches:
        rows.append([
            m.get("ioc", ""),
            (m.get("ioc_type") or "").upper(),
            m.get("source", ""),
            m.get("snippet", ""),
        ])
    return [
        adf.heading(3, "Direct Whitelist Match"),
        adf.paragraph(
            adf.text("IOC values found verbatim in the customer's Confluence knowledge base — strong signal of a known-benign destination/source.", italic=True)
        ),
        adf.table(["IOC", "Type", "Source", "Context"], rows),
    ]


def _adf_sentinel_block(kql_result: dict | None) -> list[dict]:
    from tools import adf
    if not kql_result:
        return []
    queries = kql_result.get("queries") or []
    if not queries:
        return []
    workspace = kql_result.get("workspace_name") or "(unnamed)"
    iters = kql_result.get("iterations", len(queries))
    total = kql_result.get("total_rows", 0)
    iter_word = "iteration" if iters == 1 else "iterations"
    row_word = "row" if total == 1 else "rows"

    rows = []
    for q in queries:
        i = q.get("iteration", 0)
        table_name = q.get("table") or "(unspecified)"
        rationale = (q.get("rationale") or "").strip()
        row_count = q.get("row_count", 0)
        if len(rationale) > 200:
            rationale = rationale[:197] + "..."
        rows.append([str(i), table_name, str(row_count), rationale or "—"])

    return [
        adf.heading(3, f"Sentinel Evidence ({workspace})"),
        adf.paragraph(
            adf.text(f"{iters} {iter_word} · {total} {row_word} total", italic=True)
        ),
        adf.table(["#", "Table", "Hits", "LLM rationale"], rows),
    ]


def _adf_customer_knowledge_block(rag_info: dict | None) -> list[dict]:
    from tools import adf
    if not rag_info:
        return []
    pages = int(rag_info.get("pages_searched") or 0)
    if pages <= 0:
        return []
    chunks = list(rag_info.get("chunks") or [])
    page_word = "page" if pages == 1 else "pages"

    blocks = [
        adf.heading(3, "Customer Knowledge Base (Confluence)"),
        adf.paragraph(
            adf.text(f"Searched {pages} {page_word}", italic=True)
        ),
    ]
    if not chunks:
        blocks.append(adf.paragraph(
            adf.text("No relevant matches above similarity threshold.", italic=True)
        ))
        return blocks

    rows = []
    for c in chunks:
        text_val = (c.get("text") or "").strip()
        if not text_val:
            continue
        source = c.get("source") or "doc"
        score = float(c.get("score") or 0.0)
        oneline = " ".join(text_val.split())
        if len(oneline) > 240:
            oneline = oneline[:237] + "..."
        rows.append([source, f"{score:.2f}", oneline])
    blocks.append(adf.table(["Source", "Score", "Snippet"], rows))
    return blocks


def _adf_historical_block(historical: dict | None) -> list[dict]:
    from tools import adf
    if not historical or historical.get("total", 0) <= 0:
        return []
    window = historical.get("window_hours", 24)
    total = historical["total"]
    tp = historical.get("true_positive", 0)
    fp = historical.get("false_positive", 0)
    unk = historical.get("unknown", 0)
    unt = historical.get("untriaged", 0)
    prefix = historical.get("rule_prefix") or ""
    first_seen = _format_sgt(historical.get("first_seen_at") or "")

    rows = [
        ["True-Positive", str(tp)],
        ["Benign-Positive", str(fp)],
        ["Unknown", str(unk)],
        ["Untriaged", f"{unt} (still in flight)" if unt else "0"],
    ]
    if prefix:
        rows.append(["Matched on", f'"{prefix}"'])
    if first_seen:
        rows.append(["Earliest sibling", first_seen])

    return [
        adf.heading(3, f"Similar Alerts (past {window}h)"),
        adf.paragraph(adf.text(f"{total} similar alert(s) found", italic=True)),
        adf.table(["Category", "Count"], rows),
    ]


def _build_comment_adf(ioc_results: list[dict], overall_verdict: str, action_taken: str,
                      mitre_result: dict | None = None,
                      historical: dict | None = None,
                      rag_info: dict | None = None,
                      kql_evidence: dict | None = None,
                      recommendation: str | None = None,
                      whitelist_matches: list[dict] | None = None,
                      ticket_key: str = "") -> dict:
    """Return a full ADF document for the enrichment comment. Same input
    signature as _build_comment() so callers don't change."""
    from tools import adf

    verdict_display = _VERDICT_LABEL.get(overall_verdict, overall_verdict.upper())
    panel_type = _VERDICT_PANEL_TYPE.get(overall_verdict, "note")

    # Verdict panel at the top — color-coded for one-second triage.
    # VERDICT (outcome) → AUTO-TRIAGE (mechanical routing) → RECOMMENDED ACTION
    # (Phase 6 AI guidance, only when synthesis produced one).
    verdict_paras = [
        adf.paragraph(adf.text("VERDICT: ", bold=True), adf.text(verdict_display, bold=True)),
        adf.paragraph(adf.text("AUTO-TRIAGE: ", bold=True), adf.text(action_taken)),
    ]
    if recommendation:
        verdict_paras.append(
            adf.paragraph(adf.text("RECOMMENDED ACTION: ", bold=True), adf.text(recommendation))
        )

    blocks: list[dict] = [
        adf.panel(panel_type, *verdict_paras),
        adf.heading(2, "L1 Triage Report (Automated)"),
    ]

    blocks.extend(_adf_ioc_block(ioc_results, ticket_key))
    blocks.extend(_adf_whitelist_match_block(whitelist_matches))
    blocks.extend(_adf_customer_knowledge_block(rag_info))
    blocks.extend(_adf_sentinel_block(kql_evidence))
    blocks.extend(_adf_historical_block(historical))
    blocks.extend(_adf_insights_block(ioc_results))
    blocks.extend(_adf_mitre_block(mitre_result))

    return adf.doc(*blocks)


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
    """Post a plain-text comment to a Jira issue. Each input line becomes one
    ADF paragraph — preserves today's pre-Phase-5c layout. Used as the
    fallback path when the structured ADF post fails."""
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


def post_jira_comment_adf(ticket_key: str, adf_doc: dict) -> bool:
    """Post a pre-built ADF document as a Jira comment (Phase 5c).

    Returns True on success, False on any failure (HTTP error, network, or
    bad ADF shape). Caller is expected to fall back to ``post_jira_comment``
    with a plain-text rendering when this returns False so the analyst
    never sees an empty comment."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot post ADF comment to %s", ticket_key)
        return False

    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}/comment"
    body = {"body": adf_doc}

    try:
        r = httpx.post(url, headers=_jira_headers(), json=body, timeout=30)
        if r.status_code >= 400:
            logger.error("post_jira_comment_adf %s HTTP %s: %s",
                         ticket_key, r.status_code, r.text[:500])
            return False
        logger.info("Posted ADF enrichment comment to %s", ticket_key)
        return True
    except Exception as e:
        logger.error("post_jira_comment_adf %s failed: %s", ticket_key, e)
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
                  historical: dict | None = None,
                  rag_info: dict | None = None,
                  kql_evidence: dict | None = None,
                  schema=None) -> dict:
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

    Phase 4 / 4b (2026-06-13 → 2026-06-15): optional `rag_info` arg built by
    routes/webhook.py from tools.rag_retrieval.retrieve_customer_context().
    Shape: {"pages_searched": int, "status": "matched"|"no_matches",
    "chunks": list[dict]}. Caller passes None to suppress the section.
    When present, renders a 'Customer Knowledge Base (Confluence)' block
    so analysts can see the AI consulted the customer's Confluence pages
    even when no relevant matches were found. Phase 4 deliberately does
    NOT pass rag_info into the LLM Triage call (mitigation against prior
    failure where bad retrievals confused the model).
    """
    from tools.secrets import get_secret
    from tools.jira_schema import detect_schema_mismatch

    sch = schema or default_schema()
    summary = fields.get("summary") or ""
    desc_text = _extract_adf_text(fields.get("description"))

    # Primary source: typed entity fields (canonical, populated by Sentinel)
    entity_iocs = extract_iocs_from_entity_fields(fields, sch)

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

    # Fail-LOUD: a public IP or file hash present in the ticket but 0 IOCs
    # extracted almost always means this customer's entity field mapping is
    # wrong. Surface it (log + health signal) instead of silently triaging blind.
    schema_warning = detect_schema_mismatch(fields, sch, iocs)
    if schema_warning:
        logger.warning("enrich_ticket(%s): SCHEMA MISMATCH — %s (suspect fields: %s)",
                       ticket_key, schema_warning["detail"], schema_warning.get("suspect_fields"))
        try:
            from tools.triage_health import record_schema_mismatch
            record_schema_mismatch(ticket_key.split("-")[0], schema_warning["detail"])
        except Exception:
            pass

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

    # Improvement #2 (2026-07-03): AI web-research insights for MALICIOUS IOCs.
    # For each IOC the vendors confirmed malicious, search the open web + have the
    # LLM write a short GROUNDED note, attached as ioc_result["insights"] and
    # rendered in an "Additional Insights" section. Killswitch IOC_INSIGHTS_ENABLED
    # (default off); capped per ticket; failure-isolated (never breaks the comment).
    if os.environ.get("IOC_INSIGHTS_ENABLED", "false").lower() == "true":
        try:
            from tools.ioc_insights import fetch_insights_for_malicious
            insights_map = fetch_insights_for_malicious(ioc_results)
            for r in ioc_results:
                val = (r.get("ioc") or {}).get("value")
                if r.get("verdict") == "malicious" and val in insights_map:
                    r["insights"] = insights_map[val]
        except Exception:
            logger.exception("enrich_ticket(%s): IOC insights synthesis failed — skipping",
                             ticket_key)

    l1_id = get_secret("JIRA_L1_ACCOUNT_ID")
    l2_id = get_secret("JIRA_L2_ACCOUNT_ID")

    # Phase 1 (2026-06-08): verdict-to-label mapping is now explicit across all
    # three outcomes (True-Positive / Benign-Positive / Unknown). The "unknown"
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
        action_taken = (f"Ticket judged a Benign Positive — labelled "
                        f"'{_TRIAGE_CLEAN_LABEL}'. Routed to L2 SOC Analyst for sign-off.")
        if l2_id:
            assign_jira_ticket(ticket_key, l2_id)
        else:
            action_taken += " (JIRA_L2_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L2_ACCOUNT_ID not set — cannot assign %s to L2", ticket_key)

    # Phase 5e (2026-06-16) — literal-substring IOC lookup in the customer's
    # Confluence chunks. Sidesteps vector-RAG's weakness on tabular whitelist
    # data. Killswitch-gated; returns [] silently on any failure.
    whitelist_matches: list[dict] = []
    try:
        from tools.whitelist_match import find_direct_matches
        from tools.customers import find_customer_by_jira_project
        project_key = ticket_key.split("-")[0] if ticket_key else ""
        cust = find_customer_by_jira_project(project_key) if project_key else None
        cid = (cust or {}).get("id", "")
        ioc_list = [r["ioc"] for r in ioc_results if isinstance(r, dict) and r.get("ioc")]
        whitelist_matches = find_direct_matches(customer_id=cid, iocs=ioc_list)
    except Exception:
        logger.exception("whitelist_match dispatch failed for %s", ticket_key)
        whitelist_matches = []

    # Phase 6 (2026-06-19) — synthesise a recommended next-action from ALL the
    # evidence assembled above and render it as a 'RECOMMENDED ACTION' line
    # inside the verdict box. Killswitch-gated (RECOMMENDATION_SYNTHESIS_ENABLED,
    # default OFF), failure-isolated (returns None on any error), and bounded by
    # RECOMMENDATION_TIMEOUT_S. Never short-circuits the rest of the comment.
    # Industry-aware context (2026-06-19): the customer's structured profile +
    # curated industry lens + asset-inventory match tailor the recommendation to
    # the customer's vertical and the asset at stake. Resolved here (failure-
    # isolated) so a lookup miss degrades to the prior generic recommendation
    # rather than dropping the line. Lens/profile are deterministic (no RAG
    # dependency); asset match is killswitch-gated substring lookup.
    customer_profile = None
    industry_lens = ""
    asset_matches: list[dict] = []
    try:
        from tools.customers import find_customer_by_jira_project
        from tools.industry_lens import get_industry_lens
        from tools.asset_inventory import find_asset_matches
        _pkey = ticket_key.split("-")[0] if ticket_key else ""
        _cust = find_customer_by_jira_project(_pkey) if _pkey else None
        if _cust:
            customer_profile = {
                "industry": _cust.get("industry") or "",
                "org_profile": _cust.get("org_profile") or "",
                "compliance_regime": _cust.get("compliance_regime") or [],
            }
            industry_lens = get_industry_lens(_cust.get("industry"))
            _ioc_list = [r["ioc"] for r in ioc_results if isinstance(r, dict) and r.get("ioc")]
            asset_matches = find_asset_matches(customer_id=_cust.get("id", ""), iocs=_ioc_list)
    except Exception:
        logger.exception("Industry-context resolution failed for %s", ticket_key)

    recommendation = None
    try:
        from tools.recommendation import synthesize_recommendation
        recommendation = synthesize_recommendation(
            ticket_summary=summary,
            ticket_description=desc_text,
            overall_verdict=overall_verdict,
            action_taken=action_taken,
            ioc_results=ioc_results,
            mitre_result=mitre_result,
            historical=historical,
            rag_info=rag_info,
            kql_evidence=kql_evidence,
            customer_profile=customer_profile,
            industry_lens=industry_lens,
            asset_matches=asset_matches,
        )
    except Exception:
        logger.exception("Recommendation synthesis dispatch failed for %s", ticket_key)
        recommendation = None

    # Phase 5c (2026-06-16) — try ADF first when killswitch ON; on any failure
    # (HTTP 400 from Jira on a malformed doc, network glitch, our renderer
    # throwing on unexpected input) fall back to the plain-text comment so an
    # analyst always sees the triage evidence.
    posted = False
    if os.environ.get("COMMENT_ADF_ENABLED", "false").lower() == "true":
        try:
            adf_doc = _build_comment_adf(ioc_results, overall_verdict, action_taken,
                                          mitre_result, historical, rag_info, kql_evidence,
                                          recommendation=recommendation,
                                          whitelist_matches=whitelist_matches,
                                          ticket_key=ticket_key)
            posted = post_jira_comment_adf(ticket_key, adf_doc)
        except Exception as e:
            logger.exception("ADF comment build/post failed for %s — falling back to plain text", ticket_key)

    if not posted:
        comment_text = _build_comment(ioc_results, overall_verdict, action_taken,
                                       mitre_result, historical, rag_info, kql_evidence,
                                       recommendation=recommendation,
                                       whitelist_matches=whitelist_matches,
                                       ticket_key=ticket_key)
        post_jira_comment(ticket_key, comment_text)

    return {
        "ticket": ticket_key,
        "iocs": ioc_results,
        "verdict": overall_verdict,
        "action": action_taken,
    }
