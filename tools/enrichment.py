"""
IOC enrichment pipeline for Jira webhook processing.

Flow:
  1. extract_iocs()      — regex extraction of IPs, domains, hashes from ticket text
  2. check_reputation()  — fan-out to SOCRadar (+ VT/AbuseIPDB when keys present)
  3. determine_verdict() — aggregate: any malicious → malicious
  4. post_jira_comment() — post enrichment summary as ADF comment
  5. assign_jira_ticket()— reassign based on verdict
  6. enrich_ticket()     — orchestrates all steps end-to-end
"""
import ipaddress
import logging
import os
import re

import httpx

logger = logging.getLogger(__name__)

JIRA_URL = os.environ.get("JIRA_URL", "").rstrip("/")

# ─── IOC regex patterns ───────────────────────────────────────────────────────

_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_IPV4   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|biz|info|xyz|ru|cn|tk|top|cc|pw|onion)\b',
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


# ─── Reputation Checking ──────────────────────────────────────────────────────

def check_reputation(ioc: dict) -> dict:
    """Fan out IOC to all configured reputation sources.

    Returns a result dict merging all source results and an individual verdict.
    """
    from tools import socradar_rest, virustotal_client, abuseipdb_client

    ioc_type = ioc["type"]
    value = ioc["value"]
    threshold = int(os.environ.get("MALICIOUS_SCORE_THRESHOLD", "70"))

    result: dict = {
        "ioc": ioc,
        "socradar": None,
        "virustotal": None,
        "abuseipdb": None,
        "verdict": "unknown",
    }

    result["socradar"] = socradar_rest.check_ioc(value, ioc_type)
    result["virustotal"] = virustotal_client.check_ioc(value, ioc_type)
    if ioc_type == "ip":
        result["abuseipdb"] = abuseipdb_client.check_ip(value)

    malicious = False
    if result["socradar"] and result["socradar"].get("score", 0) >= threshold:
        malicious = True
    if result["virustotal"] and result["virustotal"].get("malicious_count", 0) > 0:
        malicious = True
    if result["abuseipdb"] and result["abuseipdb"].get("confidence_score", 0) > 50:
        malicious = True

    all_none = all(
        result[k] is None for k in ("socradar", "virustotal", "abuseipdb")
    )
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

def _build_comment(ioc_results: list[dict], overall_verdict: str, action_taken: str) -> str:
    lines = ["=== IOC Enrichment Report (Automated) ===", ""]

    if not ioc_results:
        lines += ["No extractable IOCs found in this ticket.", "No automated action taken."]
        return "\n".join(lines)

    lines.append(f"IOCs found: {len(ioc_results)}")
    lines.append("")

    for i, result in enumerate(ioc_results, 1):
        ioc = result["ioc"]
        lines.append(f"[{i}] {ioc['value']} ({ioc['type'].upper()})")

        sr = result.get("socradar")
        if sr:
            v = sr.get("verdict", "unknown").upper()
            lines.append(f"  SOCRadar: Score {sr.get('score', 'N/A')}/100 — {v}")
        else:
            lines.append("  SOCRadar: No data")

        vt = result.get("virustotal")
        if vt:
            lines.append(f"  VirusTotal: {vt.get('malicious_count', 0)}/{vt.get('total_engines', 0)} detections")
        else:
            lines.append("  VirusTotal: Not configured")

        if ioc["type"] == "ip":
            ab = result.get("abuseipdb")
            if ab:
                lines.append(f"  AbuseIPDB: Confidence {ab.get('confidence_score', 0)}%")
            else:
                lines.append("  AbuseIPDB: Not configured")
        else:
            lines.append("  AbuseIPDB: N/A (IP only)")

        lines.append("")

    lines.append(f"VERDICT: {overall_verdict.upper()}")
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


# ─── Main Orchestrator ────────────────────────────────────────────────────────

def enrich_ticket(ticket_key: str, summary: str, description_adf) -> dict:
    """Full enrichment pipeline for one Jira ticket.

    Extracts IOCs, checks reputation across all configured sources, posts a
    comment with the findings, and reassigns the ticket based on verdict.
    Returns a summary dict for job status tracking.
    """
    from tools.secrets import get_secret

    desc_text = _extract_adf_text(description_adf)
    full_text = f"{summary}\n{desc_text}"

    iocs = extract_iocs(full_text)
    logger.info("enrich_ticket(%s): %d IOCs extracted", ticket_key, len(iocs))

    ioc_results = [check_reputation(ioc) for ioc in iocs]
    overall_verdict = determine_verdict(ioc_results)

    l1_id = get_secret("JIRA_L1_ACCOUNT_ID")
    l2_id = get_secret("JIRA_L2_ACCOUNT_ID")

    if not ioc_results:
        action_taken = "No IOCs found — no automated action taken."
        post_jira_comment(ticket_key, _build_comment([], overall_verdict, action_taken))
        return {"ticket": ticket_key, "iocs": [], "verdict": "unknown", "action": "none"}

    if overall_verdict == "malicious":
        action_taken = "Ticket escalated — assigned to L1 Lead as potential True Positive."
        if l1_id:
            assign_jira_ticket(ticket_key, l1_id)
        else:
            action_taken += " (JIRA_L1_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L1_ACCOUNT_ID not set — cannot assign %s to L1 lead", ticket_key)
    else:
        action_taken = "No malicious IOCs detected — assigned to L2 for review."
        if l2_id:
            assign_jira_ticket(ticket_key, l2_id)
        else:
            action_taken += " (JIRA_L2_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L2_ACCOUNT_ID not set — cannot assign %s to L2", ticket_key)

    comment_text = _build_comment(ioc_results, overall_verdict, action_taken)
    post_jira_comment(ticket_key, comment_text)

    return {
        "ticket": ticket_key,
        "iocs": ioc_results,
        "verdict": overall_verdict,
        "action": action_taken,
    }
