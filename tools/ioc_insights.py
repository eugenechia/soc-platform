"""
Improvement #2 (2026-07-03) — AI web-research insights for malicious IOCs.

When an IOC came back MALICIOUS from the threat-intel vendors (VirusTotal /
AbuseIPDB / SOCRadar), this module searches the open web (Tavily) for additional
context and asks the LLM to write a short, GROUNDED "additional insights" note —
e.g. the malware family / campaign / threat actor the indicator is associated
with, and how recently it was seen. Rendered as an "Additional Insights" section
in the Jira enrichment comment.

Design (mirrors tools/recommendation.py):
- Killswitch ``IOC_INSIGHTS_ENABLED`` defaults OFF — ships dark until verified.
- Only MALICIOUS IOCs trigger it; capped at ``IOC_INSIGHTS_MAX_IOCS`` per ticket
  (mirrors the SOCRadar per-ticket budget) so a noisy ticket can't blow the
  webhook latency / API budget.
- Per-IOC (Tavily-in-thread → LLM) runs CONCURRENTLY via asyncio.gather, so total
  added latency ≈ one IOC rather than the sum.
- STRICTLY grounded: the prompt may only state what the search sources support,
  must cite source domains, and must emit the literal ``_NO_CONTEXT`` string when
  the search yields nothing useful. False threat attribution in a SOC comment is
  dangerous — this is a hard requirement, not a nicety.
- Fail-silent: any error (killswitch off, no key, timeout, LLM error) → that IOC
  is simply omitted. Never raises; the comment always still posts.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

logger = logging.getLogger(__name__)

TIMEOUT_S = int(os.environ.get("IOC_INSIGHTS_TIMEOUT_S", "25"))
MAX_IOCS = int(os.environ.get("IOC_INSIGHTS_MAX_IOCS", "3"))
MAX_CHARS = int(os.environ.get("IOC_INSIGHTS_MAX_CHARS", "600"))
_WEB_CONTEXT_CAP = 3500  # trim Tavily payload before it hits the LLM

# Literal the LLM must emit (and we render) when nothing useful surfaced. Kept as
# a constant so the caller/tests can recognise the honest-null case.
_NO_CONTEXT = "No additional open-source context found."

_SYSTEM_PROMPT = """You are a SOC threat-intelligence analyst writing a SHORT "additional insights" note about a single indicator of compromise (IOC) that reputation vendors flagged as malicious. Your job is to tell the analyst WHAT THIS IOC ACTUALLY IS, based only on open-source web results gathered just now — so they can judge the alert faster.

You are given: the IOC value and type, a one-line summary of which vendors flagged it, a block of STRUCTURED FACTS the reputation vendors already returned (ISP/owner, domain, reverse-DNS, country, usage type, categories), and a block of open-source web-search results. Characterise the IOC using BOTH the structured vendor facts and the web results. Often the vendor facts alone identify it — e.g. ISP "Censys, Inc." with reverse-DNS "*.censys-scanner.com" is a benign scanner. It could be ANY of:
- Malicious infrastructure — a malware family, C2, phishing/campaign, or threat-actor association.
- A legitimate/benign scanner or research service — e.g. Censys, Shodan, BinaryEdge, Palo Alto Cortex Xpanse, academic scanners. These are routinely OVER-FLAGGED by reputation engines. If the sources show this, SAY SO plainly — it tells the analyst the "malicious" rating is likely a scanner false-positive.
- Infrastructure context — the hosting provider / ISP / CDN / VPN/proxy/Tor exit, or a shared-hosting IP, when that is the most useful thing the sources establish.

STRICT GROUNDING RULES — mandatory:
- State ONLY what the provided structured vendor facts or web-search results actually support. Do NOT use prior knowledge to add malware names, campaigns, actors, CVEs, or dates that neither source states.
- Cite the basis in parentheses for each claim — a source domain for web claims, or "(vendor data)" for the structured facts, e.g. "(vendor data: reverse-DNS censys-scanner.com)", "(abuse.ch)".
- Only if NEITHER the vendor facts NOR the web results identify or characterise this IOC, output EXACTLY: "No additional open-source context found." Do not use the null string just because the IOC turned out to be a benign scanner — that characterisation IS the insight.
- Never invent facts. Never hedge with "possibly/likely" to dress up a guess.

STYLE:
- Plain text only. No markdown, no bullet points, no headings.
- 2-3 sentences, ~60 words max. Lead with the single most decision-relevant fact.
- When relevant, end with the so-what (e.g. "consistent with benign internet-wide scanning" or "treat as active C2").

Examples of good output:
"This IP belongs to Censys, a legitimate internet-wide research scanner (censys.io; reverse-DNS *.censys-scanner.com). Reputation 'malicious' ratings for Censys ranges are common false positives — consistent with benign scanning rather than a targeted threat."
"Associated with the AsyncRAT commodity RAT; listed on abuse.ch ThreatFox as an active C2 as of June 2026 (threatfox.abuse.ch). Multiple sandbox reports tie it to phishing-delivered loaders (any.run) — treat as live C2."
"Hosted on a Hangzhou data-centre range frequently cited in brute-force and phishing reports (abuseipdb.com); no specific malware family attributed in sources."
"No additional open-source context found."

Now write the insights note."""


async def _call_llm(ioc_value: str, ioc_type: str, verdict_summary: str,
                    vendor_facts: str, web_context: str) -> str:
    from tools.llm_client import make_chat_client
    client, model = make_chat_client()
    user_msg = (
        f"IOC value: {ioc_value}\n"
        f"IOC type: {ioc_type}\n"
        f"Vendor verdicts: {verdict_summary}\n\n"
        f"Structured facts from reputation vendors (grounded — you may use these):\n"
        f"{vendor_facts or '(none)'}\n\n"
        f"Open-source web-search results:\n{web_context or '(no results)'}"
    )
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        # gpt-5.3-chat is a reasoning model: reasoning tokens count against this
        # cap before any visible text, so keep generous headroom. MAX_CHARS still
        # enforces brevity on the rendered output.
        max_completion_tokens=512,
    )
    return (response.choices[0].message.content or "").strip()


def _web_search(query: str) -> str | None:
    """Thin, patchable wrapper around Tavily (lazy import, like recommendation.py)."""
    from tools.tavily_client import fetch_web_context
    return fetch_web_context(query)


def _strip_markdown(s: str) -> str:
    """LLM occasionally ignores the no-markdown rule; strip common offenders so the
    ADF comment renders cleanly. (Same intent as recommendation._strip_markdown.)"""
    s = re.sub(r"```[\s\S]*?```", "", s)
    s = re.sub(r"(?m)^\s*[-*+]\s+", "", s)
    s = s.replace("**", "").replace("__", "")
    return s.strip()


def _build_query(ioc: dict) -> str:
    """Identity-seeking search query per IOC type.

    Deliberately NOT malicious-biased: a query like '<ip> malicious threat
    intelligence' returns only blocklist pages and never the 'this is a Censys
    scanner' identity pages. We want Tavily to surface WHAT the IOC is — scanner,
    hosting/ISP, or genuine malware infra — so the LLM can characterise it."""
    value = ioc.get("value", "")
    t = (ioc.get("type") or "").lower()
    if t == "ip":
        return f'"{value}" IP address who is reputation scanner hosting provider abuse'
    if t == "hash":
        return f'"{value}" file hash malware analysis sandbox report'
    if t in ("domain", "url"):
        return f'"{value}" domain reputation malware phishing hosting'
    return f'"{value}" {t} reputation threat intelligence'


def _verdict_summary(reputation_result: dict) -> str:
    """One-line summary of which vendors flagged this IOC (context for the LLM)."""
    parts = []
    vt = reputation_result.get("virustotal") or {}
    if vt:
        parts.append(f"VirusTotal {vt.get('malicious_count', 0)}/{vt.get('total_engines', 0)}")
    ab = reputation_result.get("abuseipdb") or {}
    if ab:
        parts.append(f"AbuseIPDB confidence {ab.get('confidence_score', 0)}")
    sr = reputation_result.get("socradar") or {}
    if sr:
        cats = ", ".join((sr.get("categories") or [])[:3])
        parts.append(f"SOCRadar {sr.get('verdict', '?')}" + (f" [{cats}]" if cats else ""))
    return "; ".join(parts) or "flagged malicious"


def _vendor_facts(reputation_result: dict) -> str:
    """Structured identifying facts the vendors ALREADY returned — ISP/owner,
    domain, reverse-DNS, country, usage, categories. These are grounded facts
    (not web results) and are often the strongest characterisation signal: an
    ISP of 'Censys, Inc.' + reverse-DNS '*.censys-scanner.com' identifies a benign
    scanner outright. Returns a short newline block, or "" if nothing useful."""
    facts = []
    vt = reputation_result.get("virustotal") or {}
    ab = reputation_result.get("abuseipdb") or {}

    owner = ab.get("isp") or vt.get("as_owner")
    if owner:
        facts.append(f"ISP/owner: {owner}")
    domain = ab.get("domain")
    if domain:
        facts.append(f"Domain: {domain}")
    hostnames = ab.get("hostnames") or []
    if hostnames:
        facts.append(f"Reverse DNS: {', '.join(hostnames[:2])}")
    country = ab.get("country_name") or vt.get("country")
    if country:
        facts.append(f"Country: {country}")
    usage = ab.get("usage_type")
    if usage:
        facts.append(f"Usage type: {usage}")
    network = vt.get("network")
    if network:
        facts.append(f"Network: {network}")
    sr = reputation_result.get("socradar") or {}
    cats = sr.get("categories") or []
    if cats:
        facts.append(f"SOCRadar categories: {', '.join(cats[:5])}")
    return "\n".join(facts)


def fetch_insights_for_malicious(ioc_results: list[dict], max_iocs: int | None = None) -> dict:
    """Return ``{ioc_value: insight_text}`` for the malicious IOCs in ``ioc_results``.

    Only IOCs whose ``verdict == "malicious"`` are researched, capped at
    ``max_iocs`` (default IOC_INSIGHTS_MAX_IOCS). Returns ``{}`` if the killswitch
    is OFF or nothing qualifies. Never raises — a per-IOC failure just omits that
    IOC from the result.
    """
    if os.environ.get("IOC_INSIGHTS_ENABLED", "false").lower() != "true":
        return {}

    cap = MAX_IOCS if max_iocs is None else max_iocs
    malicious = [r for r in (ioc_results or [])
                 if r.get("verdict") == "malicious" and (r.get("ioc") or {}).get("value")]
    if not malicious:
        return {}

    capped = malicious[:cap]
    if len(malicious) > cap:
        logger.info("ioc_insights: %d malicious IOCs, researching first %d (IOC_INSIGHTS_MAX_IOCS)",
                    len(malicious), cap)

    async def _one(r: dict):
        ioc = r["ioc"]
        value = ioc["value"]
        # Tavily is blocking (requests under the hood) — run it off the event loop
        # so the N searches overlap instead of serialising.
        web = await asyncio.to_thread(_web_search, _build_query(ioc))
        facts = _vendor_facts(r)
        # Only truly-null when BOTH web results AND vendor facts are empty.
        if not web and not facts:
            return value, _NO_CONTEXT
        web_context = (web or "")[:_WEB_CONTEXT_CAP]
        text = await _call_llm(value, ioc.get("type", ""), _verdict_summary(r), facts, web_context)
        cleaned = _strip_markdown(text)
        if not cleaned:
            return value, None
        if len(cleaned) > MAX_CHARS:
            cleaned = cleaned[: MAX_CHARS - 3] + "..."
        return value, cleaned

    async def _runner():
        results = await asyncio.gather(*[_one(r) for r in capped], return_exceptions=True)
        out: dict = {}
        for res in results:
            if isinstance(res, Exception):
                logger.warning("ioc_insights: per-IOC research failed: %s", res)
                continue
            value, text = res
            if text:
                out[value] = text
        return out

    try:
        return asyncio.run(asyncio.wait_for(_runner(), timeout=TIMEOUT_S))
    except asyncio.TimeoutError:
        logger.warning("ioc_insights: research timed out after %ds", TIMEOUT_S)
        return {}
    except Exception as e:
        logger.exception("ioc_insights: synthesis failed: %s", e)
        return {}
