"""
Phase 6 (2026-06-16) — Recommendation Synthesis.

After every other enrichment step has populated its evidence, this module
asks the LLM to read EVERYTHING together (verdict, IOCs, MITRE, historical,
RAG, KQL) and produce a concrete next-action recommendation for the L2
analyst. Rendered as a one-line "RECOMMENDED ACTION" inside the color-coded
Verdict box at the top of the Jira enrichment comment (one-second scan).

Distinct from Phase 1 (priority override) and Phase 4c (RAG-into-prompt) —
this is the *final* step that synthesises the assembled evidence into an
actionable instruction, not a verdict input.

Killswitch ``RECOMMENDATION_SYNTHESIS_ENABLED`` defaults OFF — code ships
dark until verified on a synthetic webhook. Failure mode: any exception →
log and return None. The comment still posts without the recommendation
section; analyst sees the rest of the evidence as before.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re

logger = logging.getLogger(__name__)

TIMEOUT_S = int(os.environ.get("RECOMMENDATION_TIMEOUT_S", "30"))
MAX_CHARS = int(os.environ.get("RECOMMENDATION_MAX_CHARS", "280"))

_SYSTEM_PROMPT = """You are a senior SOC analyst writing a concise next-action recommendation for an L2 analyst who is about to triage a Microsoft Sentinel alert.

You will be given a JSON object containing every piece of enrichment evidence the platform collected for this ticket:
- The ticket summary + description
- The overall verdict the platform settled on (malicious / suspicious / benign / unknown) + how it got there
- The IOC reputation results from VirusTotal, AbuseIPDB, SOCRadar (with confidence scores)
- MITRE ATT&CK techniques the LLM mapped (with confidence)
- Historical alert correlation (similar alerts in the past 24h and their L2 outcomes)
- Customer Knowledge Base chunks retrieved from the customer's Confluence pages
- Sentinel KQL hunting evidence (if any)
- The CUSTOMER PROFILE: the customer's industry, a short org profile, and any compliance regimes
- An INDUSTRY LENS: curated guidance on what an analyst in this customer's industry prioritises, the compliance framing that applies, which patterns are routinely benign for this vertical, and the default escalation posture
- ASSET CONTEXT: whether the affected host/IP matched the customer's documented asset inventory, and its criticality

Your job: write a SHORT, ACTIONABLE recommendation telling the analyst what to do next, TAILORED TO THIS CUSTOMER'S INDUSTRY and the asset at stake. Not a summary of the data — they can read that themselves. A recommendation. It will be shown on a single line inside the color-coded verdict box at the top of the ticket, so it must be scannable in one second.

Output rules:
- Plain text only — no markdown, no JSON, no bullet points.
- ONE imperative sentence (two at most). Hard ceiling ~40 words. Be specific, not wordy.
- Lead with the recommended action (verb-first): "Verify ...", "Contain ...", "Escalate ...", "Close ...", "Hunt ...".
- Reference the single strongest piece of evidence by name (e.g. "Defender already quarantined", "VirusTotal 47/86", "documented critical HVT"). Pick the one that most drives the decision — do not list every signal.
- WEIGHT the recommendation through the INDUSTRY LENS: bias toward its escalation posture, treat its listed priorities as high-stakes, and lean toward de-escalation when the alert matches one of its common false-positive patterns. Where compliance framing materially changes the action (e.g. PCI cardholder data, PHI), name it briefly.
- If ASSET CONTEXT shows the affected host is a documented CRITICAL/HIGH asset, weight that very heavily and escalate accordingly. The structured asset match and industry lens OVERRIDE generic reputation when they conflict (a clean-reputation IP hitting a crown-jewel system still warrants verification).
- The INDUSTRY LENS is curated guidance — apply it, but do NOT invent compliance obligations or industry facts beyond what it states.
- If historical similar alerts were mostly False-Positive, lean toward auto-suppression guidance.
- If the platform's verdict is "unknown" because evidence is conflicting, name the single contradiction driving the uncertainty.
- NEVER restate the verdict — that's already shown on the line above this one.
- NEVER hedge ("possibly", "it might be"). Pick a recommendation. If genuinely uncertain, say "Escalate to L2 — confirm <the one thing>" naming the single fact that would resolve it.

Examples of good output:

"Verify with the device owner that the 14:32 PowerShell run was an authorized helpdesk task; if not, isolate the host (3 similar TPs in 24h)."

"Close as False Positive — source IP is the Confluence-documented vuln scanner (10.20.15.7) and AbuseIPDB confidence is 0."

"Escalate to L2 now — VirusTotal 47/86 on a destination documented as a critical asset; pull EDR timeline and check lateral movement."

"Escalate — outbound to this host originates from a documented cardholder-data server (PCI scope); confirm no card data left the segment before closing."

"Close as benign — open-campus scan against a low-criticality lab host matches expected academic-network noise; no crown-jewel asset involved."

Now produce the recommendation."""


async def _call_llm(payload_json: str) -> str:
    from tools.llm_client import make_chat_client
    client, model = make_chat_client()
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": payload_json},
        ],
        # gpt-5.3-chat is a reasoning model: ~64 reasoning tokens (occasionally
        # more) count against this cap BEFORE any visible text. A tight cap
        # (e.g. 120) intermittently gets fully consumed by reasoning, leaving
        # finish_reason='length' with empty content. Keep generous headroom —
        # billing is per token actually generated, not the cap — while
        # MAX_CHARS still enforces a concise one-line recommendation.
        max_completion_tokens=512,
    )
    return (response.choices[0].message.content or "").strip()


def _strip_markdown(s: str) -> str:
    """Belt-and-braces: LLM sometimes ignores the no-markdown instruction.
    Strip the most common offenders so the ADF comment renders cleanly."""
    # Code fences
    s = re.sub(r"```[\s\S]*?```", "", s)
    # Bullet prefixes
    s = re.sub(r"(?m)^\s*[-*+]\s+", "", s)
    # Bold/italic markers (leave the text)
    s = s.replace("**", "").replace("__", "")
    # Trim
    return s.strip()


def _summarise_evidence(*, ticket_summary: str, ticket_description: str,
                       overall_verdict: str, action_taken: str,
                       ioc_results: list[dict],
                       mitre_result: dict | None,
                       historical: dict | None,
                       rag_info: dict | None,
                       kql_evidence: dict | None,
                       customer_profile: dict | None = None,
                       industry_lens: str = "",
                       asset_matches: list[dict] | None = None) -> dict:
    """Build a compact JSON-ready dict from the assembled evidence.

    We deliberately trim each section: full IOC payloads + chunk texts can be
    thousands of tokens. The LLM only needs the headline facts to write a
    recommendation. Anything trimmed here remains visible to the analyst in
    the comment.
    """
    def _trim(s: str, n: int) -> str:
        s = " ".join((s or "").split())
        return s if len(s) <= n else s[: n - 3] + "..."

    iocs_for_llm = []
    for r in (ioc_results or []):
        ioc = r.get("ioc") or {}
        vt = r.get("virustotal") or {}
        ab = r.get("abuseipdb") or {}
        sr = r.get("socradar") or {}
        iocs_for_llm.append({
            "value": ioc.get("value"),
            "type": ioc.get("type"),
            "verdict": r.get("verdict"),
            "virustotal": (
                {"malicious": vt.get("malicious_count"), "engines": vt.get("total_engines"),
                 "reputation": vt.get("reputation")} if vt else None),
            "abuseipdb_confidence": ab.get("confidence_score") if ab else None,
            "socradar": (
                {"verdict": sr.get("verdict"), "score": sr.get("score"),
                 "categories": (sr.get("categories") or [])[:3]} if sr else None),
        })

    techniques = []
    if mitre_result and (mitre_result.get("techniques") or []):
        for t in mitre_result["techniques"][:3]:
            techniques.append({
                "id": t.get("id"),
                "name": t.get("name"),
                "confidence": round(float(t.get("confidence", 0)), 2),
            })

    historical_compact = None
    if historical and historical.get("total", 0) > 0:
        historical_compact = {
            "window_hours": historical.get("window_hours", 24),
            "total": historical.get("total"),
            "true_positive": historical.get("true_positive", 0),
            "false_positive": historical.get("false_positive", 0),
            "unknown": historical.get("unknown", 0),
            "untriaged": historical.get("untriaged", 0),
        }

    rag_compact = None
    if rag_info and (rag_info.get("chunks") or []):
        rag_compact = {
            "pages_searched": rag_info.get("pages_searched"),
            "matches": [
                {"source": c.get("source"),
                 "score": round(float(c.get("score") or 0.0), 2),
                 "snippet": _trim(c.get("text") or "", 300)}
                for c in rag_info["chunks"][:4]
            ],
        }

    kql_compact = None
    if kql_evidence and (kql_evidence.get("queries") or []):
        kql_compact = {
            "workspace": kql_evidence.get("workspace_name"),
            "iterations": kql_evidence.get("iterations"),
            "total_rows": kql_evidence.get("total_rows"),
            "queries": [
                {"table": q.get("table"), "rows": q.get("row_count"),
                 "rationale": _trim(q.get("rationale") or "", 200)}
                for q in kql_evidence["queries"][:3]
            ],
        }

    profile_compact = None
    if customer_profile:
        profile_compact = {
            "industry": customer_profile.get("industry") or "unspecified",
            "org_profile": _trim(customer_profile.get("org_profile") or "", 400),
            "compliance_regime": [str(c) for c in (customer_profile.get("compliance_regime") or [])][:6],
        }

    asset_compact = None
    if asset_matches:
        asset_compact = [
            {"value": a.get("value"), "type": a.get("type"),
             "criticality": a.get("criticality"),
             "snippet": _trim(a.get("snippet") or "", 240)}
            for a in asset_matches[:4]
        ]

    return {
        "ticket_summary": _trim(ticket_summary, 400),
        "ticket_description": _trim(ticket_description, 1500),
        "platform_verdict": overall_verdict,
        "platform_action": action_taken,
        "customer_profile": profile_compact,
        "industry_lens": industry_lens or None,
        "asset_context": asset_compact,
        "iocs": iocs_for_llm,
        "mitre_techniques": techniques,
        "historical": historical_compact,
        "customer_knowledge": rag_compact,
        "sentinel_kql": kql_compact,
    }


def synthesize_recommendation(*, ticket_summary: str = "", ticket_description: str = "",
                              overall_verdict: str = "unknown",
                              action_taken: str = "",
                              ioc_results: list[dict] | None = None,
                              mitre_result: dict | None = None,
                              historical: dict | None = None,
                              rag_info: dict | None = None,
                              kql_evidence: dict | None = None,
                              customer_profile: dict | None = None,
                              industry_lens: str = "",
                              asset_matches: list[dict] | None = None) -> str | None:
    """Synthesise a next-action recommendation from all available evidence.

    Returns the recommendation string (one concise imperative line, plain
    text), or None if killswitch is OFF or anything fails. Never raises.

    Industry-aware (2026-06-19): callers may pass ``customer_profile``
    (industry / org_profile / compliance_regime), ``industry_lens`` (a
    pre-rendered text block from tools.industry_lens.get_industry_lens), and
    ``asset_matches`` (from tools.asset_inventory.find_asset_matches) to tailor
    the recommendation to the customer's vertical and the asset at stake. All
    optional — omitting them reproduces the prior generic behaviour.
    """
    if os.environ.get("RECOMMENDATION_SYNTHESIS_ENABLED", "false").lower() != "true":
        return None

    try:
        evidence = _summarise_evidence(
            ticket_summary=ticket_summary,
            ticket_description=ticket_description,
            overall_verdict=overall_verdict,
            action_taken=action_taken,
            ioc_results=ioc_results or [],
            mitre_result=mitre_result,
            historical=historical,
            rag_info=rag_info,
            kql_evidence=kql_evidence,
            customer_profile=customer_profile,
            industry_lens=industry_lens,
            asset_matches=asset_matches or [],
        )
        payload = json.dumps(evidence, ensure_ascii=False)

        # asyncio.run is safe here: synthesize_recommendation is called from
        # the enrichment thread, not from inside an existing event loop.
        async def _runner():
            return await asyncio.wait_for(_call_llm(payload), timeout=TIMEOUT_S)

        text = asyncio.run(_runner())
        cleaned = _strip_markdown(text)
        if not cleaned:
            return None
        if len(cleaned) > MAX_CHARS:
            cleaned = cleaned[: MAX_CHARS - 3] + "..."
        return cleaned
    except asyncio.TimeoutError:
        logger.warning("Recommendation synthesis timed out after %ds", TIMEOUT_S)
        return None
    except Exception as e:
        logger.exception("Recommendation synthesis failed: %s", e)
        return None
