"""
Phase 1 L1 Triage redesign — pre-enrichment LLM priority call.

Runs after severity-sync and GSOC-assign, before the IOC enrichment pipeline.
Reads the ticket summary + description + entity IOCs + current severity, asks
the LLM whether the actual impact warrants a different priority than the
severity-mapped baseline, and returns a structured recommendation. The
caller in routes/webhook.py decides whether to accept the override based on
confidence threshold.

Failure mode: any exception → log and return None. The caller keeps the
severity-mapped baseline in place. Pipeline never blocks on an LLM hiccup.
"""
import asyncio
import json
import logging
import re

logger = logging.getLogger(__name__)

# Confidence threshold for accepting the LLM's recommendation. Below this,
# we keep the severity-mapped baseline. Tuned conservatively for Phase 1 —
# can lower later as we build confidence in the model's judgment.
TRIAGE_CONFIDENCE_THRESHOLD = 0.7

_VALID_PRIORITIES = {"Highest", "High", "Medium", "Low", "Lowest"}

_SYSTEM_PROMPT = """You are an L1 SOC analyst doing initial triage on a security incident ticket from Microsoft Sentinel.

You will be given:
- The ticket summary
- The ticket description
- The SIEM severity (already mapped to a Jira priority — your "baseline")
- The IOCs (IPs, hostnames, domains, URLs, file hashes) that the SIEM extracted from the alert

Your job: decide what priority this ticket should ACTUALLY have based on the apparent impact, regardless of the SIEM severity. The SIEM tends to over-flag (lots of false positives) and occasionally under-flag (e.g. a "Low" alert that actually indicates a serious compromise).

Output JSON ONLY, no prose, with these keys:
{
  "recommended_priority": "Highest" | "High" | "Medium" | "Low" | "Lowest",
  "rationale": "1-2 sentence justification grounded in what the ticket actually says",
  "confidence": 0.0-1.0
}

Confidence guidance:
- 0.9+  : strong evidence in the ticket text supports the recommendation (e.g. explicit mention of compromise, sensitive system, or clearly benign scanner activity)
- 0.7-0.9 : reasonably confident; the ticket text supports the recommendation but is not conclusive
- below 0.7 : uncertain; the baseline will be kept regardless of what you recommend, so be honest

Examples that warrant override:
- Baseline Low but description mentions "domain controller", "admin account dumped", "ransomware", or "data exfiltration" → escalate
- Baseline High but description clearly says "test alert", "scheduled scan from internal vuln scanner", or known whitelisted automation → de-escalate

If the description is empty or unhelpful, return the baseline priority with confidence ~0.5 so the override is rejected.

Historical context (when present) is a strong signal. A rule firing many times in the past 24h with mostly False-Positive outcomes is statistically likely to be FP again — be willing to de-escalate confidently. A rule with mixed outcomes deserves the baseline. A rule firing rarely or for the first time should rely on the ticket text itself."""


async def _call_llm(prompt: str) -> str:
    from tools.llm_client import make_chat_client
    client, model = make_chat_client()
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        max_completion_tokens=500,
        response_format={"type": "json_object"},
    )
    return (response.choices[0].message.content or "").strip()


def _parse_llm_response(raw: str) -> dict | None:
    """Tolerant JSON parser, same pattern as tools/advisory_extractor.py."""
    if not raw:
        return None
    fence = re.match(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
    if fence:
        raw = fence.group(1).strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            logger.warning("LLM Triage returned non-JSON: %r", raw[:200])
            return None
        try:
            parsed = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _extract_text(adf_or_str) -> str:
    """Best-effort text extraction; reuses jira_client's ADF helper if available."""
    if not adf_or_str:
        return ""
    if isinstance(adf_or_str, str):
        return adf_or_str
    try:
        from tools.jira_client import _extract_adf_text
        return _extract_adf_text(adf_or_str) or ""
    except Exception:
        return ""


def _build_user_prompt(fields: dict, severity: str, baseline_priority: str,
                       entity_iocs: list[dict] | None,
                       historical: dict | None = None) -> str:
    summary = fields.get("summary") or "(none)"
    desc = _extract_text(fields.get("description")) or "(none)"
    # Cap description so we stay within token budget regardless of upstream size.
    if len(desc) > 6000:
        desc = desc[:6000] + " ...[truncated]"
    iocs_str = "(none extracted yet)"
    if entity_iocs:
        iocs_str = "\n".join(
            f"- {i.get('type', '?').upper()}: {i.get('value', '')}"
            for i in entity_iocs[:30]
        )

    # Phase 3 (2026-06-13): if a historical lookup was performed, include the
    # counts in the prompt so the LLM can weigh "rule firing constantly with
    # mostly FP outcomes" as a de-escalation signal. Format-suppressed when
    # the lookup returned nothing.
    historical_block = ""
    if historical and historical.get("total", 0) > 0:
        prefix = historical.get("rule_prefix", "(unknown)")
        window = historical.get("window_hours", 24)
        historical_block = (
            f"\nHistorical context for this rule (past {window}h):\n"
            f"- {historical['total']} similar alerts matched by summary prefix "
            f"\"{prefix}\"\n"
            f"- {historical['true_positive']} confirmed True-Positive · "
            f"{historical['false_positive']} confirmed False-Positive · "
            f"{historical['unknown']} Unknown · "
            f"{historical['untriaged']} still untriaged\n"
        )

    return (
        f"SIEM severity: {severity or '(unknown)'}\n"
        f"Severity-mapped baseline priority: {baseline_priority or '(none — severity not recognised)'}\n\n"
        f"Ticket summary:\n{summary}\n\n"
        f"Ticket description:\n{desc}\n\n"
        f"Extracted IOCs:\n{iocs_str}"
        f"{historical_block}"
    )


def triage_priority(ticket_key: str, fields: dict, severity: str,
                    baseline_priority: str | None,
                    historical: dict | None = None) -> dict | None:
    """Synchronous wrapper around the async LLM call.

    Returns a dict like:
        {"recommended_priority": str, "rationale": str, "confidence": float}
    or None if the LLM call fails / returns malformed output. The caller
    (routes/webhook.py) decides whether to accept the override based on
    TRIAGE_CONFIDENCE_THRESHOLD and whether recommended differs from baseline.

    Phase 3 (2026-06-13): optional `historical` arg from
    tools.historical_alerts.query_similar_alerts(). When present and total>0,
    the LLM prompt includes the rule's recent FP/TP distribution as
    de-escalation evidence.
    """
    try:
        from tools.enrichment import extract_iocs_from_entity_fields
        entity_iocs = extract_iocs_from_entity_fields(fields)
    except Exception as e:
        logger.warning("triage_priority(%s): IOC extraction for prompt failed (%s); proceeding without IOCs",
                       ticket_key, e)
        entity_iocs = []

    if historical and historical.get("total", 0) > 0:
        logger.info("triage_priority(%s): historical context included (%d siblings)",
                    ticket_key, historical["total"])
    user_prompt = _build_user_prompt(fields, severity, baseline_priority or "",
                                     entity_iocs, historical)

    try:
        # asyncio.run is safe here because the webhook background thread has no
        # running event loop. Each call gets its own short-lived loop.
        raw = asyncio.run(_call_llm(user_prompt))
    except Exception as e:
        logger.warning("triage_priority(%s): LLM call failed (%s: %s); keeping baseline",
                       ticket_key, type(e).__name__, e)
        return None

    parsed = _parse_llm_response(raw)
    if not parsed:
        logger.warning("triage_priority(%s): LLM response could not be parsed; keeping baseline", ticket_key)
        return None

    rec = (parsed.get("recommended_priority") or "").strip()
    if rec not in _VALID_PRIORITIES:
        logger.warning("triage_priority(%s): invalid recommended_priority %r; keeping baseline",
                       ticket_key, rec)
        return None

    try:
        confidence = float(parsed.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    rationale = (parsed.get("rationale") or "").strip()

    logger.info("triage_priority(%s): recommended=%s, confidence=%.2f, rationale=%s",
                ticket_key, rec, confidence, rationale[:200])

    return {
        "recommended_priority": rec,
        "rationale": rationale,
        "confidence": confidence,
    }
