"""
Phase 2 L1 Triage redesign — MITRE ATT&CK mapping.

Two-tier approach:
  1. Heuristics: IOC types + SOCRadar categories → coarse hints fed to the LLM prompt
  2. LLM: full ticket context → ranked techniques validated against the index

Failure mode: any exception → log and return None. The caller in enrichment.py
wraps the call in its own try/except. The pipeline never blocks or fails because
of MITRE mapping.
"""
import asyncio
import json
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_INDEX_PATH = Path(__file__).parent.parent / "data" / "mitre_attack_index.json"
_MITRE_MAPPING_ENABLED = os.environ.get("MITRE_MAPPING_ENABLED", "true").lower() != "false"

# Module-level singleton — loaded once on first call, reused for the container lifetime.
_index_by_id: dict[str, dict] | None = None
_index_loaded: bool = False


def _load_index() -> dict[str, dict] | None:
    global _index_by_id, _index_loaded
    if _index_loaded:
        return _index_by_id
    _index_loaded = True
    if not _INDEX_PATH.exists():
        logger.warning("mitre_mapper: index not found at %s — MITRE mapping disabled", _INDEX_PATH)
        _index_by_id = None
        return None
    try:
        data = json.loads(_INDEX_PATH.read_text())
        _index_by_id = {t["id"]: t for t in data.get("techniques", [])}
        logger.info("mitre_mapper: loaded %d ATT&CK techniques (v%s)",
                    len(_index_by_id), data.get("version", "?"))
    except Exception as e:
        logger.warning("mitre_mapper: failed to load index (%s) — MITRE mapping disabled", e)
        _index_by_id = None
    return _index_by_id


def _get_heuristic_hints(ioc_results: list[dict]) -> list[str]:
    """Extract IOC types and SOCRadar categories as seed hints for the LLM prompt."""
    hints: list[str] = []
    ioc_types: set[str] = set()
    for r in ioc_results:
        ioc_type = (r.get("ioc") or {}).get("type", "")
        if ioc_type:
            ioc_types.add(ioc_type)
        sr = r.get("socradar") or {}
        for cat in sr.get("categories") or []:
            if cat and cat not in hints:
                hints.append(cat)
    for t in sorted(ioc_types):
        hints.append(t)
    return hints


def _extract_text(adf_or_str) -> str:
    if not adf_or_str:
        return ""
    if isinstance(adf_or_str, str):
        return adf_or_str
    try:
        from tools.jira_client import _extract_adf_text
        return _extract_adf_text(adf_or_str) or ""
    except Exception:
        return ""


_SYSTEM_PROMPT = """You are a MITRE ATT&CK expert analyst. Given a security alert ticket and its IOC reputation results, identify the most likely ATT&CK techniques being used.

You will be given:
- The ticket summary and description
- IOC types observed (IP addresses, domains, file hashes)
- Threat intelligence categories from reputation sources (e.g. "C2", "Phishing", "Malware")
- Optional heuristic hints

Return JSON ONLY, no prose, with this structure:
{
  "techniques": [
    {
      "id": "T1071.001",
      "name": "Web Protocols",
      "tactic": "Command and Control",
      "confidence": 0.85,
      "rationale": "1-sentence reason"
    }
  ]
}

Rules:
- Return at most 3 techniques, ordered by confidence descending
- Only use real MITRE ATT&CK technique IDs (e.g. T1071, T1566.002). Never invent IDs.
- confidence is 0.0-1.0: 0.8+ means strong indicator in the ticket, 0.5-0.8 means plausible, below 0.5 is speculative
- If the ticket gives insufficient context to map reliably, return an empty list
- Do not include techniques with confidence below 0.4"""


def _build_user_prompt(fields: dict, ioc_results: list[dict], hints: list[str]) -> str:
    summary = fields.get("summary") or "(none)"
    desc = _extract_text(fields.get("description")) or "(none)"
    if len(desc) > 3000:
        desc = desc[:3000] + " ...[truncated]"

    ioc_lines = []
    for r in ioc_results[:20]:
        ioc = r.get("ioc") or {}
        verdict = r.get("verdict", "unknown")
        sr = r.get("socradar") or {}
        cats = ", ".join(sr.get("categories") or [])
        line = f"- {ioc.get('type', '?').upper()} {ioc.get('value', '')} — verdict: {verdict}"
        if cats:
            line += f" — categories: {cats}"
        ioc_lines.append(line)

    hints_str = ", ".join(hints) if hints else "(none)"
    iocs_str = "\n".join(ioc_lines) if ioc_lines else "(none)"

    return (
        f"Alert summary:\n{summary}\n\n"
        f"Alert description:\n{desc}\n\n"
        f"IOCs and reputation:\n{iocs_str}\n\n"
        f"Heuristic hints (IOC types + threat categories):\n{hints_str}"
    )


async def _call_llm(user_prompt: str) -> str:
    from tools.llm_client import make_chat_client
    client, model = make_chat_client()
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        max_completion_tokens=600,
        response_format={"type": "json_object"},
    )
    return (response.choices[0].message.content or "").strip()


def _parse_llm_response(raw: str) -> list[dict] | None:
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
            logger.warning("mitre_mapper: LLM returned non-JSON: %r", raw[:200])
            return None
        try:
            parsed = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    if not isinstance(parsed, dict):
        return None
    techniques = parsed.get("techniques")
    if not isinstance(techniques, list):
        return None
    return techniques


def _validate_techniques(raw_techniques: list[dict], index: dict[str, dict]) -> list[dict]:
    """Keep only entries with valid ATT&CK IDs present in the index, cap at 3."""
    validated = []
    for entry in raw_techniques:
        if not isinstance(entry, dict):
            continue
        tech_id = (entry.get("id") or "").strip().upper()
        if not tech_id or tech_id not in index:
            if tech_id:
                logger.debug("mitre_mapper: dropping unknown technique ID %r", tech_id)
            continue
        canonical = index[tech_id]
        try:
            confidence = float(entry.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        validated.append({
            "id":         tech_id,
            "name":       canonical["name"],
            "tactic":     canonical["tactic"],
            "confidence": round(confidence, 2),
            "rationale":  (entry.get("rationale") or "").strip(),
        })
    validated.sort(key=lambda t: t["confidence"], reverse=True)
    return validated[:3]


def map_mitre(ticket_key: str, fields: dict, ioc_results: list[dict]) -> dict | None:
    """Map a Jira ticket to MITRE ATT&CK techniques.

    Returns {"techniques": [...]} or None if mapping is disabled, the index is
    unavailable, or any error occurs. Caller should treat None as "skip section".
    """
    if not _MITRE_MAPPING_ENABLED:
        return None

    index = _load_index()
    if index is None:
        logger.info("mitre_mapper: map_mitre(%s): index not loaded — skipping", ticket_key)
        return None

    hints = _get_heuristic_hints(ioc_results)
    user_prompt = _build_user_prompt(fields, ioc_results, hints)

    try:
        raw = asyncio.run(_call_llm(user_prompt))
    except Exception as e:
        logger.warning("mitre_mapper: map_mitre(%s): LLM call failed (%s: %s) — skipping",
                       ticket_key, type(e).__name__, e)
        return None

    raw_techniques = _parse_llm_response(raw)
    if raw_techniques is None:
        logger.warning("mitre_mapper: map_mitre(%s): LLM response could not be parsed — skipping",
                       ticket_key)
        return None

    techniques = _validate_techniques(raw_techniques, index)
    logger.info("mitre_mapper: map_mitre(%s): %d technique(s) mapped", ticket_key, len(techniques))

    return {"techniques": techniques}
