"""
Improvement #4 (2026-07-06) — AI command-line reputation check.

Scenario (uniform for every customer): for a process / PowerShell command line
associated with an alert, have the AI check it against online resources and the
command line's own structure, and decide whether it is MALICIOUS or is
LEGITIMATELY associated with known software — so an L1 analyst can judge the
alert faster.

The command line is NOT in the Jira ticket; it is fetched from the customer's
Sentinel workspace (``SecurityAlert.Entities``) by :mod:`tools.cmdline_source`.
This module takes those command lines, researches each on the open web (Tavily),
and asks the LLM for a GROUNDED verdict + short rationale. Rendered as a
"Command-Line Analysis" advisory section in the Jira enrichment comment.

Design (mirrors tools/ioc_insights.py deliberately):
- Killswitch ``CMDLINE_ANALYSIS_ENABLED`` defaults OFF — ships dark.
- ADVISORY ONLY (v1): the verdict here NEVER changes the ticket's overall
  verdict. Reputation/whitelist still drive that (honours the Phase-4 / #3
  "RAG/advisory must not drive the verdict" invariant).
- Per-command-line (Tavily-in-thread → LLM) runs CONCURRENTLY via asyncio.gather,
  so added latency ≈ one command line rather than the sum. Count is already
  bounded by tools.cmdline_source (CMDLINE_SOURCE_MAX_CMDLINES).
- Grounded: the LLM reasons about the command-line STRUCTURE directly (LOLBin
  abuse, obfuscation, encoded payloads, download-and-execute) and may only make
  IDENTITY claims ("X is a known installer for Y") that the web results support,
  citing the source domain. Honest "Inconclusive" when nothing supports a call.
- Fail-silent: any error → that command line is omitted; a total failure returns
  None and the caller renders nothing. Never raises; the comment always posts.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

logger = logging.getLogger(__name__)

TIMEOUT_S = int(os.environ.get("CMDLINE_ANALYSIS_TIMEOUT_S", "30"))
MAX_CHARS = int(os.environ.get("CMDLINE_ANALYSIS_MAX_CHARS", "700"))
_WEB_CONTEXT_CAP = 3500  # trim Tavily payload before it hits the LLM

# Verdict vocabulary the LLM must choose from (validated on parse).
_VERDICTS = {"Malicious", "Suspicious", "Legitimate", "Inconclusive"}
_DEFAULT_VERDICT = "Inconclusive"

_SYSTEM_PROMPT = """You are a SOC analyst assessing a single process or PowerShell COMMAND LINE pulled from a security alert. Decide whether it is malicious or is legitimately associated with known software, so an L1 analyst can triage faster.

You are given: the process image name, the command line, the parent process (if known), the alert name Defender assigned, and a block of open-source web-search results gathered just now.

HOW TO REASON:
1. Analyse the command line's STRUCTURE directly — this is legitimate first-hand evidence, use it freely:
   - LOLBin / living-off-the-land abuse (powershell, cmd, mshta, rundll32, regsvr32, certutil, bitsadmin, wmic, msbuild used to run/download code).
   - Obfuscation & evasion: `-enc`/`-EncodedCommand` base64, `-nop -w hidden -ep bypass`, string concatenation, char codes, `IEX`/`Invoke-Expression`, `DownloadString`/`DownloadFile`, `FromBase64String`, gzip/deflate.
   - Download-and-execute cradles, suspicious URLs/IPs, writes to temp/startup, scheduled-task or service creation, credential access.
   - Benign-looking, well-formed invocations of known software (e.g. an installer, updater, or a document opened by its app) with ordinary arguments.
2. Use the WEB RESULTS only to IDENTIFY what the binary/software is (e.g. "Gt.exe is a bundled adware installer", "this is the legitimate Zoom updater"). Cite the source domain in parentheses for any identity claim. Do NOT invent identity facts the results don't support.

VERDICT — choose exactly one:
- "Malicious": the command line shows clear attack tradecraft, or web results identify the binary as malware/PUA and the arguments are consistent with that.
- "Suspicious": LOLBin/obfuscation/evasion patterns that warrant analyst review but are not conclusively malicious on their own.
- "Legitimate": the command line is an ordinary, well-formed invocation of identifiable legitimate software, with nothing evasive.
- "Inconclusive": neither the structure nor the web results support a call.

OUTPUT JSON ONLY, no prose, no markdown fences:
{
  "verdict": "Malicious" | "Suspicious" | "Legitimate" | "Inconclusive",
  "analysis": "<2-4 sentences, plain text, ~90 words max. Lead with the single most decision-relevant observation. State the concrete command-line evidence for the verdict. Cite source domains for identity claims. No markdown, no bullets.>"
}

Examples of good analysis text:
"Legitimate: this is Adobe Acrobat opening a PDF from the user's Downloads folder (\"Acrobat.exe\" \"...pdf\") — an ordinary document-open with no scripting, download, or evasion. The 'child process blocked' alert reflects Adobe's own attack-surface-reduction rule firing, not malicious behaviour."
"Malicious: powershell with -nop -w hidden -enc followed by a base64 blob is a classic hidden, execution-policy-bypassing encoded payload; decoding conventions and the DownloadString cradle indicate remote code execution. Treat as a live compromise."
"Suspicious: rundll32 loading a DLL from %TEMP% with an ordinal export is a common proxy-execution technique, but nothing here identifies the DLL as known malware — recommend analyst review of the DLL hash."

Now assess the command line."""


async def _call_llm(image: str, command_line: str, parent_image: str,
                    alert_name: str, web_context: str) -> tuple[str, str]:
    """Return (verdict, analysis). Verdict is validated against _VERDICTS."""
    from tools.llm_client import make_chat_client
    client, model = make_chat_client()
    user_msg = (
        f"Process image: {image or '(unknown)'}\n"
        f"Command line: {command_line}\n"
        f"Parent process: {parent_image or '(unknown)'}\n"
        f"Defender alert name: {alert_name or '(none)'}\n\n"
        f"Open-source web-search results:\n{web_context or '(no results)'}"
    )
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        # Reasoning model: reasoning tokens count against this cap before any
        # visible text — keep generous headroom. MAX_CHARS enforces brevity.
        max_completion_tokens=700,
        response_format={"type": "json_object"},
    )
    raw = (response.choices[0].message.content or "").strip()
    return _parse_verdict(raw)


def _parse_verdict(raw: str) -> tuple[str, str]:
    import json
    if not raw:
        return _DEFAULT_VERDICT, ""
    fence = re.match(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
    if fence:
        raw = fence.group(1).strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            return _DEFAULT_VERDICT, _strip_markdown(raw)[:MAX_CHARS]
        try:
            parsed = json.loads(m.group(0))
        except json.JSONDecodeError:
            return _DEFAULT_VERDICT, ""
    if not isinstance(parsed, dict):
        return _DEFAULT_VERDICT, ""
    verdict = str(parsed.get("verdict", "")).strip().title()
    if verdict not in _VERDICTS:
        verdict = _DEFAULT_VERDICT
    analysis = _strip_markdown(str(parsed.get("analysis", "")).strip())
    if len(analysis) > MAX_CHARS:
        analysis = analysis[: MAX_CHARS - 3] + "..."
    return verdict, analysis


def _web_search(query: str) -> str | None:
    """Thin, patchable wrapper around Tavily (lazy import, like ioc_insights)."""
    from tools.tavily_client import fetch_web_context
    return fetch_web_context(query)


def _strip_markdown(s: str) -> str:
    s = re.sub(r"```[\s\S]*?```", "", s)
    s = re.sub(r"(?m)^\s*[-*+]\s+", "", s)
    s = s.replace("**", "").replace("__", "")
    return s.strip()


def _build_query(item: dict) -> str:
    """Identity-seeking query: what IS this binary — malware/PUA or legit software.
    Uses the image name plus the Defender family hint (alert name) when present;
    NOT biased to 'malicious' so legit-software identity pages surface too."""
    image = item.get("image") or "process"
    alert = item.get("alert_name") or ""
    # Pull a family/keyword hint out of the alert name (e.g. "'Kepuall' unwanted
    # software..." -> Kepuall) to sharpen the search without leaking the whole
    # Defender verdict string.
    fam = ""
    m = re.search(r"'([^']+)'", alert)
    if m:
        fam = m.group(1)
    hint = f" {fam}" if fam else ""
    return f'"{image}"{hint} process what is it malware analysis or legitimate software'


def analyze_ticket_command_lines(customer: dict | None, ticket_key: str,
                                 fields: dict) -> dict | None:
    """Fetch the ticket's process command lines from Sentinel, research + judge
    each, and return a render-ready structure — or None on any skip/failure.

    Return shape::

        {
          "items": [
            {"command_line": str, "image": str, "parent_image": str,
             "alert_name": str, "verdict": "Malicious|Suspicious|Legitimate|Inconclusive",
             "analysis": str},
            ...
          ]
        }

    Never raises.
    """
    if os.environ.get("CMDLINE_ANALYSIS_ENABLED", "false").lower() != "true":
        return None

    try:
        from tools.cmdline_source import fetch_command_lines
        cmdlines = fetch_command_lines(customer, ticket_key, fields)
    except Exception:
        logger.exception("cmdline_analysis %s: source fetch failed", ticket_key)
        return None

    if not cmdlines:
        return None

    async def _one(item: dict):
        # Tavily is blocking — run it off the event loop so searches overlap.
        web = await asyncio.to_thread(_web_search, _build_query(item))
        web_context = (web or "")[:_WEB_CONTEXT_CAP]
        verdict, analysis = await _call_llm(
            item.get("image", ""), item["command_line"],
            item.get("parent_image", ""), item.get("alert_name", ""), web_context)
        if not analysis:
            return None
        return {
            "command_line": item["command_line"],
            "image": item.get("image", ""),
            "parent_image": item.get("parent_image", ""),
            "alert_name": item.get("alert_name", ""),
            "verdict": verdict,
            "analysis": analysis,
        }

    async def _runner():
        results = await asyncio.gather(*[_one(i) for i in cmdlines],
                                       return_exceptions=True)
        out = []
        for res in results:
            if isinstance(res, Exception):
                logger.warning("cmdline_analysis %s: per-command-line analysis failed: %s",
                               ticket_key, res)
                continue
            if res:
                out.append(res)
        return out

    try:
        items = asyncio.run(asyncio.wait_for(_runner(), timeout=TIMEOUT_S))
    except asyncio.TimeoutError:
        logger.warning("cmdline_analysis %s: analysis timed out after %ds", ticket_key, TIMEOUT_S)
        return None
    except Exception as e:
        logger.exception("cmdline_analysis %s: synthesis failed: %s", ticket_key, e)
        return None

    if not items:
        return None
    return {"items": items}
