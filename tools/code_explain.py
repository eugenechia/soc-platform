"""
Improvement #5 (2026-07-06) — AI decodes SIEM/XDR codes.

Scenario: an L1 analyst sees raw codes on a logon/authentication alert — Windows
Security Event IDs (4625, 4624, 4740…), a Logon Type, an NTSTATUS logon
sub-status (0xC000006A…), or a Kerberos failure code — and may not remember what
each means. This module finds those codes in the ticket text (and any alert text
passed in), decodes them, and renders a "Security Code Explanations" advisory
section in the enrichment comment.

## What this is and isn't (read before extending)

Investigation against the live Logicalis Sentinel stack (2026-07-06) found these
codes are USUALLY NOT present in the Jira ticket or the SecurityAlert for this
customer's detection set — cloud/identity logon-failure alerts (MCAS/IPC/AAD)
carry IP/country/app but no Windows codes, and raw SecurityEvent 4625 lives only
in high-volume logs not attached to a ticket. So this section is SILENT on most
tickets by design, and adds value on the subset that DO carry codes (Defender
evidence text, on-prem AD alert rules that put the code in the description, or an
analyst-pasted raw event).

## Design

- **Deterministic first.** A curated static dictionary decodes the common codes —
  free, offline, precise, and works even where the LLM endpoint is unreachable.
  The LLM (grounded by Tavily) is used ONLY for codes not in the dictionary, and
  only when both the killswitch and an API are available.
- **Precision over recall.** We NEVER decode a bare number. A code is only decoded
  when it appears with an explicit context marker ("Event ID", "Logon Type",
  "Sub Status", "Failure Code", "NTSTATUS") AND (for Event IDs) is in the curated
  security set. This is deliberate: mislabelling a random 4-digit number as a
  logon event in a SOC comment is worse than saying nothing.
- **Advisory only.** Never changes the ticket verdict.
- **Fail-silent.** Killswitch ``CODE_EXPLAIN_ENABLED`` (default off). Any error →
  the section is omitted. Never raises.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

logger = logging.getLogger(__name__)

TIMEOUT_S = int(os.environ.get("CODE_EXPLAIN_TIMEOUT_S", "20"))
MAX_CODES = int(os.environ.get("CODE_EXPLAIN_MAX_CODES", "8"))
MAX_LLM_CODES = int(os.environ.get("CODE_EXPLAIN_MAX_LLM_CODES", "3"))
MAX_CHARS = int(os.environ.get("CODE_EXPLAIN_MAX_CHARS", "240"))
_WEB_CONTEXT_CAP = 2500

# ── Curated decoders (the deterministic fast-path) ──────────────────────────────

# Windows Security Event IDs an L1 actually meets on logon/auth/account alerts.
# Kept intentionally to the well-known security set — membership here is also the
# precision guard for Event-ID extraction.
_EVENT_IDS = {
    "4624": "An account was successfully logged on.",
    "4625": "An account failed to log on (failed logon).",
    "4634": "An account was logged off.",
    "4647": "User-initiated logoff.",
    "4648": "A logon was attempted using explicit credentials (runas / stored creds).",
    "4672": "Special privileges assigned to a new logon (admin-equivalent logon).",
    "4688": "A new process has been created.",
    "4697": "A service was installed in the system.",
    "4698": "A scheduled task was created.",
    "4700": "A scheduled task was enabled.",
    "4702": "A scheduled task was updated.",
    "4720": "A user account was created.",
    "4722": "A user account was enabled.",
    "4723": "An attempt was made to change an account's password.",
    "4724": "An attempt was made to reset an account's password.",
    "4725": "A user account was disabled.",
    "4726": "A user account was deleted.",
    "4728": "A member was added to a security-enabled global group.",
    "4732": "A member was added to a security-enabled local group.",
    "4738": "A user account was changed.",
    "4740": "A user account was locked out.",
    "4767": "A user account was unlocked.",
    "4768": "A Kerberos authentication ticket (TGT) was requested.",
    "4769": "A Kerberos service ticket (TGS) was requested.",
    "4771": "Kerberos pre-authentication failed.",
    "4776": "The domain controller attempted to validate credentials (NTLM).",
    "4778": "A session was reconnected to a Window Station (RDP reconnect).",
    "4779": "A session was disconnected from a Window Station (RDP disconnect).",
    "1102": "The audit log was cleared.",
    "7045": "A new service was installed in the system (System log).",
}

# Windows Logon Types (Event 4624/4625 field).
_LOGON_TYPES = {
    "2":  "Interactive — logon at the console (keyboard).",
    "3":  "Network — access to a share or service over the network.",
    "4":  "Batch — scheduled task.",
    "5":  "Service — a service started by the Service Control Manager.",
    "7":  "Unlock — the workstation was unlocked.",
    "8":  "NetworkCleartext — network logon sending the password in clear text (often IIS basic auth).",
    "9":  "NewCredentials — RunAs with /netonly (alternate credentials for network access).",
    "10": "RemoteInteractive — Remote Desktop (RDP / Terminal Services).",
    "11": "CachedInteractive — logon using cached domain credentials (DC unreachable).",
}

# NTSTATUS / logon sub-status codes seen on 4625/4776 (the 'why it failed').
_NTSTATUS = {
    "0xC0000064": "The user name does not exist.",
    "0xC000006A": "The user name is correct but the password is wrong.",
    "0xC000006D": "Bad user name or password (generic logon failure).",
    "0xC000006E": "Account restriction prevents this logon (e.g. policy).",
    "0xC000006F": "The user is not allowed to log on at this time (logon hours).",
    "0xC0000070": "The user is not allowed to log on from this workstation.",
    "0xC0000071": "The account's password has expired.",
    "0xC0000072": "The account is currently disabled.",
    "0xC0000133": "Clocks between the DC and the client are too far out of sync.",
    "0xC0000193": "The account has expired.",
    "0xC0000224": "The user must change their password before logging on.",
    "0xC0000234": "The account is currently locked out.",
    "0xC00002EE": "An error occurred during logon.",
    "0xC0000371": "The local account store does not contain secret material.",
}

# Kerberos pre-auth / TGS failure codes (Event 4768/4769/4771 'Failure Code').
_KERBEROS = {
    "0x6":  "Client not found in the Kerberos database (bad/disabled account).",
    "0x7":  "Server not found in the Kerberos database (SPN missing).",
    "0x12": "Client credentials revoked (account disabled, expired, or locked out).",
    "0x17": "The password has expired.",
    "0x18": "Pre-authentication failed — usually a wrong password.",
    "0x1d": "The server is not available.",
    "0x25": "Clock skew too great between client and DC.",
}

_KIND_LABEL = {"event_id": "Windows Event ID", "logon_type": "Logon Type",
               "ntstatus": "NTSTATUS / sub-status", "kerberos": "Kerberos failure code"}

# ── Extraction (precision-guarded) ──────────────────────────────────────────────

_RE_EVENT_ID = re.compile(r"\bevent\s*id\s*[:#]?\s*(\d{3,5})\b", re.IGNORECASE)
_RE_LOGON_TYPE = re.compile(r"\blogon\s*type\s*[:#]?\s*(\d{1,2})\b", re.IGNORECASE)
_RE_NTSTATUS = re.compile(
    r"\b(?:sub[\s-]*status|status|ntstatus)\s*[:#]?\s*(0x[0-9A-Fa-f]{8})\b", re.IGNORECASE)
# A bare 0xC0000... logon status is also decodable — but ONLY if it's a known one.
_RE_NTSTATUS_BARE = re.compile(r"\b(0xC0000[0-9A-Fa-f]{3})\b")
_RE_KERBEROS = re.compile(
    r"\b(?:failure\s*code|kerberos.*?code)\s*[:#]?\s*(0x[0-9A-Fa-f]{1,2})\b", re.IGNORECASE)


def extract_codes(text: str) -> list[dict]:
    """Return decodable codes found in ``text`` with strict context markers.

    Each item: ``{"kind", "code", "meaning"}`` for codes in the curated
    dictionaries, or ``{"kind", "code", "meaning": None}`` for a marker-qualified
    code we don't know (candidate for LLM lookup). De-duplicated by (kind, code).
    """
    if not text:
        return []
    found: dict[tuple, dict] = {}

    def add(kind: str, code: str, meaning: str | None):
        key = (kind, code.upper() if code.startswith(("0x", "0X")) else code)
        if key not in found:
            found[key] = {"kind": kind, "code": code, "meaning": meaning}

    for m in _RE_EVENT_ID.finditer(text):
        code = m.group(1)
        # Precision guard: only decode Event IDs in the curated security set.
        if code in _EVENT_IDS:
            add("event_id", code, _EVENT_IDS[code])

    for m in _RE_LOGON_TYPE.finditer(text):
        code = m.group(1)
        if code in _LOGON_TYPES:
            add("logon_type", code, _LOGON_TYPES[code])

    for m in _RE_NTSTATUS.finditer(text):
        code = "0x" + m.group(1)[2:].upper()
        add("ntstatus", code, _NTSTATUS.get(code))  # meaning None if unknown -> LLM candidate

    for m in _RE_NTSTATUS_BARE.finditer(text):
        code = "0x" + m.group(1)[2:].upper()
        if code in _NTSTATUS:           # bare form: only if KNOWN (no LLM guessing)
            add("ntstatus", code, _NTSTATUS[code])

    for m in _RE_KERBEROS.finditer(text):
        code = "0x" + m.group(1)[2:].lower()
        add("kerberos", code, _KERBEROS.get(code))

    return list(found.values())


# ── Optional LLM grounding for unknown, marker-qualified codes ───────────────────

_SYSTEM_PROMPT = """You are a SOC analyst assistant. You are given a single SIEM/XDR code (a Windows Security Event ID, an NTSTATUS/logon sub-status, or a Kerberos failure code) that a curated dictionary did not cover, plus optional web-search results. State concisely what the code means in a security-logon context.

RULES:
- 1 sentence, ~30 words, plain text. No markdown.
- Only state what the web results support (cite the source domain) OR well-established Windows documentation facts. If you cannot identify it, output EXACTLY: "Unknown code — not identified."
- Do not speculate or invent a meaning to fill the gap."""


async def _call_llm(kind: str, code: str, web_context: str) -> str:
    from tools.llm_client import make_chat_client
    client, model = make_chat_client()
    user = (f"Code type: {_KIND_LABEL.get(kind, kind)}\nCode: {code}\n\n"
            f"Web-search results:\n{web_context or '(none)'}")
    resp = await client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": _SYSTEM_PROMPT},
                  {"role": "user", "content": user}],
        max_completion_tokens=200,
    )
    return (resp.choices[0].message.content or "").strip()


def _web_search(query: str) -> str | None:
    from tools.tavily_client import fetch_web_context
    return fetch_web_context(query)


def _strip_markdown(s: str) -> str:
    s = re.sub(r"```[\s\S]*?```", "", s)
    s = s.replace("**", "").replace("__", "")
    return s.strip()


def _gather_text(fields: dict, extra_texts: list[str] | None) -> str:
    """Assemble the text to scan: ticket summary + description + any extra alert
    text (e.g. Sentinel ExtendedProperties) the caller supplies."""
    from tools.enrichment import _extract_adf_text  # reuse the ADF flattener
    parts = []
    if fields:
        summ = fields.get("summary")
        if summ:
            parts.append(str(summ))
        desc = fields.get("description")
        if desc:
            try:
                parts.append(_extract_adf_text(desc))
            except Exception:
                parts.append(str(desc))
    for t in (extra_texts or []):
        if t:
            parts.append(str(t))
    return "\n".join(parts)


def explain_ticket_codes(fields: dict, extra_texts: list[str] | None = None) -> dict | None:
    """Find + decode SIEM/XDR codes for a ticket. Returns a render-ready structure
    or None on any skip/failure.

    Return shape::

        {"items": [{"kind", "code", "label", "meaning", "source": "dictionary"|"web"}, ...]}

    Deterministic dictionary decode always runs (offline). The LLM is consulted
    only for marker-qualified codes the dictionary didn't cover, capped and
    time-boxed, and only when the killswitch is on. Never raises.
    """
    if os.environ.get("CODE_EXPLAIN_ENABLED", "false").lower() != "true":
        return None

    try:
        text = _gather_text(fields, extra_texts)
        codes = extract_codes(text)
    except Exception:
        logger.exception("code_explain: extraction failed")
        return None

    if not codes:
        return None

    codes = codes[:MAX_CODES]
    known = [c for c in codes if c.get("meaning")]
    unknown = [c for c in codes if not c.get("meaning")][:MAX_LLM_CODES]

    items = [{
        "kind": c["kind"], "code": c["code"], "label": _KIND_LABEL.get(c["kind"], c["kind"]),
        "meaning": c["meaning"], "source": "dictionary",
    } for c in known]

    # Only reach for the LLM if there are unknown codes AND the killswitch is on.
    if unknown:
        async def _one(c: dict):
            query = f'{c["code"]} {_KIND_LABEL.get(c["kind"], "")} windows security meaning'
            web = await asyncio.to_thread(_web_search, query)
            text_ = await _call_llm(c["kind"], c["code"], (web or "")[:_WEB_CONTEXT_CAP])
            meaning = _strip_markdown(text_)[:MAX_CHARS]
            if not meaning or meaning.lower().startswith("unknown code"):
                return None
            return {"kind": c["kind"], "code": c["code"],
                    "label": _KIND_LABEL.get(c["kind"], c["kind"]),
                    "meaning": meaning, "source": "web"}

        async def _runner():
            res = await asyncio.gather(*[_one(c) for c in unknown], return_exceptions=True)
            return [r for r in res if r and not isinstance(r, Exception)]

        try:
            items.extend(asyncio.run(asyncio.wait_for(_runner(), timeout=TIMEOUT_S)))
        except Exception as e:
            logger.warning("code_explain: LLM lookup skipped (%s): %s", type(e).__name__, e)

    if not items:
        return None
    return {"items": items}
