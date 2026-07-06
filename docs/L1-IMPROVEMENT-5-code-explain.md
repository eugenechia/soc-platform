# L1 Triage Improvement #5 — AI Decodes SIEM/XDR Codes

**Status:** Implemented, ships dark (2026-07-06)
**Batch:** L1 improvements from the 2026-07-03 colleague meeting — #1/#2/#3/#4 done, **this is #5** (last of the batch)
**Current implementation:** [L1-TRIAGE.md](L1-TRIAGE.md)
**Sibling:** [Improvement #4](L1-IMPROVEMENT-4-command-line-analysis.md)
**Killswitch:** `CODE_EXPLAIN_ENABLED` (default **off**)

---

## 1. What this delivers

When a ticket carries raw security codes, the enrichment comment gains a
**Security Code Explanations** section that decodes them in plain English:

- **Windows Security Event IDs** — 4624/4625/4634/4672/4688/4720/4740/4768/4769/4771…
- **Logon Types** — 2/3/4/5/7/8/9/10/11
- **NTSTATUS / logon sub-status** — 0xC000006A (wrong password), 0xC0000234 (locked out)…
- **Kerberos failure codes** — 0x18 (pre-auth failed), 0x17 (password expired)…

Sample comment output:

```
Security Code Explanations:
  [Windows Event ID] 4625
    An account failed to log on (failed logon).
  [Logon Type] 3
    Network — access to a share or service over the network.
  [NTSTATUS / sub-status] 0xC000006A
    The user name is correct but the password is wrong.
```

**ADVISORY ONLY.** Never changes the ticket verdict.

## 2. Honest scope — read this before enabling

Investigation against the live Logicalis Sentinel stack (2026-07-06, no sample
ticket was available so this substituted for one) found that **these codes are
usually NOT present** in the Jira ticket or the `SecurityAlert` for this
customer's detection set:

- Cloud/identity logon-failure alerts (MCAS / IPC / AAD) carry IP / country / app
  but **no Windows Event IDs or NTSTATUS**.
- No NTSTATUS `0xC0000…` codes appear in alerts at all.
- Raw `SecurityEvent` 4625 / `SigninLogs` failures exist only as high-volume logs
  not attached to a ticket.
- (An earlier marker scan that seemed to find `EventID`/`LogonType` was a false
  positive — those strings were column names inside the analytics rule's KQL
  query text embedded in `ExtendedProperties`, not decodable event data.)

So **this section is silent on most tickets by design.** It adds value on the
subset that genuinely carry codes: Defender evidence text, on-prem AD alert rules
that put the code in the description, or an analyst-pasted raw event. It never
invents a code that isn't there.

If a future sample shows codes reliably living in a specific place (e.g. a
`SecurityEvent` 4625 join by account + time), a v2 can fetch them the way #4
fetches command lines. That was deliberately NOT built blind here.

## 3. How it works

```
enrich_ticket(ticket_key, fields)
  │  CODE_EXPLAIN_ENABLED == true
  ▼
tools/code_explain.py :: explain_ticket_codes(fields, extra_texts=None)
  │  gather text = ticket summary + description (+ any extra alert text passed in)
  │
  ├─ extract_codes(text): regex with STRICT context markers
  │    "Event ID N"  -> only if N is in the curated security Event-ID set
  │    "Logon Type N"
  │    "Sub Status / Status / NTSTATUS 0x........"
  │    "Failure Code 0x.." (Kerberos)
  │    NEVER decodes a bare number.
  │
  ├─ DETERMINISTIC decode from curated dictionaries (offline, free, precise)
  │
  └─ for the FEW marker-qualified codes NOT in the dictionary (capped,
     time-boxed): Tavily web search + LLM one-liner, honest "Unknown" if
     unidentifiable. Skipped entirely if there are no unknowns.
  ▼
{"items": [{kind, code, label, meaning, source: "dictionary"|"web"}, ...]}
  ▼
_append_code_explain_section() (text)  /  _adf_code_explain_block() (table)
```

**Precision over recall** is the core design choice: mislabelling a random
4-digit number as a logon event in a SOC comment is worse than saying nothing, so
extraction requires an explicit marker and (for Event IDs) membership in the
curated set.

## 4. Files

| File | Role |
|------|------|
| `tools/code_explain.py` | Extract + decode. Curated dicts (Event IDs / Logon Types / NTSTATUS / Kerberos) + strict-marker regex + optional LLM for unknowns. Killswitch owner. Returns `{"items": [...]}` or `None`. Never raises. |
| `tools/enrichment.py` | Orchestration in `enrich_ticket` + `_append_code_explain_section` / `_adf_code_explain_block`; threaded through `_build_comment` / `_build_comment_adf`. |
| `tools/test_code_explain.py` | Unit tests — extraction precision, dictionary decode, killswitch, dedupe. |

## 5. Configuration

| Var | Default | Purpose |
|-----|---------|---------|
| `CODE_EXPLAIN_ENABLED` | `false` | Master killswitch. Ships dark. |
| `CODE_EXPLAIN_TIMEOUT_S` | `20` | Budget for the LLM lookups (unknown codes only). |
| `CODE_EXPLAIN_MAX_CODES` | `8` | Max codes decoded per ticket. |
| `CODE_EXPLAIN_MAX_LLM_CODES` | `3` | Max unknown codes sent to the LLM per ticket. |
| `CODE_EXPLAIN_MAX_CHARS` | `240` | Cap on each LLM-sourced explanation. |

Notably, the common path (known codes) is **fully deterministic and needs no LLM
or network** — it works even where the Azure OpenAI endpoint is VNet-unreachable.

## 6. Testing

```bash
.venv/bin/python tools/test_code_explain.py   # fast, no network
```

## 7. Rollout

1. Deploy with `CODE_EXPLAIN_ENABLED=false` (default — ships dark).
2. Confirm the L1 probe (SCDM-727) still enriches normally.
3. When you have a ticket that actually carries codes (e.g. an on-prem AD
   logon-failure alert with "Event ID 4625 / Logon Type 3 / Sub Status 0x…"),
   flip `CODE_EXPLAIN_ENABLED=true` and verify the Security Code Explanations
   table renders with correct decodes.
