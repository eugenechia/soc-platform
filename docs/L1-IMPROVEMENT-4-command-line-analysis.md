# L1 Triage Improvement #4 — AI Command-Line Reputation Check

**Status:** Implemented, ships dark (2026-07-06)
**Batch:** [L1 improvements from the 2026-07-03 colleague meeting] — #1 satisfied, #2 + #3 live, **this is #4**
**Current implementation:** [L1-TRIAGE.md](L1-TRIAGE.md)
**Mirrors:** [ioc_insights.py](../tools/ioc_insights.py) (Improvement #2) — same fail-silent / async / grounded pattern
**Killswitch:** `CMDLINE_ANALYSIS_ENABLED` (default **off**)

---

## 1. What this delivers

The scenario, uniform for every customer:

> AI checks the process / PowerShell command line against online resources and the
> command line's own structure, and decides whether it is **malicious** or is
> **legitimately associated with known software** — so an L1 analyst triages faster.

Every triaged ticket that has an associated process command line gains a
**Command-Line Analysis** section in the enrichment comment: one colour-coded
panel per command line, verdict + a short grounded rationale with cited sources.

Sample comment output:

```
Command-Line Analysis (AI + Open-Source Web Research):
  [Malicious] powershell.exe
    Command line: powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgA...
    Parent: winword.exe
    Hidden, execution-policy-bypassing encoded payload with a DownloadString
    cradle to a hardcoded IP — a classic LOLBin RCE pattern. Treat as live
    compromise.

  [Legitimate] Acrobat.exe
    Command line: "Acrobat.exe" "C:\Users\j\Downloads\Invoice.pdf"
    Adobe Acrobat opening a PDF from Downloads; no scripting, download, or
    evasion. The 'child process blocked' alert is Adobe's own ASR rule firing,
    not malicious behaviour (file.net).
```

Silently omitted when there is no command line, when the customer has no Sentinel
workspace configured, or when the killswitch is off.

**ADVISORY ONLY.** The verdict here NEVER changes the ticket's overall verdict —
reputation and the Confluence whitelist still drive that. This honours the
Phase-4 / #3 invariant: *AI advisory output must not drive the verdict.*

## 2. The key finding — where the command line actually lives

Investigated against three real DKSH tickets (DKSH-57946, DKSH-59187 "Suspicious
behavior by powershell.exe", DKSH-5949). Result:

| Source | Carries the command line? |
|--------|---------------------------|
| The Jira ticket | **No** — Sentinel exports only a canned narrative ("powershell.exe was observed") + typed entity fields (ip/host/dns/url/hash). No process/command field anywhere. |
| `DeviceProcessEvents` (Advanced Hunting) | **No** — frequently not streamed into the Log Analytics workspace (empty in the tested workspace). |
| **`SecurityAlert.Entities`** | **Yes** — every MDATP/Defender process alert carries a Process entity with `CommandLine` + `ImageFile.Name` (and often the parent process). |

So the command line is **fetched upstream from the customer's own Sentinel
workspace**, not read from Jira. Proven end-to-end on live MDATP alerts (e.g. a
`Gt.exe --softname=... ('Kepuall' PUA)` and an `Acrobat.exe` PDF open).

## 3. How it works

```
Jira webhook → enrich_ticket(ticket_key, fields)
  │
  ▼  CMDLINE_ANALYSIS_ENABLED == true
  │
  ▼  tools/cmdline_analysis.py :: analyze_ticket_command_lines(customer, ticket_key, fields)
     │
     ├─ tools/cmdline_source.py :: fetch_command_lines(...)
     │    resolve customer's first Sentinel workspace (same per-workspace SP auth
     │    as Phase 5 KQL expansion — tools/kql_expansion.py)
     │    PRIMARY  key: ticket incident number (customfield_10071)
     │             SecurityIncident.AlertIds → SecurityAlert.Entities
     │    FALLBACK key: host name (customfield_10078) + time window
     │    → parse Process entities → [{command_line, image, parent_image, ...}]
     │    → dedupe, rank LOLBins/script-hosts first, cap (CMDLINE_SOURCE_MAX_CMDLINES)
     │
     ├─ per command line, CONCURRENTLY (asyncio):
     │    Tavily web search (identity-seeking, image + Defender family hint)
     │    → LLM grounded verdict: Malicious | Suspicious | Legitimate | Inconclusive
     │
     ▼  {"items": [{command_line, image, parent_image, alert_name, verdict, analysis}, ...]}
  │
  ▼  rendered as the "Command-Line Analysis" section
     _append_cmdline_section() (plain text)  /  _adf_cmdline_block() (colour-coded panels)
```

**How the LLM decides:** it reasons about the command line's *structure* directly
(LOLBin abuse, `-enc`/hidden/bypass flags, obfuscation, download-and-execute
cradles, suspicious writes/tasks) as first-hand evidence, and uses the web results
only to *identify* what the binary is (citing the source domain). Honest
"Inconclusive" when neither supports a call.

## 4. Files

| File | Role |
|------|------|
| `tools/cmdline_source.py` | Fetch command lines from `SecurityAlert.Entities` (incident / device key). Never raises; returns `[]` on any skip/failure. |
| `tools/cmdline_analysis.py` | Research + LLM verdict per command line. Killswitch owner. Returns render-ready `{"items": [...]}` or `None`. |
| `tools/enrichment.py` | Orchestration in `enrich_ticket` + `_append_cmdline_section` / `_adf_cmdline_block`; threaded through `_build_comment` / `_build_comment_adf`. |
| `tools/test_cmdline_source.py` | Unit tests — entity parsing, KQL-injection safety, dedupe/ranking. |
| `tools/test_cmdline_analysis.py` | Mocked orchestration tests + `--live` quality check. |

## 5. Configuration (env / killswitches)

| Var | Default | Purpose |
|-----|---------|---------|
| `CMDLINE_ANALYSIS_ENABLED` | `false` | Master killswitch. Ships dark. |
| `CMDLINE_ANALYSIS_TIMEOUT_S` | `30` | Total budget for all per-command-line research. |
| `CMDLINE_ANALYSIS_MAX_CHARS` | `700` | Cap on each rendered analysis note. |
| `CMDLINE_SOURCE_MAX_CMDLINES` | `5` | Distinct command lines analysed per ticket. |
| `CMDLINE_SOURCE_MAX_ALERTS` | `25` | Alerts scanned per Sentinel query. |
| `CMDLINE_SOURCE_LOOKBACK` | `P7D` | KQL timespan for the alert lookup. |
| `JIRA_FIELD_INCIDENT_NUMBER` | `customfield_10071` | Ticket field holding the Sentinel incident number. |

Requires (already present for the report/KQL paths): the customer record's
`sentinel_workspaces[0]` (`workspace_id` / `tenant_id` / `client_id` /
`client_secret_kv_name`), `TAVILY_API_KEY`, and an LLM via `tools/llm_client.py`.

## 6. Prerequisite / caveat — customer must have a Sentinel workspace onboarded

The mechanism is uniform, but it can only fire for a customer whose Sentinel
workspace is configured on their platform record. As of build time only the
**Logicalis** customer record has one. In particular:

- **DKSH is not onboarded** (no customer record, not on the `JIRA_ENRICHMENT_PROJECT`
  allowlist), and its workspace `log-sg-cc-sentinel01p` is not configured. So #4
  will not fire for DKSH tickets until DKSH's workspace is added — a **config /
  onboarding task, not a code change**. See [L1-TRIAGE-CUSTOMER-ONBOARDING.md](L1-TRIAGE-CUSTOMER-ONBOARDING.md).
- For any customer that *does* have a workspace, #4 works today (proven live).

## 7. Testing

```bash
# fast, no network
.venv/bin/python tools/test_cmdline_source.py
.venv/bin/python tools/test_cmdline_analysis.py

# real Tavily + LLM (Azure OpenAI is VNet-only — locally point at public OpenAI)
.venv/bin/python tools/test_cmdline_analysis.py --live
```

Note: the Azure OpenAI endpoint is private-endpoint / VNet-only and is **not
reachable from a dev machine** (DNS does not resolve off-VNet). Prod (the
Container App) reaches it in-VNet. Validate LLM verdict quality locally via the
public OpenAI fallback in `tools/llm_client.py`.

## 8. Rollout

1. Deploy with `CMDLINE_ANALYSIS_ENABLED=false` (ships dark — default).
2. Confirm the L1 probe ticket still enriches normally (no regression).
3. Flip `CMDLINE_ANALYSIS_ENABLED=true` for a customer with a Sentinel workspace
   and fire a process/PowerShell alert; verify the Command-Line Analysis panel
   renders with a sane verdict.
4. Watch webhook latency — the research is time-boxed by `CMDLINE_ANALYSIS_TIMEOUT_S`
   and count-capped by `CMDLINE_SOURCE_MAX_CMDLINES`.
