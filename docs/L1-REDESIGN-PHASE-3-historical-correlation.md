# L1 Triage AI Redesign — Phase 3: Historical Alert Correlation

**Status:** Implementation in progress (2026-06-13)
**Roadmap:** [L1-TRIAGE-REDESIGN-ROADMAP.md](L1-TRIAGE-REDESIGN-ROADMAP.md)
**Current implementation:** [L1-TRIAGE.md](L1-TRIAGE.md)
**Predecessors:** [Phase 1](L1-REDESIGN-PHASE-1-triage-foundation.md) (Triage Foundation), [Phase 2](L1-REDESIGN-PHASE-2-mitre-mapping.md) (MITRE Mapping)
**Rollback checkpoint:** `pre-phase-3-2026-06-13`

---

## 1. What this phase delivers

Every triaged Jira ticket gains a **Similar Alerts (past 24h)** section in the enrichment comment, broken down by Phase 1 verdict label, plus the same historical context is fed into the Phase 1 LLM Triage call so the model can de-escalate priority when a rule has a high false-positive rate.

Sample comment output:

```
Similar Alerts (past 24h): 12
  ├─ True-Positive:  2
  ├─ False-Positive: 8
  ├─ Unknown:        1
  └─ Untriaged:      1 (still in flight)
  Matched on: "Brute force attempt on host srv-"
  Earliest sibling: 2026-06-13 11:14:00 SGT
```

The section is silently omitted when there are zero prior matches in the window (so first-time alerts don't get noise) and when the killswitch is off.

## 2. How it works

```
Sentinel/SIEM alert
  │
  ▼
Logic App → creates Jira ticket
  │
  ▼
Jira webhook → POST /webhook/jira?secret=...
  │
  ▼
Background thread:
  poll for entity fields → stabilization → dedup
  │
  ▼  ┌─────────────────── PHASE 1 + PHASE 3 ─────────────────┐
     │  (1) severity sync                                    │
     │  (2) GSOC assign                                      │
     │  (3) [PHASE 3 NEW]  historical lookup                 │
     │      tools/historical_alerts.py::query_similar_alerts │
     │      JQL: same project + past 24h + summary ~ prefix  │
     │      → {total, tp, fp, unknown, untriaged}            │
     │  (4) LLM Triage  ← historical context in prompt       │
     └───────────────────────────────────────────────────────┘
  │
  ▼
enrich_ticket()  ← historical context surfaced in comment
  │
  ▼
Comment order:
  Origin → IOC reputations → Similar Alerts → MITRE → VERDICT
```

The historical lookup is computed once per ticket and passed to BOTH the LLM Triage call (Phase 1) and the enrichment comment builder (Phase 1 + 2). Failure is silent — pipeline keeps going with the Phase 1/2 behaviour.

## 3. Match signal

Phase 3 identifies "same alert" by **Jira summary prefix**. The first N characters of the summary (default 50, configurable via `HISTORICAL_LOOKUP_SUMMARY_PREFIX_LEN`) are normalized — leading bracket prefixes like `[DUPLICATE]` are stripped — and used in JQL phrase search:

```
project = "<project>"
AND key != "<current_ticket_key>"
AND created >= -24h
AND summary ~ "\"<prefix>\""
```

Why summary prefix, not SIEM rule_id? Because Sentinel Logic App tickets don't expose the rule name in a parseable Jira field; the summary prefix is the only universal signal across both Sentinel-Logic-App and soc-ticket-gateway ticket sources.

## 4. Status breakdown

Each matched sibling is categorised by reading its `labels` array:

| Label present | Category |
|---|---|
| `True-Positive` (or env-overridden `JIRA_TRIAGE_MALICIOUS_LABEL`) | True-Positive |
| `False-Positive` (or env-overridden `JIRA_TRIAGE_CLEAN_LABEL`) | False-Positive |
| `Unknown` (or env-overridden `JIRA_TRIAGE_UNKNOWN_LABEL`) | Unknown |
| None of the above | Untriaged (still in flight or never triaged) |

## 5. LLM Triage integration

When historical data is present, the Phase 1 LLM Triage call gets an additional context block in the user prompt:

> Historical context for this rule (past 24h):
> - 12 similar alerts (matched by summary prefix "Brute force attempt on host srv-")
> - 2 confirmed True-Positive · 8 confirmed False-Positive · 1 Unknown · 1 still untriaged

System-prompt guidance added:

> Historical context is a strong signal. A rule firing many times in 24h with mostly False-Positive outcomes is statistically likely to be FP again — be willing to de-escalate confidently. A rule with mixed outcomes deserves the baseline. A rule firing rarely or for the first time should rely on the ticket text itself.

The same `confidence ≥ 0.7` override threshold from Phase 1 still gates whether the LLM's recommendation takes effect.

## 6. New environment variables

```bash
HISTORICAL_LOOKUP_ENABLED=true                  # killswitch — set false to disable Phase 3 entirely
HISTORICAL_LOOKUP_WINDOW_HOURS=24               # lookback window
HISTORICAL_LOOKUP_SUMMARY_PREFIX_LEN=50         # chars used for "same alert" match
```

All have safe defaults; nothing else needs touching on the Container App.

## 7. Test plan for the team

After deploy, validate by creating test tickets in the SCDM Jira project.

| # | Scenario | Setup | Expected result |
|---|---|---|---|
| 1 | First occurrence | Create ticket with a brand-new summary pattern | No Historical section in comment (silently omitted). Webhook log shows `Historical lookup: 0 similar alerts in past 24h`. |
| 2 | Repeating noisy rule (mostly FP) | Create 5 tickets with the same summary prefix; mark first 4 as False-Positive. Create the 5th. | 5th ticket shows 4 prior, 4 FP. LLM Triage rationale references the FP context; priority may de-escalate. |
| 3 | Alert storm of confirmed threats | Create 3 tickets with same prefix; label all as True-Positive. Create a 4th. | 4th ticket shows 3 TP siblings. LLM holds or escalates priority. |
| 4 | Mixed verdicts | Create siblings: 2 TP, 2 FP, 1 Unknown. Create another. | Comment shows clean per-verdict breakdown; LLM rationale reflects the mix. |
| 5 | Untriaged sibling | Create a sibling 30 min ago that's still in enrichment | Comment shows "1 still untriaged" line; no crash. |
| 6 | Stability with summary noise | Two tickets with same first-50-chars but differing trailing tokens | Both match each other; webhook log shows the match prefix. |
| 7 | Jira API timeout *(optional)* | Block egress to Jira temporarily | Pipeline continues; comment has NO Historical section; LLM Triage uses baseline; webhook log shows `Historical lookup failed`. |
| 8 | Killswitch off *(optional)* | Set `HISTORICAL_LOOKUP_ENABLED=false` and deploy | No JQL query made; no Historical section; LLM prompt back to Phase 1 shape. |
| 9 | End-to-end smoke | Standard Sentinel-originated ticket | All sections present: Origin → IOC reputations → Historical → MITRE → VERDICT. Webhook completes in <90s. |

Phase 3 is **signed off** when scenarios 1–6 and 9 all pass.

### Where to look in logs

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| where Log_s contains "Historical lookup" or Log_s contains "triage_priority"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
```

Look for:
- `Historical lookup: N similar alerts in past 24h (TP=x FP=y U=z untriaged=w)` — successful lookup
- `Historical lookup failed: <reason>` — JQL/network error; pipeline continues without it
- `triage_priority(KEY): historical context included (N siblings)` — LLM call saw the history
- `Historical lookup disabled by env` — killswitch path

## 8. Rollback

If Phase 3 needs to be reverted:

```bash
az containerapp update \
  --name soc-platform --resource-group rg-soc-platform \
  --image socplatformreg.azurecr.io/soc-platform:pre-phase-3-2026-06-13 \
  --revision-suffix "rollback-$(date +%s)"
```

Quickest config-only revert (keep new code, disable Phase 3): set `HISTORICAL_LOOKUP_ENABLED=false` on the Container App. No redeploy needed.

## 9. Known limitations / what's next

- **Match is summary-prefix-based.** Two rules whose summaries share the same opening phrase will collide. If we see this in practice, lengthen `HISTORICAL_LOOKUP_SUMMARY_PREFIX_LEN` or move to a SIEM-side rule_id field in a future phase.
- **24h window only.** Longer windows are an env tweak away but the comment can get noisy with old data.
- **No cross-project correlation.** Current code is single-project (SCDM).
- **No KQL-side lookup.** Sentinel-direct correlation comes in Phase 5.

See the [roadmap](L1-TRIAGE-REDESIGN-ROADMAP.md) for what follows after Phase 3 sign-off.
