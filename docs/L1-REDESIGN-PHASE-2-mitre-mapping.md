# L1 Triage AI Redesign — Phase 2: MITRE ATT&CK Mapping

**Status:** Implementation complete (2026-06-10); awaiting SOC team test sign-off

**Roadmap:** [L1-TRIAGE-REDESIGN-ROADMAP.md](L1-TRIAGE-REDESIGN-ROADMAP.md)
**Current implementation:** [L1-TRIAGE.md](L1-TRIAGE.md)
**Rollback checkpoint:** `pre-phase-2-2026-06-10` (git tag + ACR image tag)

---

## 1. What this phase delivers

After Phase 2 ships, every triaged Jira ticket will include a `MITRE ATT&CK Mapping:` section in the enrichment comment showing which tactics and techniques the observed activity maps to. Example:

```
MITRE ATT&CK Mapping:
  [T1071.001] Command and Control — Web Protocols (85% confidence)
  [T1566.002] Initial Access — Phishing: Spearphishing Link (72% confidence)
  [T1027]     Defense Evasion — Obfuscated Files or Information (61% confidence)

VERDICT: TRUE-POSITIVE
ACTION:  Ticket flagged as a True Positive — labelled 'True-Positive'.
```

If MITRE mapping fails for any reason (LLM error, index missing, etc.), the section is silently omitted — the rest of the comment is unaffected. The existing pipeline behaviour is preserved exactly.

---

## 2. How it works

### ATT&CK index
MITRE publishes the full ATT&CK Enterprise dataset as a STIX 2.x bundle. The ingest script (`tools/mitre_ingest.py`) downloads it, strips it to a compact index (~300KB), and writes `data/mitre_attack_index.json`. This file is committed to the repo and baked into the Docker image. Re-run the script and rebuild whenever MITRE publishes a new ATT&CK version.

### Two-tier mapping
1. **Heuristics** — extract coarse signals from `ioc_results`: SOCRadar threat categories (e.g. "C2", "Phishing", "Malware") and IOC types (ip, domain, hash). These are injected into the LLM prompt as seed hints so the model doesn't start cold.
2. **LLM** — reads ticket summary + description (capped at 3 000 chars) + IOC context + hints and returns a ranked JSON list of up to 3 technique IDs with confidence scores. Returned IDs are validated against the index; any unknown ID is silently dropped.

The LLM call uses `asyncio.run()` on the webhook background thread — same pattern as `tools/triage.py` (Phase 1). Each call gets its own short-lived event loop.

### Integration point
`tools/mitre_mapper.map_mitre()` is called in `enrich_ticket()` **after** `determine_verdict()`, so the full reputation picture (including SOCRadar categories) is available as context. The result is passed to `_build_comment()` which injects the MITRE section before the `VERDICT:` line.

---

## 3. New files

| File | Purpose |
|---|---|
| `tools/mitre_ingest.py` | CLI — download STIX, write `data/mitre_attack_index.json` |
| `tools/mitre_mapper.py` | `map_mitre(ticket_key, fields, ioc_results)` — returns mapping or None |
| `data/mitre_attack_index.json` | Pre-processed ATT&CK index (generated; committed to repo) |

## 4. Modified files

| File | Change |
|---|---|
| `tools/enrichment.py` | Call `mitre_mapper.map_mitre()` in `enrich_ticket()`; add MITRE section to `_build_comment()` |
| `.env.example` | Add `MITRE_MAPPING_ENABLED=true` |

---

## 5. New environment variables

| Variable | Default | Purpose |
|---|---|---|
| `MITRE_MAPPING_ENABLED` | `true` | Set to `false` to skip MITRE mapping entirely (instant killswitch, no rebuild needed) |

No new API keys or secrets required — mapping uses the existing Azure OpenAI / LLM configured in Phase 1.

---

## 6. Updating the ATT&CK index

MITRE releases ATT&CK updates roughly twice a year. When a new version ships:

```bash
cd /path/to/soc-platform
python3 tools/mitre_ingest.py
# Verify: jq .count data/mitre_attack_index.json
git add data/mitre_attack_index.json
git commit -m "chore: refresh MITRE ATT&CK index to v<new-version>"
# Then rebuild and deploy as normal
```

---

## 7. Test plan for the team

After deploy, validate by creating test tickets in the SCDM Jira project.

| # | Scenario | Setup | Expected result |
|---|---|---|---|
| 1 | MITRE section present — malicious ticket | Ticket with a known-malicious IOC (C2 IP that VT/SOCRadar flags) | Enrichment comment includes `MITRE ATT&CK Mapping:` section with 1–3 techniques before `VERDICT: TRUE-POSITIVE` |
| 2 | MITRE section present — clean ticket | Ticket with `8.8.8.8` or `google.com` | Comment includes MITRE section (techniques may be generic); `VERDICT: BENIGN-POSITIVE` unchanged |
| 3 | MITRE section present — no IOCs | Ticket with empty entity fields | Comment includes MITRE section if LLM can infer from summary; `VERDICT: UNKNOWN` unchanged |
| 4 | Killswitch | Set `MITRE_MAPPING_ENABLED=false` on Container App; create any ticket | Comment posts without `MITRE ATT&CK Mapping:` section; rest unchanged |
| 5 | Failure resilience | (Internal test) Temporarily rename `data/mitre_attack_index.json`; rebuild; create ticket | Comment posts without MITRE section; webhook log shows `MITRE mapping failed … skipping`; no pipeline failure |
| 6 | End-to-end smoke | Standard Sentinel-originated ticket | All Phase 1 behaviour intact PLUS MITRE section in comment |

Phase 2 is **signed off** when scenarios 1, 2, 4, and 6 pass.

### Where to look in logs

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| where Log_s contains "mitre"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
```

Look for:
- `mitre_mapper: map_mitre(<KEY>): N techniques mapped`
- `mitre_mapper: map_mitre(<KEY>): index not loaded — skipping` (index missing)
- `enrich_ticket(<KEY>): MITRE mapping failed … skipping` (any other error)

---

## 8. Rollback

```bash
az containerapp update \
  --name soc-platform --resource-group rg-soc-platform \
  --image socplatformreg.azurecr.io/soc-platform:pre-phase-2-2026-06-10 \
  --revision-suffix "rollback-$(date +%s)"
```

Config-only rollback (keep code, disable feature):
```bash
az containerapp update \
  --name soc-platform --resource-group rg-soc-platform \
  --set-env-vars MITRE_MAPPING_ENABLED=false
```

---

## 9. Known limitations / what's next

Phase 2 mapping is based solely on the ticket context available at triage time (summary, description, IOC types, reputation categories). It does **not** yet:

- Use historical alert data to refine technique attribution — Phase 3
- Use customer-specific asset context (HVT/HRT) to assess technique severity — Phase 4
- Incorporate KQL-derived Sentinel evidence — Phase 5
- Appear in the structured AI Recommendation section — Phase 6

See the [roadmap](L1-TRIAGE-REDESIGN-ROADMAP.md) for the full sequence.

---

## 10. Addendum — TTP update (2026-07-10)

Analyst request: "when a malicious ticket comes in, add TTP for L1 triage." Three changes, all rendering/gating — `tools/mitre_mapper.py` logic untouched:

1. **Malicious-only gating.** `map_mitre()` is now called only when `overall_verdict == "malicious"` (after the whitelist override, so benign-overridden tickets also skip). Clean and unknown tickets no longer pay the LLM call. New env `MITRE_MALICIOUS_ONLY` (default `true`); set `false` to restore Phase 2's run-on-every-ticket behavior without a redeploy. `MITRE_MAPPING_ENABLED` remains the master killswitch.

2. **Richer rendering.** The section is retitled "MITRE ATT&CK — Attack TTPs". The ADF table gains a "Why" column showing the per-technique `rationale` (captured since Phase 2, previously discarded at render time), and technique IDs link to their attack.mitre.org page. The plain-text fallback renders the same rationale + URL under each technique line.

3. **Prominent placement.** The section moved from the very bottom of the comment to the FIRST section under the "L1 Triage Report (Automated)" heading — directly below the color-coded VERDICT panel — in both the ADF and text renderers.

Deferred (recorded in KIV): feeding mapped TTPs into the LLM Triage prompt. Blocked on pipeline ordering — `triage_priority()` runs in the pre-enrichment foundation phase, before IOC reputation determines the verdict, so verdict-gated TTPs cannot exist yet at prompt-assembly time. Revisit only with a pipeline restructure.

Rollback: git tag `pre-ttp-malicious-2026-07-10`, or config-only via `MITRE_MALICIOUS_ONLY=false` (gating) — the placement/rendering changes are code-level and need the image rollback.
