# L1 Triage AI Redesign — Roadmap

**Status:** Phase 1 in progress (2026-06-08)
**Owner:** Eugene Chia
**Related docs:** [L1-TRIAGE.md](L1-TRIAGE.md) (current implementation), [architecture/](architecture/)
**Rollback point:** `pre-l1-redesign-2026-06-08` (git tag + ACR image tag + Azure Files snapshot `2026-06-08T11:23:04.0000000Z`)

---

## 1. Context & motivation

The current L1 Triage pipeline (see [L1-TRIAGE.md](L1-TRIAGE.md)) does the rote first-line work — IOC extraction, threat intel lookup against SOCRadar/VirusTotal/AbuseIPDB, post-comment-to-Jira, and tag with `Potential-TP` if malicious indicators are found. That's been live since 2026-05-01 and is stable.

The team has since approved a far richer design (captured in the swim-lane diagram) that turns the pipeline into a proper AI Agent for L1. The new design adds:

- A **pre-enrichment LLM Triage call** that reads the ticket and sets initial priority based on impact
- **MITRE ATT&CK mapping** of alerts to tactics/techniques
- **Historical alert correlation** (past 24h of the same alert type)
- **RAG over Confluence** — retrieval-augmented context using Customer Escalation Matrix, HRT/HVT, Asset Inventory, Network Architecture, IOC lists, Whitelists, Finetuning List
- **AI-driven KQL expansion** — LLM generates Sentinel queries from observed IOCs, executes them, feeds results back as context
- **AI Recommendation Synthesis** combining all evidence into a MITRE-aligned action plan
- **Finetuning feedback loop** — analyst-confirmed verdicts get fed back into the RAG store for future triages
- **Auto-close high-confidence False Positives**

Goal: deliver each capability incrementally, with team validation between phases, so the production pipeline stays trustworthy throughout the redesign.

---

## 2. Target state architecture (AI Agent for L1 swim lane)

```
Sentinel/SIEM alert
        │
        ▼
Logic App (pre-existing) ── creates Jira ticket with default Medium priority
        │
        ▼
Jira webhook → POST /webhook/jira?secret=...                ◄── routes/webhook.py
        │
        ▼
[NEW PHASE 1]  Auto-set severity from SIEM AlertSeverity field
[NEW PHASE 1]  Auto-assign ticket to GSOC queue
[NEW PHASE 1]  Triage Phase: LLM reads ticket + sets priority based on impact
        │
        ▼
Investigation Phase (status → "Investigation")              ◄── tools/enrichment.py
        │
        ├─ Extract IOCs from typed entity fields + regex fallback   [EXISTS]
        ├─ Threat Intel: SOCRadar + VirusTotal + AbuseIPDB          [EXISTS]
        ├─ [NEW PHASE 2]  MITRE ATT&CK mapping → tactics + techniques
        ├─ [NEW PHASE 3]  Historical alert lookup (past 24h, same type)
        ├─ [NEW PHASE 4]  RAG retrieval from Confluence vector DB:
        │       - Customer Escalation Matrix
        │       - HRT/HVT (high-risk / high-value targets)
        │       - Asset Inventory
        │       - Network Architecture Documentation
        │       - IOC list + Whitelist
        │       - Finetuning List
        └─ [NEW PHASE 5]  AI-driven KQL: LLM generates queries → Sentinel → context
        │
        ▼
[NEW PHASE 6]  AI Recommendation Synthesis (MITRE-aligned)
        │
        ▼
Update Jira: explicit verdict label (True-Positive / False-Positive / Unknown)   ◄── [NEW PHASE 1]
Post enrichment comment summarising all evidence                                 ◄── enhanced over phases
        │
        ▼
Decision: True Positive?
        ├─ NO  → record outcome → [NEW PHASE 7] feed to Finetuning List + auto-close
        └─ YES → handoff to AI Agent / Member lane (out of scope of this roadmap)
```

---

## 3. Gap analysis

| Design step | Today | Phase that closes it |
|---|---|---|
| Sentinel/Logic App → Jira ticket | ✅ exists | — |
| Jira webhook → soc-platform | ✅ exists (`routes/webhook.py`) | — |
| Auto-update Jira severity from SIEM | ⚠️ partial (Logic App sets at creation; no re-mapping) | **Phase 1** |
| Auto-assign to GSOC queue | ⚠️ only individual L1/L2 supported (currently empty) | **Phase 1** |
| Pre-enrichment LLM Triage call | ❌ not implemented | **Phase 1** |
| Extract IOCs from entity fields | ✅ exists (`tools/enrichment.py`) | — |
| Threat Intel — VT / AbuseIPDB / SOCRadar | ✅ exists; SOCRadar bypasses KV abstraction | **Phase 1** (tech debt fix) |
| MITRE ATT&CK mapping | ❌ not implemented | **Phase 2** |
| Historical alert correlation (24h, same type) | ❌ not implemented | **Phase 3** |
| RAG over Confluence | ❌ not implemented | **Phase 4** |
| AI-driven KQL expansion via Sentinel | ❌ not implemented | **Phase 5** |
| Add enrichment comment to Jira | ✅ exists | enhanced across all phases |
| Auto-update Jira label | ✅ `Potential-TP` only | **Phase 1** (explicit verdicts) |
| AI Recommendation aligned with MITRE | ❌ not implemented | **Phase 6** |
| True Positive / False Positive decision | ⚠️ implicit (only "potential") | **Phase 1** (label) + **Phase 6** (synthesis) |
| Finetuning feedback loop | ❌ not implemented | **Phase 7** |
| Auto-close FP tickets | ❌ not implemented | **Phase 7** |

---

## 4. Phasing

| # | Phase | Scope summary | Depends on | Rough effort |
|---|---|---|---|---|
| 1 | **Triage Foundation & Housekeeping** | Severity sync, GSOC auto-assign, SOCRadar KV cleanup, pre-enrichment LLM triage, explicit verdict labels | — | 1–2 weeks |
| 2 | **MITRE ATT&CK Mapping** | Ingest ATT&CK STIX bundle, map alerts/IOCs → TTPs, surface in comment | 1 | 1 week |
| 3 | **Historical Alert Correlation** | Past 24h same-type alert lookup via Jira, count + summary in comment | 1 | 1 week |
| 4 | **RAG over Confluence** (largest) | Vector DB, Confluence connector, ingest pipeline, retrieval API, wire into LLM context | 1 | 3–4 weeks |
| 5 | **AI-driven KQL Expansion** | LLM generates KQL from IOCs, executes against Sentinel, iterative refinement loop | 1 | 2 weeks |
| 6 | **AI Recommendation Synthesis** | Combine all evidence into MITRE-aligned recommendation with confidence | 2, 3, 4, 5 | 1–2 weeks |
| 7 | **Finetuning Loop & Auto-close FP** | Capture analyst verdicts → Finetuning List in RAG; auto-close high-confidence FPs | 4, 6 | 1–2 weeks |

**Why this order:**

- **Phases 1–3 need no new infrastructure** — quick wins that demonstrate the LLM-in-pipeline pattern and earn team trust before the big foundational lift.
- **Phase 4 (RAG)** is the foundational piece everything richer depends on. Done after the team is comfortable with smaller AI changes.
- **Phase 5 (KQL)** is the most complex AI integration (agentic loop with self-correcting query refinement). Benefits from established patterns by this point.
- **Phase 6 (Synthesis)** needs the full evidence stack from prior phases to produce non-trivial recommendations.
- **Phase 7 (Finetuning + Auto-close)** depends on Phase 4 (RAG store to write into) and Phase 6 (verdict confidence to gate auto-close).

Phases 2/3/4/5 could technically run in parallel after Phase 1 — but the chosen workflow is sequential team validation, so they run one at a time.

---

## 5. Per-phase scope summaries

> Each phase will get its own detailed planning doc (`docs/L1-REDESIGN-PHASE-N-<name>.md`) when work on that phase begins. The summaries below are intentionally high-level so the team can preview the journey without being locked into implementation choices that may change as we learn.

### Phase 1 — Triage Foundation & Housekeeping

**Goal:** Bring the pipeline up to baseline before adding richer intelligence. Small, safe changes that establish patterns the later phases reuse.

**Scope:**
- Auto-update Jira severity from SIEM AlertSeverity (verify gap, fix if needed)
- Auto-assign tickets to a GSOC group/queue (not individual L1/L2)
- Switch `tools/socradar_rest.py` from `os.environ.get` to `tools/secrets.get_secret()`
- Add a pre-enrichment LLM Triage call that updates Jira priority based on impact analysis
- Replace single `Potential-TP` label with explicit verdicts: `True-Positive`, `False-Positive`, `Unknown`
- Update enrichment comment template to reflect new verdict states

**Team-visible after Phase 1:** Tickets arrive with correct severity + GSOC assignment, get an initial priority update from AI within seconds, and end up with one of three explicit verdict labels.

### Phase 2 — MITRE ATT&CK Mapping

**Goal:** Every triaged ticket shows which ATT&CK tactics/techniques the observed activity maps to.

**Scope:**
- Ingest MITRE ATT&CK STIX bundle as static data (re-ingest periodically when MITRE publishes updates)
- Heuristic mapping by alert type/rule name where possible
- LLM-based mapping for ambiguous cases
- Surface mapped TTPs in the Jira enrichment comment

**Team-visible after Phase 2:** Enrichment comment includes "Mapped MITRE TTPs: T1059.001 (PowerShell), T1071.001 (Web Protocols)" alongside the existing IOC/reputation block.

### Phase 3 — Historical Alert Correlation

**Goal:** Surface whether this alert is new, repeating, or part of a recent burst — strong signal for FP/TP separation.

**Scope:**
- Query Jira for tickets in the past 24h matching the same alert type/rule
- Compute counts + status breakdown (still open vs already resolved as FP)
- Add to enrichment context
- Surface "Similar alerts in past 24h: 12 (10 closed as FP, 2 open)" in the comment

**Team-visible after Phase 3:** Comment now includes a "Historical Context" line that helps analysts spot alert storms and recurring FPs immediately.

### Phase 4 — RAG over Confluence (foundational, largest phase)

**Goal:** AI triage can reason about customer-specific context — who owns the affected asset, is it an HVT, is the IOC on the customer's whitelist, what's the escalation path, etc.

**Scope:**
- Pick vector DB and embedding model (decision deferred to per-phase plan; candidates: pgvector / Azure AI Search / Chroma)
- Build Confluence connector using the Confluence API
- Ingest pipeline: chunk + embed + index the following knowledge sources:
  - Customer Escalation Matrix
  - HRT (High-Risk Targets) / HVT (High-Value Targets)
  - Asset Inventory
  - Network Architecture Documentation
  - IOC list
  - Whitelisted list
  - Finetuning List (populated in Phase 7)
- Retrieval API (top-K relevant chunks for a given alert)
- Wire retrieved context into the enrichment LLM prompt
- Initial re-index strategy (manual trigger; scheduled re-index can come later)

**Team-visible after Phase 4:** Comment includes an "Asset Context" section like *"Server SG-FILE-01 is HVT for Customer ACME. Owner: jdoe@acme.com. Escalation: page acme-soc-oncall."* — pulled directly from Confluence.

### Phase 5 — AI-driven KQL Expansion

**Goal:** AI runs Sentinel queries itself to corroborate or refute the alert, instead of analysts pivoting manually.

**Scope:**
- LLM generates KQL queries from the alert's IOCs/entities (e.g., "show all sign-ins from this IP in past 7 days")
- Execute via existing Log Analytics integration (extend `tools/sentinel_client.py`)
- Feed results back into the LLM context for iterative refinement
- Bound to a sensible query/iteration budget per ticket
- Add correlation findings to the enrichment comment

**Team-visible after Phase 5:** Comment now includes "Sentinel Correlation: this IP made 47 failed sign-in attempts across 12 accounts in the past 24h" — query was AI-generated, not analyst-typed.

### Phase 6 — AI Recommendation Synthesis

**Goal:** Replace the current ad-hoc enrichment comment with a single structured recommendation that ties together everything from Phases 1–5.

**Scope:**
- Synthesis LLM call takes all evidence (IOCs, threat intel, MITRE TTPs, historical, RAG context, KQL findings) and produces:
  - One paragraph executive summary
  - MITRE-aligned action items
  - Confidence score (drives Phase 7 auto-close gating)
  - Links to source evidence
- Render as a polished "Recommended Actions" section at the top of the Jira comment

**Team-visible after Phase 6:** Top of every triaged ticket has a clear "What you need to do" section grounded in concrete evidence, not generic guidance.

### Phase 7 — Finetuning Loop & Auto-close FP

**Goal:** System learns from analyst decisions and stops bothering them about trivially-FP tickets.

**Scope:**
- Webhook on Jira label/status change to capture analyst-confirmed verdicts
- Append confirmed verdicts (with ticket context) to the Finetuning List in the RAG store
- Future triages retrieve similar past verdicts as additional context ("3 similar alerts in past 30 days were all confirmed FP")
- Auto-close gating: if confidence ≥ X% AND historical FP rate ≥ Y%, auto-transition the ticket to Closed with a notification
- Grace period before auto-close so analysts can intervene

**Team-visible after Phase 7:** Trivial FPs disappear from the queue automatically. Tickets the AI was wrong about feed back into the system so it learns.

---

## 6. Workflow per phase

Strictly sequential. No phase starts until the previous one has team sign-off.

1. **Plan the phase** — write `docs/L1-REDESIGN-PHASE-N-<name>.md` with: implementation plan, files to modify, dependencies, test plan, rollback plan, risks
2. **Capture rollback point** — git tag + ACR re-tag + Azure Files snapshot, same pattern as `pre-l1-redesign-2026-06-08`
3. **Implement** — code, commit, push, deploy via the standard ACR build → Container App update flow
4. **Team tests** — team works through the test plan in the phase doc; any blockers go back to implementation
5. **Sign-off** — team confirms phase is acceptable; checklist item ticked in this roadmap's status tracker
6. **Update memory** — auto-memory entry created for the phase (so future Claude sessions can pick up)
7. **Begin next phase** — repeat

---

## 7. Cross-cutting concerns

**Production rollout strategy.** Today there's no staging Container App — `soc-platform` in `rg-soc-platform` is single-revision-mode and serves prod. Each phase ships with a rollback point captured **before** deploy. Container Apps' revision mechanism gives us instant rollback if a deploy breaks something obvious. For risky phases (particularly 4, 5, 6) consider switching temporarily to multi-revision mode + traffic-splitting for canary rollout. Decision to be made per phase.

**Secrets pattern.** All API keys go through `tools/secrets.py` → Azure Key Vault. The pre-existing SOCRadar bypass (env var direct) is fixed in Phase 1. New API keys (Confluence service account in Phase 4) follow the kebab-case KV-secret naming convention.

**Data sensitivity.** RAG content includes customer-specific asset inventory and escalation paths. The vector DB must be in the same security boundary as the existing `soc-platform-data` Azure Files share. Embedding model choice is constrained by data residency — prefer Azure OpenAI Embeddings (already in our tenant) over external providers.

**Observability.** Every new pipeline step should log structured entries to ContainerAppConsoleLogs_CL (visible in the existing Log Analytics workspace `a5be1877-ff08-4a4f-8fba-9b3e0664ded4`). Phase docs include a "what to grep for in logs" section.

**Doc maintenance.** When a phase ships, the existing [L1-TRIAGE.md](L1-TRIAGE.md) is updated to reflect the new behaviour, and this roadmap's status tracker (Section 8) is ticked off.

---

## 8. Phase status tracker

Update this section as each phase progresses. `[ ]` not started → `[~]` in progress → `[x]` complete (with date).

- [~] **Phase 1** — Triage Foundation & Housekeeping (implementation complete 2026-06-08; awaiting team test sign-off — see [L1-REDESIGN-PHASE-1-triage-foundation.md](L1-REDESIGN-PHASE-1-triage-foundation.md))
- [~] **Phase 2** — MITRE ATT&CK Mapping (implementation complete 2026-06-10; awaiting team test sign-off — see [L1-REDESIGN-PHASE-2-mitre-mapping.md](L1-REDESIGN-PHASE-2-mitre-mapping.md))
- [~] **Phase 3** — Historical Alert Correlation (implementation complete 2026-06-13; awaiting team test sign-off — see [L1-REDESIGN-PHASE-3-historical-correlation.md](L1-REDESIGN-PHASE-3-historical-correlation.md))
- [~] **Phase 4** — RAG over Confluence (MVP implementation complete 2026-06-13, killswitch OFF; awaiting Stage 2 content seed + team test sign-off — see [L1-REDESIGN-PHASE-4-rag-confluence.md](L1-REDESIGN-PHASE-4-rag-confluence.md))
- [ ] **Phase 5** — AI-driven KQL Expansion
- [ ] **Phase 6** — AI Recommendation Synthesis
- [ ] **Phase 7** — Finetuning Loop & Auto-close FP

---

## 9. Open questions (to resolve before / during Phase 1)

- **Staging environment** — ship each phase straight to prod, or stand up a staging Container App first? Affects Phase 1 rollout strategy onward.
- **Swim-lane diagram artefact** — currently shared as an image. Commit a copy to `docs/architecture/` so this roadmap can link to it.
- **Confluence service account** — does the SOC team already have one with API access? If not, provisioning is a Phase 4 blocker worth surfacing now.
- **GSOC assignment target** — is "GSOC" a single Jira account, a group, or a project-default-assignee? Affects Phase 1 implementation.
- **Existing data in Confluence** — are the seven knowledge sources (Escalation Matrix, HRT/HVT, etc.) already populated and current in Confluence, or do they need to be authored before Phase 4 can ingest them?
