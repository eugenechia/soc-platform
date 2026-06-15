# L1 Triage AI Redesign — Phase 4: RAG over Confluence (Lean MVP)

**Status:** Implementation in progress (2026-06-13)
**Roadmap:** [L1-TRIAGE-REDESIGN-ROADMAP.md](L1-TRIAGE-REDESIGN-ROADMAP.md)
**Current implementation:** [L1-TRIAGE.md](L1-TRIAGE.md)
**Predecessors:** [Phase 1](L1-REDESIGN-PHASE-1-triage-foundation.md), [Phase 2](L1-REDESIGN-PHASE-2-mitre-mapping.md), [Phase 3](L1-REDESIGN-PHASE-3-historical-correlation.md)
**Rollback checkpoint:** `pre-phase-4-2026-06-13`

---

## 1. Important constraints

A prior attempt at RAG/Confluence integration **affected the entire triage flow**. The reported failure modes were:

1. **Errors propagated and killed the whole triage pipeline.**
2. **Bad retrievals confused the LLM, leading to wrong triage decisions.**

This Phase 4 MVP is designed defensively around both:

- **Phase 4 NEVER feeds RAG output into the LLM Triage prompt.** Retrieved context is shown in the Jira comment for the analyst, not in any LLM call. This directly addresses failure mode #2.
- **Every entry point is wrapped in try/except with a 5-second hard timeout.** Any failure → log + skip → pipeline continues with the existing Phase 1/2/3 behaviour. This addresses failure mode #1.
- **Killswitch off by default** (`RAG_LOOKUP_ENABLED=false`). The team flips it on only after validating retrieval quality.

LLM Triage prompt integration is deliberately deferred to a future Phase 4b, contingent on Phase 4 stability.

---

## 2. What this phase delivers

A new **Customer Context** section in the enrichment comment showing the top-K most relevant chunks from indexed knowledge documents. Example:

```
Customer Context:
  ► [HRT-HVT] srv-FILE-01 is a High-Value Target for Customer ACME (owner jdoe@acme.com) — 0.82
  ► [Whitelist] 13.107.6.152 is on the Microsoft Azure infrastructure whitelist — 0.79
  ► [EscalationMatrix] After-hours escalation: page acme-soc-oncall — 0.71
```

Source tag in `[brackets]` matches the subdirectory name under `RAG_DOCS_DIR`. The similarity score (cosine, 0–1) is appended so analysts can sanity-check relevance.

The section is silently omitted when:
- The killswitch is off, OR
- Retrieval fails for any reason, OR
- No chunk scores above `RAG_MIN_SCORE` (default 0.5)

So a first-time alert with no matching context simply gets no Customer Context line — no noise.

---

## 3. Architecture

### Stack (no new managed services)

| Component | Choice | Rationale |
|---|---|---|
| Vector store | Chroma (persistent client) | Embedded, in-process. Persists to `/tmp/rag/` (see "SMB caveat" below). Zero new managed infrastructure. |
| Embedding model | Azure OpenAI `text-embedding-3-small` | Already in tenant (data residency satisfied), ~$0.02/1M tokens. |
| Ingest source | Local Markdown files | `/app/data/rag_docs/<bucket>/*.md`. Team drops files via Storage Explorer; ingest is manual via `/admin/rag/reingest`. |
| Chunking | Paragraph-based, 500 char cap | Good-enough MVP. |
| Retrieval | Cosine similarity, top-K=3, min-score=0.5 | All env-tunable. |

### Flow

```
Sentinel → Logic App → Jira ticket created
  ↓
Webhook (poll → stabilize → dedup)
  ↓
[Phase 3] historical_alerts.query_similar_alerts()
  ↓
[Phase 4 NEW] rag_retrieval.retrieve_customer_context(summary + IOCs)
              ──► 5s hard timeout
              ──► silent skip on any failure
  ↓
[Phase 1] _run_triage_foundation(historical)     ← LLM prompt unchanged
  ↓
enrich_ticket(fields, historical, rag_chunks)    ← comment renders Customer Context
  ↓
Comment posted to Jira
```

### Module map (new)

- `tools/rag_embed.py` — embedding helper (Azure OpenAI client cached)
- `tools/rag_store.py` — Chroma wrapper (persistent client cached)
- `tools/rag_retrieval.py` — single hot-path entry: `retrieve_customer_context(query) -> list[dict] | None`
- `tools/rag_ingest.py` — CLI tool: `python -m tools.rag_ingest [--dry-run] [--source <bucket>]`

### Modified files

- `routes/webhook.py` — wire the retrieval call between Phase 3 and Phase 1; thread result to `enrich_ticket()` only
- `tools/enrichment.py` — `enrich_ticket()` and `_build_comment()` accept optional `rag_chunks`; new helper `_append_customer_context_section()` follows the Phase 2/3 pattern
- `routes/admin.py` — new `POST /admin/rag/reingest` route + UI tile on `/admin` showing chunk count + last-ingest timestamp + re-ingest button
- `requirements.txt` — add `chromadb>=0.5.0`

---

## 4. New environment variables

```bash
RAG_LOOKUP_ENABLED=false                   # killswitch — OFF by default; flip to true after team validates
RAG_TIMEOUT_SECONDS=5                      # hard cap on retrieval time
RAG_TOP_K=3                                # max chunks to return per query
RAG_MIN_SCORE=0.5                          # cosine similarity threshold; chunks below this are dropped
RAG_DOCS_DIR=/app/data/rag_docs            # ingest source (mounted Azure Files)
RAG_CHROMA_DIR=/app/data/rag               # vector DB persistence (mounted Azure Files)
```

All defaults are safe. No Container App env changes are required to deploy Phase 4 in its initial "killswitch off" state.

---

## 5. Two-stage rollout (this is intentional)

### Stage 1 — Infrastructure live, killswitch OFF

After deploy:
- Container starts cleanly with `chromadb` installed
- `POST /admin/rag/reingest` succeeds against empty `/app/data/rag_docs/` ("0 chunks ingested")
- Test ticket flows through with **NO Customer Context section** in the comment (proves no behaviour change, no errors)
- Logs show `RAG lookup disabled by env`

This is the proof point: infrastructure is in place but invisible to the triage pipeline.

### Stage 2 — Seed content + flip killswitch

1. Drop 3–5 test markdown files under `/app/data/rag_docs/`. Recommended bucket layout:
   - `data/rag_docs/HRT-HVT/customer-acme-hvts.md`
   - `data/rag_docs/Whitelist/azure-infra.md`
   - `data/rag_docs/EscalationMatrix/after-hours.md`
2. Trigger re-ingest via `/admin/rag` UI or `POST /admin/rag/reingest`. Verify chunk count > 0.
3. Set `RAG_LOOKUP_ENABLED=true` on the Container App.
4. Create a test ticket whose summary or IOCs match content in the seeded docs.
5. Confirm:
   - Comment includes the Customer Context section
   - Similarity scores look reasonable (0.5–1.0)
   - LLM Triage rationale structure is **unchanged** (RAG is not in the prompt)
   - Webhook completion time stays in the existing 37–90s envelope

If Stage 2 reveals quality issues, flip `RAG_LOOKUP_ENABLED=false` — no redeploy needed. Phase 1/2/3 behaviour returns instantly.

---

## 6. Test plan for the team

After Stage 2 cutover:

| # | Scenario | Setup | Expected result |
|---|---|---|---|
| 1 | RAG off (Stage 1 baseline) | `RAG_LOOKUP_ENABLED=false`; create any test ticket | No Customer Context section. Webhook log: `RAG lookup disabled by env`. |
| 2 | RAG on, content match | Seed `HRT-HVT/srv-FILE-01.md` saying "srv-FILE-01 is HVT for ACME". Create ticket with summary "Unusual access to srv-FILE-01" | Comment shows Customer Context with the HRT-HVT chunk. Similarity > 0.5. |
| 3 | RAG on, no content match | Create ticket about a host/IOC not in any seeded doc | No Customer Context section (all retrieved chunks scored below threshold). Webhook log: `RAG retrieval: 0 chunks above threshold`. |
| 4 | RAG retrieval failure | Temporarily corrupt the Chroma DB or kill the embedding service | Pipeline continues normally. Comment has no Customer Context. Logs show the failure. **Verify enrich + label + Jira comment all still happen.** |
| 5 | Killswitch flip | While running, set `RAG_LOOKUP_ENABLED=false` and create a ticket | No Customer Context. Phase 1/2/3 comment unchanged. |
| 6 | LLM Triage rationale check | Several tickets with and without RAG matches | Compare LLM Triage rationale text. There should be **no structural difference** because RAG content does not enter the LLM prompt. |
| 7 | Re-ingest after content change | Add a new markdown file. Trigger re-ingest. Create a relevant ticket | New chunk appears in Customer Context retrieval. Old chunks unaffected. |
| 8 | Performance | Time 10 webhooks end-to-end | Same envelope as Phase 3 (37–90s typical). RAG adds <5s. |

Phase 4 is **signed off** when scenarios 1–6 pass.

### Where to look in logs

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| where Log_s contains "RAG"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
```

Look for:
- `RAG lookup disabled by env` — killswitch off, expected when not yet flipped
- `RAG retrieval: N chunks above threshold (top score X.XX)` — success path
- `RAG retrieval: 0 chunks above threshold` — content didn't match, comment skipped
- `RAG retrieval failed (<class>): <message>` — silent failure path; pipeline still continued
- `RAG ingest: N chunks from M files` — successful re-ingest

---

## 7. Rollback

If Phase 4 misbehaves in any way:

```bash
# Instant config-only revert (no redeploy needed):
az containerapp update --name soc-platform --resource-group rg-soc-platform \
  --set-env-vars RAG_LOOKUP_ENABLED=false
```

This kills Phase 4 immediately. Phase 1/2/3 behaviour returns; nothing else changes.

Full code rollback (only if the deploy itself broke something):

```bash
az containerapp update \
  --name soc-platform --resource-group rg-soc-platform \
  --image socplatformreg.azurecr.io/soc-platform:pre-phase-4-2026-06-13 \
  --revision-suffix "rollback-$(date +%s)"
```

---

## 8. SMB caveat (important)

`RAG_CHROMA_DIR` MUST point to a local-FS path (default `/tmp/rag`), NOT the Azure Files SMB mount at `/app/data/rag`. Chroma uses SQLite, and SQLite over SMB hangs indefinitely on the file locks. The cluster DB (`tools/db.py`) defaults `DB_PATH=/tmp/soc_platform.db` for the same reason.

**Trade-off:** `/tmp/` is ephemeral, so ingested chunks are lost on container restart (deploys, scaling, manual restarts). Re-ingest is one click on `/admin/rag` (local folder) plus one "Sync now" on the Confluence card. For Phase 4 MVP this is acceptable; a longer-term Phase 4c would move to a managed vector store (Azure AI Search / pgvector).

Symptom if `RAG_CHROMA_DIR` ever gets pointed back at `/app/data/...`: `/admin/rag` hangs forever on page load (witnessed 2026-06-15 during initial deploy). Logs show a startup warning `RAG_CHROMA_DIR=... is on the Azure Files SMB mount` — heed that warning.

## 9. What's NOT in Phase 4

- Live Confluence sync (manual local-folder ingest for MVP)
- LLM Triage prompt integration (Phase 4b — only after retrieval quality is proven and the team explicitly opts in)
- Per-customer scoping of retrieval
- Scheduled / event-driven re-ingest (manual trigger via admin route)
- Hybrid lexical + vector retrieval

See the [roadmap](L1-TRIAGE-REDESIGN-ROADMAP.md) for Phase 5+.
