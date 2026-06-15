# L1 Triage AI Redesign — Phase 4b: Confluence as a RAG source

**Status:** Implementation in progress (2026-06-15)
**Predecessor:** [Phase 4 MVP](L1-REDESIGN-PHASE-4-rag-confluence.md) (local-folder ingest, shipped 2026-06-13)
**Roadmap:** [L1-TRIAGE-REDESIGN-ROADMAP.md](L1-TRIAGE-REDESIGN-ROADMAP.md)
**Current implementation:** [L1-TRIAGE.md](L1-TRIAGE.md)
**Rollback checkpoint:** `pre-phase-4b-2026-06-15`

---

## 1. What this phase delivers

Phase 4 MVP added a Chroma vector store and a local-folder ingest (markdown files dropped under `/app/data/rag_docs/`). Phase 4b adds **Confluence** as a second source type so the team can curate knowledge from the wiki without dropping files on the share.

You designate Confluence pages by **pasting individual URLs** in the existing `/admin/rag` UI. Each entry shows last-sync state and a single **"Sync now"** button refreshes every configured page.

What appears in the Jira enrichment comment after Phase 4b is on:

```
Customer Context:
  ► [Confluence:SOC] srv-FILE-01 is a High-Value Target for Customer ACME — 0.82
  ► [HRT-HVT] (local-folder entry, still works) — 0.78
```

Source tag distinguishes Confluence pages from local-folder docs.

## 2. What this phase does NOT change

- **The hot retrieval path is unchanged.** `tools/rag_retrieval.py`, the 5-second timeout, the killswitch (`RAG_LOOKUP_ENABLED`), and the "comment-only, never LLM prompt" rule from the Phase 4 MVP — all preserved.
- **Local-folder ingest still works.** Markdown files under `/app/data/rag_docs/` keep being indexed as before. Confluence and local sources coexist in the same Chroma collection, distinguished only by the `source` metadata tag.
- **No new credentials to provision.** Confluence Cloud lives on the same Atlassian site as Jira (`logicalisasia.atlassian.net/wiki`) and accepts the same Basic Auth tokens.

## 3. How it works

```
You paste a Confluence URL like:
  https://logicalisasia.atlassian.net/wiki/spaces/SOC/pages/12345678/HRT-HVT-Master-List
                                                          ^^^^^^^^^
                                                          page id

POST /admin/api/rag/confluence/pages  {url: "..."}
  ├── extract page id via regex /pages/(\d+)
  ├── GET /wiki/api/v2/pages/12345678?body-format=storage
  ├── persist entry to data/rag_confluence_pages.json (atomic write)
  └── return {url, page_id, title, space_key, last_synced_at=null, chunk_count=0}

POST /admin/api/rag/confluence/sync  (Sync now button)
  for each configured page:
    ├── GET page body from Confluence
    ├── BeautifulSoup strip XHTML → plain text
    ├── chunk_text() — same 500-char paragraph chunking as local-folder ingest
    ├── embed_texts() — Azure OpenAI text-embedding-3-small
    ├── delete_by_file("confluence:<page_id>")     # idempotent re-sync
    ├── upsert_chunks(items)                       # source="Confluence:<SPACE>"
    └── update last_synced_at + chunk_count on the entry
```

Per-page failures are isolated: a single page returning 401/404/5xx is logged into that entry's `last_error`; other pages still sync. The whole-sync endpoint never raises.

## 4. New environment variables (all optional)

```bash
CONFLUENCE_BASE_URL=     # blank → derived as "{JIRA_URL}/wiki"
CONFLUENCE_EMAIL=        # blank → falls back to JIRA_EMAIL
CONFLUENCE_API_TOKEN=    # blank → falls back to JIRA_API_TOKEN (via get_secret)
```

The common case (Confluence on the same site as Jira) requires zero config changes.

## 5. Persisted state

`data/rag_confluence_pages.json` on the Azure Files share:

```json
[
  {
    "url": "https://logicalisasia.atlassian.net/wiki/spaces/SOC/pages/12345678/HRT-HVT-Master-List",
    "page_id": "12345678",
    "title": "HRT/HVT Master List",
    "space_key": "SOC",
    "last_synced_at": "2026-06-15T03:14:00+00:00",
    "chunk_count": 8,
    "last_error": null
  }
]
```

## 6. Test plan for the team

| # | Scenario | Setup | Expected result |
|---|---|---|---|
| 1 | Add a page | Open `/admin/rag` → paste a Confluence page URL → click "Add page" | Entry appears in the Confluence table with title fetched from Confluence. Chunks=0. |
| 2 | Initial sync | Click "Sync now" | Each entry shows `last_synced_at` (SGT) + `chunk_count > 0`. Logs show one fetch + embed per page. |
| 3 | Retrieval cutover (RAG on) | Set `RAG_LOOKUP_ENABLED=true`. Create a Jira ticket whose summary mentions content from the synced page. | Customer Context section in the comment shows the Confluence chunk with `[Confluence:<SPACE>]` tag. |
| 4 | Page edit + re-sync | Edit the Confluence page; click "Sync now" again | Old chunks replaced; new content retrievable; chunk count may shift. |
| 5 | Remove a page | Click "Remove" on an entry | Entry gone + chunks deleted from Chroma + subsequent retrievals don't surface them. |
| 6 | Bad URL paste | Paste `https://example.com` | UI shows error "could not extract Confluence page id". No entry added. |
| 7 | 401/404 on a page (optional) | Add a URL that Jira creds can't access (or that was deleted) | Page appears in the table with `last_error: "<reason>"`. Other pages still sync OK. |
| 8 | Killswitch interaction (optional) | With pages indexed, flip `RAG_LOOKUP_ENABLED=false`, then create a ticket | No Customer Context section. Phase 1/2/3 behaviour unchanged. Flipping ON brings it back. |

Phase 4b is **signed off** when scenarios 1–6 pass.

### Where to look in logs

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| where Log_s contains "Confluence" or Log_s contains "rag_confluence"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
```

Useful lines:
- `Confluence sync: N pages, M chunks total` — successful run
- `Confluence sync: page <id> failed (<reason>) — continuing` — per-page failure isolated
- `Confluence fetch_page(<id>) HTTP <code>` — raw API response code

## 7. Rollback

Fastest revert (kills the whole RAG path — including Confluence retrieval — without redeploy):

```bash
az containerapp update --name soc-platform --resource-group rg-soc-platform \
  --set-env-vars RAG_LOOKUP_ENABLED=false
```

The Confluence admin UI stays accessible (admin-only) so the team can fix configuration without flipping retrieval back on.

Full code revert:
```bash
az containerapp update --name soc-platform --resource-group rg-soc-platform \
  --image socplatformreg.azurecr.io/soc-platform:pre-phase-4b-2026-06-15 \
  --revision-suffix "rollback-$(date +%s)"
```

## 8. What's NOT in Phase 4b

- Scheduled sync via APScheduler — manual button only for MVP
- Space-level or label-based bulk selection
- Image / attachment extraction
- Confluence webhook → push-driven re-sync
- LLM Triage prompt integration (still Phase 4c onwards)
