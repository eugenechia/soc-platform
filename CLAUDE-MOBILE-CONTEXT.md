# SOC-System — Claude Mobile Context Brief

## What this project is

A merged Flask web app called **soc-platform** that combines two existing tools:
- **SOC-Report**: scheduled report generation (Jira + Splunk + Sentinel data, charts, PDF/DOCX/XLSX/PPTX export, multi-customer, APScheduler, SQLite history, SMTP delivery)
- **SOCRadar AI Analyst**: interactive LLM investigation (streaming queries, SOCRadar MCP + OAuth PKCE, Tavily web search, Entra ID SSO)

Goal: one Flask deployable, two modes ("Generate Report" / "Investigate"), shared Entra ID auth, deployed to Azure Container Apps.

There is also a **soc-ticket-gateway**: a **Flask container** (Python) that receives normalized alerts from Splunk and Sentinel, deduplicates them by `siem:rule_id|primary_entity` SHA-256 key, and creates/updates Jira tickets. This is a separate deployable.

**Canonical source: `Office/Cisco-OCP/soc-ticket-gateway/`** — same image deploys to both Cisco OCP and Azure Container Apps. The previous Azure Functions implementation was archived on 2026-05-05 (see `_archive-soc-ticket-gateway-azure-functions/ARCHIVED.md`).

---

## Project location (on Mac)

```
/Work/Office/SOC-System/
├── soc-platform/                                       ← main Flask app
├── _archive-soc-ticket-gateway-azure-functions/        ← old Functions impl (NOT used)
├── soc_platform_repo_layout.md                         ← detailed file-by-file migration map
├── soc_workflow_setup_guide.md                         ← full architecture + phase guide
└── soc-system-context.zip                              ← all source files zipped

/Work/Office/Cisco-OCP/
└── soc-ticket-gateway/    ← canonical Flask container (deploys to both OCP AND Azure)
```

---

## soc-platform current state

The scaffold is largely **complete** — most files are written, not stubs. Key things already done:

| File | Status |
|---|---|
| `app.py` | Done — thin entrypoint, blueprint registration, auth hook |
| `routes/auth.py` | Done — Entra ID MSAL flow |
| `routes/investigate.py` | Done — streaming LLM, SOCRadar MCP, OAuth PKCE, Tavily |
| `routes/reports.py` | Done (ported from SOC-Report) |
| `routes/admin.py` | Done — customer/schedule/history CRUD APIs |
| `routes/exports.py` | Done — PDF/DOCX/XLSX/PPTX download |
| `routes/webhook.py` | Done — inbound webhook receiver |
| `tools/secrets.py` | Done — env/.env local, Key Vault in Azure |
| `tools/socradar_mcp.py` | Done — MCP client, OAuth session-backed |
| `tools/tavily_client.py` | Done |
| `tools/jira_client.py` | Done |
| `tools/splunk_client.py` | Done |
| `tools/sentinel_client.py` | Done |
| `tools/db.py` | Done — SQLite for reports/schedules |
| `tools/scheduler.py` | Done — APScheduler + SMTP |
| `tools/chart_generator.py` | Done — matplotlib charts |
| `tools/enrichment.py` | Done — VT / AbuseIPDB |
| `export/*.py` | Done — pdf, docx, xlsx, pptx |
| `templates/*.html` | Done — base.html + all page templates |
| `Dockerfile` | Done — gunicorn --workers 1 --threads 4, port 5060 |
| `docker-compose.yml` | Done |
| `requirements.txt` | Done |

---

## Architecture

```
Browser → Entra ID SSO → Flask app (port 5060)
                              ├─ /reports → APScheduler → Jira/Splunk/Sentinel → Charts → Export
                              ├─ /investigate → OpenAI Responses API → SOCRadar MCP / Tavily
                              ├─ /admin → Customer + schedule management
                              ├─ /exports → PDF/DOCX/XLSX/PPTX download
                              └─ /webhook → inbound alert receiver

Azure: Container Apps (min=max=1 replica), Azure Files for /app/data, Key Vault for secrets
```

---

## Key design decisions already made

- **APScheduler requires `--workers 1`** — hardcoded in Dockerfile, WEB_CONCURRENCY env var checked at startup
- **SOCRadar OAuth state in `session["socradar"]`** — not module-level dict (multi-user bug fix)
- **`tools/secrets.py`** is the single abstraction — all credential reads go through `get_secret(name)`, never `os.environ` directly in route/tool code
- **Sentinel uses `DefaultAzureCredential`** in Azure (Managed Identity), falls back to client_credentials for local dev
- **Session cookie**: Secure + HttpOnly + SameSite=Lax (reports contain sensitive SIEM data)
- **No `APP_PASSWORD`** — Entra ID is the only auth path

---

## Live URL

`https://soc-platform.yellowflower-c7c34b87.southeastasia.azurecontainerapps.io/`

## What's NOT done yet (next steps)
   - Resource group `rg-soc-platform`
   - Azure Container Registry
   - Azure Files share (for `/app/data`)
   - Azure Key Vault (with all secrets listed below)
   - Azure OpenAI (GPT-4o deployment)
   - Container Apps Environment
3. **Deploy** — `az acr build` + `az containerapp create` with Managed Identity, Key Vault refs, Azure Files volume
4. **Update Entra ID app registration** with new Container App redirect URI
5. **Smoke test in Azure** — login, sample report, investigate, schedule delivery

---

## Environment variables (local `.env`)

```env
FLASK_SECRET_KEY=<random 32-byte hex>
ENTRA_TENANT_ID=7cf1bf61-082f-40f3-a95a-1333d539fcc4
ENTRA_CLIENT_ID=<soc-platform app registration client ID>
ENTRA_CLIENT_SECRET=<from Entra app registration>
ENTRA_REDIRECT_URI=http://localhost:5060/auth/callback
ENTRA_ALLOWED_GROUP_ID=<security group GUID>
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_DEPLOYMENT=gpt-5.2
AZURE_OPENAI_API_VERSION=2024-10-21
JIRA_URL=
JIRA_EMAIL=
JIRA_API_TOKEN=
USE_SAMPLE_DATA=false
SPLUNK_HOST=
SPLUNK_TOKEN=
SENTINEL_WORKSPACE_ID=
SOCRADAR_API_KEY=
SOCRADAR_COMPANY_ID=
SOCRADAR_MCP_URL=https://mcp.socradar.com
TAVILY_API_KEY=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
PORT=5060
WEB_CONCURRENCY=1
```

---

## soc-ticket-gateway (Flask container)

Separate deployable, lives at `Office/Cisco-OCP/soc-ticket-gateway/`. Implements:
- HTTP service (Flask + gunicorn, port 8080, `/api/ingest` and `/api/health`)
- Normalized alert payload ingestion from Splunk + Sentinel
- Dedup by SHA-256 of `siem:rule_id|primary_entity`
- Jira ticket create (new) or append comment + increment occurrence count (duplicate)
- `gateway/secrets.py` resolves env first, then optional Azure Key Vault — same image works in both Azure Container Apps (KV-backed) and Cisco OCP (env-only)

Status: scaffold complete with tests. **Not yet deployed to Azure Container Apps or OCP** — but the previous Azure Functions deployment was retired in favour of this container on 2026-05-05.

---

## Existing related projects (for context)

- **SOCRadar** (deployed): `Office/SOCRadar/` — the standalone SOCRadar AI Analyst app (the source being merged in)
  - Live at: `https://socradarv2.salmonsky-993de2d6.southeastasia.azurecontainerapps.io`
  - ACR: `socradarregistry`, container app: `socradarv2`, resource group: `rg-eugene-socradar`

---

## Notes for Claude mobile

The full codebase zip is at `SOC-System/soc-system-context.zip` (139KB, all source files). You can attach individual files from it if you need to look at specific code. Key files to attach if you want to discuss implementation:

- `soc-platform/app.py` — entrypoint
- `soc-platform/routes/investigate.py` — LLM investigation mode
- `soc-platform/routes/reports.py` — report generation
- `soc-platform/tools/secrets.py` — Key Vault abstraction
- `soc_platform_repo_layout.md` — complete file map
- `soc_workflow_setup_guide.md` — full architecture guide
