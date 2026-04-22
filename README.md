# soc-platform (scaffold)

Merged SOC Report + Investigation app. Combines:
- **SOC-Report** — scheduled reports, charts, PDF/DOCX/XLSX/PPTX, multi-customer, APScheduler, SQLite history
- **SOCRadar AI Analyst** — streaming LLM investigation, SOCRadar MCP + OAuth, Tavily web search, Entra ID

## What's in this scaffold

The files that are load-bearing for the merge (auth, entrypoint, blueprints wiring, the multi-user OAuth fix, Key Vault abstraction) are written in full. The files that are copy-paste from SOC-Report (report generation logic, export formatters) are stubs with explicit port-from instructions.

| Written in full | Stub with port instructions | Copy as-is from sources |
|---|---|---|
| `app.py` | `routes/reports.py` | `export/*.py` (from SOC-Report) |
| `routes/auth.py` | `routes/admin.py` | `tools/jira_client.py`, `tools/splunk_client.py`, `tools/sentinel_client.py`, `tools/socradar_rest.py`, `tools/chart_generator.py`, `tools/scheduler.py`, `tools/db.py` (from SOC-Report) |
| `routes/investigate.py` | | `templates/reports.html`, `templates/customers.html`, `templates/history.html`, `templates/schedules.html` (from SOC-Report, strip `<html>` / header) |
| `routes/exports.py` | | `templates/investigate.html` (from SOCRadar AI Analyst, strip `<html>` / header) |
| `tools/secrets.py` | | |
| `tools/socradar_mcp.py` | | |
| `tools/tavily_client.py` | | |
| `templates/base.html` | | |

See `../soc_platform_repo_layout.md` (one level up from this scaffold) for the full file-by-file migration map.

## Local dev

```bash
cp .env.example .env
# fill in values — at minimum ENTRA_* and OPENAI_API_KEY
docker compose up --build
# visit http://localhost:5060
```

## Deployment

See `../soc_workflow_setup_guide.md` Phase 6 for Azure Container Apps deployment.

## What to port next (in order)

1. Copy `tools/*.py` from the SOC-Report repo (jira, splunk, sentinel, socradar_rest, chart_generator, scheduler, db). Swap every `os.environ.get(SECRET)` call for `secrets.get_secret(SECRET)`.
2. Copy `export/*.py` from SOC-Report — no changes needed.
3. Flesh out `routes/reports.py` and `routes/admin.py` per the inline comments.
4. Copy the HTML templates, strip their `<html>` / `<head>` / header, wrap each in `{% extends "base.html" %}{% block content %}...{% endblock %}`.
5. Run locally, verify login → both modes → export end-to-end.
6. Deploy per Phase 6.
