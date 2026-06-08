# L1 Triage — IOC Enrichment Pipeline

> **See also:** [L1-TRIAGE-REDESIGN-ROADMAP.md](L1-TRIAGE-REDESIGN-ROADMAP.md) — phased plan for evolving this pipeline into a full AI Agent for L1 (MITRE mapping, RAG over Confluence, AI-driven KQL, recommendation synthesis, finetuning loop). This doc describes the **current** implementation; the roadmap describes where it's going.

Backend documentation for the automated Jira ticket enrichment flow ("L1 Triage").

## Purpose

When a Jira Service Desk Incident is created (typically by Sentinel/Splunk via the soc-ticket-gateway), this pipeline:

1. Re-fetches the ticket from Jira after a short delay (to allow Service Desk form merging)
2. Extracts IOCs from structured Sentinel-style entity custom fields, plus a regex fallback over the description
3. Checks each IOC's reputation against SOCRadar, VirusTotal, and AbuseIPDB
4. Posts an enrichment summary as a Jira comment
5. Optionally labels and reassigns the ticket based on the verdict

The goal is to do the rote first-line work (IOC lookups, threat intel cross-reference) automatically so the human L1 analyst gets a pre-enriched ticket.

## End-to-End Flow

```
Sentinel/Splunk alert
        │
        ▼
soc-ticket-gateway (Azure Function) ── creates Jira ticket with entity fields
        │
        ▼
Jira  Issue Created event
        │
        ▼
POST /webhook/jira?secret=<JIRA_WEBHOOK_SECRET>      ◄── webhook.py
        │ (webhook returns 200 immediately)
        ▼
Background thread:
  ├─ poll loop (every WEBHOOK_FETCH_DELAY_SECONDS, default 5s):
  │    ├─ jira_client.fetch_issue_by_key(ticket_key)
  │    └─ break early if has_entity_data(fields) is True
  ├─ hard timeout at WEBHOOK_FETCH_MAX_WAIT_SECONDS (default 60s)
  │    (pipeline still runs on timeout — produces "No IOCs" comment)
  ├─ stabilization sleep WEBHOOK_FETCH_STABILIZATION_SECONDS (default 30s)
  │    after first entity detected — lets later waves of fields land
  ├─ final fetch (post-stabilization snapshot)
  ├─ dedup check (catches Sentinel Logic App duplicates)
  │
  ├─ [Phase 1] _run_triage_foundation():
  │    ├─ severity sync: read customfield_10038 → set Jira priority
  │    ├─ GSOC auto-assign: if JIRA_GSOC_ACCOUNT_ID set
  │    └─ LLM Triage priority override (tools/triage.py):
  │         confidence ≥ 0.7 AND recommendation ≠ baseline → set new priority
  │
  └─ enrichment.enrich_ticket(ticket_key, fields)
        │
        ▼
1. extract_iocs_from_entity_fields(fields)       # primary: typed entity fields
2. extract_iocs(summary + description)           # fallback: regex over text
3. dedupe by value
        │
        ▼
For each IOC:
  ├─ socradar_rest.check_ioc()    ── score 0..100
  ├─ virustotal_client.check_ioc() ── malicious_count / total_engines
  └─ abuseipdb_client.check_ip()   ── confidence_score (IPs only)
        │
        ▼
determine_verdict(): malicious | clean | unknown
        │
        ▼
post_jira_comment(ticket_key, summary)                # always runs
add_jira_label(ticket_key, "True-Positive")           # if malicious
add_jira_label(ticket_key, "False-Positive")          # if clean
add_jira_label(ticket_key, "Unknown")                 # if unknown
assign_jira_ticket(ticket_key, JIRA_L1_ACCOUNT_ID)    # if malicious AND L1 set
assign_jira_ticket(ticket_key, JIRA_L2_ACCOUNT_ID)    # if clean/unknown AND L2 set
```

## File Map

| File | Purpose |
|---|---|
| [routes/webhook.py](../routes/webhook.py) | HTTP entry point. Validates secret, queues background job. Hosts `_run_triage_foundation()` (Phase 1: severity sync, GSOC assign, LLM Triage). |
| [tools/enrichment.py](../tools/enrichment.py) | IOC extraction + reputation + comment/label/assign logic. `set_priority()` and `remove_jira_label()` helpers live here too. |
| [tools/triage.py](../tools/triage.py) | LLM Triage call (Phase 1). Returns `{recommended_priority, rationale, confidence}` for the webhook to act on. |
| [tools/jira_client.py](../tools/jira_client.py) | `fetch_issue_by_key()`, `_extract_adf_text()`, `severity_to_priority()` (Phase 1 mapping), Basic Auth headers. |
| [tools/socradar_rest.py](../tools/socradar_rest.py) | SOCRadar REST API client. Reads `SOCRADAR_THREAT_ANALYSIS_KEY` via `tools/secrets.get_secret()`. |
| [tools/virustotal_client.py](../tools/virustotal_client.py) | VirusTotal v3 client. Reads `VT_API_KEY` via `get_secret()`. |
| [tools/abuseipdb_client.py](../tools/abuseipdb_client.py) | AbuseIPDB client (IPs only). Reads `ABUSEIPDB_API_KEY` via `get_secret()`. |

## Configuration

All env vars required for the pipeline. Production values live in the `soc-platform` Container App env (and Key Vault for secrets). See [`.env.example`](../.env.example) for full annotations.

### Webhook + auth

| Variable | Purpose |
|---|---|
| `JIRA_URL` | Base Jira URL, e.g. `https://logicalisasia.atlassian.net/` |
| `JIRA_EMAIL` | Service account email for Basic Auth |
| `JIRA_API_TOKEN` | Service account API token (in KV as `jira-api-token`) |
| `JIRA_WEBHOOK_SECRET` | Token in the webhook URL `?secret=...`; rejects requests on mismatch |
| `JIRA_ENRICHMENT_PROJECT` | Comma-separated allowlist of project keys (e.g. `SCDM,LOGICALIS`). Blank = all. |

### Triage routing (currently unset by design)

| Variable | Purpose |
|---|---|
| `JIRA_L1_ACCOUNT_ID` | Jira account ID assigned when verdict is malicious. Empty = comment-only, no assignment. |
| `JIRA_L2_ACCOUNT_ID` | Jira account ID assigned when verdict is clean. Empty = comment-only, no assignment. |

When empty, [`enrich_ticket()`](../tools/enrichment.py) logs a warning and skips assignment. The comment still posts. This is intentional during the rollout phase — every analyst should see the ticket while routing is being validated.

### Reputation API keys

| Variable | KV secret name | Purpose |
|---|---|---|
| `SOCRADAR_API_KEY` | (bypasses KV — see Known Issues) | SOCRadar threat intel score |
| `VT_API_KEY` | `vt-api-key` | VirusTotal detection counts |
| `ABUSEIPDB_API_KEY` | `abuseipdb-api-key` | AbuseIPDB IP confidence |
| `MALICIOUS_SCORE_THRESHOLD` | (env) | SOCRadar score >= this → contributes to malicious verdict (default 70) |

### Async fetch + Sentinel field IDs

| Variable | Default | Purpose |
|---|---|---|
| `WEBHOOK_FETCH_DELAY_SECONDS` | `5` | Interval between Jira API polls in the background thread. |
| `WEBHOOK_FETCH_MAX_WAIT_SECONDS` | `60` | Polling timeout. If no entity field appears within this window, the pipeline runs anyway (typically posts a "No IOCs" comment). |
| `WEBHOOK_FETCH_STABILIZATION_SECONDS` | `30` | Once any entity field is detected, sleep this long before the final fetch. Service Desk merges fields in waves; SCDM-43 showed Host/Hash arriving ~30s after IP. Set to 0 to disable. |
| `JIRA_FIELD_IP_ENTITIES` | `customfield_10079` | IP Address Entities (ADF doc) |
| `JIRA_FIELD_HOST_ENTITIES` | `customfield_10078` | Host Entities (ADF doc) |
| `JIRA_FIELD_DNS_ENTITIES` | `customfield_10080` | DNS Entities (ADF doc) |
| `JIRA_FIELD_URL_ENTITIES` | `customfield_10081` | URL Entities (ADF doc) — host extracted via urlparse |
| `JIRA_FIELD_HASH_ENTITIES` | `customfield_10082` | FileHash Entities (ADF doc) — md5/sha1/sha256 detected by length |

**Why polling instead of a fixed delay?** Service Desk request forms merge entity fields asynchronously after `issue_created` fires. In SCDM-42 (2026-05-05) this took ~37 seconds. Tickets created programmatically (e.g. by `soc-ticket-gateway` via the REST API) populate fields atomically and trigger after the first poll (~5s). Polling adapts to both flows without locking everyone into the worst-case delay.

## IOC Extraction — Two Sources

### Primary: structured entity fields

Each Sentinel entity type maps to a typed Jira custom field. The pipeline reads each, flattens the ADF, splits on whitespace/comma/semicolon, and produces typed IOCs without any regex guessing. This is the canonical source — no false-positive risk because the field name guarantees the type.

Allowlists still apply (private IPs, Microsoft/Atlassian/etc. domains).

### Fallback: regex over description + summary

Free-text mentions (analyst-pasted IOCs, narrative descriptions) are caught by the same regex extractor used before the structured-field path was added. Results are deduped against the entity-field results by value.

This belt-and-suspenders behaviour exists so that:
- Tickets created manually (no Sentinel entity fields) still get triaged
- Analysts who paste an IOC into the description as context get it picked up too

## Verdict Logic

Per IOC:
- **malicious** if SOCRadar score >= threshold (default 70), or VT detections > 0, or AbuseIPDB confidence > 50
- **clean** if at least one source returned data and none flagged malicious
- **unknown** if all three sources returned None (misconfigured or no data)

Per ticket (aggregated across all IOCs):
- **malicious** if any IOC malicious
- **unknown** if all IOCs unknown
- **clean** otherwise

## Verifying the Pipeline Works

### From a new test ticket

1. Create a new issue in a project listed in `JIRA_ENRICHMENT_PROJECT` (e.g. SCDM)
2. Populate at least one entity field (Host Entities, IP Address Entities, etc.)
3. Wait ~10 seconds (5s delay + ~2-5s for reputation lookups + comment post)
4. The ticket should have a new comment titled `=== IOC Enrichment Report (Automated) ===`

### From the live logs

```bash
az containerapp logs show \
  --name soc-platform \
  --resource-group rg-soc-platform \
  --tail 200 --format text \
  | grep -iE "webhook|enrich|jira|<TICKET-KEY>|ioc"
```

Look for:
```
routes.webhook: queued enrichment job <uuid> for ticket <KEY>
tools.enrichment: extract_iocs_from_entity_fields: found N IOCs
tools.enrichment: extract_iocs: found M IOCs
tools.enrichment: enrich_ticket(<KEY>): X IOCs total (entity=N, regex-fallback=M-overlap)
tools.enrichment: Posted enrichment comment to <KEY>
routes.webhook: Enrichment <uuid> complete: ticket=<KEY> verdict=<verdict>
```

### From the Jira API

```bash
source .env
AUTH=$(printf "%s:%s" "$JIRA_EMAIL" "$JIRA_API_TOKEN" | base64)
curl -s -H "Authorization: Basic $AUTH" \
  "${JIRA_URL}/rest/api/3/issue/<KEY>?fields=labels,assignee,comment" \
  | python3 -m json.tool
```

Expect `comment.comments[]` to contain at least one comment from the service account starting with `=== IOC Enrichment Report (Automated) ===`.

## Known Issues / Tech Debt

1. **VT secret name is `VT_API_KEY` not `VIRUSTOTAL_API_KEY`.** Maps to KV secret `vt-api-key` via kebab-case translation in `tools/secrets.py`. Works fine, just inconsistent with vendor naming. Not worth changing.

2. **No retry on Jira API failures.** If `post_jira_comment()` or `assign_jira_ticket()` fails (transient 5xx, rate limit), the job is marked error and there is no automatic retry. Manual intervention required.

3. **In-memory job store.** `_jobs` dict in `routes/webhook.py` is process-local. Surviving across deploys requires durable storage (out of scope today since `min_replicas = max_replicas = 1`).

4. **L1/L2 routing intentionally disabled.** `JIRA_L1_ACCOUNT_ID` and `JIRA_L2_ACCOUNT_ID` are deliberately empty during rollout — every analyst sees every ticket. Set these once routing is finalised.

## Local Development

To trigger the pipeline locally without a real Jira webhook:

```bash
# Run the app
PORT=5060 .venv/bin/python3 app.py

# In another terminal, simulate the webhook
curl -X POST "http://localhost:5060/webhook/jira?secret=$JIRA_WEBHOOK_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
        "webhookEvent": "jira:issue_created",
        "issue": {"key": "SCDM-41"}
      }'
```

The handler will fetch SCDM-41 via the Jira API (using the configured creds) and run the full pipeline against the live ticket. **Caution:** this WILL post a comment to the real ticket if creds are valid.

## History

- 2026-04-28: Initial pipeline added (`2a52df0`). Description-only regex extraction.
- 2026-05-01: Webhook activated in production (`3d2936d`). Added VT/AbuseIPDB KV secrets.
- 2026-05-05: Refactored to read structured entity fields + delayed API re-fetch. Added this doc.
- 2026-05-05 (later): Replaced fixed 5s delay with adaptive poll-until-populated loop (5s interval, 60s max). SCDM-42 testing showed Service Desk forms can take 37s to merge entity fields.
- 2026-05-05 (later still): Added 30s stabilization sleep after first entity detected. SCDM-43 testing revealed Service Desk merges fields in waves — IP arrived first, Host/Hash arrived ~30s later. Without stabilization, only the first wave of IOCs was triaged.
