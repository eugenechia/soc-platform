# L1 Triage — Customer Onboarding Runbook

How to onboard a new customer's Jira project to L1 Triage on the shared
soc-platform instance so it works as smoothly as SCDM. Follow every step; the
**validate** step is the go-live gate.

## Why this exists
Entity field IDs, the severity field, and the severity scheme differ per customer
Jira project. If the mapping is wrong, triage fails **silently** (0 IOCs, no
priority, everything "Unknown"). This runbook + the discover/validate endpoints
make each onboarding correct and verified before real tickets flow.

## Prerequisites
- The customer's Jira project key (e.g. `ACME`).
- One representative **sample ticket** in that project that already has entities
  populated (IPs/hashes/domains) — used for schema discovery + validation.
- Admin access to soc-platform (`/admin/customers`).

## Steps

### 1. Create the customer record
`/admin/customers` → **+ New Customer**. Set name, short name, and the Jira
project key. Add Sentinel workspace + Confluence pages if the customer has them
(optional — triage runs without them, just with less context).

### 2. Discover the Jira schema
The customer's field IDs are almost certainly NOT SCDM's. Discover them from the
sample ticket:

```
POST /admin/api/customers/<cid>/discover-schema?ticket=<SAMPLE-KEY>
```
Returns `current` (what's configured now — defaults to SCDM) and `discovery`
(suggested `entity_fields`, `severity_field`, `siem_source`, with per-field
evidence). Review the suggestion.

### 3. Save the schema override
Add the confirmed mapping to the customer's `jira_projects[]` entry under
`schema` (customer Edit modal / `customers.json`). Only include what differs from
SCDM — omitted keys fall back to the global defaults:

```json
"schema": {
  "siem_source": "crowdstrike",
  "entity_fields": {"ip":"customfield_XXXXX","host":"customfield_XXXXX",
                    "dns":"customfield_XXXXX","url":"customfield_XXXXX",
                    "hash":"customfield_XXXXX"},
  "severity_field": "customfield_XXXXX",
  "severity_map": {"p1":"Highest","p2":"High","p3":"Medium","p4":"Low"}
}
```

### 4. Validate (dry-run) — GO-LIVE GATE
Confirm the mapping actually parses the sample ticket, WITHOUT posting a comment
or touching the ticket:

```
POST /admin/api/customers/<cid>/validate?ticket=<SAMPLE-KEY>
```
Check the response:
- `ioc_count` > 0 and `iocs` are the real indicators (not JSON fragments).
- `severity.value` is read and `mapped_priority` is correct.
- `schema_mismatch` is `null`.

If `schema_mismatch` is non-null or `ioc_count` is 0 with entities present, the
mapping is still wrong → back to step 2. **Do not proceed until this is clean.**

### 5. Enable processing (allowlist)
Add the project key to `JIRA_ENRICHMENT_PROJECT` on soc-platform (comma-separated)
and roll a revision:
```
az containerapp update -n soc-platform -g rg-soc-platform \
  --set-env-vars "JIRA_ENRICHMENT_PROJECT=SCDM,LOGICALIS,<NEWKEY>"
```
Note: the allowlist is **fail-closed** — a project not listed here is never
processed.

### 6. Register the Jira webhook
In the customer's Jira: System → Webhooks → Create. URL:
`https://<soc-platform-fqdn>/webhook/jira?secret=<JIRA_WEBHOOK_SECRET>`, event
`Issue Created`. (One shared endpoint; the allowlist scopes what's processed.)

### 7. Post-go-live check
After the first real ticket, confirm the enrichment comment posted correctly. If
anything looks off, `triage_health()` surfaces `schema_mismatches` per project —
watch it for the "N consecutive tickets with 0 IOCs" tell of a bad mapping.

## Ongoing monitoring
`schema_mismatches` in the triage-health snapshot flags any project whose tickets
carry a public IP or file hash but yield 0 IOCs — the signature of a broken field
mapping. Investigate promptly; re-run discover/validate on a fresh ticket.
