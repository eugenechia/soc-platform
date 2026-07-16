# Duplicate SOC-Platform into a New Azure Subscription

How to stand up a **second, independent** SOC-Platform instance in another Azure
subscription. This is a **fresh-environment** build: same code and configuration,
**no production data carried over** (empty customers, empty database, fresh
secrets). The new instance is fully self-contained and isolated from the live one.

Pairs with [INFRASTRUCTURE.md](INFRASTRUCTURE.md) (what each resource is) and
[DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) (restore procedures). Read the
"Decisions to lock first" section before running any command.

---

## What "duplicate" means here

The live instance is one Flask container on Azure Container Apps backed by seven
resources in `rg-soc-platform` plus a handful of external dependencies. Duplicating
it = recreating that whole stack under new (globally-unique) names in the target
subscription, then re-supplying secrets and pointing it at the integrations you
choose.

| Live resource (`rg-soc-platform`) | Type | Action in the duplicate |
|---|---|---|
| `soc-platform` | Container App | recreate |
| `soc-platform-env` | ACA managed environment | recreate |
| `socplatformreg` | Container Registry | **new name**, build/push the image |
| `kv-socplatform` | Key Vault | **new name**, re-enter all secrets |
| `socdataplatform` → share `soc-platform-data` | Storage + Azure Files | **new name**, empty share |
| `pg-soc-platform` (db `socplatform`) | Postgres Flexible Server | **new name**, empty DB (app builds schema) |
| `workspace-rgsocplatformfbrm` | Log Analytics | recreate (empty) |

External dependencies (not owned in the RG):
- **Azure OpenAI** (`lsg-soc-foundry`) — embeddings + chat. See Decision B.
- **Entra ID app registration** — SSO for `/admin/*`. See Decision A.
- **External SaaS** — Jira, SOCRadar, VirusTotal, AbuseIPDB, Tavily, Splunk,
  Defender, Sentinel, Confluence. See Decision C.

> **Names that must be globally unique** (pick new ones): the ACR, the Key Vault,
> the storage account, and the Postgres server. The container-app FQDN is
> auto-generated, so it's unique automatically.

---

## Decisions to lock first

These three were left open. Each maps to a specific step below — decide before you
reach it.

### Decision A — Tenant (Step 8: Entra SSO)
Is the target subscription in the **same Entra tenant** (`7cf1bf61…`, LSG) or a
**different tenant**?
- **Same tenant:** reuse the existing Entra app registration or create a second
  one; you only add the new redirect URI. Managed identity, KV access, and ACR
  pull all behave exactly as today.
- **Different tenant:** create a **brand-new app registration** in the target
  tenant, a new allowed-group, and a new client secret. The container's managed
  identity is always local to the resource's subscription/tenant, so identity →
  KV / ACR still works within the target tenant — but any *cross-tenant* reuse of
  `lsg-soc-foundry` (Decision B) needs explicit cross-tenant grants.

### Decision B — Azure OpenAI (Step 7)
The app needs an **embeddings** deployment (`text-embedding-3-large`) and a **chat**
deployment (currently `gpt-5.3-chat`).
- **New Azure OpenAI in the target sub (recommended for true isolation):** request
  Azure OpenAI quota in the target subscription **early — approval can take days**,
  it is the critical-path long-lead item. Then create the resource and re-deploy
  both models.
- **Reuse `lsg-soc-foundry`:** set the new app's `AZURE_OPENAI_ENDPOINT` +
  `azure-openai-api-key` to the existing resource. Fast, but the two environments
  then share one quota and a cross-sub (possibly cross-tenant) dependency.

### Decision C — External integrations & the double-triage trap (Step 10)
For a fresh environment you will typically use **new/separate credentials**. If you
instead reuse the **same Jira**, you must prevent both instances from triaging the
same tickets:
- Only **one** instance's URL may be registered as the Jira webhook for a given
  project, **and**
- `JIRA_ENRICHMENT_PROJECT` allowlists must **not overlap** between the two
  instances (it is fail-closed, so an empty/again non-overlapping list = safe).

There is an explicit checklist at Step 10.

---

## Prerequisites

- Owner (or Contributor + User Access Administrator) on the **target subscription**.
- The soc-platform source checked out locally (this repo) — the `Dockerfile` builds
  the image.
- `az` CLI logged in. If the session expired (24h conditional access on
  kkchia@lsgazure.com): `az login --use-device-code`.
- Decisions A/B/C above at least provisionally made.
- If Decision B = new Azure OpenAI: **submit the quota request now**, before Step 1.

---

## Step 0 — Parameters (edit once, reused by every command)

Pick a short, lowercase, unique `SUFFIX` (e.g. a customer code or `2`). It keeps the
globally-unique names distinct from the live instance.

```bash
# --- target ---
export SUB="<TARGET_SUBSCRIPTION_ID>"
export LOC="southeastasia"                 # match live, or choose per data-residency
export RG="rg-soc-platform-${SUFFIX:=2}"

# --- new globally-unique resource names (no hyphens where the service forbids them) ---
export ACR="socplatformreg${SUFFIX}"       # 5-50 alnum, globally unique
export KV="kv-socplatform-${SUFFIX}"       # 3-24, globally unique
export SA="socdataplatform${SUFFIX}"       # 3-24 lowercase alnum, globally unique
export PG="pg-soc-platform-${SUFFIX}"      # globally unique
export ENVNAME="soc-platform-env-${SUFFIX}"
export APP="soc-platform-${SUFFIX}"
export LAW="workspace-socplatform-${SUFFIX}"
export SHARE="soc-platform-data"
export IMAGE_TAG="dup-$(date +%Y-%m-%d)"

az account set --subscription "$SUB"
az group create -n "$RG" -l "$LOC"
```

Register the resource providers once per subscription (skip any already registered):
```bash
for ns in Microsoft.App Microsoft.ContainerRegistry Microsoft.KeyVault \
          Microsoft.Storage Microsoft.DBforPostgreSQL Microsoft.OperationalInsights \
          Microsoft.CognitiveServices; do az provider register -n $ns; done
```

---

## Step 1 — Container Registry + build the image

```bash
az acr create -n "$ACR" -g "$RG" --sku Basic --admin-enabled false
```

Build the image directly in the new ACR from the local source (cleanest for a fresh
environment — no coupling to the old registry). Run from the repo root:
```bash
az acr build --registry "$ACR" --image soc-platform:$IMAGE_TAG -f Dockerfile .
```

> Alternative (copy the exact live image instead of rebuilding):
> `az acr import -n "$ACR" --source socplatformreg.azurecr.io/soc-platform:onboarding-tooling-2026-07-02 -t soc-platform:$IMAGE_TAG`
> — needs pull creds on the source ACR; harder across tenants. Prefer `acr build`.

---

## Step 2 — Postgres Flexible Server (empty)

The app's `init_db()` runs `CREATE TABLE IF NOT EXISTS` for `reports` and
`schedules` on boot, so the duplicate only needs an **empty database** — no schema
import, no data copy.

```bash
export PGADMIN="socadmin"
export PGPASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-28)"   # save this

az postgres flexible-server create \
  -n "$PG" -g "$RG" -l "$LOC" \
  --tier Burstable --sku-name Standard_B1ms --version 16 \
  --storage-size 32 \
  --admin-user "$PGADMIN" --admin-password "$PGPASS" \
  --public-access 0.0.0.0    # AllowAzureServices; add your admin IP below

az postgres flexible-server db create -g "$RG" --server-name "$PG" --database-name socplatform

# add your current admin IP so you can psql in if needed
MYIP=$(curl -s ifconfig.me)
az postgres flexible-server firewall-rule create -g "$RG" --name "$PG" \
  --rule-name admin-ip --start-ip-address "$MYIP" --end-ip-address "$MYIP"
```

Build the connection string (goes into Key Vault in Step 4, **not** into an env var):
```bash
export DATABASE_URL="postgresql://${PGADMIN}:${PGPASS}@${PG}.postgres.database.azure.com:5432/socplatform?sslmode=require"
```

---

## Step 3 — Storage account + Azure Files share (empty)

```bash
az storage account create -n "$SA" -g "$RG" -l "$LOC" --sku Standard_LRS --kind StorageV2
SAKEY=$(az storage account keys list -n "$SA" -g "$RG" --query "[0].value" -o tsv)
az storage share create --account-name "$SA" --account-key "$SAKEY" --name "$SHARE" --quota 32

# Seed an empty customers file so first boot has a valid (empty) roster.
printf '[]' > /tmp/customers.json
az storage file upload --account-name "$SA" --account-key "$SAKEY" \
  --share-name "$SHARE" --source /tmp/customers.json --path customers.json
```

> The share also backs `logos/`, `rag_docs/`, `reports/*.json`, `backups/`, and
> `mitre_attack_index.json`. All are created on demand; the MITRE index also ships
> inside the image, so nothing needs pre-seeding beyond `customers.json`.

---

## Step 4 — Key Vault + secrets

```bash
az keyvault create -n "$KV" -g "$RG" -l "$LOC" --enable-rbac-authorization false
# give yourself access to write secrets (access-policy model, matching live)
ME=$(az ad signed-in-user show --query id -o tsv)
az keyvault set-policy -n "$KV" --object-id "$ME" --secret-permissions get list set delete
```

Create every secret the app resolves. **Fresh-environment guidance** in the right
column — reuse the same third-party key only if Decision C says to share that
integration; otherwise mint a new one.

```bash
az keyvault secret set --vault-name "$KV" -n postgres-connection-string --value "$DATABASE_URL"
az keyvault secret set --vault-name "$KV" -n flask-secret-key --value "$(openssl rand -hex 32)"
az keyvault secret set --vault-name "$KV" -n gateway-shared-secret --value "$(openssl rand -hex 24)"
```

| Secret | Fresh-env source |
|---|---|
| `postgres-connection-string` | generated in Step 2 (above) |
| `flask-secret-key` | generate fresh (above) — must differ from live |
| `gateway-shared-secret` | generate fresh (above) |
| `entra-client-secret` | **new** — from the Entra app reg in Step 8 |
| `azure-openai-api-key` | new resource key (Decision B: new) or existing (reuse) |
| `openai-api-key` | OpenAI key if used; else set a placeholder |
| `jira-api-token` | new Jira API token (or shared per Decision C) |
| `vt-api-key`, `abuseipdb-api-key`, `tavily-api-key` | reuse or new per Decision C |
| `socradar-api-key` + the 11 `socradar-*-key` variants | reuse or new per Decision C |
| `sentinel-client-secret`, `customer-logicalis-sentinel-client-secret` | per customer set you onboard |
| `defender-client-secret` | per Defender app reg |
| `splunk-token` | per Splunk deployment |

> Set a non-empty placeholder for any integration you are not wiring yet — the app
> tolerates a missing feature but a *referenced* secret must exist. The full live
> list is in [INFRASTRUCTURE.md](INFRASTRUCTURE.md#secrets).

---

## Step 5 — Log Analytics workspace

```bash
az monitor log-analytics workspace create -g "$RG" -n "$LAW" -l "$LOC"
export LAW_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query customerId -o tsv)
export LAW_KEY=$(az monitor log-analytics workspace get-shared-keys -g "$RG" -n "$LAW" --query primarySharedKey -o tsv)
```

---

## Step 6 — Container Apps managed environment + storage link

```bash
az containerapp env create -n "$ENVNAME" -g "$RG" -l "$LOC" \
  --logs-workspace-id "$LAW_ID" --logs-workspace-key "$LAW_KEY"

# mount the Azure Files share into the environment (ReadWrite), same as live
az containerapp env storage set -n "$ENVNAME" -g "$RG" \
  --storage-name socdata \
  --azure-file-account-name "$SA" \
  --azure-file-account-key "$SAKEY" \
  --azure-file-share-name "$SHARE" \
  --access-mode ReadWrite
```

---

## Step 7 — Azure OpenAI (Decision B)

**If new (recommended):**
```bash
export AOAI="lsg-soc-foundry-${SUFFIX}"
az cognitiveservices account create -n "$AOAI" -g "$RG" -l "$LOC" \
  --kind OpenAI --sku S0 --custom-domain "$AOAI"
# deploy the two models (names/capacity depend on approved quota)
az cognitiveservices account deployment create -n "$AOAI" -g "$RG" \
  --deployment-name text-embedding-3-large --model-name text-embedding-3-large \
  --model-version 1 --model-format OpenAI --sku-capacity 1 --sku-name Standard
az cognitiveservices account deployment create -n "$AOAI" -g "$RG" \
  --deployment-name gpt-5.3-chat --model-name gpt-5.3-chat \
  --model-version <ver> --model-format OpenAI --sku-capacity 1 --sku-name Standard

export AOAI_ENDPOINT="https://${AOAI}.cognitiveservices.azure.com/"
export AOAI_KEY=$(az cognitiveservices account keys list -n "$AOAI" -g "$RG" --query key1 -o tsv)
az keyvault secret set --vault-name "$KV" -n azure-openai-api-key --value "$AOAI_KEY"
```

**If reusing `lsg-soc-foundry`:**
```bash
export AOAI_ENDPOINT="https://lsg-soc-foundry.cognitiveservices.azure.com/"
# copy the existing key into the new KV (read it from the live KV or portal)
az keyvault secret set --vault-name "$KV" -n azure-openai-api-key --value "<existing key>"
```

---

## Step 8 — Entra ID app registration (Decision A)

**Same tenant:** you may reuse the live app registration (`ENTRA_CLIENT_ID`
`498340cb…`) — just add the new redirect URI — or create a second app for clean
isolation. **Different tenant:** create a new app registration in the target tenant.

Creating a fresh app registration (works for either tenant):
```bash
# 1) determine the app FQDN AFTER Step 9 deploy, then register its callback:
#    https://<APP-FQDN>/auth/callback
az ad app create --display-name "SOC-Platform (${SUFFIX})" \
  --web-redirect-uris "https://PLACEHOLDER/auth/callback"
# 2) note the appId (-> ENTRA_CLIENT_ID), create a client secret (-> entra-client-secret in KV),
# 3) create/choose an Entra security group for allowed admins (-> ENTRA_ALLOWED_GROUP_ID),
# 4) grant Microsoft Graph 'User.Read' + admin-consent as the live app has.
```
Because the redirect URI needs the final FQDN, this step is **finished after
Step 9** (deploy) once the FQDN exists. Put a placeholder now, update after deploy.

---

## Step 9 — Deploy the container app

Create the app with the managed identity, the volume mount, ingress on 5060, and the
`DATABASE_URL` secretRef — then attach the full env. Set the identity-, integration-,
and secret-bound values to **your new** values; keep the engine-config values as-is.

```bash
az containerapp create -n "$APP" -g "$RG" --environment "$ENVNAME" \
  --image "${ACR}.azurecr.io/soc-platform:${IMAGE_TAG}" \
  --registry-server "${ACR}.azurecr.io" --registry-identity system \
  --system-assigned \
  --ingress external --target-port 5060 \
  --min-replicas 1 --max-replicas 3 \
  --secrets postgres-connection-string=keyvaultref:https://${KV}.vault.azure.net/secrets/postgres-connection-string,identityref:system \
  --env-vars DATABASE_URL=secretref:postgres-connection-string
```

Grant the app's identity what it needs (order matters — the identity exists only
after create):
```bash
PRINCIPAL=$(az containerapp show -n "$APP" -g "$RG" --query identity.principalId -o tsv)
# ACR pull
az role assignment create --assignee "$PRINCIPAL" --role AcrPull \
  --scope $(az acr show -n "$ACR" -g "$RG" --query id -o tsv)
# KV get/list (access-policy model, matching live)
az keyvault set-policy -n "$KV" --object-id "$PRINCIPAL" --secret-permissions get list
```

Now apply the full environment. Everything below is **engine config — copy as-is**
(these are per-Jira/behaviour defaults the code expects). See the *Environment
template* section for the identity/secret/integration values you must replace.

```bash
az containerapp update -n "$APP" -g "$RG" --set-env-vars \
  PORT=5060 WEB_CONCURRENCY=1 USE_SAMPLE_DATA=false \
  DB_PATH=/tmp/soc_platform.db \
  MALICIOUS_SCORE_THRESHOLD=70 \
  WEBHOOK_FETCH_DELAY_SECONDS=5 WEBHOOK_FETCH_MAX_WAIT_SECONDS=240 WEBHOOK_FETCH_STABILIZATION_SECONDS=30 \
  JIRA_FIELD_IP_ENTITIES=customfield_10079 JIRA_FIELD_HOST_ENTITIES=customfield_10078 \
  JIRA_FIELD_DNS_ENTITIES=customfield_10080 JIRA_FIELD_URL_ENTITIES=customfield_10081 \
  JIRA_FIELD_HASH_ENTITIES=customfield_10082 \
  JIRA_FIELD_SOURCE_SIEM=customfield_11588 JIRA_FIELD_SOURCE_ALERT_ID=customfield_10125 \
  JIRA_FIELD_SEVERITY=customfield_10038 JIRA_FIELD_ENTITIES=customfield_10074 \
  JIRA_FIELD_RAW_LINK=customfield_10073 JIRA_FIELD_OCCURRENCE_COUNT=customfield_11589 \
  JIRA_FIELD_LAST_SEEN=customfield_11590 \
  JIRA_ISSUE_TYPE='[System] Incident' \
  DEDUP_WEBHOOK_ENABLED=true JIRA_DUPLICATE_SUMMARY_PREFIX='[DUPLICATE]' \
  JIRA_CLOSE_TRANSITION_ID=181 JIRA_FIELD_CLOSE_JUSTIFICATION=customfield_10057 \
  JIRA_CLOSE_JUSTIFICATION_VALUE='Other Comments' \
  JIRA_FIELD_RESOLUTION_SUMMARY=customfield_10127 JIRA_FIELD_RESOLUTION_CATEGORY=customfield_10521 \
  JIRA_RESOLUTION_CATEGORY_VALUE=Duplicate JIRA_LABEL_REMOVE_ON_CLOSE=True-Positive \
  JIRA_TRIAGE_MALICIOUS_LABEL=True-Positive JIRA_TRIAGE_CLEAN_LABEL=Benign-Positive \
  JIRA_TRIAGE_UNKNOWN_LABEL=Unknown JIRA_GSOC_ACCOUNT_ID=611ca5f3aee32f006f99cf9d \
  AZURE_OPENAI_DEPLOYMENT=gpt-5.3-chat AZURE_OPENAI_API_VERSION=2024-10-21 INVESTIGATE_MODEL=gpt-5.2 \
  AZURE_OPENAI_EMBEDDING_DEPLOYMENT=text-embedding-3-large \
  RAG_LOOKUP_ENABLED=true RAG_TIMEOUT_SECONDS=5 RAG_TOP_K=3 RAG_MIN_SCORE=0.5 \
  RAG_DOCS_DIR=/app/data/rag_docs RAG_CHROMA_DIR=/tmp/rag \
  RAG_TO_LLM_PROMPT_ENABLED=true RAG_PROMPT_MIN_SCORE=0.7 \
  KQL_EXPANSION_ENABLED=true IOC_HISTORY_ENABLED=true \
  COMMENT_ADF_ENABLED=true WHITELIST_MATCH_ENABLED=true \
  RECOMMENDATION_SYNTHESIS_ENABLED=true DECISION_CAPTURE_ENABLED=true \
  BACKUP_ENABLED=true BACKUP_DIR=/app/data/backups BACKUP_RETENTION_DAYS=30 BACKUP_SCHEDULE_HOUR=2 \
  SMTP_PORT=587
```

Then set the **replace-me** values (identity / integrations / fresh secret) — see the
template below for exactly which:
```bash
FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
az containerapp update -n "$APP" -g "$RG" --set-env-vars \
  AZURE_KEYVAULT_URL=https://${KV}.vault.azure.net \
  AZURE_OPENAI_ENDPOINT="$AOAI_ENDPOINT" \
  ENTRA_TENANT_ID=<target-tenant-id> ENTRA_CLIENT_ID=<new-app-id> \
  ENTRA_ALLOWED_GROUP_ID=<new-group-id> \
  ENTRA_REDIRECT_URI="https://${FQDN}/auth/callback" \
  JIRA_URL=<jira-base-url> JIRA_EMAIL=<jira-service-account> \
  JIRA_PROJECT_KEY=<primary-project> JIRA_ENRICHMENT_PROJECT=<non-overlapping-allowlist> \
  JIRA_WEBHOOK_SECRET="$(openssl rand -base64 32 | tr -d '/+=' )" \
  SOCRADAR_MCP_URL=https://mcp.socradar.com SOCRADAR_COMPANY_ID=<id> \
  SOCRADAR_REDIRECT_URI="https://${FQDN}/investigate/oauth/callback" \
  SENTINEL_TENANT_ID=<..> SENTINEL_CLIENT_ID=<..> SENTINEL_WORKSPACE_ID=<..> \
  DEFENDER_TENANT_ID=<..> DEFENDER_CLIENT_ID=<..> \
  SPLUNK_HOST=<..> SPLUNK_VERIFY_SSL=false
```
Finally, go back to **Step 8** and set the Entra app's redirect URI to
`https://${FQDN}/auth/callback`.

---

## Step 10 — Wire integrations & AVOID double-triage (Decision C)

Before pointing any live SIEM/Jira at the new instance:

- [ ] **Jira webhook:** register `https://<FQDN>/webhook/jira?secret=<new-secret>`
      for a project **only if no other instance already processes that project.**
- [ ] **Allowlist isolation:** the new `JIRA_ENRICHMENT_PROJECT` must **not share
      any key** with the live instance's `SCDM,LOGICALIS`. It is fail-closed, so an
      unlisted project is silently ignored — but a *shared* project would be
      triaged by **both** apps (duplicate comments, double API spend).
- [ ] **Same Jira, different projects:** fine — each app owns its own project keys.
- [ ] **Same Jira, same project:** not allowed for two live instances. Pick one
      owner.
- [ ] **SOCRadar / VT / AbuseIPDB quotas:** if reusing the same accounts, the two
      instances share the daily/'minute quotas. Budget accordingly or use separate
      accounts.
- [ ] **Sentinel/Defender:** add only the customers this instance actually serves.

---

## Step 11 — First-boot verification

```bash
FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
curl -fsS "https://${FQDN}/healthz" && echo "  <- healthz OK"

# Postgres schema self-created on boot?
az containerapp logs show -n "$APP" -g "$RG" --tail 100 --format text | grep -iE "init_db|reports|schedules|listening"

# psql check (needs your admin IP in the firewall from Step 2)
psql "$DATABASE_URL" -c "\dt"     # expect: reports, schedules
```
- [ ] `/healthz` returns 200.
- [ ] Logs show the app listening on 5060, no KV/DB errors.
- [ ] `reports` + `schedules` tables exist (auto-created).
- [ ] Browse to `https://<FQDN>/admin` → Entra login works → **empty** customer list.
- [ ] `/admin/customers` shows no customers (clean bootstrap confirmed).

---

## Environment template — what to copy vs replace

**Copy as-is (engine config)** — the block in Step 9's first `update` command:
field-ID mappings, thresholds, RAG/backup params, killswitch states, model
deployment *names*, label taxonomy. These are behaviour the code expects; changing
them changes how triage works.

**Replace (identity / integration / secret)** — the block in Step 9's second
`update`, plus KV secrets:

| Variable | Why it changes |
|---|---|
| `AZURE_KEYVAULT_URL` | points at the new KV |
| `AZURE_OPENAI_ENDPOINT` | new Foundry or reused (Decision B) |
| `ENTRA_TENANT_ID` / `ENTRA_CLIENT_ID` / `ENTRA_ALLOWED_GROUP_ID` / `ENTRA_REDIRECT_URI` | new app reg + FQDN (Decision A) |
| `JIRA_URL` / `JIRA_EMAIL` / `JIRA_PROJECT_KEY` / `JIRA_ENRICHMENT_PROJECT` | your Jira + non-overlapping scope (Decision C) |
| `JIRA_WEBHOOK_SECRET` | **generate fresh** — never reuse the live secret |
| `SOCRADAR_*`, `SENTINEL_*`, `DEFENDER_*`, `SPLUNK_HOST` | per this instance's integrations |
| All Key Vault secrets | re-entered in Step 4 (new DB/flask/gateway secrets; third-party keys per Decision C) |

> `DATABASE_URL` stays an empty env var — it is injected from the KV secret via
> `secretref`. `DB_PATH` is legacy/unused under Postgres but kept to match live.

---

## Cost

A duplicate mirrors the live footprint: **~USD 33/month** (Postgres B1ms ~$21,
Container App 1 replica ~$5, ACR Basic ~$5, Files+KV ~$2). A **new** Azure OpenAI
(Decision B) is billed per-token on top and requires approved quota.

---

## Teardown (if the duplicate is ever abandoned)

Everything is in one resource group, so removal is one command:
```bash
az group delete -n "$RG" --yes
```
Plus: delete the Entra app registration (Step 8) and remove the new instance's Jira
webhook. If a separate Azure OpenAI was created, `az group delete` covers it since
it lives in the same RG.

---

## Quick sequence recap

1. Params + RG (Step 0) → 2. ACR + build image (1) → 3. Postgres empty (2) →
4. Storage + empty share + seed `customers.json` (3) → 5. KV + secrets (4) →
6. Log Analytics (5) → 7. ACA env + storage link (6) → 8. Azure OpenAI (7, **quota
lead time**) → 9. Entra app reg (8, finish after deploy) → 10. Deploy app + identity
grants + env (9) → 11. Integrations + anti-double-triage (10) → 12. Verify clean
boot (11).
