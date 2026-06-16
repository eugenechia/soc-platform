# SOC-Platform Infrastructure

Single-page overview of the live infrastructure that backs the SOC-Platform Flask app: compute, persistence, secrets, backup, rollback, cost.

Last updated: 2026-06-16 (post-D1 migration to Postgres).

## Architecture

```mermaid
flowchart TB
    %% Users / triggers
    subgraph users["Users & Triggers"]
        analyst["SOC Analyst<br/>(browser, Entra ID SSO)"]
        cron["APScheduler<br/>(in-process,<br/>02:00 SGT nightly backup +<br/>5min schedule poll)"]
        jira_wh["Jira Webhook<br/>(secret-token auth)"]
    end

    %% Compute
    subgraph aca["Azure Container Apps · rg-soc-platform · southeastasia"]
        subgraph env["Managed env: soc-platform-env<br/>(shared with soc-triage)"]
            container["soc-platform<br/>Flask + Gunicorn<br/>1 worker · 4 threads · 360s timeout<br/>image: socplatformreg.azurecr.io/soc-platform:&lt;tag&gt;"]
        end
        identity[("System-Assigned<br/>Managed Identity")]
        container -.uses.-> identity
    end

    acr[("Azure Container Registry<br/>socplatformreg<br/>tags: latest + dated rollback markers")]

    %% Data
    subgraph data["Persistence — rg-soc-platform"]
        pg[("Azure Postgres Flexible Server<br/>pg-soc-platform · B1ms · PG 16<br/>db: socplatform<br/>tables: reports, schedules<br/>firewall: AllowAzureServices + admin IP")]
        files[("Azure Files SMB<br/>socdataplatform / soc-platform-data<br/>mounted at /app/data<br/>customers.json · logos · reports/*.json ·<br/>rag_docs · backups · mitre_attack_index.json")]
        kv[("Key Vault<br/>kv-socplatform<br/>(access policies — not RBAC)<br/>26+ secrets<br/>incl. postgres-connection-string")]
    end

    %% External APIs
    subgraph ext["External APIs"]
        jira_api["Jira REST"]
        sentinel["MS Sentinel"]
        socradar["SOCRadar"]
        vt["VirusTotal"]
        abuse["AbuseIPDB"]
        openai["Azure OpenAI"]
        conf["Confluence"]
    end

    %% Flows
    analyst -- HTTPS · Entra ID --> container
    cron -.in-process.-> container
    jira_wh -- POST /webhook/jira --> container
    container <==>|"reports + schedules<br/>(psycopg2 pool)"| pg
    container <==>|customers · logos · RAG · backups| files
    container <-->|secretref via MI| kv
    acr -- image pull --> container
    container -.HTTPS.-> jira_api
    container -.HTTPS.-> sentinel
    container -.HTTPS.-> socradar
    container -.HTTPS.-> vt
    container -.HTTPS.-> abuse
    container -.HTTPS.-> openai
    container -.HTTPS.-> conf

    classDef compute fill:#dbe7ff,stroke:#3060c8,stroke-width:2px,color:#000
    classDef datacls fill:#e8f5e0,stroke:#3a8a1a,stroke-width:2px,color:#000
    classDef extcls fill:#fff4d6,stroke:#d49c20,stroke-width:1px,color:#000
    class container,identity compute
    class pg,files,kv,acr datacls
    class jira_api,sentinel,socradar,vt,abuse,openai,conf extcls
```

## Backup layers

```mermaid
flowchart LR
    %% Live data
    pglive[("LIVE: Postgres<br/>pg-soc-platform")]
    custfile["LIVE: /app/data/customers.json<br/>(Azure Files)"]
    repjson["LIVE: /app/data/reports/*.json<br/>(parallel-write, dual-read fallback)"]

    %% Layer 1
    subgraph L1["Layer 1 — App-level (nightly 02:00 SGT, 30-day retention)"]
        sched["APScheduler<br/>cron · run_nightly_backup()"]
        pgdump["pg_dump<br/>--format=custom<br/>--no-owner --no-privileges"]
        snap["shutil.copy<br/>(NOT copy2 — see commit f6008e9)"]
        prune["prune_old_backups<br/>(delete > 30d old)"]
        dbdir[("/app/data/backups/db/<br/>socplatform-YYYY-MM-DD-HHMMSS.dump<br/>~213 KB / file")]
        custdir[("/app/data/backups/customers/<br/>customers-YYYY-MM-DD-HHMMSS.json<br/>~10 KB / file")]
    end

    %% Layer 2
    subgraph L2["Layer 2 — Azure-managed (continuous, 7-day PITR)"]
        azurepg[("Postgres Flexible Server<br/>automated backups<br/>point-in-time within last 7 days")]
    end

    %% UI surface
    subgraph ui["UI surface (admin freshness pills)"]
        pill1["/admin/history<br/>'Last DB backup: Xh ago'"]
        pill2["/admin/customers<br/>'Last customers backup: Xh ago'"]
    end

    %% Rollback
    subgraph rb["Rollback markers"]
        gittag["Git: pre-d1-postgres-2026-06-16"]
        acrtag["ACR: pre-d1-postgres-2026-06-16"]
    end

    pglive -.dumped.-> pgdump
    custfile -.copied.-> snap
    sched --> pgdump --> dbdir
    sched --> snap --> custdir
    sched --> prune
    pglive --> azurepg

    dbdir -.mtime.-> pill1
    custdir -.mtime.-> pill2

    classDef live fill:#dbe7ff,stroke:#3060c8,color:#000
    classDef backup fill:#e8f5e0,stroke:#3a8a1a,color:#000
    classDef rollback fill:#ffe0e0,stroke:#c83030,color:#000
    class pglive,custfile,repjson live
    class dbdir,custdir,azurepg backup
    class gittag,acrtag rollback
```

## What's backed up (vs what isn't)

| Data | Live location | Backup | Retention | Notes |
|---|---|---|---|---|
| **reports** table | Postgres `socplatform.reports` | App-level pg_dump → Azure Files **+** Azure PITR **+** dual-read JSON fallback at `data/reports/*.json` | 30d / 7d / forever | Triple-redundant by accident — once 2-week stability window passes (after 2026-06-30), the JSON fallback is removed |
| **schedules** table | Postgres `socplatform.schedules` | App-level pg_dump + Azure PITR | 30d / 7d | RPO = up to 24h via nightly snapshot, or ~5min via PITR |
| **customers.json** | `/app/data/customers.json` (Azure Files) | App-level snapshot + Azure Files inherent redundancy | 30d snapshots; share is LRS-replicated | RPO = 24h via app snapshot; live file itself is highly durable |
| **customer logos** | `/app/data/logos/*` | Azure Files inherent redundancy only | — | Re-uploadable from admin UI if lost |
| **MITRE static index** | `/app/data/mitre_attack_index.json` | Azure Files + ships in container image | — | Re-derivable from MITRE source |
| **RAG vectors** | `/tmp/rag/` (Chroma SQLite) | **NOT backed up — ephemeral by design** | — | Re-synced per-customer via admin UI; SQLite + SMB don't mix |
| **RAG source docs** | `/app/data/rag_docs/` + `customers.json::confluence_pages` | Azure Files inherent | — | Confluence pages re-fetchable on `Sync now` |
| **Job state (jobs dict)** | Gunicorn process memory | Not persisted | — | Container restart = in-flight reports lost. Accepted; single-replica APScheduler constraint |

## Secrets (in `kv-socplatform`, accessed via Managed Identity)

`postgres-connection-string` · `jira-api-token` · `azure-openai-api-key` · `openai-api-key` · `vt-api-key` · `abuseipdb-api-key` · `entra-client-secret` · `flask-secret-key` · `socradar-*-key` (12 SOCRadar variants) · `sentinel-client-secret` · `customer-logicalis-sentinel-client-secret` · `defender-client-secret` · `splunk-token` · `tavily-api-key` · `gateway-shared-secret`

## Rollback paths

| Scenario | Command |
|---|---|
| App regression | `az containerapp update -n soc-platform -g rg-soc-platform --image socplatformreg.azurecr.io/soc-platform:pre-d1-postgres-2026-06-16` |
| Recent DB corruption (≤7d) | Postgres portal → Restore → point-in-time within last 7d |
| DB corruption ≤30d | `pg_restore --clean --if-exists --no-owner --no-privileges -d $DATABASE_URL /app/data/backups/db/<latest>.dump` |
| customers.json corrupted | `cp /app/data/backups/customers/<latest>.json /app/data/customers.json` |
| Catastrophic Postgres loss | Provision new server, restore from latest app-level dump (≤30d) or Azure PITR (≤7d) |

## Rough monthly cost

| Component | ~USD / month |
|---|---|
| Postgres B1ms (compute) | ~17 |
| Postgres storage (32GB Premium SSD v2) | ~4 |
| Container App (1 replica, low traffic) | ~5 |
| Azure Files (LRS, ~2GB used) | ~1 |
| Key Vault (low ops) | ~1 |
| ACR Basic | ~5 |
| **Total** | **~33** |

## Adjacent (out of frame)

- **soc-triage** container app (`rg-soc-triage` / `soctriagereg`) — built as prep work for L1 Triage extraction; shares the managed env, Azure Files share, and KV. Not yet receiving live traffic.
- **Microsoft Sentinel workspaces** (per-customer) — read-only data source, no infra owned by us.

## Operational quick reference

| Action | Where |
|---|---|
| Trigger manual backup | `/admin/history` or `/admin/customers` → "Run backup now" |
| View backup freshness | Pill on `/admin/history` (DB) and `/admin/customers` (customers.json) |
| Configure scheduled reports | `/admin/schedules` (SMTP env vars must be set first) |
| Read live container logs | `az containerapp logs show --name soc-platform --resource-group rg-soc-platform --revision <name> --tail 200 --format text` |
| List backup files on share | `az storage file list --account-name socdataplatform --share-name soc-platform-data --path "backups/db" --account-key $(az storage account keys list --account-name socdataplatform --resource-group rg-soc-platform --query "[0].value" -o tsv)` |
| Manually connect to Postgres | `psql "$(az keyvault secret show --vault-name kv-socplatform --name postgres-connection-string --query value -o tsv)"` (requires your admin IP in the firewall) |

---

# Network

## Public ingress (Internet → SOC-Platform)

```mermaid
flowchart TB
    %% Internet zone
    subgraph internet["Internet (untrusted)"]
        analyst["SOC Analyst<br/>browser"]
        jira_send["Atlassian Cloud<br/>(Jira webhook)"]
        siem["SIEM connector<br/>(future — ticket gateway)"]
        admin["Eugene (admin)<br/>103.252.200.183<br/>direct DB / Storage / KV"]
    end

    %% Azure edge
    subgraph edge["Azure edge — TLS terminates here"]
        acaTLS["ACA managed ingress<br/>soc-platform.yellowflower-c7c34b87<br/>.southeastasia.azurecontainerapps.io<br/>:443 (HTTPS only) · auto cert"]
        pgTLS["pg-soc-platform.postgres.<br/>database.azure.com:5432<br/>(sslmode=require · firewall)"]
        kvTLS["kv-socplatform.vault.<br/>azure.net:443<br/>(public + access policies)"]
        stTLS["socdataplatform.file.core.<br/>windows.net:445/443<br/>(SMB/REST)"]
    end

    %% App-internal routing & auth
    subgraph app["Inside container — Gunicorn :5060 — Flask"]
        unauthRoutes["Unauthenticated routes<br/>· /healthz<br/>· /auth/login + /auth/callback (Entra OAuth start)"]
        webhookRoutes["Secret-token gated<br/>· /webhook/jira<br/>  (token via ?secret= query)"]
        gatewayRoutes["Shared-secret gated<br/>· /gateway/* (SIEM tickets)<br/>  (KV: gateway-shared-secret)"]
        entraRoutes["Entra ID + group-membership gated<br/>· /admin/* · /reports/* · /api/*<br/>  (cookie session after OAuth)"]
    end

    %% Identity provider
    entra["login.microsoftonline.com<br/>(Entra ID tenant)"]

    %% Traffic
    analyst -- HTTPS:443 --> acaTLS
    jira_send -- HTTPS:443 webhook --> acaTLS
    siem -- HTTPS:443 --> acaTLS
    admin -. psql :5432 .-> pgTLS
    admin -. az storage :445/443 .-> stTLS
    admin -. az keyvault :443 .-> kvTLS

    acaTLS --> unauthRoutes
    acaTLS --> webhookRoutes
    acaTLS --> gatewayRoutes
    acaTLS --> entraRoutes
    analyst -. OAuth redirect .-> entra -. JWT .-> entraRoutes

    classDef untrust fill:#ffe0e0,stroke:#c83030,color:#000
    classDef tls fill:#fff4d6,stroke:#d49c20,color:#000
    classDef gated fill:#dbe7ff,stroke:#3060c8,color:#000
    classDef open fill:#f1f1f1,stroke:#888,color:#000
    class analyst,jira_send,siem,admin untrust
    class acaTLS,pgTLS,kvTLS,stTLS tls
    class entraRoutes,webhookRoutes,gatewayRoutes gated
    class unauthRoutes open
```

## Container egress (SOC-Platform → outside)

```mermaid
flowchart LR
    container["soc-platform container<br/>(no egress firewall — open by default)"]

    %% Azure backbone — these stay on Microsoft network
    subgraph azureNet["Azure backbone (private-by-default routing)"]
        pg[("Postgres :5432<br/>TLS required<br/>SQL auth via DATABASE_URL")]
        files[("Azure Files :445<br/>SMB v3.1.1<br/>auth via managed env mount config")]
        kv[("Key Vault :443<br/>TLS · MI bearer token")]
        acr[("ACR :443<br/>image pull · MI bearer")]
        openai[("Azure OpenAI :443<br/>lsg-soc-foundry.openai.azure.com<br/>API key from KV")]
    end

    %% External
    subgraph internet["Public Internet"]
        jira[("Jira REST<br/>logicalisasia.atlassian.net:443<br/>basic auth from KV")]
        sentinel[("MS Sentinel / Defender<br/>api.loganalytics.io · api.security.microsoft.com<br/>OAuth2 client_credentials from KV")]
        socradar[("SOCRadar :443<br/>api.socradar.io<br/>API key from KV")]
        vt[("VirusTotal :443<br/>www.virustotal.com<br/>API key from KV")]
        abuse[("AbuseIPDB :443<br/>api.abuseipdb.com<br/>API key from KV")]
        confluence[("Confluence :443<br/>logicalisasia.atlassian.net/wiki<br/>basic auth from KV")]
        entraEgress[("Entra ID :443<br/>login.microsoftonline.com<br/>(token validation)")]
        smtp[("SMTP (TBD)<br/>smtp.office365.com:587<br/>STARTTLS · NOT configured yet")]
    end

    container -- TCP:5432 TLS --> pg
    container -- TCP:445 SMB --> files
    container -- TCP:443 TLS --> kv
    container -- TCP:443 TLS --> acr
    container -- TCP:443 TLS --> openai
    container -- TCP:443 TLS --> jira
    container -- TCP:443 TLS --> sentinel
    container -- TCP:443 TLS --> socradar
    container -- TCP:443 TLS --> vt
    container -- TCP:443 TLS --> abuse
    container -- TCP:443 TLS --> confluence
    container -- TCP:443 TLS --> entraEgress
    container -. TCP:587 STARTTLS .- smtp

    classDef ctn fill:#dbe7ff,stroke:#3060c8,color:#000
    classDef az fill:#e8f5e0,stroke:#3a8a1a,color:#000
    classDef pub fill:#fff4d6,stroke:#d49c20,color:#000
    classDef tbd stroke-dasharray:4 4,fill:#f1f1f1,color:#000
    class container ctn
    class pg,files,kv,acr,openai az
    class jira,sentinel,socradar,vt,abuse,confluence,entraEgress pub
    class smtp tbd
```

## Firewall + access control summary

| Resource | Public network | Allow rules / auth |
|---|---|---|
| **Container App ingress** | Enabled (external) | Anyone can reach the FQDN; auth enforced at app layer (Entra for `/admin/*` + `/reports/*` + `/api/*`; secret-token for `/webhook/jira`; shared-secret for `/gateway/*`) |
| **Postgres** | Enabled with firewall | `AllowAzureServices` (0.0.0.0–0.0.0.0) + `FirewallIPAddress_2026-6-16_9-0-27` (admin IP 103.252.200.183). TLS required (`sslmode=require`). SQL auth only. |
| **Key Vault** | Enabled | **Access policies** (not RBAC). MI of soc-platform container has `get`/`list` on secrets. Admin user (kkchia@lsgazure.com) has full access. |
| **Storage account `socdataplatform`** | Enabled | Account key auth for admin operations. ACA managed env mount uses storage account credentials configured at env level. |
| **ACR `socplatformreg`** | Enabled | Anonymous pull disabled. ACA managed env / container MI pulls via `AcrPull` role assignment. Admin operations via Entra. |
| **Container App egress** | Unrestricted | No NSG, no egress firewall. Container can reach any public endpoint. (Acceptable for current threat model; can tighten with VNet integration later.) |

## DNS / FQDN reference

| Purpose | FQDN | Resolved by |
|---|---|---|
| App | `soc-platform.yellowflower-c7c34b87.southeastasia.azurecontainerapps.io` | Microsoft (auto) |
| Postgres | `pg-soc-platform.postgres.database.azure.com` | Microsoft (auto) |
| Key Vault | `kv-socplatform.vault.azure.net` | Microsoft (auto) |
| Files share | `socdataplatform.file.core.windows.net` | Microsoft (auto) |
| ACR | `socplatformreg.azurecr.io` | Microsoft (auto) |
| Azure OpenAI | `lsg-soc-foundry.openai.azure.com` | Microsoft (auto) |
| Jira / Confluence | `logicalisasia.atlassian.net` | Atlassian |
| SOCRadar | `api.socradar.io` | SOCRadar |
| VirusTotal | `www.virustotal.com` | Google |
| AbuseIPDB | `api.abuseipdb.com` | AbuseIPDB |

No custom domain — using the auto-provisioned `*.azurecontainerapps.io` FQDN. Adding a custom domain would require: CNAME on `logicalis.com`-controlled DNS → ACA domain binding + Microsoft-managed cert (or your own).

## TLS posture

- **Public ingress**: TLS 1.2+ enforced by ACA. Cert auto-provisioned + auto-renewed by Microsoft. Hostname matches the auto FQDN.
- **Postgres**: `sslmode=require` in the connection string — server presents Microsoft-issued cert; client (psycopg2) validates default CA bundle.
- **Egress to all listed APIs**: TLS 1.2+, default Python `httpx` / `requests` validates standard CA bundle. No custom CA pinning in app code.
- **Container internals** (proxy → Gunicorn): plain HTTP on `:5060` — never traverses the public network.
- **SMB to Azure Files**: SMB 3.1.1 with encryption (default since 2019).

## Attack surface summary

| Surface | Auth | Risk | Mitigation today |
|---|---|---|---|
| `/webhook/jira?secret=…` | Query-string secret | Secret leak via logs/referer | Secret stored in KV; webhook is read-only intake; rate-limited by Jira-side |
| `/admin/*`, `/reports/*` | Entra ID + group | Standard SSO | Group membership enforced server-side, not just IdP |
| `/gateway/*` | Shared secret header | Same as webhook | Header-based, less likely to leak than query string |
| Postgres `5432` from Internet | SQL auth + IP firewall | Brute-force on admin user | Strong random password (28 chars), IP whitelist limits to admin + Azure services |
| KV public endpoint | Access policies | MI compromise = secret access | MI scoped to one container; rotate KV secrets if container ever shows signs of compromise |
| ACR public endpoint | MI / Entra | Unauthorized push | Only Eugene + the build pipeline have push perms; pulls are MI-only |

## Notable gaps / future hardening

- **No VNet integration** — container egress is open. A future tightening: put ACA into a VNet, route egress through Azure Firewall, deny everything except whitelisted FQDNs.
- **Postgres has public endpoint** — fine for current threat model but a private endpoint inside a VNet is the next-step posture.
- **No WAF in front of ingress** — direct ACA ingress. Add Azure Front Door + WAF if exposed to direct attack.
- **No mTLS / cert-bound auth** for webhooks — token-only.
- **Custom domain + DMARC/SPF** for sending — applies once SMTP is configured.
