# SOC-Platform — Disaster Recovery Setup Guide

**Last updated:** 2026-05-10
**Live app:** https://soc-platform.yellowflower-c7c34b87.southeastasia.azurecontainerapps.io/
**Source repo:** `git@github.com:eugenechia/soc-platform.git`
**Local path on Mac:** `~/Library/CloudStorage/GoogleDrive-eugeneckk@gmail.com/My Drive/Work/Office/Office-lab/SOC-Platform/`

---

## When to use this guide

Pick the scenario that matches what's broken:

| Scenario | Steps you need |
|---|---|
| New Mac, Azure intact (most common) | Steps 1 → 3 |
| Mac alive, Azure resources gone | Steps 4 → 6 |
| Mac dead AND Azure gone (worst case) | All steps 1 → 6 |

---

## Pre-flight: accounts you must be able to log into

Confirm access to all of these before starting. Missing access here = blocked recovery.

- [ ] **GitHub** — `eugenechia` account, with an SSH key registered at https://github.com/settings/keys
- [ ] **Google Drive** — `eugeneckk@gmail.com` (your `.env` and `data/customers.json` live here, since both are gitignored)
- [ ] **Azure** — subscription containing `kv-socplatform`, the resource group, ACA, ACR
- [ ] **Microsoft Entra ID admin** — tenant `7cf1bf61-082f-40f3-a95a-1333d539fcc4` (for the SOC-Platform app registration)
- [ ] **Jira admin** — for webhook configuration and custom field IDs
- [ ] **Each customer's Azure tenant admin** — only needed if KV is gone (Step 5)
- [ ] **External services** — SOCRadar, Anthropic / Azure OpenAI, Tavily, VirusTotal, AbuseIPDB, SMTP provider

---

## Step 1 — Get source code on the new machine

Install prerequisites:

```bash
# Homebrew if missing
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Required tools
brew install git python@3.12 azure-cli gh
brew install --cask docker        # or: brew install colima  (lightweight)
```

Set up SSH for GitHub (skip if `~/.ssh/id_rsa.pub` already on GitHub):

```bash
ssh-keygen -t ed25519 -C "eugeneckk@gmail.com"
cat ~/.ssh/id_ed25519.pub
# Paste the output at https://github.com/settings/keys → New SSH key
```

Test and clone. **Recommended:** clone INTO Google Drive sync so the working copy is automatically backed up:

```bash
ssh -T git@github.com  # should say "Hi eugenechia!"

DEST="$HOME/Library/CloudStorage/GoogleDrive-eugeneckk@gmail.com/My Drive/Work/Office/Office-lab/SOC-Platform"
mkdir -p "$(dirname "$DEST")"
git clone git@github.com:eugenechia/soc-platform.git "$DEST"
cd "$DEST"
```

(If Google Drive isn't ready yet, clone to `~/SOC-Platform` and move it later.)

---

## Step 2 — Recover secrets and customer data from Google Drive

Two files are intentionally NOT in GitHub (gitignored) and live only in Google Drive sync:

| File | Contains |
|---|---|
| `.env` | All API keys, secrets, configuration |
| `data/customers.json` | Customer records (names, KV secret refs, default sections, schedules) |

If you cloned INTO Google Drive in Step 1, these files are already alongside the code — nothing to do. Verify:

```bash
ls -la .env data/customers.json
```

If you cloned to `~/SOC-Platform` instead:

```bash
GDRIVE="$HOME/Library/CloudStorage/GoogleDrive-eugeneckk@gmail.com/My Drive/Work/Office/Office-lab/SOC-Platform"
cp "$GDRIVE/.env" ./.env
cp -R "$GDRIVE/data" ./data
```

If Google Drive is ALSO gone, jump to the **Known gaps** section near the end.

---

## Step 3 — Run locally to verify

```bash
docker compose up --build
```

App listens on http://localhost:5060. Smoke tests:

- Open http://localhost:5060/ in a browser → should redirect to Microsoft login (Entra ID)
- Log in with your Entra ID account that's in group `c7b2add1-617b-4576-9773-29b77cddc87c`
- Land on the dashboard — Customers, Reports, Investigate, Schedules tabs should all load

If anything 500s, check `docker compose` logs in the same terminal.

If Entra ID redirect fails with a callback URL mismatch, register `http://localhost:5060/auth/callback` as a redirect URI on the Entra app registration (Client ID `498340cb-369b-4075-b197-5a99e343620f`).

**At this point — if Azure is intact — you are recovered.** Skip to the Verification checklist.

---

## Step 4 — Recreate Azure infrastructure (only if Azure is gone)

> Replace resource names below if you want different ones; just keep them consistent across all commands and update `.env` to match.

```bash
RG=rg-soc-platform
LOC=southeastasia
KV=kv-socplatform
ACR=socplatformreg
ACA_ENV=soc-platform-env
ACA_APP=soc-platform

# 1. Resource group
az group create --name $RG --location $LOC

# 2. Azure Container Registry
az acr create --resource-group $RG --name $ACR --sku Basic --admin-enabled true

# 3. Key Vault
az keyvault create --name $KV --resource-group $RG --location $LOC

# 4. Container Apps environment
az containerapp env create --name $ACA_ENV --resource-group $RG --location $LOC
```

Build the image and push to ACR:

```bash
az acr build --registry $ACR --image soc-platform:latest .
```

Create the Container App with system-assigned managed identity. **`min/max replicas must both be 1`** (APScheduler keeps in-process state — multiple replicas would duplicate scheduled jobs):

```bash
az containerapp create --name $ACA_APP \
  --resource-group $RG --environment $ACA_ENV \
  --image $ACR.azurecr.io/soc-platform:latest \
  --target-port 5060 --ingress external \
  --min-replicas 1 --max-replicas 1 \
  --system-assigned
```

Grant the Container App's managed identity access to Key Vault. Note `set` is required (the app writes per-customer Sentinel secrets to KV, not just reads):

```bash
PID=$(az containerapp identity show --name $ACA_APP \
  --resource-group $RG --query principalId -o tsv)

az keyvault set-policy --name $KV \
  --object-id $PID \
  --secret-permissions get list set
```

Set environment variables on the Container App (full list in `.env.example`). Critical ones:

- `FLASK_SECRET_KEY` (generate fresh: `python3 -c "import secrets;print(secrets.token_hex(32))"`)
- `AZURE_KEYVAULT_URL=https://kv-socplatform.vault.azure.net/`
- All `ENTRA_*` (Entra ID config — Client ID, Secret, Redirect URI for the ACA URL)
- All `JIRA_*` (Jira creds + custom field IDs for IOC entities + gateway dedup fields)
- All `SOCRADAR_*` (API keys + MCP URL + OAuth redirect)
- `OPENAI_API_KEY` or the `AZURE_OPENAI_*` block
- `TAVILY_API_KEY`, `VT_API_KEY`, `ABUSEIPDB_API_KEY`
- `GATEWAY_SHARED_SECRET` (for SIEM `/api/ingest` endpoint)
- `SMTP_*` (for scheduled report email delivery)

Easiest: paste the contents of `.env` into the Azure Portal under Container App → Settings → Environment variables, OR script with `az containerapp update --set-env-vars`.

**DO NOT put any per-customer secret as an env var** — those go into Key Vault under names like `customer-<id>-sentinel-client-secret` (the app writes them via the Manage Customers admin UI in Step 5).

---

## Step 5 — Re-onboard each customer (only if Azure KV is gone)

Per-customer Sentinel SP credentials live ONLY in `kv-socplatform`. If KV is destroyed, you must request fresh SP credentials from each customer's IT admin.

Send each customer this verbatim:

> 1. Go to your Azure Active Directory → App registrations → New registration. Name it e.g. "SOC Report Generator".
> 2. Note the **Application (client) ID** and **Tenant ID**.
> 3. Certificates & secrets → New client secret — copy the **value** (one-time view).
> 4. Your Log Analytics workspace → Access control (IAM) → Add role assignment → **Log Analytics Reader** to the App Registration above.
> 5. Copy the **Workspace ID** from workspace Properties.
> 6. Send back: Tenant ID, Client ID, Client Secret, Workspace ID.

Then in the SOC-Platform admin UI: **Customers → Add (or Edit existing)** → fill in the four Sentinel fields. The Client Secret is written to Key Vault automatically; never persisted in `data/customers.json`.

---

## Step 6 — Deploy

Once Azure is rebuilt and customers re-onboarded:

```bash
RG=rg-soc-platform
ACR=socplatformreg
ACA_APP=soc-platform

az acr build --registry $ACR --image soc-platform:latest .

az containerapp update --name $ACA_APP \
  --resource-group $RG \
  --image $ACR.azurecr.io/soc-platform:latest \
  --revision-suffix "recovery-$(date +%s)"
```

The `--revision-suffix` flag forces a new revision when redeploying with the same `:latest` tag.

---

## Verification checklist

After recovery, confirm everything works:

- [ ] `git remote -v` → SSH URL, no embedded token
- [ ] `git status` → clean, in sync with `origin/main`
- [ ] App starts locally with `docker compose up`
- [ ] Entra ID login works (group membership check passes)
- [ ] Generate Report runs end-to-end for at least one customer (Sentinel SP auth resolves correctly)
- [ ] `POST /api/ingest` with valid `X-Shared-Secret` creates a Jira ticket; second call with same payload increments `occurrence_count`
- [ ] `POST /webhook/jira` (Jira-fired) triggers L1 triage IOC enrichment, applies `Potential-TP` or `Potential-FP` label
- [ ] Container App is reachable on its public ingress URL
- [ ] No secrets leaked into the repo: `git log -p | grep -E '(ghp_|sk_[a-z]+_|client_secret|api_key)' | head` returns nothing

---

## Known gaps — single-source-of-truth files

If both Mac AND Google Drive AND Azure die simultaneously, these are unrecoverable from GitHub alone:

| File / Resource | Sole location | Mitigation |
|---|---|---|
| `.env` (all API keys) | Mac + Google Drive | Maintain a secondary copy in 1Password / Bitwarden, kept in sync whenever you rotate credentials |
| `data/customers.json` | Mac + Google Drive | Periodically export and back up to a separate cloud (e.g. Azure Storage with versioning) |
| Per-customer Sentinel SP secrets | Azure Key Vault `kv-socplatform` only | Unavoidable — re-collect from each customer per Step 5 if KV dies |
| Jira ticket history & SOCRadar threat data | External (Jira, SOCRadar) | Owned by those systems; not your responsibility to back up |
| `SOCRadar.zip` and other archives | Google Drive only (gitignored) | Low value — these are snapshots; safe to lose |

**If Google Drive is also gone,** rebuild `.env` from your password manager using `.env.example` as the template:

```bash
cp .env.example .env
# edit .env with values from your password manager
```

`data/customers.json` would have to be rebuilt by adding each customer back through the admin UI (Step 5 process for each).

---

## Maintenance — keep this guide accurate

This document is committed to GitHub so it survives even if Mac + Google Drive both die. Update it whenever any of these change:

- New env var added → mention it in Step 4
- Azure resource names change → update Step 4 commands
- New external dependency added → add to Pre-flight checklist
- Recovery process discovered to be wrong → fix immediately

Review this guide quarterly to make sure it still works.
