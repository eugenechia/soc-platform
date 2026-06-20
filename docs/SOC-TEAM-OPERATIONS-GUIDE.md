# SOC Platform — Team Operations Guide

**Audience:** SOC analysts and team leads  
**Last updated:** 2026-06-10

This guide covers what the SOC team needs to do on a daily, weekly, and monthly basis to keep the platform running well. It does not cover infrastructure or code — that is handled separately.

---

## What the platform does (quick reference)

When a Sentinel or Splunk alert creates a Jira ticket, the platform automatically:

1. Sets the ticket priority based on the SIEM severity level
2. Assigns the ticket to the GSOC queue (`soc@ap.logicalis.com`)
3. Runs an AI priority check — escalates or de-escalates if warranted
4. Looks up every IOC (IP, domain, hash) against threat intel sources
5. Maps the alert to MITRE ATT&CK tactics and techniques
6. Posts an enrichment comment to the Jira ticket
7. Labels the ticket: `True-Positive`, `Benign-Positive`, or `Unknown`

The SOC team's job is to **review the AI output, confirm or override the verdict, and handle True Positives** for escalation.

---

## Platform links

| Resource | URL / Location |
|---|---|
| Jira (SCDM project) | https://logicalisasia.atlassian.net/jira/servicedesk/projects/SCDM |
| SOC Platform web portal | https://soc-platform.yellowflower-c7c34b87.southeastasia.azurecontainerapps.io |
| Azure Log Analytics | Azure Portal → Log Analytics workspace → `a5be1877-ff08-4a4f-8fba-9b3e0664ded4` |

---

## Daily tasks

### 1. Review overnight triage queue (15–30 min)

Open Jira SCDM and filter by:
- **Label = `True-Positive`** — these need analyst review first. Confirm the verdict and escalate if necessary.
- **Label = `Unknown`** — the platform could not reach a verdict. These need manual IOC review.
- **Assignee = GSOC** — any ticket still assigned to GSOC without a label means the enrichment pipeline did not run (rare). Manually triage these.

**What to look for in the enrichment comment:**
- The `VERDICT:` line confirms what the AI decided
- The `MITRE ATT&CK Mapping:` section shows the suspected tactics — use this to prioritise True Positives
- The IOC block shows which specific indicators were flagged and by which source

### 2. Spot-check that enrichment is running (5 min)

Pick any 2–3 tickets created in the last 24 hours and confirm they have:
- [ ] An `=== L1 Triage Report (Automated) ===` comment
- [ ] A label (`True-Positive`, `Benign-Positive`, or `Unknown`)
- [ ] Priority set (not left as default "Medium" unless that's genuinely correct)

If tickets are missing comments or labels, flag to the platform administrator — do not triage manually until confirmed.

### 3. Confirm False Positives (5 min)

Tickets labelled `Benign-Positive` by the platform still require a brief analyst confirmation before closing:
- Glance at the IOC block and the MITRE mapping
- If you agree it's benign, close the ticket using the standard close workflow (Resolution Category: False Positive)
- If you disagree, re-label manually and escalate

---

## Weekly tasks

### 1. Verdict distribution review (Monday, 15 min)

In Jira, run a report or count for the past 7 days:
- How many `True-Positive` vs `Benign-Positive` vs `Unknown`?
- Is the `Unknown` count unusually high? (Indicates IOCs not covered by threat intel — flag to platform admin)
- Are any `True-Positive` tickets going unreviewed past 24 hours?

If the False Positive rate is above ~80% for a specific alert rule repeatedly across the week, flag the rule name to the platform administrator for suppression (the L2 suppression list is maintained in Confluence).

### 2. L2 Suppression list review (Wednesday, 10 min)

The platform automatically suppresses certain recurring false-positive alert types using a list maintained in Confluence. Weekly check:

- Open Confluence → SOC Runbooks → L2 Suppression List
- Review any entries added in the past week
- Confirm suppressed rules are still correct — remove entries for rules that are no longer false positives

If a new alert rule is generating consistent False Positives, add it to the suppression list in Confluence. The platform syncs from Confluence daily.

### 3. Scheduled reports verification (Friday, 10 min)

Log in to the SOC Platform web portal → **Reports** tab:
- Confirm the last scheduled report for each customer ran successfully (green status)
- If any report shows a failure, note the customer name and report time and flag to the platform administrator with that information
- Spot-check one delivered report (open the PDF/DOCX) to confirm it has data and looks correct

---

## Monthly tasks

### 1. Database backup (1st of each month, 10 min)

The platform stores customer configuration and report history in a database file on Azure. This is the one item not backed up automatically. **Back it up manually each month.**

Steps:
1. Log in to the **Azure Portal** (portal.azure.com)
2. Go to **Storage accounts** → search for `socplatformdata` (or ask your platform administrator for the exact name)
3. Navigate to **File shares** → `soc-platform-data` → `data/`
4. Download `soc_platform.db`
5. Save it to the shared drive at: `[Team SharePoint / Google Drive path — update with your team's location]`
   - Name the file `soc_platform_backup_YYYY-MM-DD.db`
   - Keep the last 3 months of backups; delete older ones

> If you cannot access Azure Storage, ask the platform administrator to do this step.

### 2. Report file cleanup (1st of each month, 5 min)

In the same Azure Files location (`soc-platform-data` → `data/reports/`):
- Delete report files older than 90 days
- This keeps storage costs down and prevents the share from filling up

### 3. Logo and asset check (quarterly is fine, but worth reviewing monthly)

In `soc-platform-data` → `data/logos/`:
- Confirm each active customer has a logo file
- Remove logos for customers who are no longer active

---

## Incident response: if the platform stops working

### Enrichment comments stop appearing on tickets

1. Check the last Jira ticket — does it have an enrichment comment at all?
2. If no comment for 2+ hours on new tickets: flag to platform administrator with the ticket keys affected and the approximate time it stopped
3. Do NOT triage manually while waiting — log the affected tickets so they can be re-run once the platform recovers

### Jira tickets not being created from Sentinel alerts

This is upstream of the SOC Platform (Sentinel Logic App, not the platform itself). Check:
1. Is Microsoft Sentinel showing the alert as fired?
2. If yes but no Jira ticket: flag to platform administrator — the Logic App or gateway may be down

### SOC Platform web portal not loading

Flag to platform administrator. The portal going down does not affect L1 Triage — enrichment and labelling run independently via the Jira webhook.

### Scheduled reports not delivering

1. Log in to the portal → Reports tab → check the status column
2. Screenshot the failure status and flag to platform administrator with the customer name and scheduled time

---

## Jira label reference

| Label | Meaning | What to do |
|---|---|---|
| `True-Positive` | AI confirmed malicious IOC | Review MITRE mapping, escalate if warranted, close after investigation |
| `Benign-Positive` | All IOCs checked and clean | Confirm briefly, close as False Positive |
| `Unknown` | No IOCs found or intel sources returned no data | Manual IOC review required |
| `[DUPLICATE]` in summary | Automatically detected duplicate of an existing ticket | Already auto-closed; no action needed |
| `auto-suppressed-tuning` | Suppressed by the L2 suppression list | Confirm suppression is still correct; no action otherwise |

---

## Escalation contacts

| Issue | Who to contact |
|---|---|
| Platform not enriching tickets | Platform administrator (Eugene) |
| Sentinel alert logic / Logic App | Sentinel team |
| Jira project config / permissions | Jira administrator |
| Threat intel source access (VirusTotal, AbuseIPDB, SOCRadar) | Platform administrator (Eugene) |
