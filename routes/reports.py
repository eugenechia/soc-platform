"""
Generate Report mode — structured, calendar-driven report generation.
"""
import os
import json
import uuid
import asyncio
import logging
import threading
import base64
from datetime import datetime
from io import BytesIO
import zipfile

from flask import Blueprint, render_template, session, request, jsonify, Response, send_file
from openai import AsyncAzureOpenAI

from routes.auth import require_login
from tools.jira_client import (fetch_incidents_for_report, fetch_incidents_from_csv,
                                fetch_service_requests, fetch_change_requests)
from tools.chart_generator import generate_all_charts
from tools import sentinel_client, splunk_client, socradar_rest as socradar_client
import tools.db as db

log = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")

JOB_TIMEOUT_SECONDS = 600

# In-memory job store (single replica = APScheduler constraint)
jobs: dict = {}

# LLM model: use AZURE_OPENAI_DEPLOYMENT if set, else gpt-4o
_LLM_MODEL = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")


REPORT_SECTIONS = [
    {"id": "introduction", "label": "1.1 Introduction", "source": "jira"},
    {"id": "incident_overview", "label": "1.2 Incident Overview", "source": "jira"},
    {"id": "incident_severity", "label": "1.3 Incident Severity", "source": "jira"},
    {"id": "incident_status", "label": "1.4 Incident Status", "source": "jira"},
    {"id": "incident_details", "label": "1.5 Incident Ticket Details", "source": "jira"},
    {"id": "sentinel_utilization", "label": "1.6 Sentinel Monthly Utilization", "source": "sentinel"},
    {"id": "top_alerts_sentinel", "label": "1.7 Top Alert Triggered on Sentinel", "source": "sentinel"},
    {"id": "total_assets", "label": "1.8 Total Assets Under Monitoring", "source": "sentinel"},
    {"id": "sensor_health", "label": "1.9 Managed Assets by Sensor Health State", "source": "sentinel"},
    {"id": "vulnerability_details", "label": "1.10 Vulnerability Details", "source": "sentinel"},
    {"id": "threat_analytics", "label": "1.11 Threat Analytics Hunting", "source": "sentinel"},
    {"id": "vulnerability_devices", "label": "1.12 Monthly Vulnerability Exposed Devices", "source": "sentinel"},
    {"id": "ioc_update", "label": "1.13 Indicators of Compromise (IOC) Update", "source": "sentinel"},
    {"id": "splunk_event_volume", "label": "Splunk Event Volume", "source": "splunk"},
    {"id": "splunk_top_alerts", "label": "Top Alerts from Splunk", "source": "splunk"},
    {"id": "pending_tickets", "label": "1.14 Pending Tickets", "source": "jira"},
    {"id": "monitoring_scope", "label": "1.15 GSOC Monitoring Scope", "source": "jira"},
    {"id": "recommendations", "label": "GSOC Recommendation Summary", "source": "jira"},
    {"id": "service_requests", "label": "1.17 Service Requests Summary", "source": "jira"},
    {"id": "change_requests", "label": "1.18 Change Requests Summary", "source": "jira"},
    {"id": "socradar_threat_intel", "label": "SOCRadar Threat Intelligence", "source": "socradar"},
]

_REPORT_TAIL = """
## References

- **Inactive devices**: Devices that may no longer be in use, were reinstalled or renamed, have been offboarded, or are not currently sending signals to the monitoring platform.
- **No sensor data**: Devices that are misconfigured or whose agents have stopped reporting. Remediation steps include verifying agent installation, checking network connectivity to the SIEM collector, and reviewing agent logs for errors.

For further guidance refer to the [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/).

## Confidentiality Statement

The contents of this document are confidential and proprietary to Logicalis. This document is submitted on the condition that the customer does not disclose the information contained herein to any third party without the written consent of Logicalis. By receiving Logicalis submission of this document, the customer further agrees not to disclose the contents hereof internally other than to those of its agents, principals, representatives, consultants or employees who need to know these contents for the purposes of the customer evaluation of the document.

The customer agrees to inform such persons of the confidential nature of the contents hereof and to obtain their agreement to preserve the confidentiality hereof to the same extent as the customer further agrees to treat the confidential information contained herein with at least the same level of care as it takes with respect to its own confidential information, but in no event with less than reasonable care.

© Logicalis {report_year}
"""

REPORT_SYSTEM_PROMPT = """You are a professional SOC report writer for Logicalis GSOC (Global Security Operations Centre).
You are generating a monthly security operations report for a client. Follow the exact structure and tone of the Logicalis GSOC Monthly Report template.

CRITICAL RULES:
- Write in a professional, third-person tone suitable for a client-facing security report
- Use markdown formatting throughout
- Include specific numbers, dates, and details from the provided data
- Do NOT fabricate or hallucinate data - use only what is provided
- For sections where the data source is NOT connected (marked as UNAVAILABLE below), generate a placeholder block exactly like this:
  > **Data Source Pending Integration** — This section requires data from [source name] which is not yet connected. Data will be populated once the integration is configured.
- If a data source IS connected but returned no data for the period (empty lists, zero counts), do NOT show the placeholder. Instead write a brief note such as: "No data was recorded for this section during the reporting period." Then continue with any context or analysis that can be drawn from zero activity.

REPORT CONTEXT:
- Customer: {customer_name}
- Report Period: {start_date} to {end_date}
- Report Type: {report_type}
- Available data sources: {available_sources}

SECTIONS TO GENERATE (in this exact order, using these exact headings):
{sections_list}

DATA PROVIDED:
{data_json}

SECTION-BY-SECTION INSTRUCTIONS:

**## Section 1. Executive Summary** (only if "introduction" or "incident_overview" is selected)
Start with a top-level heading "## Section 1. Executive Summary"

**### 1.1. Introduction** (if "introduction" is selected)
Write 2-3 paragraphs:
- First paragraph: "Logicalis is excited & honoured to share monthly report for {customer_name}, prepared by GSOC – our cybersecurity expert team. It provides data and information on activity observed during [month year]."
- Briefly describe what the report covers: incident triage, threat intelligence, monitoring status
- Mention the reporting period

**### 1.2. Incident Overview** (if "incident_overview" is selected)
Write 2-4 paragraphs covering:
- Total number of incidents triaged and reported by GSOC during the period
- Mention "Security Intelligence Platform ({customer_name} Microsoft Sentinel)" as the source
- Break down incidents by close justification (True Positive, False Positive, Benign Positive) with counts
- Mention Threat Intelligence reports shared on weekly/ad-hoc basis
- Confirm that all onboarded log sources are functioning optimally

**### 1.3. Incident Severity** (if "incident_severity" is selected)
- State total incidents by severity with exact counts
- List each severity level with count: Informational, Low, Medium, High, Critical
- Provide 2-3 paragraphs of analysis on severity trends
- Highlight which severity level was most common and what it means

**### 1.4. Incident Status** (if "incident_status" is selected)
- State total incidents categorized by status
- List: Pending, True Positive, False Positive, Benign Positive with counts
- Under "Key Insights:" provide analysis on:
  - Incident resolution rate (percentage closed)
  - True vs Benign Positive breakdown and implications

**### 1.5. Incident Ticket Details** (if "incident_details" is selected)
Present a markdown table with these exact columns: Incident ID | Date | Incident Subject | Category | Severity | Status | TP/FP/BP

IMPORTANT rules for this table:
- Include ALL incidents from the provided data — do not truncate, summarise, or omit any rows
- **Incident ID**: Use the ticket key exactly as provided (e.g. "CAM-11469")
- **Date**: Use the created date formatted as "d/m/YYYY H:MM" (e.g. "25/2/2026 6:18")
- **Incident Subject**: Use the FULL summary text as provided in the data. Do NOT shorten, truncate, or paraphrase it. Include the full text even if it is long.
- **Category**: Use the category/incident_type field (e.g. "Suspicious-activity", "Exfiltration", "DefenseEvasion"). If empty, use the labels field.
- **Severity**: Use the severity field exactly (e.g. "Medium", "Low", "High")
- **Status**: Use the status field exactly (e.g. "Closed", "Open", "Pending")
- **TP/FP/BP**: Use the close_justification field exactly (e.g. "Benign Positive", "True Positive", "False Positive")
- Sort rows by date descending (most recent first)

**### 1.6. Sentinel Monthly Utilization** (if "sentinel_utilization" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Total utilisation in GB, average daily utilisation, trend vs previous month.

**### 1.7. Top Alert Triggered on Sentinel** (if "top_alerts_sentinel" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Table showing top alerts with count, sorted by frequency.

**### 1.8. Total Assets Under Monitoring** (if "total_assets" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: State total asset count. Note: asset data may come from Microsoft Defender for Endpoint (DeviceInfo table) or CrowdStrike (CrowdStrikeHosts table) depending on the EDR deployed for this customer.

**### 1.9. Managed Assets by Sensor Health State** (if "sensor_health" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Table of devices with columns: Device Name | Last Update | OS Platform | Exposure Level | Health Status.
Note: if data comes from CrowdStrike (fields DeviceName, OnboardingStatus, HealthStatus, OSPlatform, ExposureLevel, LastSeen), map them directly. HealthStatus values are "Active" (seen within 7 days) or "Inactive".

**### 1.10. Vulnerability Details** (if "vulnerability_details" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Exposure score explanation, severity breakdown, Microsoft Secure Score details.

**### 1.11. Threat Analytics Hunting** (if "threat_analytics" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: The data contains threat intelligence indicators grouped by ObservableKey (STIX observable type, e.g. "network-traffic:src_ref.value", "url:value", "domain-name:value", "file:hashes.MD5").
Present a summary table with columns: Indicator Type | Count. Map STIX keys to human-readable labels (e.g. "network-traffic:src_ref.value" → "IP Address", "url:value" → "URL", "domain-name:value" → "Domain", "file:hashes.MD5" → "File Hash (MD5)", "file:hashes.'SHA-256'" → "File Hash (SHA-256)").
Follow with 2-3 paragraphs of analysis covering the distribution of indicator types and what they indicate about the threat landscape.

**### 1.12. Monthly Vulnerability Exposed Devices** (if "vulnerability_devices" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Statistics on exposed devices, recommendation to patch immediately.

**### 1.13. Indicators of Compromise (IOC) Update** (if "ioc_update" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: The data contains IOC entries with fields: Id, ObservableKey, ObservableValue, Pattern, Tags, Confidence, TimeGenerated.
Present a table with columns: Date | Indicator Type | Value | Confidence | Tags.
- Map ObservableKey to a human-readable Indicator Type (same mapping as 1.11 above)
- ObservableValue is the actual indicator value (IP, URL, domain, hash, etc.)
- Confidence is an integer 0-100; display as a percentage
- Tags is a comma-separated string; show the first 2-3 meaningful tags (skip internal ones like "p:default", "ic:*", "vic:*", "gid:*", "cid:*")
Follow with a paragraph describing the IOC hunting process and how indicators are added to the blocklist.

**### Splunk Event Volume** (if "splunk_event_volume" is selected, REQUIRES SPLUNK)
If Splunk is NOT connected (not listed in available data sources), show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Total event count ingested during the period, breakdown by index, and brief analysis of volume trends.

**### Top Alerts from Splunk** (if "splunk_top_alerts" is selected, REQUIRES SPLUNK)
If Splunk is NOT connected (not listed in available data sources), show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Table showing top Splunk correlation rules / notable events with count, sorted by frequency. Include severity breakdown if available.

**### 1.14. Pending Tickets** (if "pending_tickets" is selected)
Present a markdown table with columns: Incident ID | Incident Subject | Severity | Created | Status
Include only tickets with status "Pending" or "Open". If none, show a table with a single row: "- | No pending tickets | - | - | -"

**### 1.15. GSOC Monitoring Scope** (if "monitoring_scope" is selected)
Write: "Below are the log sources that are onboarded to Microsoft Sentinel SIEM currently for GSOC monitoring."
Then list common log sources as bullet points. If specific log source data is not available, list typical enterprise sources:
- Azure Activity, Azure Firewall, Microsoft 365, Microsoft Defender for Cloud Apps, Microsoft Defender for Endpoint, Microsoft Defender for Identity, Microsoft Defender XDR, Microsoft Entra ID, etc.

**## GSOC Recommendation Summary** (if "recommendations" is selected)

Analyse the incident data provided and generate 3-5 SPECIFIC, ACTIONABLE recommendations. Each recommendation must be grounded in a pattern observed in the data — do not fabricate generic advice.

Patterns to detect and act on:
- False Positive rate > 40% of closed incidents → recommend tuning the specific alert rules generating FPs
- Repeated True Positives of the same category (e.g. Exfiltration, DefenceEvasion) → recommend controls improvement or additional detection coverage
- High volume of Benign Positives → recommend allowlist/whitelist review for that alert type
- Pending/Open tickets older than reporting period → recommend SLA review or escalation process improvement
- Single severity level dominates (>70%) → recommend review of alert thresholds for that level
- If SOCRadar threat intelligence data is present → add one recommendation cross-referencing active threat actors with the customer's observed incident categories

For each recommendation assign a Priority: Critical / High / Medium.

Output format — present a markdown table with these exact columns:
S.No | Priority | Recommendation | Affected Area | GSOC Action | Customer Action | Status

- **S.No**: sequential number
- **Priority**: Critical / High / Medium
- **Recommendation**: concise description of the specific finding and what should be done
- **Affected Area**: the specific alert rule, incident category, or process area
- **GSOC Action**: what GSOC will do (e.g. "Tune correlation rule threshold", "Submit IOC to blocklist")
- **Customer Action**: what the customer must do (e.g. "Review allowlist entries", "Apply patch MS-XXXX")
- **Status**: New / Ongoing / Resolved

**### SOCRadar Threat Intelligence** (if "socradar_threat_intel" is selected, REQUIRES SOCRADAR)
If SOCRadar data is unavailable, show the placeholder block.
Otherwise, write 3-4 paragraphs covering:
1. **Company Alarms**: Summary of company-specific alarms/detections during the period (count, top types)
2. **Active Threat Actors**: Table with columns: Threat Actor | Origin | Target Industries | TTPs | Status. List top actors from socradar.threat_actors data.
3. **Critical CVEs**: Table with columns: CVE ID | CVSS Score | Affected Products | Exploit Available | Recommendation. List top CVEs from socradar.cve_intel.
4. **Dark Web Monitoring**: Summary of any dark web mentions, leaked credentials, or mentions of the company domain. If socradar.dark_web_alarms is empty, state "No dark web mentions detected during this period."
Close with a paragraph of analyst commentary tying SOCRadar intelligence to the observed incident patterns.

**### 1.17. Service Requests Summary** (if "service_requests" is selected)
If service_requests.unavailable is true, show the placeholder block noting the issue type is not configured in this Jira project.
Otherwise:
- State total Service Requests raised during the period
- Present a markdown table: SR ID | Subject | Priority | Status | Created | Assignee
- Include all items; if empty show "No service requests raised during this period."
- Provide a 1-paragraph summary of request trends (most common priority, most common status)

**### 1.18. Change Requests Summary** (if "change_requests" is selected)
If change_requests.unavailable is true, show the placeholder block noting the issue type is not configured in this Jira project.
Otherwise:
- State total Change Requests raised during the period
- Present a markdown table: CR ID | Subject | Priority | Status | Created | Assignee
- Include all items; if empty show "No change requests raised during this period."
- Provide a 1-paragraph summary noting change volume and any pending/open changes that require attention

IMPORTANT: Do NOT generate a table of contents. Do NOT generate a References section. Do NOT generate a Confidentiality Statement. Only generate the assigned sections listed above. These boilerplate sections will be appended automatically after all sections are combined.

SECTION HEADING FORMAT:
Each section heading must use an HTML anchor tag so the TOC links work:
### <a id="11-introduction"></a>1.1. Introduction
### <a id="12-incident-overview"></a>1.2. Incident Overview
etc.

The anchor id must exactly match the one used in the TOC link above.

**QUARTERLY REPORT MODE** (when report_type is "Quarterly Report")
When the report_type is "Quarterly Report", the data_json includes quarterly_data:
- quarterly_data.months: list of monthly summaries (month_label, total_incidents, by_severity, top_alerts)
- quarterly_data.quarter_label: e.g. "Q2 2026"
- quarterly_data.missing_months: list of month labels with no data

Write the report as a quarterly review:
1. Executive Summary: Overall Q totals, trend direction (improving/worsening), key themes
2. Month-by-Month Comparison: table with columns Month | Total Incidents | High+ | TP Rate | Top Alert
3. Trend Analysis: narrative on escalating/de-escalating threat categories across the 3 months
4. Highlight any months with missing data explicitly
5. Recommendations: based on the full quarter's patterns

Generate the complete report now."""


# ── Persistence helpers ────────────────────────────────────────────────────────

def _save_report(job_id: str, config: dict, markdown: str, data: dict,
                 charts: dict | None = None):
    charts_b64 = {}
    if charts:
        for name, png_bytes in charts.items():
            if png_bytes:
                charts_b64[name] = base64.b64encode(png_bytes).decode()
    report = {
        "id": job_id,
        "customer_id": config.get("customer_id", ""),
        "customer_name": config.get("customer_name", ""),
        "report_type": config.get("report_type", ""),
        "start_date": config.get("start_date", ""),
        "end_date": config.get("end_date", ""),
        "sections": config.get("sections", []),
        "customer_logo": config.get("customer_logo", ""),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "markdown": markdown,
        "data": data,
        "charts_b64": charts_b64,
    }
    filepath = os.path.join(REPORTS_DIR, f"{job_id}.json")
    with open(filepath, "w") as f:
        json.dump(report, f)
    try:
        db.save_report(report)
    except Exception as e:
        log.error(f"db.save_report failed: {e}")


def _load_reports_list(customer_id: str = "", start_date: str = "",
                       end_date: str = "", report_type: str = "") -> list:
    try:
        return db.load_reports_list(customer_id=customer_id, start_date=start_date,
                                    end_date=end_date, report_type=report_type)
    except Exception as e:
        log.error(f"db.load_reports_list failed, falling back to JSON: {e}")
    reports = []
    if not os.path.exists(REPORTS_DIR):
        return reports
    for fname in os.listdir(REPORTS_DIR):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(REPORTS_DIR, fname)) as f:
                r = json.load(f)
            reports.append({
                "id": r["id"],
                "customer_name": r.get("customer_name", ""),
                "report_type": r.get("report_type", ""),
                "start_date": r.get("start_date", ""),
                "end_date": r.get("end_date", ""),
                "generated_at": r.get("generated_at", ""),
            })
        except Exception:
            continue
    reports.sort(key=lambda x: x.get("generated_at", ""), reverse=True)
    return reports


def _load_report(report_id: str) -> dict | None:
    try:
        record = db.load_report(report_id)
        if record:
            return record
    except Exception as e:
        log.error(f"db.load_report failed, falling back to JSON: {e}")
    filepath = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if not os.path.exists(filepath):
        return None
    with open(filepath) as f:
        return json.load(f)


def _get_charts_bytes(report_or_job: dict) -> dict:
    if "charts" in report_or_job and isinstance(report_or_job["charts"], dict):
        return {k: v for k, v in report_or_job["charts"].items() if v}
    charts_b64 = report_or_job.get("charts_b64", {})
    return {k: base64.b64decode(v) for k, v in charts_b64.items() if v}


# ── Report generation logic ────────────────────────────────────────────────────

def _collect_quarterly_data(config: dict) -> dict:
    from calendar import monthrange
    from dateutil.relativedelta import relativedelta

    start_date = config.get("start_date", "")
    customer_id = config.get("customer_id", "")
    quarter_label = config.get("quarter_label", "")

    saved_reports = db.load_reports_list(
        customer_id=customer_id,
        start_date=start_date,
        end_date=config.get("end_date", ""),
        report_type="Monthly SOC Report",
    )

    try:
        qs = datetime.strptime(start_date, "%Y-%m-%d")
        expected_months = [
            (qs + relativedelta(months=i)).strftime("%Y-%m")
            for i in range(3)
        ]
    except Exception:
        expected_months = []

    monthly_summaries = []
    found_months = set()
    total_incidents = 0
    merged_severity: dict = {}
    merged_top_alerts: dict = {}

    for report_meta in saved_reports:
        full = db.load_report(report_meta["id"])
        if not full:
            continue
        stats = (full.get("data") or {}).get("stats") or {}
        report_start = report_meta.get("start_date", "")
        month_key = report_start[:7] if report_start else ""
        if month_key:
            found_months.add(month_key)

        month_total = stats.get("total", 0)
        total_incidents += month_total
        for sev, cnt in stats.get("by_severity", {}).items():
            merged_severity[sev] = merged_severity.get(sev, 0) + cnt
        for alert, cnt in stats.get("top_alerts", {}).items():
            merged_top_alerts[alert] = merged_top_alerts.get(alert, 0) + cnt

        try:
            month_label = datetime.strptime(report_start, "%Y-%m-%d").strftime("%B %Y")
        except Exception:
            month_label = month_key

        monthly_summaries.append({
            "month_label": month_label,
            "month_key": month_key,
            "total_incidents": month_total,
            "by_severity": stats.get("by_severity", {}),
            "top_alerts": stats.get("top_alerts", {}),
        })

    monthly_summaries.sort(key=lambda x: x.get("month_key", ""))
    missing_months = [
        datetime.strptime(m, "%Y-%m").strftime("%B %Y")
        for m in expected_months if m not in found_months
    ]

    return {
        "incidents": [],
        "stats": {
            "total": total_incidents,
            "by_severity": merged_severity,
            "by_close_justification": {},
            "top_alerts": merged_top_alerts,
            "monthly_trend": {},
        },
        "quarterly_data": {
            "quarter_label": quarter_label,
            "months": monthly_summaries,
            "missing_months": missing_months,
            "total_incidents": total_incidents,
        },
    }


def _collect_report_data(config: dict) -> dict:
    if config.get("report_type") == "Quarterly Report":
        return _collect_quarterly_data(config)

    project_key = config.get("jira_project_key", "")
    start_date = config.get("start_date", "")
    end_date = config.get("end_date", "")
    csv_path = config.get("csv_path", "")

    if csv_path:
        result = fetch_incidents_from_csv(project_key, start_date, end_date, csv_path=csv_path)
    else:
        result = fetch_incidents_for_report(project_key, start_date, end_date)

    if result.get("error"):
        log.error(f"Jira data collection error: {result['error']}")

    sections = config.get("sections", [])
    fetch_tasks = {}
    if config.get("use_sentinel"):
        fetch_tasks["sentinel"] = lambda: sentinel_client.fetch_data(config, start_date, end_date)
    if config.get("use_splunk"):
        fetch_tasks["splunk"] = lambda: splunk_client.fetch_data(config, start_date, end_date)
    if config.get("use_socradar"):
        fetch_tasks["socradar"] = lambda: socradar_client.fetch_data(config, start_date, end_date)
    if "service_requests" in sections and project_key:
        fetch_tasks["service_requests"] = lambda: fetch_service_requests(project_key, start_date, end_date)
    if "change_requests" in sections and project_key:
        fetch_tasks["change_requests"] = lambda: fetch_change_requests(project_key, start_date, end_date)

    if fetch_tasks:
        fetch_results: dict = {}
        fetch_errors: dict = {}

        def _run_task(key, fn):
            try:
                log.info(f"Fetching {key}...")
                fetch_results[key] = fn()
            except Exception as e:
                log.error(f"{key} fetch error: {e}")
                fetch_errors[key] = str(e)

        threads = [
            threading.Thread(target=_run_task, args=(k, v), daemon=True)
            for k, v in fetch_tasks.items()
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=180)

        result.update(fetch_results)
        for key, err in fetch_errors.items():
            result[f"{key}_error"] = err

    return result


def _build_report_context(data: dict, config: dict) -> dict:
    section_meta = {s["id"]: s for s in REPORT_SECTIONS}
    sections = config.get("sections", [])

    connected = ["Jira"]
    if data.get("sentinel"):
        connected.append("Microsoft Sentinel")
    if data.get("splunk"):
        connected.append("Splunk")
    if data.get("socradar"):
        connected.append("SOCRadar")

    source_notes = []
    for src_key, src_label in [("sentinel", "Microsoft Sentinel"), ("splunk", "Splunk"),
                                ("socradar", "SOCRadar")]:
        src_sections = [sid for sid in sections if section_meta.get(sid, {}).get("source") == src_key]
        if src_sections and src_label not in connected:
            err = data.get(f"{src_key}_error", "not connected")
            source_notes.append(f"{src_label} is NOT connected ({err}) — sections requiring it must show placeholder.")

    available_sources_str = ", ".join(f"{s} (connected)" for s in connected)
    if source_notes:
        available_sources_str += ". " + " ".join(source_notes)

    try:
        report_year = datetime.strptime(config.get("end_date", ""), "%Y-%m-%d").year
    except Exception:
        report_year = datetime.now().year

    jira_data = {
        "total_incidents": data.get("stats", {}).get("total", 0),
        "by_severity": data.get("stats", {}).get("by_severity", {}),
        "by_status": data.get("stats", {}).get("by_status", {}),
        "by_priority": data.get("stats", {}).get("by_priority", {}),
        "by_close_justification": data.get("stats", {}).get("by_close_justification", {}),
        "top_alerts": data.get("stats", {}).get("top_alerts", {}),
        "monthly_trend": data.get("stats", {}).get("monthly_trend", {}),
        "assignee_distribution": data.get("stats", {}).get("assignee_distribution", {}),
        "incident_details": [
            {
                "key": i["key"], "summary": i["summary"], "severity": i["severity"],
                "status": i["status"], "priority": i["priority"], "assignee": i["assignee"],
                "created": i["created"], "resolved": i["resolved"],
                "close_justification": i["close_justification"],
                "labels": i["labels"], "category": i.get("incident_type", ""),
            }
            for i in data.get("incidents", [])
        ],
    }

    sr = data.get("service_requests")
    if sr is not None:
        jira_data["service_requests"] = {
            "unavailable": sr.get("unavailable", False),
            "total": sr.get("stats", {}).get("total", 0),
            "items": [
                {"key": i["key"], "summary": i["summary"], "status": i["status"],
                 "priority": i["priority"], "created": i["created"]}
                for i in sr.get("items", [])
            ],
        }

    cr = data.get("change_requests")
    if cr is not None:
        jira_data["change_requests"] = {
            "unavailable": cr.get("unavailable", False),
            "total": cr.get("stats", {}).get("total", 0),
            "items": [
                {"key": i["key"], "summary": i["summary"], "status": i["status"],
                 "priority": i["priority"], "created": i["created"]}
                for i in cr.get("items", [])
            ],
        }

    if data.get("quarterly_data"):
        jira_data["quarterly_data"] = data["quarterly_data"]

    sentinel_data = {}
    sentinel = data.get("sentinel")
    if sentinel:
        sentinel_data = {
            "utilization_total_gb": sentinel.get("utilization", {}).get("total_gb"),
            "utilization_avg_daily_gb": sentinel.get("utilization", {}).get("avg_daily_gb"),
            "utilization_daily_breakdown": sentinel.get("utilization", {}).get("daily_breakdown", []),
            "top_alerts": sentinel.get("top_alerts", []),
            "total_assets": sentinel.get("total_assets"),
            "sensor_health": sentinel.get("sensor_health", []),
            "vulnerability_by_severity": sentinel.get("vulnerabilities", {}).get("by_severity", []),
            "vulnerability_exposed_devices": sentinel.get("vulnerabilities", {}).get("exposed_devices", []),
            "threat_analytics": sentinel.get("threat_analytics", []),
            "ioc_updates": sentinel.get("ioc_updates", []),
        }

    splunk_data = {}
    splunk = data.get("splunk")
    if splunk:
        splunk_data = {
            "total_events": splunk.get("event_volume", {}).get("total_events"),
            "events_by_index": splunk.get("event_volume", {}).get("by_index", []),
            "top_alerts": splunk.get("top_alerts", []),
            "severity_breakdown": splunk.get("severity_breakdown", []),
        }

    socradar_data = {}
    socradar = data.get("socradar")
    if socradar:
        socradar_data = {
            "company_alarms": socradar.get("company_alarms", []),
            "threat_actors": socradar.get("threat_actors", []),
            "cve_intel": socradar.get("cve_intel", []),
            "dark_web_alarms": socradar.get("dark_web_alarms", []),
        }

    return {
        "section_meta": section_meta,
        "sections": sections,
        "available_sources_str": available_sources_str,
        "report_year": report_year,
        "jira_data": jira_data,
        "sentinel_data": sentinel_data,
        "splunk_data": splunk_data,
        "socradar_data": socradar_data,
    }


def _build_unified_toc(content: str) -> str:
    import re
    content = re.sub(r'(?m)^## Contents\s*\n(?:(?!^##\s)[\s\S])*', '', content)
    for heading in ("References", "Confidentiality Statement"):
        content = re.sub(
            rf'(?m)^## {re.escape(heading)}\s*\n(?:(?!^##\s)[\s\S])*', '', content)
    content = content.strip()

    headings = re.findall(
        r'^#{1,4}\s+<a id="([^"]+)"></a>(.+?)$',
        content, flags=re.MULTILINE,
    )
    if not headings:
        return content

    toc_lines = ["## Contents\n"]
    for anchor_id, heading_text in headings:
        toc_lines.append(f"- [{heading_text.strip()}](#{anchor_id})")
    return "\n".join(toc_lines) + "\n\n" + content


def _azure_openai_client() -> AsyncAzureOpenAI:
    from tools.secrets import get_secret
    return AsyncAzureOpenAI(
        azure_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT", ""),
        api_key=get_secret("AZURE_OPENAI_API_KEY"),
        api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
    )


async def _generate_group(group_sections: list, data_subset: dict, ctx: dict, config: dict) -> str:
    if not group_sections:
        return ""

    section_meta = ctx["section_meta"]
    sections_list = "\n".join(
        f"- {section_meta[sid]['label']} (source: {section_meta[sid]['source']})"
        for sid in group_sections if sid in section_meta
    )

    prompt = REPORT_SYSTEM_PROMPT.format(
        customer_name=config.get("customer_name", "Client"),
        start_date=config.get("start_date", ""),
        end_date=config.get("end_date", ""),
        report_type=config.get("report_type", "Monthly SOC Report"),
        sections_list=sections_list,
        data_json=json.dumps(data_subset, indent=2),
        available_sources=ctx["available_sources_str"],
        report_year=ctx["report_year"],
    )

    client = _azure_openai_client()
    response = await client.chat.completions.create(
        model=_LLM_MODEL,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Generate the assigned report sections now."},
        ],
        max_tokens=16000,
    )
    return (response.choices[0].message.content or "").strip()


async def _run_report_agent(data: dict, config: dict) -> str:
    ctx = _build_report_context(data, config)
    sections = ctx["sections"]
    section_meta = ctx["section_meta"]

    jira_early = [s for s in sections if section_meta.get(s, {}).get("source") == "jira"
                  and s not in ("pending_tickets", "monitoring_scope", "recommendations",
                                "service_requests", "change_requests")]
    sentinel_grp = [s for s in sections if section_meta.get(s, {}).get("source") == "sentinel"]
    splunk_grp = [s for s in sections if section_meta.get(s, {}).get("source") == "splunk"]
    jira_late = [s for s in sections if s in ("pending_tickets", "monitoring_scope",
                                               "recommendations", "service_requests",
                                               "change_requests")]
    socradar_grp = [s for s in sections if section_meta.get(s, {}).get("source") == "socradar"]

    jira_payload = ctx["jira_data"]
    sentinel_payload = {"sentinel": ctx["sentinel_data"]} if ctx["sentinel_data"] else {}
    splunk_payload = {"splunk": ctx["splunk_data"]} if ctx["splunk_data"] else {}
    socradar_payload = {"socradar": ctx["socradar_data"]} if ctx["socradar_data"] else {}

    groups = [
        (jira_early, jira_payload),
        (sentinel_grp, sentinel_payload),
        (splunk_grp, splunk_payload),
        (jira_late, jira_payload),
        (socradar_grp, socradar_payload),
    ]
    active_groups = [(secs, payload) for secs, payload in groups if secs]

    tasks = [_generate_group(secs, payload, ctx, config) for secs, payload in active_groups]
    parts = await asyncio.gather(*tasks)

    assembled = "\n\n".join(p for p in parts if p.strip())
    assembled = _build_unified_toc(assembled)
    assembled += _REPORT_TAIL.format(report_year=ctx["report_year"])
    return assembled


def run_report_job(job_id: str, config: dict) -> None:
    def _timeout():
        if jobs.get(job_id, {}).get("status") == "running":
            log.warning(f"[{job_id[:8]}] Report job timed out")
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = "Report generation timed out after 10 minutes."

    timer = threading.Timer(JOB_TIMEOUT_SECONDS, _timeout)
    timer.daemon = True
    timer.start()

    log.info(f"[{job_id[:8]}] Report job started for {config.get('customer_name', 'unknown')}")
    try:
        jobs[job_id]["progress"] = "Collecting data..."
        data = _collect_report_data(config)

        if data.get("error") and not data.get("incidents"):
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = f"Failed to collect data: {data['error']}"
            return

        jobs[job_id]["progress"] = "Generating charts..."
        charts = {}
        if data.get("stats"):
            try:
                charts = generate_all_charts(data["stats"], end_date=config.get("end_date", ""))
                log.info(f"[{job_id[:8]}] Generated {len(charts)} charts")
            except Exception as e:
                log.error(f"[{job_id[:8]}] Chart generation failed: {e}")

        jobs[job_id]["progress"] = "Writing report sections..."
        output = asyncio.run(_run_report_agent(data, config))

        if jobs[job_id]["status"] == "running":
            jobs[job_id]["text"] = output
            jobs[job_id]["data"] = data
            jobs[job_id]["charts"] = charts
            jobs[job_id]["status"] = "done"
            _save_report(job_id, config, output, data, charts)
            log.info(f"[{job_id[:8]}] Report done, text_len={len(output)}")

    except Exception as e:
        log.error(f"[{job_id[:8]}] Exception: {e}")
        if jobs[job_id]["status"] == "running":
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = str(e)
    finally:
        timer.cancel()
        csv_path = config.get("csv_path", "")
        if csv_path and os.path.exists(csv_path):
            try:
                os.remove(csv_path)
            except OSError:
                pass


# ── Routes ────────────────────────────────────────────────────────────────────

@reports_bp.route("/")
@require_login
def index():
    return render_template("reports.html", user=session.get("user", {}), active_mode="reports")


@reports_bp.route("/api/sections")
@require_login
def api_sections():
    return jsonify(REPORT_SECTIONS)


@reports_bp.route("/api/generate", methods=["POST"])
@require_login
def generate():
    if request.content_type and "multipart/form-data" in request.content_type:
        customer_name = request.form.get("customer_name", "").strip()
        customer_id = request.form.get("customer_id", "").strip()
        jira_project_key = request.form.get("jira_project_key", "").strip()
        report_type = request.form.get("report_type", "Monthly SOC Report")
        start_date = request.form.get("start_date", "")
        end_date = request.form.get("end_date", "")
        quarter_label = request.form.get("quarter_label", "")
        sections_raw = request.form.get("sections", "")
        sections = json.loads(sections_raw) if sections_raw else []
        customer_logo = request.form.get("customer_logo", "")
        jira_source = request.form.get("jira_source", "api")
        use_sentinel = request.form.get("use_sentinel", "false").lower() == "true"
        use_splunk = request.form.get("use_splunk", "false").lower() == "true"
        use_socradar = request.form.get("use_socradar", "false").lower() == "true"
        csv_file = request.files.get("csv_file")
    else:
        body = request.json or {}
        customer_name = body.get("customer_name", "").strip()
        customer_id = body.get("customer_id", "").strip()
        jira_project_key = body.get("jira_project_key", "").strip()
        report_type = body.get("report_type", "Monthly SOC Report")
        start_date = body.get("start_date", "")
        end_date = body.get("end_date", "")
        quarter_label = body.get("quarter_label", "")
        sections = body.get("sections", [])
        customer_logo = body.get("customer_logo", "")
        jira_source = body.get("jira_source", "api")
        use_sentinel = bool(body.get("use_sentinel", False))
        use_splunk = bool(body.get("use_splunk", False))
        use_socradar = bool(body.get("use_socradar", False))
        csv_file = None

    if not customer_name:
        return jsonify({"error": "Customer name is required."}), 400
    if not start_date or not end_date:
        return jsonify({"error": "Date range is required."}), 400
    if not sections:
        return jsonify({"error": "At least one section must be selected."}), 400

    csv_path = ""
    if jira_source == "csv" and csv_file:
        upload_dir = os.path.join(DATA_DIR, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        csv_path = os.path.join(upload_dir, f"{uuid.uuid4()}.csv")
        csv_file.save(csv_path)
    elif jira_source == "csv" and not csv_file:
        return jsonify({"error": "CSV file is required when using CSV upload."}), 400

    job_id = str(uuid.uuid4())
    config = {
        "customer_name": customer_name,
        "customer_id": customer_id,
        "jira_project_key": jira_project_key,
        "report_type": report_type,
        "start_date": start_date,
        "end_date": end_date,
        "quarter_label": quarter_label,
        "sections": sections,
        "customer_logo": customer_logo,
        "csv_path": csv_path,
        "use_sentinel": use_sentinel,
        "use_splunk": use_splunk,
        "use_socradar": use_socradar,
    }
    jobs[job_id] = {
        "status": "running", "text": "", "data": None,
        "error": None, "progress": "", "charts": {}, "config": config,
    }

    threading.Thread(target=run_report_job, args=(job_id, config), daemon=True).start()
    return jsonify({"job_id": job_id})


@reports_bp.route("/api/generate-poll/<job_id>")
@require_login
def generate_poll(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job."}), 404
    return jsonify({
        "status": job["status"],
        "text": job["text"],
        "error": job["error"],
        "progress": job.get("progress", ""),
    })


@reports_bp.route("/api/reports", methods=["GET"])
@require_login
def api_reports_list():
    return jsonify(_load_reports_list())


@reports_bp.route("/api/reports/<report_id>", methods=["GET"])
@require_login
def api_reports_get(report_id):
    report = _load_report(report_id)
    if not report:
        return jsonify({"error": "Report not found."}), 404
    return jsonify(report)


@reports_bp.route("/api/reports/<report_id>", methods=["DELETE"])
@require_login
def api_reports_delete(report_id):
    filepath = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if not os.path.exists(filepath) and not db.load_report(report_id):
        return jsonify({"error": "Report not found."}), 404
    if os.path.exists(filepath):
        os.remove(filepath)
    try:
        db.delete_report(report_id)
    except Exception as e:
        log.error(f"db.delete_report failed: {e}")
    return jsonify({"ok": True})
