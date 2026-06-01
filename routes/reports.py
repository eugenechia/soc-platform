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
from tools.llm_client import make_chat_client

from routes.auth import require_login
from tools.jira_client import (fetch_incidents_for_report, fetch_incidents_from_csv,
                                fetch_service_requests, fetch_change_requests,
                                fetch_monthly_counts_12m, DEFAULT_INCIDENT_ISSUE_TYPE)
from tools.jira_verifier import verify_monthly_counts, format_verification_error
from tools.chart_generator import (
    generate_all_charts,
    generate_sentinel_utilization_chart,
    generate_top_alerts_chart,
    generate_total_assets_chart,
    generate_sensor_health_chart,
    generate_vulnerability_severity_chart,
    generate_vulnerability_exposed_devices_chart,
)
from tools import sentinel_client, defender_client, splunk_client, socradar_rest as socradar_client, tavily_client
from tools.customers import get_customer
from tools.customer_advisories import (
    load_threat_analytics_advisories,
    load_ioc_advisories,
)
from tools.sentinel_history import (
    load_historical_sentinel_data,
    load_sentinel_data_from_saved_report,
    is_outside_sentinel_retention,
)
import tools.db as db

log = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__)


def _render_socradar_alarms_html(alarms: list) -> str:
    """Pre-render the SOCRadar Company Alarms table as a single-line HTML
    string that markdown will pass through verbatim into the PDF.

    Why pre-render: when the LLM tried to emit this as a markdown pipe-table,
    rows containing long values (file paths, review notes) got line-wrapped
    mid-row, which the markdown `tables` extension can't parse — the PDF
    rendered the raw `|` characters instead of an actual table.

    Building the HTML in Python guarantees consistent formatting.
    """
    if not alarms:
        return ""

    import html as _html

    def _cell(value: str, max_chars: int = 60) -> str:
        s = str(value or "").strip()
        if len(s) > max_chars:
            s = s[:max_chars - 1] + "…"
        return _html.escape(s)

    def _status(raw: str) -> str:
        # SOCRadar returns SCREAMING_SNAKE_CASE — humanise.
        s = (raw or "").replace("_", " ").strip().title()
        return _cell(s, 24)

    def _file_from(alarm: dict) -> str:
        c = alarm.get("content") or {}
        if isinstance(c, dict):
            return c.get("file_name") or c.get("filename") or ""
        return ""

    def _date(raw: str) -> str:
        return _cell((raw or "")[:16], 18)  # YYYY-MM-DD HH:MM

    rows_html = []
    for a in alarms:
        if not isinstance(a, dict):
            continue
        rows_html.append(
            "<tr>"
            f"<td>{_cell(a.get('alarm_id'), 12)}</td>"
            f"<td>{_date(a.get('date'))}</td>"
            f"<td>{_cell(a.get('alarm_asset'), 22)}</td>"
            f"<td>{_cell(_file_from(a), 36)}</td>"
            f"<td>{_cell(a.get('alarm_risk_level'), 10)}</td>"
            f"<td>{_status(a.get('status'))}</td>"
            "</tr>"
        )

    if not rows_html:
        return ""

    return (
        '<table class="socradar-alarms">'
        "<thead><tr>"
        "<th>Alarm ID</th><th>Date</th><th>Asset</th>"
        "<th>File / Source</th><th>Risk</th><th>Status</th>"
        "</tr></thead>"
        "<tbody>" + "".join(rows_html) + "</tbody>"
        "</table>"
    )


# Sentinel marker for the pre-rendered incident details table. The LLM is told
# to emit this token verbatim where the table belongs; after section assembly
# we swap it for the HTML rendered by `_render_incident_details_html`. This
# keeps a 1,400-row table out of the LLM output budget (max_completion_tokens=
# 16000), which was previously truncating the table with a "..." row and a "for
# brevity" warning.
INCIDENT_DETAILS_TOKEN = "<!--INCIDENT_DETAILS_TABLE-->"

# Same pattern for pending tickets. Ticket summaries contain literal `|`
# characters (e.g. "LTW | LOGICALIS-27964 | LOW | AD account...") which
# break markdown pipe-tables when the LLM emits them — pipes get parsed as
# column separators and the row's cells shift one column right. Pre-rendered
# HTML cells side-step that entirely.
PENDING_TICKETS_TOKEN = "<!--PENDING_TICKETS_TABLE-->"


def _render_incident_details_html(incidents: list) -> str:
    """Pre-render the full Incident Ticket Details table as HTML.

    Same rationale as `_render_socradar_alarms_html` — but the row count is
    much higher (1,400+), so we must NEVER ask the LLM to emit this verbatim
    in the prompt. Caller swaps INCIDENT_DETAILS_TOKEN for this string after
    the LLM has produced the section heading + intro.

    Columns / formatting match the previous Section 1.5 prompt:
      Incident ID | Date | Incident Subject | Category | Severity | Status | TP/FP/BP
    """
    if not incidents:
        return ""

    import html as _html
    from dateutil.parser import parse as _dateparse

    def _fmt_date(raw: str) -> str:
        if not raw:
            return ""
        try:
            dt = _dateparse(raw)
            return dt.strftime("%-d/%-m/%Y %-H:%M")
        except Exception:
            return str(raw)[:19]

    def _category(rec: dict) -> str:
        cat = (rec.get("category") or "").strip()
        if cat:
            return cat
        labels = rec.get("labels") or []
        if isinstance(labels, list):
            return ", ".join(str(l) for l in labels[:3])
        return str(labels)

    def _esc(value) -> str:
        return _html.escape(str(value or "").strip())

    sortable = []
    for rec in incidents:
        if not isinstance(rec, dict):
            continue
        try:
            sort_key = _dateparse(rec.get("created") or "")
        except Exception:
            sort_key = datetime.min
        sortable.append((sort_key, rec))
    sortable.sort(key=lambda pair: pair[0], reverse=True)

    rows_html = []
    for _, rec in sortable:
        rows_html.append(
            "<tr>"
            f"<td>{_esc(rec.get('key'))}</td>"
            f"<td>{_esc(_fmt_date(rec.get('created')))}</td>"
            f"<td>{_esc(rec.get('summary'))}</td>"
            f"<td>{_esc(_category(rec))}</td>"
            f"<td>{_esc(rec.get('severity'))}</td>"
            f"<td>{_esc(rec.get('status'))}</td>"
            f"<td>{_esc(rec.get('close_justification'))}</td>"
            "</tr>"
        )

    if not rows_html:
        return ""

    return (
        '<table class="incident-details">'
        "<thead><tr>"
        "<th>Incident ID</th><th>Date</th><th>Incident Subject</th>"
        "<th>Category</th><th>Severity</th><th>Status</th><th>TP/FP/BP</th>"
        "</tr></thead>"
        "<tbody>" + "".join(rows_html) + "</tbody>"
        "</table>"
    )


def _render_pending_tickets_html(pending: list) -> str:
    """Pre-render the Pending Tickets table as HTML.

    Columns match the previous Section 1.8 prompt:
      Incident ID | Incident Subject | Severity | Created | Status

    Sorted by created date descending (most recent first).
    """
    if not pending:
        return (
            '<table class="pending-tickets">'
            "<thead><tr>"
            "<th>Incident ID</th><th>Incident Subject</th>"
            "<th>Severity</th><th>Created</th><th>Status</th>"
            "</tr></thead>"
            '<tbody><tr><td colspan="5" style="text-align:center;">'
            "No pending tickets."
            "</td></tr></tbody>"
            "</table>"
        )

    import html as _html
    from dateutil.parser import parse as _dateparse

    def _esc(value) -> str:
        return _html.escape(str(value or "").strip())

    def _fmt_created(raw: str) -> str:
        if not raw:
            return ""
        try:
            return _dateparse(raw).strftime("%Y-%m-%d %H:%M")
        except Exception:
            return str(raw)[:19]

    sortable = []
    for rec in pending:
        if not isinstance(rec, dict):
            continue
        try:
            sort_key = _dateparse(rec.get("created") or "")
        except Exception:
            sort_key = datetime.min
        sortable.append((sort_key, rec))
    sortable.sort(key=lambda pair: pair[0], reverse=True)

    rows_html = []
    for _, rec in sortable:
        rows_html.append(
            "<tr>"
            f"<td>{_esc(rec.get('key'))}</td>"
            f"<td>{_esc(rec.get('summary'))}</td>"
            f"<td>{_esc(rec.get('severity'))}</td>"
            f"<td>{_esc(_fmt_created(rec.get('created')))}</td>"
            f"<td>{_esc(rec.get('status'))}</td>"
            "</tr>"
        )

    return (
        '<table class="pending-tickets">'
        "<thead><tr>"
        "<th>Incident ID</th><th>Incident Subject</th>"
        "<th>Severity</th><th>Created</th><th>Status</th>"
        "</tr></thead>"
        "<tbody>" + "".join(rows_html) + "</tbody>"
        "</table>"
    )

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")

JOB_TIMEOUT_SECONDS = 600

# In-memory job store (single replica = APScheduler constraint)
jobs: dict = {}

# LLM client + model are resolved at call time via tools.llm_client.make_chat_client(),
# which detects the provider from env (AZURE_OPENAI_ENDPOINT vs OPENAI_COMPAT_BASE_URL
# vs OPENAI_API_KEY). No module-level constant — different providers use different
# model identifiers and we don't want to bake one in at import time.


REPORT_SECTIONS = [
    {"id": "introduction", "label": "1.1 Introduction", "source": "jira"},
    {"id": "incident_overview", "label": "1.2 Incident Overview", "source": "jira"},
    {"id": "incident_severity", "label": "1.3 Incident Severity", "source": "jira"},
    {"id": "incident_status", "label": "1.4 Incident Status", "source": "jira"},
    {"id": "incident_details", "label": "1.5 Incident Ticket Details", "source": "jira"},
    {"id": "service_requests", "label": "1.6 Service Requests Summary", "source": "jira"},
    {"id": "change_requests", "label": "1.7 Change Requests Summary", "source": "jira"},
    {"id": "pending_tickets", "label": "1.8 Pending Tickets", "source": "jira"},
    {"id": "monitoring_scope", "label": "1.9 GSOC Monitoring Scope", "source": "jira"},
    {"id": "recommendations", "label": "GSOC Recommendation Summary", "source": "jira"},
    {"id": "sentinel_utilization", "label": "1.10 Sentinel Monthly Utilization", "source": "sentinel"},
    {"id": "top_alerts_sentinel", "label": "1.11 Top Alert Triggered on Sentinel", "source": "sentinel"},
    {"id": "total_assets", "label": "1.12 Total Assets Under Monitoring", "source": "sentinel"},
    {"id": "sensor_health", "label": "1.13 Managed Assets by Sensor Health State", "source": "sentinel"},
    {"id": "vulnerability_details", "label": "1.14 Vulnerability Details", "source": "sentinel"},
    {"id": "threat_analytics", "label": "1.15 Threat Analytics Hunting", "source": "sentinel"},
    {"id": "vulnerability_devices", "label": "1.16 Monthly Vulnerability Exposed Devices", "source": "sentinel"},
    {"id": "ioc_update", "label": "1.17 Indicators of Compromise (IOC) Update", "source": "sentinel"},
    {"id": "splunk_event_volume", "label": "Splunk Event Volume", "source": "splunk"},
    {"id": "splunk_top_alerts", "label": "Top Alerts from Splunk", "source": "splunk"},
    {"id": "socradar_threat_intel", "label": "SOCRadar Threat Intelligence", "source": "socradar"},
    {"id": "industry_threat_intel", "label": "Industry Threat Landscape", "source": "general"},
]

_REPORT_TAIL = """
## References

- **Inactive devices**: Devices that may no longer be in use, were reinstalled or renamed, have been offboarded, or are not currently sending signals to the monitoring platform.
- **No sensor data**: Devices that are misconfigured or whose agents have stopped reporting. Remediation steps include verifying agent installation, checking network connectivity to the SIEM collector, and reviewing agent logs for errors.

## Confidentiality Statement

The contents of this document are confidential and proprietary to Logicalis. This document is submitted on the condition that the customer does not disclose the information contained herein to any third party without the written consent of Logicalis. By receiving Logicalis submission of this document, the customer further agrees not to disclose the contents hereof internally other than to those of its agents, principals, representatives, consultants or employees who need to know these contents for the purposes of the customer evaluation of the document.

The customer agrees to inform such persons of the confidential nature of the contents hereof and to obtain their agreement to preserve the confidentiality hereof to the same extent as the customer further agrees to treat the confidential information contained herein with at least the same level of care as it takes with respect to its own confidential information, but in no event with less than reasonable care.

© Logicalis {report_year}
"""

REPORT_SYSTEM_PROMPT = """You are a professional SOC report writer for Logicalis GSOC (Global Security Operations Centre).
You are generating a monthly security operations report for a client. Follow the exact structure and tone of the Logicalis GSOC Monthly Report template.

CRITICAL RULES:
- **Generate ONLY the sections listed in `SECTIONS TO GENERATE` below.** Other section descriptions appear later in this prompt as a reference template — do NOT generate them. If a section is not in `SECTIONS TO GENERATE`, omit it entirely.
- **Do NOT write any closing markers, terminators, or footers.** Do not write phrases like "End of Report Section", "End of Document", "End of Report", "---", or any goodbye/signature line. End your output immediately after the last assigned section's content.
- Write in a professional, third-person tone suitable for a client-facing security report
- Use markdown formatting throughout
- Include specific numbers, dates, and details from the provided data
- Do NOT fabricate or hallucinate data - use only what is provided
- For an assigned section whose data source is NOT connected (marked as UNAVAILABLE below), generate a placeholder block exactly like this:
  > **Data Source Pending Integration** — This section requires data from [source name] which is not yet connected. Data will be populated once the integration is configured.
- If a data source IS connected but returned no data for the period (empty lists, zero counts), do NOT show the placeholder. Instead write a brief note such as: "No data was recorded for this section during the reporting period." Then continue with any context or analysis that can be drawn from zero activity.

REPORT CONTEXT:
- Customer: {customer_name}
- Customer Industry: {customer_industry}
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
The full incident table is pre-rendered as HTML in Python (covering every incident, sorted by date descending) and will be substituted in by the report assembly step. Do NOT generate the table yourself — generating it would exceed your output token budget and cause truncation.

Output exactly these three things, in order, and nothing else for this section:
1. The heading line: `### <a id="15-incident-ticket-details"></a>1.5. Incident Ticket Details`
2. A single sentence stating the total number of incidents listed in the table (use the `incident_details` array length from the data).
3. The literal token `<!--INCIDENT_DETAILS_TABLE-->` on its own line. Output it character-for-character — including the `<!--` and `-->` — exactly as shown.

Do NOT emit any markdown table for this section. Do NOT paraphrase the rows. Do NOT comment on individual incidents — that belongs in the analysis sections (Severity, Status, Recommendations).

**### 1.6. Service Requests Summary** (if "service_requests" is selected)
If service_requests.unavailable is true, show the placeholder block noting the issue type is not configured in this Jira project.
Otherwise:
- State total Service Requests raised during the period
- Present a markdown table: SR ID | Subject | Priority | Status | Created | Assignee
- Include all items; if empty show "No service requests raised during this period."
- Provide a 1-paragraph summary of request trends (most common priority, most common status)

**### 1.7. Change Requests Summary** (if "change_requests" is selected)
If change_requests.unavailable is true, show the placeholder block noting the issue type is not configured in this Jira project.
Otherwise:
- State total Change Requests raised during the period
- Present a markdown table: CR ID | Subject | Priority | Status | Created | Assignee
- Include all items; if empty show "No change requests raised during this period."
- Provide a 1-paragraph summary noting change volume and any pending/open changes that require attention

**### 1.10. Sentinel Monthly Utilization** (if "sentinel_utilization" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise:
- State the total ingestion for the period (in GB) and the average daily ingestion (in GB/day).
- Identify the top 3 spike days from utilization_top_spike_days (if non-empty) and write a one-sentence comment about them — what dates they occurred and the GB value.
- Do NOT render any per-day table or list. The chart visualises the daily curve; a tabular daily breakdown would be redundant and noisy in the PDF.

**### 1.11. Top Alert Triggered on Sentinel** (if "top_alerts_sentinel" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Table showing top alerts with count, sorted by frequency.

**### 1.12. Total Assets Under Monitoring** (if "total_assets" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block.
Otherwise, write the section based on the value of sentinel.total_assets_source. Substitute the actual integer from sentinel.total_assets where the text below says N:
- If total_assets_source is "mde": State "N endpoints are under Microsoft Defender for Endpoint monitoring." with 1-2 sentences of analysis.
- If total_assets_source is "crowdstrike": State "N endpoints are under CrowdStrike Falcon monitoring." with 1-2 sentences of analysis.
- If total_assets_source is "heartbeat": State "N servers/VMs are reporting via Sentinel agent heartbeat for this period." Then add a separate paragraph: "**Note**: Endpoint Detection and Response (EDR) — Microsoft Defender for Endpoint or CrowdStrike — is not currently connected for this customer. The figure above reflects Sentinel agent presence (Heartbeat table) rather than EDR-managed endpoints. To populate this section with full EDR asset visibility, enable the Microsoft Defender XDR connector in Sentinel."
- If total_assets_source is "none": State "Endpoint asset visibility is currently unavailable. Microsoft Defender for Endpoint (DeviceInfo), CrowdStrike (CrowdStrikeHosts), and Sentinel agent heartbeat (Heartbeat) all returned no data for this period. **Recommended action**: verify agent deployment to monitored systems, OR enable an EDR connector (Microsoft Defender XDR or CrowdStrike Falcon) in Sentinel."

**### 1.13. Managed Assets by Sensor Health State** (if "sensor_health" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block.
Otherwise, render based on sentinel.sensor_health_source:
- If sensor_health_source is "mde" or "crowdstrike": Table of devices with columns: Device Name | Last Update | OS Platform | Exposure Level | Health Status. Map fields directly from the data.
- If sensor_health_source is "heartbeat": Render a table titled "**Sentinel Agent Heartbeat (EDR not connected)**" with columns: Computer | OS | Last Heartbeat | Status. Use DeviceName, OSPlatform, LastSeen (formatted YYYY-MM-DD HH:MM), and HealthStatus from the data. After the table, add: "**Note**: This table reflects Sentinel agent (Microsoft Monitoring Agent / Azure Monitor Agent) heartbeat status, not EDR sensor health. To enable EDR sensor health visibility, connect Microsoft Defender for Endpoint or CrowdStrike to this customer's Sentinel workspace."
- If sensor_health_source is "none": State "Sensor health visibility is currently unavailable. Neither Microsoft Defender for Endpoint, CrowdStrike, nor Sentinel agent heartbeat returned device data for this period. **Recommended action**: verify Sentinel agent installation OR enable an EDR connector."

**### 1.14. Vulnerability Details** (if "vulnerability_details" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block.
Otherwise, render based on whether `sentinel.vulnerability_by_severity` is populated:

- **If populated**, produce these four blocks in this exact order. The narrative blocks are MANDATORY — do not skip them, do not paraphrase the Secure Score explainer, do not condense the three factors into one sentence:

  1. **Sub-heading** `#### Exposure Score` followed by exactly these two paragraphs (substitute `{customer_name}` literally):

     > Microsoft Secure Score is a measurement of an organisation's security posture, with a higher number indicating more improvement actions to implement. GSOC provides a weekly Vulnerability Report for {customer_name} to reduce the score and prevent any exploit from the exposed devices.
     >
     > Microsoft Secure Score is based on three important factors:
     >
     > - **Threat** — Characteristics of the vulnerabilities and exploits in your organisation's devices and breach history. Based on these factors, the security recommendations show the corresponding links to active alerts, ongoing threat campaigns, and their corresponding threat-analytic reports.
     > - **Breach likelihood** — Your organisation's security posture and resilience against threats.
     > - **Business value** — Your organisation's assets, critical processes, and intellectual properties.

  2. The transitional sentence (verbatim, with `{customer_name}` substituted):

     > Following chart provides an overview of {customer_name} vulnerability details by severity.

  3. A markdown table titled `**Vulnerability counts by severity**` with columns `Severity | Count`, rows derived from `sentinel.vulnerability_by_severity` (sort Critical → High → Medium → Low → Informational → Unspecified; only include severities with count > 0). The chart for this section is auto-injected by the export layer immediately after the heading — do NOT attempt to embed it yourself.

  4. The closing sentence (verbatim):

     > Please refer to the attached Vulnerability Report for the full per-device breakdown.

- **If empty**: State "Vulnerability intelligence is currently unavailable for this customer. This section is populated by Microsoft Defender for Endpoint with the Threat & Vulnerability Management (TVM) module — specifically the `DeviceTvmSoftwareVulnerabilities` table. TVM is not currently active for this customer's Sentinel workspace. **Recommended action**: enable Microsoft Defender XDR's TVM module to populate this section."

**### 1.15. Threat Analytics Hunting** (if "threat_analytics" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block.

Produce the section in two distinct parts, in this exact order:

**Part A — Microsoft Defender XDR Threat Analytics (advisory-driven)**

1. Open with one short paragraph defining Microsoft Defender XDR Threat Analytics. Use this verbatim:
   > Microsoft Defender XDR Threat Analytics is an in-product threat-intelligence solution from Microsoft security researchers. It surfaces active threat actors and their campaigns, popular and emerging attack techniques, critical vulnerabilities, common attack surfaces, and prevalent malware. GSOC hunts each published advisory across the {customer_name} estate via MDE/Sentinel and records the outcome.

2. Then render a markdown table with columns: `Threat | Report Type | Published | Hunting Result`. Source the rows from `customer_advisories.threat_analytics` (each row has `threat`, `report_type`, `published`, `hunting_result`). Sort by `published` descending.

3. If `customer_advisories.threat_analytics` is empty, replace the table with this line and skip to Part B:
   > No Microsoft Defender XDR Threat Analytics advisories were tracked for this customer during the reporting period. To enable this view, GSOC maintains the advisory feed at `data/{{customer-slug}}/threat_analytics_advisories.json`.

**Part B — Threat Intelligence Indicator Coverage (STIX feed summary)**

1. Sub-heading `#### Threat Intelligence Indicator Coverage`.

2. One short paragraph stating the total count of indicators ingested for hunting/correlation across the period.

3. A markdown summary table from `sentinel.threat_analytics` (grouped by STIX ObservableKey) with columns: `Indicator Type | Count`. Map STIX keys to human-readable labels:
   - `network-traffic:src_ref.value` → "IP Address"
   - `url:value` → "URL"
   - `domain-name:value` → "Domain"
   - `file:hashes.MD5` → "File Hash (MD5)"
   - `file:hashes.'SHA-1'` → "File Hash (SHA-1)"
   - `file:hashes.'SHA-256'` → "File Hash (SHA-256)"
   - `x509-certificate:hashes.'SHA-1'` → "Certificate Hash (SHA-1)"
   - `email-addr:value` → "Email Address"
   - `ipv4-addr:value` → "IP Address (IPv4)"
   - `ipv6-addr:value` → "IP Address (IPv6)"
   - For any unmapped key, render the key verbatim.

4. One short paragraph (2-3 sentences) commenting on what the indicator-type mix says about the active threat landscape — what's dominant and what it implies for detection coverage. Do NOT repeat the table content row-by-row in prose.

**### 1.16. Monthly Vulnerability Exposed Devices** (if "vulnerability_devices" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block.
Otherwise, render based on whether `sentinel.vulnerability_exposed_devices` is populated:
- If populated: Statistics on exposed devices, recommendation to patch immediately.
- If empty: State "Per-device vulnerability exposure data is currently unavailable. This section requires Microsoft Defender for Endpoint with the Threat & Vulnerability Management (TVM) module — specifically the `DeviceTvmSoftwareVulnerabilities` table. TVM is not currently active for this customer. **Recommended action**: enable Microsoft Defender XDR's TVM module to populate this section."

**### 1.17. Indicators of Compromise (IOC) Update** (if "ioc_update" is selected, REQUIRES SENTINEL)
If Microsoft Sentinel is NOT connected, show the placeholder block.

Produce the section in two distinct parts, in this exact order:

**Part A — External Advisories Actioned**

1. Open with one short paragraph stating that {customer_name} forwards external advisories (e.g. regulator circulars such as MASNET MAS-Tx, ISAC bulletins, vendor advisories) to GSOC for hunting and indicator ingestion.

2. A markdown table with columns: `Advisory | Date | Hunt Outcome`. Source the rows from `customer_advisories.ioc` (each row has `advisory`, `date`, `hunt_outcome`). Sort by `date` descending.

3. If `customer_advisories.ioc` is empty, replace the table with this line:
   > No external advisories were forwarded for hunting during this reporting period. GSOC maintains the advisory feed at `data/{{customer-slug}}/ioc_advisories.json`.

4. After the table (or the empty-state line), include these two bullets verbatim — they describe the standing process:
   > - **Hunting** — GSOC searches each indicator across MDE and Sentinel over a 30-day rolling window and records any observed matches.
   > - **Adding Indicator** — All actionable IOCs are added to the MDE Indicators allowlist/blocklist. On detection, the configured action (block, remediate, alert) is enforced and an incident is raised.

**Part B — Indicator Repository Updates (Sentinel TI feed)**

1. Sub-heading `#### Indicator Repository Updates`.

2. One short paragraph stating the total IOC count added to the TI repository during the period, drawn from the length of `sentinel.ioc_updates`.

3. A markdown table with columns: `Date | Indicator Type | Value | Confidence | Tags`. Source rows from `sentinel.ioc_updates` (fields: `Id`, `ObservableKey`, `ObservableValue`, `Pattern`, `Tags`, `Confidence`, `TimeGenerated`).
   - Map `ObservableKey` to a human-readable Indicator Type (same mapping as §1.15 above).
   - `ObservableValue` is the actual indicator value (IP, URL, domain, hash, etc.).
   - `Confidence` is an integer 0-100; display as a percentage (e.g. "100%").
   - `Tags` is a comma-separated string; show the first 2-3 meaningful tags (skip internal ones like `p:default`, `ic:*`, `vic:*`, `gid:*`, `cid:*`).
   - **Cap the table at 50 rows** — append a final note "_…and N additional indicators._" if there are more, where N is the overflow count. The full list lives in the SIEM and is not duplicated here.

**### Splunk Event Volume** (if "splunk_event_volume" is selected, REQUIRES SPLUNK)
If Splunk is NOT connected (not listed in available data sources), show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Total event count ingested during the period, breakdown by index, and brief analysis of volume trends.

**### Top Alerts from Splunk** (if "splunk_top_alerts" is selected, REQUIRES SPLUNK)
If Splunk is NOT connected (not listed in available data sources), show the placeholder block. If connected but no data for the period, write a brief note stating no activity was recorded.
Otherwise: Table showing top Splunk correlation rules / notable events with count, sorted by frequency. Include severity breakdown if available.

**### 1.8. Pending Tickets** (if "pending_tickets" is selected)
The pending tickets table is pre-rendered as HTML in Python (covering every non-closed ticket, sorted by created date descending) and will be substituted in by the report assembly step. Do NOT generate the table yourself — ticket summaries contain literal pipe characters that break markdown table rendering.

Output exactly these three things, in order, and nothing else for this section:
1. The heading line: `### <a id="18-pending-tickets"></a>1.8. Pending Tickets`
2. A single sentence stating the total number of pending tickets (use the `pending_tickets` array length from the data).
3. The literal token `<!--PENDING_TICKETS_TABLE-->` on its own line. Output it character-for-character — including the `<!--` and `-->` — exactly as shown.

Do NOT emit any markdown table for this section. Do NOT paraphrase the rows.

**### 1.9. GSOC Monitoring Scope** (if "monitoring_scope" is selected)
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
Otherwise, write the section in this exact order:

1. **Company Alarms**:
   - First, write 1–2 sentences summarising the count of company alarms and the dominant risk levels (e.g. "SOCRadar registered 8 company alarms during the period, all classified as HIGH risk.").
   - Then, on a new line, INSERT THE EXACT VALUE of `socradar.company_alarms_html_table` VERBATIM. Do not modify it, do not re-format the rows, do not wrap it in code fences, do not paraphrase the values. The table is pre-rendered HTML and must reach the PDF unchanged.
   - After the table, write 1 sentence noting any patterns (e.g. all related to one repository, mostly closed as false positives, etc.).
2. **Active Threat Actors**: Table with columns: Threat Actor | Origin | Target Industries | TTPs | Status. List top actors from socradar.threat_actors data.
3. **Critical CVEs**: Table with columns: CVE ID | CVSS Score | Affected Products | Exploit Available | Recommendation. List top CVEs from socradar.cve_intel.
4. **Dark Web Monitoring**: Summary of any dark web mentions, leaked credentials, or mentions of the company domain. If socradar.dark_web_alarms is empty, state "No dark web mentions detected during this period."
Close with a paragraph of analyst commentary tying SOCRadar intelligence to the observed incident patterns.

**### Industry Threat Landscape** (if "industry_threat_intel" is selected)
If industry_intel.industry is empty or not provided, write: "The customer's industry has not been configured. Please update the customer profile to enable industry-specific threat intelligence."
Otherwise, write a current threat intelligence briefing for the {customer_industry} sector. Structure it as follows:

1. **Sector Overview**: 1-2 paragraphs summarising the current cybersecurity threat climate for the {customer_industry} sector, drawing from the web intelligence in industry_intel.web_intel. Focus on the most prominent threat themes from the reporting period.
2. **Active Threat Actors**: Table with columns: Threat Actor | Origin | TTPs | Notable Activity. Use industry_intel.threat_actors if non-empty; otherwise derive top actors from the web intelligence. Limit to 5-8 actors.
3. **Key Risks and Vulnerabilities**: 1 paragraph covering the top attack vectors, vulnerabilities, and compliance pressures specific to this sector.
4. **Defensive Recommendations**: A bulleted list of 3-4 prioritised actions organisations in the {customer_industry} sector should take based on the current threat landscape.

If industry_intel.web_intel contains open-source intelligence, synthesise it throughout — do not fabricate threat actors or CVEs that are not supported by the data provided. If web_intel is absent and threat_actors is empty, write that no current threat intelligence was available for this sector during the period.

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
        # Phase C — per-workspace reports carry the workspace name so the
        # History tab can group them and the file name can disambiguate
        # multiple reports for the same customer in the same month.
        "aggregation_mode": config.get("aggregation_mode", "merged"),
        "workspace_name":   config.get("workspace_name", ""),
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

    # Per-customer issue-type overrides. Defaults match Atlassian/JSM
    # canonical names; admins can override in the Customer admin page when
    # a customer's Jira project uses different labels (e.g. "Incident",
    # "Service Desk Request", "RFC").
    customer_record = get_customer(config.get("customer_id", "")) or {}
    incident_issue_type = customer_record.get("jira_incident_issuetype", "") or DEFAULT_INCIDENT_ISSUE_TYPE
    sr_issue_type = customer_record.get("jira_service_request_issuetype", "") or "Service Request"
    cr_issue_type = customer_record.get("jira_change_request_issuetype", "") or "Change"

    if csv_path:
        result = fetch_incidents_from_csv(project_key, start_date, end_date, csv_path=csv_path)
    else:
        result = fetch_incidents_for_report(project_key, start_date, end_date,
                                            incident_issue_type=incident_issue_type)

    if result.get("error"):
        log.error(f"Jira data collection error: {result['error']}")

    sections = config.get("sections", [])
    fetch_tasks = {}

    # Phase A — Sentinel + Defender retention window.
    # Sentinel KQL only sees the trailing 90 days, and Defender's DeviceInfo
    # / TVM tables are CURRENT-state (not period-scoped) — querying them for
    # a 4-month-old report would either return empty or, worse, return
    # today's state mislabeled as that historical month. When end_date is
    # outside Sentinel's retention window, fall back to the snapshot saved
    # at the time the original report was generated.
    _outside_retention = (config.get("use_sentinel")
                          and is_outside_sentinel_retention(end_date))
    _customer_id_for_history = config.get("customer_id", "")
    if _outside_retention:
        log.info(
            "[%s] end_date %s is outside Sentinel retention; using saved snapshot for "
            "customer=%s instead of live KQL.",
            config.get("customer_name", "?"), end_date, _customer_id_for_history,
        )
        _cid, _sd = _customer_id_for_history, start_date
        def _load_saved_sentinel():
            snap = load_sentinel_data_from_saved_report(_cid, _sd)
            return snap or {}
        fetch_tasks["sentinel"] = _load_saved_sentinel
        # Defender snapshot lives inside the saved report's sentinel dict only
        # when the saved report had Defender wired in; in any case there is no
        # separate "saved Defender" feed, so we explicitly skip the live call
        # and let the downstream merge use whatever the saved sentinel carries.
        fetch_tasks["defender"] = lambda: {}
    elif config.get("use_sentinel"):
        fetch_tasks["sentinel"] = lambda: sentinel_client.fetch_data(config, start_date, end_date)
        # Defender XDR runs alongside Sentinel — when DEFENDER_* creds exist,
        # it supersedes the Sentinel-side Heartbeat/TVM fallbacks for sections
        # 1.12-1.16. When creds are missing the client returns {} and Sentinel
        # data stands as-is.
        fetch_tasks["defender"] = lambda: defender_client.fetch_data(config, start_date, end_date)
    if config.get("use_splunk"):
        fetch_tasks["splunk"] = lambda: splunk_client.fetch_data(config, start_date, end_date)
    if config.get("use_socradar"):
        fetch_tasks["socradar"] = lambda: socradar_client.fetch_data(config, start_date, end_date)
    if "service_requests" in sections and project_key:
        _sr_type = sr_issue_type
        fetch_tasks["service_requests"] = lambda: fetch_service_requests(
            project_key, start_date, end_date, issue_type=_sr_type)
    if "change_requests" in sections and project_key:
        _cr_type = cr_issue_type
        fetch_tasks["change_requests"] = lambda: fetch_change_requests(
            project_key, start_date, end_date, issue_type=_cr_type)
    industry = config.get("customer_industry", "")
    if industry and "industry_threat_intel" in sections:
        _ind, _sd, _ed = industry, start_date, end_date
        fetch_tasks["industry_tavily"] = lambda: tavily_client.fetch_industry_threat_intel(_ind, _sd, _ed)
        if config.get("use_socradar"):
            fetch_tasks["industry_socradar"] = lambda: socradar_client.fetch_industry_data(_ind, _sd, _ed)

    # Fetch 12-month incident counts for the monthly trend chart (Jira API mode only).
    # Verified against an independent JQL window in the verifier step below.
    if not csv_path and project_key:
        _pk, _ed = project_key, end_date
        _it = incident_issue_type
        fetch_tasks["monthly_trend_12m"] = lambda: fetch_monthly_counts_12m(_pk, _ed,
                                                                            incident_issue_type=_it)

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

        # 12-month chart accuracy: the primary fetch (fetch_monthly_counts_12m)
        # runs 12 separate per-month queries; the verifier runs ONE 12-month
        # query and groups locally. They must agree exactly. If they don't,
        # we refuse to ship the report rather than render a chart with
        # numbers we can't trust.
        trend_12m = fetch_results.get("monthly_trend_12m")
        if trend_12m and project_key and not csv_path:
            verification = verify_monthly_counts(
                project_key=project_key,
                end_date=end_date,
                primary_monthly_counts=trend_12m,
                incident_issue_type=incident_issue_type,
            )
            if not verification["verified"]:
                msg = format_verification_error(verification)
                log.error("Monthly count verification FAILED:\n%s", msg)
                raise ValueError(
                    "JIRA incident counts could not be verified. Refusing to "
                    "generate report with unverified numbers.\n\n" + msg
                )
            log.info(
                "Monthly count verification PASSED: %d incidents over 12 months "
                "(issue_type=%r)",
                verification["total_verifier"],
                verification.get("issue_type"),
            )
            # The verifier's by_month dict is the authoritative source of
            # truth for the chart. The in-period stats.monthly_trend is kept
            # as-is (it covers a different window and is consumed elsewhere).
            if result.get("stats") is None:
                result["stats"] = {}
            result["stats"]["monthly_trend"] = verification["by_month"]

        if industry and "industry_threat_intel" in sections:
            result["industry_intel"] = {
                "industry": industry,
                "threat_actors": (fetch_results.get("industry_socradar") or {}).get("threat_actors", []),
                "web_intel": fetch_results.get("industry_tavily"),
            }

    # Per-customer advisory feeds (§1.15 Threat Analytics + §1.17 IOC Update).
    # Local JSON, so loaded inline rather than via the threaded fetch_tasks block.
    _cust_name = config.get("customer_name", "")
    result["customer_advisories"] = {
        "threat_analytics": load_threat_analytics_advisories(_cust_name, start_date, end_date),
        "ioc": load_ioc_advisories(_cust_name, start_date, end_date),
    }

    # Phase A — layer 11 months of historical Sentinel utilization onto the
    # current report's sentinel dict, so any future caller (e.g. a 12-month
    # chart, quarterly rollup, or operator export) has the trailing-year
    # GB-ingested series available without re-querying Sentinel — which
    # would return empty past 90 days. The current month comes from the
    # live (or saved-snapshot) fetch above; we splice that on top so
    # `monthly_history` is always a complete trailing-12 picture.
    _sentinel = result.get("sentinel") or {}
    if _sentinel and _customer_id_for_history:
        try:
            _hist = load_historical_sentinel_data(_customer_id_for_history, end_date)
            _util = _sentinel.setdefault("utilization", {})
            _monthly: dict = dict(_hist.get("utilization_monthly", {}))
            _current_total = _util.get("total_gb")
            try:
                _current_month_key = datetime.strptime(end_date, "%Y-%m-%d").strftime("%Y-%m")
                if isinstance(_current_total, (int, float)):
                    _monthly[_current_month_key] = round(float(_current_total), 2)
            except ValueError:
                pass
            _util["monthly_history"] = _monthly
            _util["monthly_history_missing"] = _hist.get("missing_months", [])
        except Exception as exc:
            log.warning("Sentinel history backfill failed (non-fatal): %s", exc)

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

    _closed_statuses = {"closed", "resolved", "done", "complete", "completed"}
    _incident_records = [
        {
            "key": i["key"], "summary": i["summary"], "severity": i["severity"],
            "status": i["status"], "priority": i["priority"], "assignee": i["assignee"],
            "created": i["created"], "resolved": i["resolved"],
            "close_justification": i["close_justification"],
            "labels": i["labels"], "category": i.get("incident_type", ""),
        }
        for i in data.get("incidents", [])
    ]
    jira_data = {
        "total_incidents": data.get("stats", {}).get("total", 0),
        "by_severity": data.get("stats", {}).get("by_severity", {}),
        "by_status": data.get("stats", {}).get("by_status", {}),
        "by_priority": data.get("stats", {}).get("by_priority", {}),
        "by_close_justification": data.get("stats", {}).get("by_close_justification", {}),
        "top_alerts": data.get("stats", {}).get("top_alerts", {}),
        "monthly_trend": data.get("stats", {}).get("monthly_trend", {}),
        "assignee_distribution": data.get("stats", {}).get("assignee_distribution", {}),
        "incident_details": _incident_records,
        "pending_tickets": [
            {
                "key": i["key"], "summary": i["summary"], "severity": i["severity"],
                "status": i["status"], "created": i["created"],
            }
            for i in data.get("incidents", [])
            if i.get("status", "").strip().lower() not in _closed_statuses
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
        # Pull only the top 3 spike days from the daily breakdown — the full
        # 28-31-row table is redundant with the chart and cluttered the PDF.
        # See routes/reports.py prompt for section 1.10.
        _daily = sentinel.get("utilization", {}).get("daily_breakdown", []) or []
        _spike_days = sorted(
            ({"date": (r.get("TimeGenerated") or r.get("date") or "")[:10],
              "gb":   round(float(r.get("TotalGB") or r.get("gb") or 0), 2)}
             for r in _daily if isinstance(r, dict)),
            key=lambda d: d["gb"], reverse=True,
        )[:3]

        sentinel_data = {
            "utilization_total_gb": sentinel.get("utilization", {}).get("total_gb"),
            "utilization_avg_daily_gb": sentinel.get("utilization", {}).get("avg_daily_gb"),
            "utilization_top_spike_days": _spike_days,
            "top_alerts": sentinel.get("top_alerts", []),
            "total_assets": sentinel.get("total_assets"),
            "total_assets_source": sentinel.get("total_assets_source", "none"),
            "sensor_health": sentinel.get("sensor_health", []),
            "sensor_health_source": sentinel.get("sensor_health_source", "none"),
            "vulnerability_by_severity": sentinel.get("vulnerabilities", {}).get("by_severity", []),
            "vulnerability_exposed_devices": sentinel.get("vulnerabilities", {}).get("exposed_devices", []),
            "threat_analytics": sentinel.get("threat_analytics", []),
            "ioc_updates": sentinel.get("ioc_updates", []),
        }

        # Defender XDR overrides Sentinel's Heartbeat / TVM-empty fallbacks.
        # We replace per-field rather than dict-merge so the override is
        # explicit: only the device + vulnerability fields move; utilization,
        # top alerts, threat analytics, and IOC updates stay on Sentinel.
        defender = data.get("defender") or {}
        if defender.get("total_assets"):
            sentinel_data["total_assets"]        = defender["total_assets"]
            sentinel_data["total_assets_source"] = "mde"
        if defender.get("sensor_health"):
            sentinel_data["sensor_health"]        = defender["sensor_health"]
            sentinel_data["sensor_health_source"] = "mde"
        _defender_vulns = defender.get("vulnerabilities") or {}
        if _defender_vulns.get("by_severity"):
            sentinel_data["vulnerability_by_severity"] = _defender_vulns["by_severity"]
        if _defender_vulns.get("exposed_devices"):
            sentinel_data["vulnerability_exposed_devices"] = _defender_vulns["exposed_devices"]

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
        alarms = socradar.get("company_alarms", []) or []
        socradar_data = {
            "company_alarms": alarms,
            "company_alarms_html_table": _render_socradar_alarms_html(alarms),
            "threat_actors": socradar.get("threat_actors", []),
            "cve_intel": socradar.get("cve_intel", []),
            "dark_web_alarms": socradar.get("dark_web_alarms", []),
        }

    industry_intel_raw = data.get("industry_intel", {})
    industry_intel_data = {
        "industry": config.get("customer_industry", ""),
        "threat_actors": industry_intel_raw.get("threat_actors", []),
        "web_intel": industry_intel_raw.get("web_intel"),
    }

    advisories_raw = data.get("customer_advisories", {}) or {}
    customer_advisories_data = {
        "threat_analytics": advisories_raw.get("threat_analytics", []) or [],
        "ioc": advisories_raw.get("ioc", []) or [],
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
        "industry_intel_data": industry_intel_data,
        "customer_advisories_data": customer_advisories_data,
        # Pre-rendered HTML kept off `jira_data` so it does not bloat the LLM
        # input (a 1,400-row HTML table is ~250KB of text). The post-processor
        # in `_run_report_agent` substitutes it for INCIDENT_DETAILS_TOKEN.
        "incident_details_html_table": _render_incident_details_html(_incident_records),
        "pending_tickets_html_table": _render_pending_tickets_html(
            jira_data["pending_tickets"]
        ),
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


# LLM client construction has moved to tools.llm_client.make_chat_client().
# The factory there handles Azure OpenAI, OpenAI-compat (Ollama/vLLM), and
# public OpenAI behind one interface. Detection is env-driven so the same
# image runs against any provider.


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
        customer_industry=config.get("customer_industry", "Not specified"),
        start_date=config.get("start_date", ""),
        end_date=config.get("end_date", ""),
        report_type=config.get("report_type", "Monthly SOC Report"),
        sections_list=sections_list,
        data_json=json.dumps(data_subset, indent=2),
        available_sources=ctx["available_sources_str"],
        report_year=ctx["report_year"],
    )

    client, model = make_chat_client()
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Generate the assigned report sections now."},
        ],
        max_completion_tokens=16000,
    )
    return (response.choices[0].message.content or "").strip()


async def _run_report_agent(data: dict, config: dict) -> str:
    ctx = _build_report_context(data, config)
    sections = ctx["sections"]
    section_meta = ctx["section_meta"]

    jira_grp = [s for s in sections if section_meta.get(s, {}).get("source") == "jira"]
    sentinel_grp = [s for s in sections if section_meta.get(s, {}).get("source") == "sentinel"]
    splunk_grp = [s for s in sections if section_meta.get(s, {}).get("source") == "splunk"]
    socradar_grp = [s for s in sections if section_meta.get(s, {}).get("source") == "socradar"]
    industry_grp = [s for s in sections if section_meta.get(s, {}).get("source") == "general"]

    jira_payload = ctx["jira_data"]
    # Customer advisory feeds (§1.15 Threat Analytics, §1.17 IOC Update) ship
    # alongside the Sentinel payload because both sections are in the sentinel
    # source group. Empty lists are still passed — the prompt branches on
    # "is the list empty?" rather than "is the key present?".
    sentinel_payload = (
        {"sentinel": ctx["sentinel_data"],
         "customer_advisories": ctx["customer_advisories_data"]}
        if ctx["sentinel_data"] else {}
    )
    splunk_payload = {"splunk": ctx["splunk_data"]} if ctx["splunk_data"] else {}
    socradar_payload = {"socradar": ctx["socradar_data"]} if ctx["socradar_data"] else {}
    industry_payload = {"industry_intel": ctx["industry_intel_data"]} if industry_grp else {}

    groups = [
        (jira_grp, jira_payload),
        (sentinel_grp, sentinel_payload),
        (splunk_grp, splunk_payload),
        (socradar_grp, socradar_payload),
        (industry_grp, industry_payload),
    ]
    active_groups = [(secs, payload) for secs, payload in groups if secs]

    tasks = [_generate_group(secs, payload, ctx, config) for secs, payload in active_groups]
    parts = await asyncio.gather(*tasks)

    assembled = "\n\n".join(p for p in parts if p.strip())
    assembled = _build_unified_toc(assembled)
    assembled += _REPORT_TAIL.format(report_year=ctx["report_year"])

    # Swap the LLM-emitted tokens for the pre-rendered HTML tables. Done after
    # assembly so a single replace covers the case where the token appears in
    # any part of the markdown. If the LLM omitted the token (e.g. the section
    # was deselected), nothing to do.
    incident_html = ctx.get("incident_details_html_table") or ""
    if INCIDENT_DETAILS_TOKEN in assembled:
        assembled = assembled.replace(INCIDENT_DETAILS_TOKEN, incident_html)

    pending_html = ctx.get("pending_tickets_html_table") or ""
    if PENDING_TICKETS_TOKEN in assembled:
        assembled = assembled.replace(PENDING_TICKETS_TOKEN, pending_html)

    return assembled


def _slug(s: str) -> str:
    """Convert a workspace name to a filesystem/url-safe slug."""
    import re
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-") or "ws"


def _run_per_workspace_reports(parent_job_id: str, parent_config: dict,
                                workspaces: list) -> None:
    """Generate one report per workspace, save each separately, then mark
    the parent job complete with a summary.

    Children are executed serially to keep token usage predictable and to
    avoid hammering the LLM with N parallel completion requests. Each child
    gets its own ``jobs[]`` entry so the History tab can show them
    individually; the parent job's ``text`` field gets a short summary
    pointing at the child IDs.
    """
    import uuid

    customer_name = parent_config.get("customer_name", "?")
    log.info(
        "[%s] per-workspace mode: fanning out to %d workspaces for %s",
        parent_job_id[:8], len(workspaces), customer_name,
    )

    child_ids: list[tuple[str, str]] = []  # [(workspace_name, child_job_id), ...]
    errors: list[str] = []

    for idx, ws in enumerate(workspaces, start=1):
        ws_name = ws.get("name") or f"workspace-{idx}"
        child_id = f"{parent_job_id}--{_slug(ws_name)}"
        child_config = dict(parent_config)
        child_config["_workspace_filter"] = ws_name
        child_config["workspace_name"] = ws_name
        # Mark the child as a leaf so the fanout block doesn't re-trigger
        child_config["aggregation_mode"] = "merged"

        jobs[child_id] = {
            "status": "running",
            "text": "",
            "data": None,
            "error": None,
            "config": child_config,
            "parent_job_id": parent_job_id,
        }
        jobs[parent_job_id]["progress"] = (
            f"Workspace {idx} of {len(workspaces)}: {ws_name}"
        )

        try:
            run_report_job(child_id, child_config)
            child_status = jobs.get(child_id, {}).get("status")
            if child_status == "done":
                child_ids.append((ws_name, child_id))
            else:
                err = jobs.get(child_id, {}).get("error", "unknown error")
                errors.append(f"{ws_name}: {err}")
                log.warning(
                    "[%s] child workspace %s ended with status=%s",
                    parent_job_id[:8], ws_name, child_status,
                )
        except Exception as exc:
            errors.append(f"{ws_name}: {exc}")
            log.error("[%s] child workspace %s raised: %s",
                      parent_job_id[:8], ws_name, exc)

    # Compose parent summary
    summary_lines = [
        f"# {customer_name} — Per-Workspace Reports",
        "",
        f"Generated {len(child_ids)} of {len(workspaces)} workspace reports "
        f"for period {parent_config.get('start_date')} to "
        f"{parent_config.get('end_date')}.",
        "",
    ]
    if child_ids:
        summary_lines.append("## Reports generated")
        summary_lines.append("")
        for ws_name, cid in child_ids:
            summary_lines.append(f"- **{ws_name}** — job `{cid}`")
        summary_lines.append("")
    if errors:
        summary_lines.append("## Errors")
        summary_lines.append("")
        for e in errors:
            summary_lines.append(f"- {e}")
        summary_lines.append("")

    jobs[parent_job_id]["text"] = "\n".join(summary_lines)
    jobs[parent_job_id]["status"] = "done" if not errors else "error"
    if errors:
        jobs[parent_job_id]["error"] = "; ".join(errors)
    jobs[parent_job_id]["children"] = [cid for _, cid in child_ids]


def run_report_job(job_id: str, config: dict) -> None:
    # Phase C — multi-workspace fanout.
    # If aggregation_mode == "per_workspace" and the customer has >1 workspace
    # AND this call isn't already scoped to a single workspace (i.e. no
    # _workspace_filter set), spawn one child job per workspace and finish
    # the parent. Each child runs the normal single-pass flow with
    # _workspace_filter set, which sentinel_client + defender_client honour
    # to scope their fetches.
    #
    # When mode == "merged" (default) or the customer has only one
    # workspace, this block is a no-op and the single-pass body below runs
    # exactly like before.
    if (config.get("aggregation_mode") == "per_workspace"
            and not config.get("_workspace_filter")):
        _customer = get_customer(config.get("customer_id", "")) or {}
        _workspaces = _customer.get("sentinel_workspaces") or []
        if len(_workspaces) > 1:
            _run_per_workspace_reports(job_id, config, _workspaces)
            return

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

        sentinel = data.get("sentinel")
        if sentinel:
            # Past-3-months chart needs trailing 3-month data — daily_breakdown is
            # scoped to the report period (single month) and would render Jan/Feb
            # as 0 GB. monthly_breakdown is the dedicated chart-only feed from
            # tools/sentinel_client.py:fetch_data.
            chart_breakdown = (
                sentinel.get("utilization", {}).get("monthly_breakdown")
                or sentinel.get("utilization", {}).get("daily_breakdown")
                or []
            )
            try:
                chart = generate_sentinel_utilization_chart(
                    chart_breakdown, end_date=config.get("end_date", "")
                )
                if chart:
                    charts["sentinel_utilization"] = chart
            except Exception as e:
                log.error(f"[{job_id[:8]}] Sentinel utilization chart failed: {e}")

            sentinel_alerts = sentinel.get("top_alerts", [])
            if sentinel_alerts:
                try:
                    alert_dict = {
                        str(row.get("AlertName", "")): int(row.get("Count", 0))
                        for row in sentinel_alerts
                        if row.get("AlertName")
                    }
                    if alert_dict:
                        charts["sentinel_top_alerts"] = generate_top_alerts_chart(alert_dict)
                except Exception as e:
                    log.error(f"[{job_id[:8]}] Sentinel top alerts chart failed: {e}")

            # Defender XDR overrides sentinel for device + vulnerability data.
            # Mirror the precedence used in _build_report_context() so charts
            # render the same numbers the LLM will narrate.
            defender = data.get("defender") or {}
            sensor_health = (defender.get("sensor_health")
                             or sentinel.get("sensor_health") or [])
            if sensor_health:
                try:
                    chart = generate_total_assets_chart(sensor_health)
                    if chart:
                        charts["total_assets"] = chart
                except Exception as e:
                    log.error(f"[{job_id[:8]}] Total assets chart failed: {e}")
                try:
                    chart = generate_sensor_health_chart(sensor_health)
                    if chart:
                        charts["sensor_health"] = chart
                except Exception as e:
                    log.error(f"[{job_id[:8]}] Sensor health chart failed: {e}")

            vuln_root = (defender.get("vulnerabilities")
                         or sentinel.get("vulnerabilities") or {})
            vuln_by_severity = vuln_root.get("by_severity") or []
            if vuln_by_severity:
                try:
                    chart = generate_vulnerability_severity_chart(vuln_by_severity)
                    if chart:
                        charts["vulnerability_severity"] = chart
                except Exception as e:
                    log.error(f"[{job_id[:8]}] Vuln severity chart failed: {e}")

            vuln_exposed = vuln_root.get("exposed_devices") or []
            if vuln_exposed:
                try:
                    chart = generate_vulnerability_exposed_devices_chart(vuln_exposed)
                    if chart:
                        charts["vulnerability_exposed_devices"] = chart
                except Exception as e:
                    log.error(f"[{job_id[:8]}] Vuln exposed devices chart failed: {e}")

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
        customer_industry = request.form.get("customer_industry", "").strip()
        jira_request_type = request.form.get("jira_request_type", "Report an Incident").strip()
        sentinel_workspace_id = request.form.get("sentinel_workspace_id", "").strip()
        aggregation_mode = request.form.get("aggregation_mode", "merged").strip() or "merged"
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
        customer_industry = body.get("customer_industry", "").strip()
        jira_request_type = body.get("jira_request_type", "Report an Incident").strip()
        sentinel_workspace_id = body.get("sentinel_workspace_id", "").strip()
        aggregation_mode = (body.get("aggregation_mode") or "merged").strip() or "merged"
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
        "jira_request_type": jira_request_type or "Report an Incident",
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
        "customer_industry": customer_industry,
        "sentinel_workspace_id": sentinel_workspace_id,
        "aggregation_mode": aggregation_mode,
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
