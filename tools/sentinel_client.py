import os
import logging

import httpx

logger = logging.getLogger(__name__)

TENANT_ID = os.environ.get("SENTINEL_TENANT_ID", "")
CLIENT_ID = os.environ.get("SENTINEL_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("SENTINEL_CLIENT_SECRET", "")
WORKSPACE_ID = os.environ.get("SENTINEL_WORKSPACE_ID", "")

_LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


def _get_access_token() -> str:
    # In Azure, use Managed Identity (no credentials needed).
    # Fall back to client_credentials for local dev.
    try:
        from azure.identity import DefaultAzureCredential
        cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        token = cred.get_token(_LOG_ANALYTICS_SCOPE)
        return token.token
    except Exception:
        pass

    # Local dev fallback: client_credentials
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    r = httpx.post(url, data={
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": _LOG_ANALYTICS_SCOPE,
    }, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def _run_kql(token: str, query: str, timespan: str | None = None) -> list[dict]:
    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
    body: dict = {"query": query}
    if timespan:
        body["timespan"] = timespan

    r = httpx.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body,
        timeout=60,
    )

    if r.status_code in (400, 404):
        # Table may not exist in this workspace — treat as empty
        logger.warning(f"KQL returned {r.status_code}: {r.text[:200]}")
        return []

    r.raise_for_status()
    data = r.json()

    tables = data.get("tables", [])
    if not tables:
        return []

    table = tables[0]
    columns = [col["name"] for col in table.get("columns", [])]
    rows = table.get("rows", [])
    return [dict(zip(columns, row)) for row in rows]


def _safe_kql(token: str, query: str, timespan: str | None = None) -> list[dict]:
    try:
        return _run_kql(token, query, timespan)
    except Exception as e:
        logger.warning(f"KQL query skipped ({type(e).__name__}): {e}")
        return []


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """Fetch security data from Microsoft Sentinel / Log Analytics."""
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET, WORKSPACE_ID]):
        raise ValueError(
            "Sentinel credentials incomplete. Check SENTINEL_TENANT_ID, "
            "SENTINEL_CLIENT_ID, SENTINEL_CLIENT_SECRET, SENTINEL_WORKSPACE_ID."
        )

    token = _get_access_token()

    # ISO 8601 timespan used as the query time filter
    timespan = f"{start_date}T00:00:00Z/{end_date}T23:59:59Z"

    # 1. Monthly utilization — GB ingested per day
    utilization_rows = _safe_kql(token, """
Usage
| where IsBillable == true
| summarize TotalGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
""", timespan)

    total_gb = round(sum(float(r.get("TotalGB") or 0) for r in utilization_rows), 2)
    avg_daily_gb = round(total_gb / max(len(utilization_rows), 1), 2)

    # 2. Top alerts triggered in the period
    alerts_rows = _safe_kql(token, """
SecurityAlert
| summarize Count = count() by AlertName
| top 15 by Count desc
""", timespan)

    # 3. Total assets under monitoring (most recent snapshot — no timespan filter)
    assets_rows = _safe_kql(token, """
DeviceInfo
| summarize arg_max(TimeGenerated, *) by DeviceName
| count
""")
    total_assets = int(assets_rows[0].get("Count", 0)) if assets_rows else 0

    # 4. Per-device sensor health state (latest record per device)
    health_rows = _safe_kql(token, """
DeviceInfo
| summarize arg_max(TimeGenerated, *) by DeviceName
| project DeviceName, OnboardingStatus, HealthStatus, OSPlatform, ExposureLevel,
          LastSeen = TimeGenerated
| order by HealthStatus asc
""")

    # 5a. Vulnerability severity breakdown
    vuln_severity_rows = _safe_kql(token, """
DeviceTvmSoftwareVulnerabilities
| summarize Count = count() by VulnerabilitySeverityLevel
| order by Count desc
""", timespan)

    # 5b. Top exposed devices
    vuln_devices_rows = _safe_kql(token, """
DeviceTvmSoftwareVulnerabilities
| summarize VulnCount = count() by DeviceName
| top 20 by VulnCount desc
""", timespan)

    # 6. Threat intelligence indicators by observable type
    # ThreatIntelIndicators is the modern table (replaces ThreatIntelligenceIndicator).
    # ObservableKey holds the STIX observable type (e.g. "network-traffic:src_ref.value",
    # "url:value", "file:hashes.MD5").
    threat_rows = _safe_kql(token, """
ThreatIntelIndicators
| where IsActive == true
| summarize Count = count() by ObservableKey
| order by Count desc
""", timespan)

    # 7. Recent IOC entries
    ioc_rows = _safe_kql(token, """
ThreatIntelIndicators
| where IsActive == true
| project TimeGenerated, Id, ObservableKey, ObservableValue, Pattern,
          Tags, Confidence
| order by TimeGenerated desc
| take 50
""", timespan)

    return {
        "utilization": {
            "total_gb": total_gb,
            "avg_daily_gb": avg_daily_gb,
            "daily_breakdown": utilization_rows,
        },
        "top_alerts": alerts_rows,
        "total_assets": total_assets,
        "sensor_health": health_rows,
        "vulnerabilities": {
            "by_severity": vuln_severity_rows,
            "exposed_devices": vuln_devices_rows,
        },
        "threat_analytics": threat_rows,
        "ioc_updates": ioc_rows,
    }
