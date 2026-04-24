import os
import logging

import httpx

logger = logging.getLogger(__name__)

WORKSPACE_ID = os.environ.get("SENTINEL_WORKSPACE_ID", "")

_LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


def _get_access_token() -> str:
    # Resolve credentials at call time so Key Vault secrets are available.
    from tools.secrets import get_secret
    tenant_id = get_secret("SENTINEL_TENANT_ID")
    client_id = get_secret("SENTINEL_CLIENT_ID")
    client_secret = get_secret("SENTINEL_CLIENT_SECRET")

    # If explicit service principal credentials are configured, use them directly.
    # Required when Sentinel lives in a different tenant from the Container App's
    # Managed Identity — DefaultAzureCredential would get a token for the wrong tenant.
    if all([tenant_id, client_id, client_secret]):
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        r = httpx.post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": _LOG_ANALYTICS_SCOPE,
        }, timeout=30)
        r.raise_for_status()
        return r.json()["access_token"]

    # Fallback: same-tenant Managed Identity (no explicit credentials configured)
    from azure.identity import DefaultAzureCredential
    cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token = cred.get_token(_LOG_ANALYTICS_SCOPE)
    return token.token


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

    if r.status_code in (401, 403):
        # Auth failure — raise so the caller marks Sentinel as disconnected
        raise PermissionError(
            f"Sentinel auth denied ({r.status_code}): {r.text[:300]}"
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
    except PermissionError:
        raise  # auth failures must propagate so the caller treats Sentinel as disconnected
    except Exception as e:
        logger.warning(f"KQL query skipped ({type(e).__name__}): {e}")
        return []


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """Fetch security data from Microsoft Sentinel / Log Analytics."""
    from tools.secrets import get_secret
    if not all([get_secret("SENTINEL_TENANT_ID"), get_secret("SENTINEL_CLIENT_ID"),
                get_secret("SENTINEL_CLIENT_SECRET"), WORKSPACE_ID]):
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

    # 3. Total assets under monitoring — try MDE DeviceInfo first, fall back to CrowdStrike
    assets_rows = _safe_kql(token, """
DeviceInfo
| summarize arg_max(TimeGenerated, *) by DeviceName
| count
""")
    if not assets_rows or int(assets_rows[0].get("Count", 0)) == 0:
        assets_rows = _safe_kql(token, """
CrowdStrikeHosts
| summarize arg_max(TimeGenerated, *) by Hostname
| count
""")
    total_assets = int(assets_rows[0].get("Count", 0)) if assets_rows else 0

    # 4. Per-device sensor health state — try MDE DeviceInfo first, fall back to CrowdStrike.
    # Use extend+column_ifexists (not project+column_ifexists) — the assignment form in project
    # is not reliably supported by the Log Analytics REST API even though it works in the UI.
    health_rows = _safe_kql(token, """
DeviceInfo
| summarize arg_max(TimeGenerated, *) by DeviceName
| extend
    _OnboardingStatus = column_ifexists("OnboardingStatus", "Unknown"),
    _HealthStatus = column_ifexists("HealthStatus", "Unknown"),
    _OSPlatform = column_ifexists("OSPlatform", "Unknown"),
    _ExposureLevel = column_ifexists("ExposureLevel", "Unknown")
| project
    DeviceName,
    OnboardingStatus = _OnboardingStatus,
    HealthStatus = _HealthStatus,
    OSPlatform = _OSPlatform,
    ExposureLevel = _ExposureLevel,
    LastSeen = TimeGenerated
| order by HealthStatus asc
""")
    if not health_rows:
        health_rows = _safe_kql(token, """
CrowdStrikeHosts
| summarize arg_max(TimeGenerated, *) by Hostname
| extend
    DeviceName = Hostname,
    OnboardingStatus = iff(isnotempty(AgentVersion), "Onboarded", "Not onboarded"),
    HealthStatus = iff(LastSeen > ago(7d), "Active", "Inactive"),
    OSPlatform = OsProductName,
    ExposureLevel = iff(isnotempty(InternetExposure), InternetExposure, "Unknown")
| project DeviceName, OnboardingStatus, HealthStatus, OSPlatform, ExposureLevel, LastSeen
| order by HealthStatus asc
""")

    # 5a. Vulnerability severity breakdown
    # DeviceTvmSoftwareVulnerabilities is a snapshot table — passing timespan excludes all rows
    # written before the report period even when TVM is active. Use ago(30d) instead.
    vuln_severity_rows = _safe_kql(token, """
DeviceTvmSoftwareVulnerabilities
| where TimeGenerated > ago(30d)
| summarize Count = count() by VulnerabilitySeverityLevel
| order by Count desc
""")

    # 5b. Top exposed devices
    vuln_devices_rows = _safe_kql(token, """
DeviceTvmSoftwareVulnerabilities
| where TimeGenerated > ago(30d)
| summarize VulnCount = count() by DeviceName
| top 20 by VulnCount desc
""")

    # 6. Threat intelligence indicators by observable type.
    # Try modern ThreatIntelIndicators (STIX schema) first; fall back to the legacy
    # ThreatIntelligenceIndicator table (pre-2024 schema) which uses different field names.
    threat_rows = _safe_kql(token, """
ThreatIntelIndicators
| where IsActive == true
| summarize Count = count() by ObservableKey
| order by Count desc
""", timespan)

    if not threat_rows:
        threat_rows = _safe_kql(token, """
ThreatIntelligenceIndicator
| where Active == true
| extend ObservableKey = case(
    isnotempty(NetworkIP),       "network-traffic:src_ref.value",
    isnotempty(DomainName),      "domain-name:value",
    isnotempty(Url),             "url:value",
    isnotempty(FileHashValue),   strcat("file:hashes.", FileHashType),
    "other")
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

    if not ioc_rows:
        ioc_rows = _safe_kql(token, """
ThreatIntelligenceIndicator
| where Active == true
| extend
    ObservableKey = case(
        isnotempty(NetworkIP),     "network-traffic:src_ref.value",
        isnotempty(DomainName),    "domain-name:value",
        isnotempty(Url),           "url:value",
        isnotempty(FileHashValue), strcat("file:hashes.", FileHashType),
        "other"),
    ObservableValue = case(
        isnotempty(NetworkIP),     NetworkIP,
        isnotempty(DomainName),    DomainName,
        isnotempty(Url),           Url,
        isnotempty(FileHashValue), FileHashValue,
        "")
| project TimeGenerated, Id = IndicatorId, ObservableKey, ObservableValue,
          Pattern = Description, Tags = tostring(Tags), Confidence = ConfidenceScore
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
