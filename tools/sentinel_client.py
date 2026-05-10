import logging
from datetime import datetime

from dateutil.relativedelta import relativedelta
import httpx

logger = logging.getLogger(__name__)

_LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


def _get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire a Log Analytics access token using the customer's own SP credentials.

    Each customer brings their own SP that lives in their tenant and has
    Log Analytics Reader on their Sentinel workspace — see the per-customer
    onboarding flow. The token is issued by `tenant_id`, which must match the
    workspace's home tenant.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    r = httpx.post(url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": _LOG_ANALYTICS_SCOPE,
    }, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def _run_kql(token: str, query: str, timespan: str | None = None,
             workspace_id: str = "") -> list[dict]:
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
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


def _safe_kql(token: str, query: str, timespan: str | None = None,
              workspace_id: str = "") -> list[dict]:
    try:
        return _run_kql(token, query, timespan, workspace_id)
    except PermissionError:
        raise  # auth failures must propagate so the caller treats Sentinel as disconnected
    except Exception as e:
        logger.warning(f"KQL query skipped ({type(e).__name__}): {e}")
        return []


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """Fetch security data from Microsoft Sentinel / Log Analytics.

    Resolves the customer's own SP credentials (tenant/client/secret/workspace)
    from the customer record. The client secret value is fetched from Key Vault
    via the deterministic name stored on the record.
    """
    from tools.customers import get_customer
    from tools.secrets import get_kv_secret

    customer_id = config.get("customer_id", "")
    customer = get_customer(customer_id) or {}

    workspace_id  = customer.get("sentinel_workspace_id") or config.get("sentinel_workspace_id", "")
    tenant_id     = customer.get("sentinel_tenant_id", "")
    client_id     = customer.get("sentinel_client_id", "")
    kv_name       = customer.get("sentinel_client_secret_kv_name", "")
    client_secret = get_kv_secret(kv_name) if kv_name else ""

    if not all([tenant_id, client_id, client_secret, workspace_id]):
        raise ValueError(
            f"Customer '{customer_id}' is missing one or more Sentinel credentials. "
            "Required on the customer record: sentinel_tenant_id, sentinel_client_id, "
            "sentinel_client_secret_kv_name (with the secret present in Key Vault), "
            "sentinel_workspace_id."
        )

    token = _get_access_token(tenant_id, client_id, client_secret)

    # ISO 8601 timespan used as the query time filter
    timespan = f"{start_date}T00:00:00Z/{end_date}T23:59:59Z"

    # 1. Monthly utilization — GB ingested per day.
    # Try billable-only first; fall back to all usage if the workspace returns nothing
    # (e.g. commitment-tier workspaces where IsBillable is not set on all rows).
    utilization_rows = _safe_kql(token, """
Usage
| where IsBillable == true
| summarize TotalGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
""", timespan, workspace_id)
    if not utilization_rows:
        utilization_rows = _safe_kql(token, """
Usage
| summarize TotalGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
""", timespan, workspace_id)

    total_gb = round(sum(float(r.get("TotalGB") or 0) for r in utilization_rows), 2)
    avg_daily_gb = round(total_gb / max(len(utilization_rows), 1), 2)

    # 1b. Trailing 3-month utilization — sole consumer is the
    # "Monthly Log Ingestion (GB) — Past 3 Months" chart. Kept separate from
    # the period-scoped query above so total_gb / avg_daily_gb / spike days
    # remain accurate to the report period (e.g. just March), while the chart
    # can still show Jan / Feb / Mar bars.
    monthly_rows: list[dict] = []
    try:
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        chart_start_dt = (end_dt - relativedelta(months=2)).replace(day=1)
        chart_timespan = (
            f"{chart_start_dt.strftime('%Y-%m-%d')}T00:00:00Z/"
            f"{end_date}T23:59:59Z"
        )
        monthly_rows = _safe_kql(token, """
Usage
| where IsBillable == true
| summarize TotalGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
""", chart_timespan, workspace_id)
        if not monthly_rows:
            monthly_rows = _safe_kql(token, """
Usage
| summarize TotalGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
""", chart_timespan, workspace_id)
    except Exception as e:
        logger.warning("Trailing-3-month Usage query skipped (%s): %s", type(e).__name__, e)

    # 2. Top alerts triggered in the period.
    # Try SecurityAlert first; fall back to SecurityIncident for workspaces where
    # incidents are not surfaced as individual alerts (e.g. identity-only tenants).
    alerts_rows = _safe_kql(token, """
SecurityAlert
| summarize Count = count() by AlertName
| top 15 by Count desc
""", timespan, workspace_id)
    if not alerts_rows:
        alerts_rows = _safe_kql(token, """
SecurityIncident
| summarize Count = count() by Title
| project AlertName = Title, Count
| top 15 by Count desc
""", timespan, workspace_id)

    # 3. Total assets under monitoring — fallback chain:
    # MDE DeviceInfo → CrowdStrike → Heartbeat (Sentinel agent presence).
    # `assets_source` records which tier produced the data so the report can
    # adjust its narrative ("EDR-managed" vs "Sentinel agent heartbeat").
    assets_source = "none"
    total_assets = 0

    assets_rows = _safe_kql(token, """
DeviceInfo
| summarize arg_max(TimeGenerated, *) by DeviceName
| count
""", workspace_id=workspace_id)
    if assets_rows and int(assets_rows[0].get("Count", 0)) > 0:
        total_assets = int(assets_rows[0]["Count"])
        assets_source = "mde"
    else:
        assets_rows = _safe_kql(token, """
CrowdStrikeHosts
| summarize arg_max(TimeGenerated, *) by Hostname
| count
""", workspace_id=workspace_id)
        if assets_rows and int(assets_rows[0].get("Count", 0)) > 0:
            total_assets = int(assets_rows[0]["Count"])
            assets_source = "crowdstrike"
        else:
            # Heartbeat fallback — for customers without EDR connectors.
            # Counts distinct VMs/servers reporting to the workspace agent.
            hb_rows = _safe_kql(token, """
Heartbeat
| summarize arg_max(TimeGenerated, *) by Computer
| count
""", workspace_id=workspace_id)
            if hb_rows and int(hb_rows[0].get("Count", 0)) > 0:
                total_assets = int(hb_rows[0]["Count"])
                assets_source = "heartbeat"

    # 4. Per-device sensor health state — same fallback chain as assets above.
    # Use extend+column_ifexists (not project+column_ifexists) — the assignment form in project
    # is not reliably supported by the Log Analytics REST API even though it works in the UI.
    sensor_health_source = "none"
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
""", workspace_id=workspace_id)
    if health_rows:
        sensor_health_source = "mde"
    else:
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
""", workspace_id=workspace_id)
        if health_rows:
            sensor_health_source = "crowdstrike"
        else:
            # Heartbeat fallback — Sentinel agent presence in lieu of EDR sensor data.
            health_rows = _safe_kql(token, """
Heartbeat
| summarize arg_max(TimeGenerated, *) by Computer
| extend
    DeviceName = Computer,
    OnboardingStatus = "Reporting (Sentinel agent)",
    HealthStatus = case(
        TimeGenerated > ago(1h),  "Active",
        TimeGenerated > ago(24h), "Stale (24h)",
        TimeGenerated > ago(7d),  "Idle (7d)",
        "Inactive"),
    OSPlatform = strcat(coalesce(OSType, ""), iif(isnotempty(OSMajorVersion), strcat(" ", OSMajorVersion), "")),
    ExposureLevel = "N/A (no EDR)"
| project DeviceName, OnboardingStatus, HealthStatus, OSPlatform, ExposureLevel, LastSeen = TimeGenerated
| order by HealthStatus asc
""", workspace_id=workspace_id)
            if health_rows:
                sensor_health_source = "heartbeat"

    # 5a. Vulnerability severity breakdown
    # DeviceTvmSoftwareVulnerabilities is a snapshot table — passing timespan excludes all rows
    # written before the report period even when TVM is active. Use ago(30d) instead.
    vuln_severity_rows = _safe_kql(token, """
DeviceTvmSoftwareVulnerabilities
| where TimeGenerated > ago(30d)
| summarize Count = count() by VulnerabilitySeverityLevel
| order by Count desc
""", workspace_id=workspace_id)

    # 5b. Top exposed devices
    vuln_devices_rows = _safe_kql(token, """
DeviceTvmSoftwareVulnerabilities
| where TimeGenerated > ago(30d)
| summarize VulnCount = count() by DeviceName
| top 20 by VulnCount desc
""", workspace_id=workspace_id)

    # 6. Threat intelligence indicators by observable type.
    # Try modern ThreatIntelIndicators (STIX schema) first; fall back to the legacy
    # ThreatIntelligenceIndicator table (pre-2024 schema) which uses different field names.
    threat_rows = _safe_kql(token, """
ThreatIntelIndicators
| where IsActive == true
| summarize Count = count() by ObservableKey
| order by Count desc
""", timespan, workspace_id)

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
""", timespan, workspace_id)

    # 7. Recent IOC entries
    ioc_rows = _safe_kql(token, """
ThreatIntelIndicators
| where IsActive == true
| project TimeGenerated, Id, ObservableKey, ObservableValue, Pattern,
          Tags, Confidence
| order by TimeGenerated desc
| take 50
""", timespan, workspace_id)

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
""", timespan, workspace_id)

    return {
        "utilization": {
            "total_gb": total_gb,
            "avg_daily_gb": avg_daily_gb,
            "daily_breakdown": utilization_rows,
            "monthly_breakdown": monthly_rows,
        },
        "top_alerts": alerts_rows,
        "total_assets": total_assets,
        "total_assets_source": assets_source,           # "mde" | "crowdstrike" | "heartbeat" | "none"
        "sensor_health": health_rows,
        "sensor_health_source": sensor_health_source,   # same domain as above
        "vulnerabilities": {
            "by_severity": vuln_severity_rows,
            "exposed_devices": vuln_devices_rows,
        },
        "threat_analytics": threat_rows,
        "ioc_updates": ioc_rows,
    }
