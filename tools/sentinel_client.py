"""Microsoft Sentinel / Log Analytics client.

Phase C (2026-06): supports customers with **multiple Sentinel workspaces**,
each potentially in a different Entra tenant (cross-tenant, no
``workspace()`` KQL feature usable). ``fetch_data`` orchestrates parallel
per-workspace fetches and merges the results into the same flat dict shape
the rest of the report pipeline already consumes. Single-workspace customers
keep working unchanged via :func:`tools.customers._normalize_customer`,
which wraps legacy flat fields into a single-element ``sentinel_workspaces``
list at load time.

When the caller wants only one workspace (e.g. per-workspace report mode),
they pass ``config["_workspace_filter"] = workspace_name`` and this client
restricts the fan-out to that one workspace.
"""
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from dateutil.relativedelta import relativedelta
import httpx

from tools.device_breakdown import (
    DEVICE_SAMPLE_CAP, summarize_devices, sort_unhealthy_first)

logger = logging.getLogger(__name__)

_LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


def _get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire a Log Analytics access token using the workspace's SP credentials.

    Each workspace can live in its own tenant — the token is issued by
    ``tenant_id`` which must match the workspace's home tenant.
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
        raise PermissionError(
            f"Sentinel auth denied ({r.status_code}): {r.text[:300]}"
        )

    if r.status_code in (400, 404):
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
        raise
    except Exception as e:
        logger.warning(f"KQL query skipped ({type(e).__name__}): {e}")
        return []


# ── Per-workspace fetch ────────────────────────────────────────────────────────


def _fetch_workspace_data(workspace_spec: dict, start_date: str, end_date: str) -> dict:
    """Execute all monthly-report KQL queries against ONE workspace.

    Returns the same flat dict shape as the original single-workspace
    ``fetch_data``. The orchestrator above merges multiple of these into the
    final aggregated response.

    Raises ``ValueError`` if ``workspace_spec`` is missing any required field.
    """
    from tools.secrets import get_kv_secret

    name          = workspace_spec.get("name") or "workspace"
    workspace_id  = workspace_spec.get("workspace_id", "")
    tenant_id     = workspace_spec.get("tenant_id", "")
    client_id     = workspace_spec.get("client_id", "")
    kv_name       = workspace_spec.get("client_secret_kv_name", "")
    client_secret = get_kv_secret(kv_name) if kv_name else ""

    if not all([tenant_id, client_id, client_secret, workspace_id]):
        raise ValueError(
            f"Sentinel workspace {name!r} is missing one or more credentials: "
            "tenant_id, client_id, client_secret (via Key Vault), workspace_id."
        )

    token = _get_access_token(tenant_id, client_id, client_secret)
    timespan = f"{start_date}T00:00:00Z/{end_date}T23:59:59Z"

    # 1. Monthly utilization — GB ingested per day for the report period.
    # The billable-filtered query is authoritative. If it comes back empty we
    # fall back to UNFILTERED Usage so the section isn't blank — but that total
    # includes non-billable data and will read HIGHER than the billable figure,
    # so we log it loudly and tag the result (`billable_only=False`). An empty
    # billable result is usually a transient query error swallowed by _safe_kql,
    # NOT a genuinely idle workspace, so a silent fallback here is exactly how a
    # completed month's number could drift between reports.
    billable_only = True
    utilization_rows = _safe_kql(token, """
Usage
| where IsBillable == true
| summarize TotalGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
""", timespan, workspace_id)
    if not utilization_rows:
        billable_only = False
        logger.warning(
            "Sentinel utilization: billable-filtered Usage returned no rows for "
            "workspace %r (%s) — falling back to UNFILTERED Usage. total_gb may "
            "include non-billable data and read higher than the billable figure.",
            name, timespan,
        )
        utilization_rows = _safe_kql(token, """
Usage
| summarize TotalGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
""", timespan, workspace_id)

    total_gb = round(sum(float(r.get("TotalGB") or 0) for r in utilization_rows), 2)
    avg_daily_gb = round(total_gb / max(len(utilization_rows), 1), 2)

    # 1b. Trailing 3-month utilization for the past-3-months chart.
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
            logger.warning(
                "Sentinel trailing-3-month utilization: billable-filtered Usage "
                "returned no rows for workspace %r (%s) — falling back to "
                "UNFILTERED Usage for the chart feed.", name, chart_timespan,
            )
            monthly_rows = _safe_kql(token, """
Usage
| summarize TotalGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
""", chart_timespan, workspace_id)
    except Exception as e:
        logger.warning("Trailing-3-month Usage query skipped (%s): %s", type(e).__name__, e)

    # 2. Top alerts.
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

    # 3. Total assets — MDE → CrowdStrike → Heartbeat fallback.
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
            hb_rows = _safe_kql(token, """
Heartbeat
| summarize arg_max(TimeGenerated, *) by Computer
| count
""", workspace_id=workspace_id)
            if hb_rows and int(hb_rows[0].get("Count", 0)) > 0:
                total_assets = int(hb_rows[0]["Count"])
                assets_source = "heartbeat"

    # 4. Sensor health.
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

    # These three queries are uncapped, so aggregate the FULL row set here —
    # sections 1.12/1.13 must count the whole fleet, never the bounded sample
    # below. Doing this in Python costs no extra KQL round-trip.
    _device_summary = summarize_devices(health_rows)
    # Bound what travels into the LLM payload and the 1.13 table. Uncapped, a
    # large fleet ships thousands of device rows into the prompt (the documented
    # oversized-request / 429 failure mode). Unhealthy devices sort first, so
    # the cap only ever discards healthy ones.
    health_rows = sort_unhealthy_first(health_rows)[:DEVICE_SAMPLE_CAP]

    # 5a. Vulnerability severity breakdown.
    vuln_severity_rows = _safe_kql(token, """
DeviceTvmSoftwareVulnerabilities
| where TimeGenerated > ago(30d)
| summarize Count = count() by VulnerabilitySeverityLevel
| order by Count desc
""", workspace_id=workspace_id)

    # 5b. Top exposed devices.
    vuln_devices_rows = _safe_kql(token, """
DeviceTvmSoftwareVulnerabilities
| where TimeGenerated > ago(30d)
| summarize VulnCount = count() by DeviceName
| top 20 by VulnCount desc
""", workspace_id=workspace_id)

    # 6. Threat intelligence indicators.
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

    # 7. Recent IOCs.
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
            # False = total_gb came from the UNFILTERED Usage fallback (billable
            # query was empty) and may read higher than the billable figure.
            "billable_only": billable_only,
        },
        "top_alerts": alerts_rows,
        "total_assets": total_assets,
        "total_assets_source": assets_source,
        "sensor_health": health_rows,
        "sensor_health_source": sensor_health_source,
        "os_breakdown":     _device_summary["os_breakdown"],
        "health_breakdown": _device_summary["health_breakdown"],
        "vulnerabilities": {
            "by_severity": vuln_severity_rows,
            "exposed_devices": vuln_devices_rows,
        },
        "threat_analytics": threat_rows,
        "ioc_updates": ioc_rows,
    }


# ── Cross-workspace merge ──────────────────────────────────────────────────────


def _sum_count_rows(rows_list: list[list[dict]], key: str, count_field: str = "Count") -> list[dict]:
    """Merge multiple [{key: X, Count: N}, ...] arrays into one summed array.

    Used for top_alerts, vulnerability_by_severity, threat_analytics — anything
    where the same key (alert name, severity, observable type) can appear in
    multiple workspaces and the right merge is to add the counts.
    """
    totals: dict[str, int] = {}
    for rows in rows_list:
        for r in rows or []:
            k = r.get(key)
            if k is None:
                continue
            totals[k] = totals.get(k, 0) + int(r.get(count_field) or 0)
    return [{key: k, count_field: v} for k, v in sorted(totals.items(), key=lambda x: -x[1])]


def _concat_dedupe(rows_list: list[list[dict]], key: str) -> list[dict]:
    """Concatenate multiple lists of dicts, keeping the first occurrence of
    each ``key``. Used for sensor_health and exposed_devices where the same
    DeviceName shouldn't be double-counted across workspaces (rare but
    possible if a device is dual-homed).
    """
    seen: set = set()
    out: list[dict] = []
    for rows in rows_list:
        for r in rows or []:
            k = r.get(key)
            if k is None or k in seen:
                continue
            seen.add(k)
            out.append(r)
    return out


def _merge_workspace_results(results: list[dict]) -> dict:
    """Combine N per-workspace fetches into one aggregated report dict.

    Scalars are summed (total_gb, total_assets), source flags are picked
    by precedence (mde > crowdstrike > heartbeat > none), lists are
    concat-deduped or sum-by-key as appropriate.
    """
    if not results:
        return {}
    if len(results) == 1:
        return results[0]

    # Numerics
    total_gb = round(sum(r.get("utilization", {}).get("total_gb", 0) for r in results), 2)
    # Average daily is a weighted average over the same period — we report
    # the simple mean of per-workspace averages, which is close enough for
    # the executive-summary section. Per-workspace breakdown stays in the
    # daily_breakdown lists if anyone needs the exact figure.
    nonzero_avgs = [r.get("utilization", {}).get("avg_daily_gb", 0) for r in results
                    if r.get("utilization", {}).get("avg_daily_gb", 0) > 0]
    avg_daily_gb = round(sum(nonzero_avgs) / len(nonzero_avgs), 2) if nonzero_avgs else 0
    total_assets = sum(r.get("total_assets", 0) for r in results)

    # Source flag precedence
    src_priority = {"mde": 3, "crowdstrike": 2, "heartbeat": 1, "none": 0}
    def best_source(field: str) -> str:
        sources = [r.get(field, "none") for r in results]
        return max(sources, key=lambda s: src_priority.get(s, 0))

    return {
        "utilization": {
            "total_gb": total_gb,
            "avg_daily_gb": avg_daily_gb,
            # daily_breakdown: concatenate to retain per-day spike days from each workspace
            "daily_breakdown": [row for r in results for row in r.get("utilization", {}).get("daily_breakdown", [])],
            "monthly_breakdown": [row for r in results for row in r.get("utilization", {}).get("monthly_breakdown", [])],
        },
        "top_alerts":          _sum_count_rows([r.get("top_alerts", []) for r in results], "AlertName"),
        "total_assets":        total_assets,
        "total_assets_source": best_source("total_assets_source"),
        # Re-cap after concatenating per-workspace samples; unhealthy-first so
        # truncation only ever drops healthy devices.
        "sensor_health":       sort_unhealthy_first(_concat_dedupe(
            [r.get("sensor_health", []) for r in results], "DeviceName"))[:DEVICE_SAMPLE_CAP],
        "sensor_health_source": best_source("sensor_health_source"),
        # Summed per key so 1.12/1.13 stay whole-fleet across workspaces.
        "os_breakdown":        _sum_count_rows(
            [r.get("os_breakdown", []) for r in results], "OSPlatform"),
        "health_breakdown":    _sum_count_rows(
            [r.get("health_breakdown", []) for r in results], "HealthStatus"),
        "vulnerabilities": {
            "by_severity":     _sum_count_rows(
                [r.get("vulnerabilities", {}).get("by_severity", []) for r in results],
                "VulnerabilitySeverityLevel",
            ),
            "exposed_devices": _concat_dedupe(
                [r.get("vulnerabilities", {}).get("exposed_devices", []) for r in results],
                "DeviceName",
            ),
        },
        "threat_analytics":    _sum_count_rows([r.get("threat_analytics", []) for r in results], "ObservableKey"),
        "ioc_updates":         [row for r in results for row in r.get("ioc_updates", [])][:200],
    }


# ── Public API ─────────────────────────────────────────────────────────────────


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """Fetch Sentinel data for the customer named in ``config["customer_id"]``.

    Behaviour:

    - Resolves ``customer.sentinel_workspaces`` (a list; legacy single-workspace
      records are auto-wrapped to a one-element list by the customers helper).
    - If ``config["_workspace_filter"]`` is set, narrows the fan-out to the
      workspace whose ``name`` matches the filter — used by per-workspace
      report mode where the orchestrator runs N report jobs, each scoped to
      one workspace.
    - Runs per-workspace fetches in parallel via a thread pool.
    - Returns a single merged dict in the same shape the rest of the
      pipeline expects. For single-workspace customers, the merged dict is
      bit-identical to the pre-multi-workspace output.
    """
    from tools.customers import get_customer

    customer_id = config.get("customer_id", "")
    customer = get_customer(customer_id) or {}

    workspaces = customer.get("sentinel_workspaces") or []
    if not workspaces:
        raise ValueError(
            f"Customer '{customer_id}' has no Sentinel workspaces configured. "
            "Add at least one workspace in the customer admin page."
        )

    workspace_filter = config.get("_workspace_filter") or ""
    if workspace_filter:
        workspaces = [w for w in workspaces if w.get("name") == workspace_filter]
        if not workspaces:
            raise ValueError(
                f"Customer '{customer_id}' has no Sentinel workspace named "
                f"{workspace_filter!r}. Available: "
                f"{[w.get('name') for w in customer.get('sentinel_workspaces', [])]}"
            )

    # Parallel fan-out. Each workspace gets its own token + KQL calls; they
    # don't share connections so a slow tenant doesn't block the others.
    max_workers = min(8, len(workspaces))
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_fetch_workspace_data, w, start_date, end_date): w
                   for w in workspaces}
        for fut, w in futures.items():
            try:
                results.append(fut.result())
            except Exception as exc:
                logger.error(
                    "Sentinel fetch failed for workspace %r (customer=%s): %s",
                    w.get("name"), customer_id, exc,
                )
                # Continue with the remaining workspaces — partial report is
                # more useful than no report. The merge skips empty results.

    return _merge_workspace_results(results)
