"""
Microsoft Defender XDR — Advanced Hunting API client.

Used to populate the device-asset, sensor-health, and vulnerability sections
(1.12, 1.13, 1.14, 1.16) when MDE / TVM tables are NOT streamed into Sentinel.
The output is merged into the sentinel_data dict in routes/reports.py: when
fetch_data returns non-empty results, it OVERRIDES the Sentinel Heartbeat
fallback so the report shows real EDR data instead of "EDR not connected".

Authenticated against a separate SP from Sentinel (Defender data may live in
a different tenant entirely). Reads creds via tools.secrets.get_secret:
  - DEFENDER_TENANT_ID
  - DEFENDER_CLIENT_ID
  - DEFENDER_CLIENT_SECRET
Returns {} if any of the three is missing — caller treats that as "Defender
not configured" and the Sentinel-side fallbacks remain in effect.
"""
import logging

import httpx

from tools.secrets import get_secret

logger = logging.getLogger(__name__)

_TOKEN_SCOPE = "https://api.security.microsoft.com/.default"
_HUNTING_URL = "https://api.security.microsoft.com/api/advancedhunting/run"


def _get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    r = httpx.post(url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": _TOKEN_SCOPE,
    }, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def _run_hunt(token: str, query: str) -> list[dict]:
    r = httpx.post(
        _HUNTING_URL,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"Query": query},
        timeout=60,
    )
    if r.status_code in (401, 403):
        # Auth/role failure — propagate so the orchestrator can mark Defender
        # as disconnected and fall back to whatever Sentinel produced.
        raise PermissionError(f"Defender auth denied ({r.status_code}): {r.text[:300]}")
    if r.status_code in (400, 404):
        # Table missing or query malformed — same posture as sentinel_client._safe_kql.
        logger.warning("Defender hunt returned %s: %s", r.status_code, r.text[:200])
        return []
    r.raise_for_status()
    return r.json().get("Results", []) or []


def _safe_hunt(token: str, query: str) -> list[dict]:
    try:
        return _run_hunt(token, query)
    except PermissionError:
        raise
    except Exception as e:
        logger.warning("Defender hunt skipped (%s): %s", type(e).__name__, e)
        return []


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """Fetch device + vulnerability data from Microsoft Defender XDR.

    Returns {} if creds aren't configured — caller leaves Sentinel-side
    fallbacks in place. The returned shape mirrors the subset of sentinel
    fields that this client supersedes:
        {
            "total_assets":           int,
            "sensor_health":          list[dict],
            "vulnerabilities": {
                "by_severity":     list[dict],
                "exposed_devices": list[dict],
            },
        }
    Date args are accepted for API parity with sentinel_client.fetch_data
    but ignored: DeviceInfo and DeviceTvmSoftwareVulnerabilities are
    snapshot tables — filtering by report-period TimeGenerated would
    exclude rows that legitimately reflect current state.
    """
    tenant_id     = get_secret("DEFENDER_TENANT_ID")
    client_id     = get_secret("DEFENDER_CLIENT_ID")
    client_secret = get_secret("DEFENDER_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        logger.info("Defender XDR creds not configured — skipping.")
        return {}

    token = _get_access_token(tenant_id, client_id, client_secret)

    # 1. Total onboarded devices — one row per DeviceName via arg_max on the
    # latest Timestamp, then count. Matches sentinel_client's DeviceInfo query.
    total_assets = 0
    rows = _safe_hunt(token, """
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceName
| summarize TotalDevices = count()
""")
    if rows:
        total_assets = int(rows[0].get("TotalDevices") or 0)

    # 2. Per-device sensor health snapshot. Field names match the shape the
    # report's LLM prompt expects when total_assets_source == "mde":
    # DeviceName, OnboardingStatus, HealthStatus, OSPlatform, ExposureLevel, LastSeen.
    sensor_health = _safe_hunt(token, """
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceName
| project
    DeviceName,
    OnboardingStatus,
    HealthStatus = iff(isempty(SensorHealthState), "Unknown", SensorHealthState),
    OSPlatform   = strcat(OSPlatform, iff(isnotempty(OSVersion), strcat(" ", OSVersion), "")),
    ExposureLevel,
    LastSeen     = Timestamp
| order by HealthStatus asc
| take 200
""")

    # 3. Vulnerability severity breakdown — same shape as
    # sentinel.vulnerabilities.by_severity (columns: VulnerabilitySeverityLevel, Count).
    vuln_by_severity = _safe_hunt(token, """
DeviceTvmSoftwareVulnerabilities
| summarize Count = count() by VulnerabilitySeverityLevel
| order by Count desc
""")

    # 4. Top exposed devices — columns: DeviceName, VulnCount.
    vuln_exposed = _safe_hunt(token, """
DeviceTvmSoftwareVulnerabilities
| summarize VulnCount = count() by DeviceName
| top 20 by VulnCount desc
""")

    return {
        "total_assets":  total_assets,
        "sensor_health": sensor_health,
        "vulnerabilities": {
            "by_severity":     vuln_by_severity,
            "exposed_devices": vuln_exposed,
        },
    }
