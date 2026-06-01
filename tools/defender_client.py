"""
Microsoft Defender XDR — Advanced Hunting API client.

Used to populate the device-asset, sensor-health, and vulnerability sections
(1.12, 1.13, 1.14, 1.16) when MDE / TVM tables are NOT streamed into Sentinel.
The output is merged into the sentinel_data dict in routes/reports.py: when
fetch_data returns non-empty results, it OVERRIDES the Sentinel Heartbeat
fallback so the report shows real EDR data instead of "EDR not connected".

## Credential resolution (Phase C, 2026-06)

Defender XDR APIs are scoped per Entra tenant — there is no cross-tenant
Advanced Hunting. So if a customer like *Logicalis Asia* has multiple
Defender tenants (one per country), the client fans out N calls and merges
results. Credentials are taken from the customer record in priority order:

  1. ``customer["defender_workspaces"]`` — preferred. List of dicts, each
     with ``{name, tenant_id, client_id, client_secret_kv_name}``. The
     client secret is resolved from Key Vault at fetch time.
  2. Legacy global env vars (``DEFENDER_TENANT_ID`` / ``_CLIENT_ID`` /
     ``_CLIENT_SECRET``) — used as a single-tenant fallback when no
     per-customer ``defender_workspaces`` are configured. Preserves
     today's behaviour for installs that haven't migrated yet.

Returns ``{}`` if no credentials are resolvable — caller leaves
Sentinel-side fallbacks in place.
"""
import logging
from concurrent.futures import ThreadPoolExecutor

import httpx

from tools.secrets import get_secret, get_kv_secret

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
        raise PermissionError(f"Defender auth denied ({r.status_code}): {r.text[:300]}")
    if r.status_code in (400, 404):
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


def _resolve_defender_tenants(customer: dict) -> list[dict]:
    """Return a list of ``{name, tenant_id, client_id, client_secret}`` for
    every Defender tenant configured on this customer.

    Priority: per-customer ``defender_workspaces`` array first; fall back
    to the global env-var triple if the array is absent or empty.
    """
    tenants: list[dict] = []
    for w in (customer.get("defender_workspaces") or []):
        kv_name = w.get("client_secret_kv_name", "")
        secret = get_kv_secret(kv_name) if kv_name else ""
        if all([w.get("tenant_id"), w.get("client_id"), secret]):
            tenants.append({
                "name":          w.get("name") or "Defender",
                "tenant_id":     w["tenant_id"],
                "client_id":     w["client_id"],
                "client_secret": secret,
            })
        else:
            logger.warning(
                "Defender workspace %r is incomplete — skipping.", w.get("name"),
            )

    if tenants:
        return tenants

    # Legacy env-var single-tenant fallback.
    tenant_id     = get_secret("DEFENDER_TENANT_ID")
    client_id     = get_secret("DEFENDER_CLIENT_ID")
    client_secret = get_secret("DEFENDER_CLIENT_SECRET")
    if all([tenant_id, client_id, client_secret]):
        return [{"name": "Defender (env)", "tenant_id": tenant_id,
                 "client_id": client_id, "client_secret": client_secret}]
    return []


def _fetch_tenant_data(tenant_spec: dict) -> dict:
    """Run all four hunts against one Defender tenant and return the same
    flat dict shape as the original single-tenant fetch.
    """
    token = _get_access_token(
        tenant_spec["tenant_id"],
        tenant_spec["client_id"],
        tenant_spec["client_secret"],
    )

    total_assets = 0
    rows = _safe_hunt(token, """
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceName
| summarize TotalDevices = count()
""")
    if rows:
        total_assets = int(rows[0].get("TotalDevices") or 0)

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

    vuln_by_severity = _safe_hunt(token, """
DeviceTvmSoftwareVulnerabilities
| summarize Count = count() by VulnerabilitySeverityLevel
| order by Count desc
""")

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


def _merge_tenant_results(results: list[dict]) -> dict:
    """Combine N per-tenant Defender results into one aggregated dict.

    ``total_assets`` is summed; ``sensor_health`` and ``exposed_devices`` are
    concat-deduped by DeviceName; ``by_severity`` is summed by severity.
    """
    if not results:
        return {}
    if len(results) == 1:
        return results[0]

    seen_devices: set = set()
    sensor_health: list[dict] = []
    for r in results:
        for row in (r.get("sensor_health") or []):
            name = row.get("DeviceName")
            if name and name not in seen_devices:
                seen_devices.add(name)
                sensor_health.append(row)

    seen_exposed: set = set()
    exposed: list[dict] = []
    for r in results:
        for row in (r.get("vulnerabilities", {}).get("exposed_devices") or []):
            name = row.get("DeviceName")
            if name and name not in seen_exposed:
                seen_exposed.add(name)
                exposed.append(row)
    exposed.sort(key=lambda x: int(x.get("VulnCount") or 0), reverse=True)
    exposed = exposed[:20]

    sev_totals: dict[str, int] = {}
    for r in results:
        for row in (r.get("vulnerabilities", {}).get("by_severity") or []):
            sev = row.get("VulnerabilitySeverityLevel")
            if sev is None:
                continue
            sev_totals[sev] = sev_totals.get(sev, 0) + int(row.get("Count") or 0)
    by_severity = [{"VulnerabilitySeverityLevel": k, "Count": v}
                   for k, v in sorted(sev_totals.items(), key=lambda x: -x[1])]

    return {
        "total_assets":  sum(r.get("total_assets", 0) for r in results),
        "sensor_health": sensor_health,
        "vulnerabilities": {
            "by_severity":     by_severity,
            "exposed_devices": exposed,
        },
    }


def fetch_data(config: dict, start_date: str, end_date: str) -> dict:
    """Fetch Defender XDR device + vulnerability data for the customer.

    Returns {} if no Defender credentials are resolvable. Date args are
    accepted for parity with sentinel_client.fetch_data but ignored:
    DeviceInfo and DeviceTvmSoftwareVulnerabilities are snapshot tables
    that always reflect current state.
    """
    from tools.customers import get_customer
    customer = get_customer(config.get("customer_id", "")) or {}

    tenants = _resolve_defender_tenants(customer)
    if not tenants:
        logger.info("Defender XDR creds not configured — skipping.")
        return {}

    # Fan out across tenants. Same parallelism cap as Sentinel side.
    max_workers = min(8, len(tenants))
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_fetch_tenant_data, t): t for t in tenants}
        for fut, t in futures.items():
            try:
                results.append(fut.result())
            except Exception as exc:
                logger.error(
                    "Defender fetch failed for tenant %r: %s",
                    t.get("name"), exc,
                )

    return _merge_tenant_results(results)
