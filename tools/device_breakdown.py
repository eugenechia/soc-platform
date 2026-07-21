"""Aggregate monitored-device rows into OS / sensor-health breakdowns.

Why this module exists (2026-07-21): section 1.12 reported 200 assets for a
965-device fleet. The device hunt ended in ``| order by HealthStatus asc | take
200`` and both the 1.12 donut and the 1.13 health pie derived their totals by
counting rows of that slice -- so the cap silently became the answer. Worse, the
slice was sorted alphabetically by health state, and "Active" sorts ahead of
"ImpairedCommunication"/"Inactive"/"NoSensorData", so the 200 rows were entirely
healthy devices and section 1.13 showed a perfect fleet while hiding every
broken sensor.

The fix follows the pattern the SOCRadar payload already uses: compute
AGGREGATES over the full population, and ship only a bounded SAMPLE downstream.
Counts come from here; the sample is only ever illustrative.

``sort_unhealthy_first`` is the second half of the guarantee: whatever the cap,
the devices an analyst needs to act on are the ones that survive it.

Pure functions -- no network, no config, no side effects.
"""
from __future__ import annotations

from collections import Counter

# The only state that means "this sensor is fine". Everything else -- Inactive,
# ImpairedCommunication, NoSensorData, Misconfigured, Unknown, or missing --
# is treated as needing attention. Deliberately a whitelist: an unrecognised
# state must sort toward the analyst, never away from them.
_HEALTHY = "active"

_UNKNOWN_OS = "Unknown"
_UNKNOWN_HEALTH = "Unknown"

# How many device rows travel downstream to the 1.13 table and the LLM payload.
# This bounds the PROMPT ONLY -- reported counts always come from the aggregates
# above and cover the whole fleet. Conflating the two is what produced a
# 200-asset report for a 965-device fleet.
DEVICE_SAMPLE_CAP = 200


def _health_of(row: dict) -> str:
    return str((row or {}).get("HealthStatus")
               or (row or {}).get("health_status") or "").strip()


def _os_of(row: dict) -> str:
    return str((row or {}).get("OSPlatform")
               or (row or {}).get("os_platform") or "").strip()


def is_healthy(row: dict) -> bool:
    """True only for an explicitly Active sensor."""
    return _health_of(row).lower() == _HEALTHY


def sort_unhealthy_first(rows: list) -> list:
    """Stable sort putting every non-Active device ahead of the Active ones.

    Capping the result is then safe: truncation drops healthy devices first.
    """
    return sorted(rows or [], key=is_healthy)


def _tally(pairs: Counter, key_name: str) -> list[dict]:
    """Counter -> [{key_name: value, "Count": n}], count desc then name asc so
    the output is deterministic across runs (charts and tables read this)."""
    return [{key_name: name, "Count": count}
            for name, count in sorted(pairs.items(), key=lambda kv: (-kv[1], kv[0]))]


def summarize_devices(rows: list) -> dict:
    """Aggregate the FULL device list into totals the charts can trust.

    Returns ``{"total": int, "os_breakdown": [{OSPlatform, Count}],
    "health_breakdown": [{HealthStatus, Count}]}``. OS strings stay raw here
    (e.g. "WindowsServer2019"); rolling them into display families is the
    chart layer's job.
    """
    rows = rows or []
    os_counts: Counter = Counter()
    health_counts: Counter = Counter()
    for row in rows:
        os_counts[_os_of(row) or _UNKNOWN_OS] += 1
        health_counts[_health_of(row) or _UNKNOWN_HEALTH] += 1
    return {
        "total": len(rows),
        "os_breakdown": _tally(os_counts, "OSPlatform"),
        "health_breakdown": _tally(health_counts, "HealthStatus"),
    }
