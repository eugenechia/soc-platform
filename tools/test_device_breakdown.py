"""Regression tests for the asset-inventory truncation bug (2026-07-21).
Run: python tools/test_device_breakdown.py

Background — the complaint that triggered this:
  Section 1.12 "Total Assets Under Monitoring" reported 200 assets across 5 OS
  families for a customer whose real fleet is 965 across 15 OS strings. Root
  cause was `| order by HealthStatus asc | take 200` in defender_client's device
  hunt: both the 1.12 donut and the 1.13 health pie derived their totals by
  COUNTING ROWS of that truncated, alphabetically-biased slice.

These tests pin the two properties that were violated:
  1. Totals are computed over the FULL fleet, not the sample shipped downstream.
  2. The sample is ordered unhealthy-first, so capping it can never hide a
     broken sensor (the old `HealthStatus asc` did exactly that).

Pure functions only — no network, no matplotlib rendering, no Azure.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.device_breakdown import summarize_devices, sort_unhealthy_first
from tools.chart_generator import _family, _group_families

fails = 0


def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


# The real fleet from the analyst spreadsheet: 965 devices, 15 OS strings.
REAL_OS_COUNTS = {
    "Windows11 10.0":        605,
    "Linux 9.7":             116,
    "Windows10 10.0":         71,
    "macOS 26.5":             57,
    "Windows":                29,
    "WindowsServer2019":      19,
    "Android 15":             19,
    "WindowsServer2016":      18,
    "WindowsServer2022":      15,
    "iOS 26.5":                9,
    "WindowsServer2025":       3,
    "WindowsServer2012R2":     1,
    "Windows10WVD 10.0":       1,
    "WindowsXp":               1,
    "Windows7":                1,
}
TOTAL = 965

# A plausible health mix. The exact split does not matter; what matters is that
# unhealthy devices are a minority, so an `order by HealthStatus asc | take 200`
# slice consists entirely of "Active" and hides every one of them.
REAL_HEALTH_COUNTS = {
    "Active":                912,
    "Inactive":               31,
    "ImpairedCommunication":  18,
    "NoSensorData":            4,
}


def build_fleet():
    """965 device rows carrying the real OS and health distributions."""
    os_seq, health_seq = [], []
    for name, n in REAL_OS_COUNTS.items():
        os_seq += [name] * n
    for name, n in REAL_HEALTH_COUNTS.items():
        health_seq += [name] * n
    assert len(os_seq) == len(health_seq) == TOTAL
    return [
        {"DeviceName": f"HOST-{i:04d}", "OSPlatform": o, "HealthStatus": h}
        for i, (o, h) in enumerate(zip(os_seq, health_seq))
    ]


fleet = build_fleet()

print("the old behaviour is genuinely broken (guards against regressing to it):")
# Reproduce the old pipeline exactly: sort by HealthStatus asc, take 200,
# then count rows -- which is what both charts used to do.
old_slice = sorted(fleet, key=lambda r: r["HealthStatus"])[:200]
old_total = len(old_slice)
old_families = {}
for r in old_slice:
    fam = _family(r["OSPlatform"])
    old_families[fam] = old_families.get(fam, 0) + 1
old_health = {r["HealthStatus"] for r in old_slice}
check("old pipeline reports 200, not 965", old_total == 200 and TOTAL == 965)
check("old pipeline loses whole OS families (Android/iOS vanish)",
      "Android" not in old_families and "iOS" not in old_families)
check("old pipeline hides every unhealthy sensor (100% Active)",
      old_health == {"Active"})

print("summarize_devices aggregates over the FULL fleet:")
summary = summarize_devices(fleet)
check("total is 965", summary["total"] == TOTAL)
check("os_breakdown sums to 965",
      sum(r["Count"] for r in summary["os_breakdown"]) == TOTAL)
check("health_breakdown sums to 965",
      sum(r["Count"] for r in summary["health_breakdown"]) == TOTAL)
check("os_breakdown keeps all 15 raw OS strings",
      len(summary["os_breakdown"]) == len(REAL_OS_COUNTS))
_os_map = {r["OSPlatform"]: r["Count"] for r in summary["os_breakdown"]}
check("Windows11 count preserved (605)", _os_map.get("Windows11 10.0") == 605)
check("Android survives (19)", _os_map.get("Android 15") == 19)
_health_map = {r["HealthStatus"]: r["Count"] for r in summary["health_breakdown"]}
check("unhealthy sensors are visible (31 Inactive, 18 Impaired, 4 NoSensorData)",
      _health_map.get("Inactive") == 31
      and _health_map.get("ImpairedCommunication") == 18
      and _health_map.get("NoSensorData") == 4)
check("os_breakdown sorted by count desc",
      [r["Count"] for r in summary["os_breakdown"]]
      == sorted((r["Count"] for r in summary["os_breakdown"]), reverse=True))
check("empty input yields zero total, empty breakdowns",
      summarize_devices([]) == {"total": 0, "os_breakdown": [], "health_breakdown": []})

print("OS family rollup matches the analyst's spreadsheet:")
fam_counts = {}
for row in summary["os_breakdown"]:
    fam = _family(row["OSPlatform"])
    fam_counts[fam] = fam_counts.get(fam, 0) + row["Count"]
check("Windows Client = 707 (11 + 10 + bare + XP + 7)", fam_counts.get("Windows Client") == 707)
check("Linux = 116",         fam_counts.get("Linux") == 116)
check("macOS = 57",          fam_counts.get("macOS") == 57)
check("Windows Server = 56", fam_counts.get("Windows Server") == 56)
check("Android = 19",        fam_counts.get("Android") == 19)
check("iOS = 9",             fam_counts.get("iOS") == 9)
check("Windows AVD = 1 (Windows10WVD, not lumped into Client)",
      fam_counts.get("Windows AVD") == 1)
check("families sum to 965", sum(fam_counts.values()) == TOTAL)
check("nothing fell through to 'Other'", "Other" not in fam_counts)

print("wedge grouping keeps all 7 real families (cap raised 6 -> 8):")
grouped = _group_families(fam_counts)
check("7 wedges, no 'Other'",
      len(grouped) == 7 and all(k != "Other" for k, _ in grouped))
check("grouped total still 965", sum(v for _, v in grouped) == TOTAL)
check("largest wedge first", grouped[0] == ("Windows Client", 707))
# A pathological long tail must still be capped.
many = {f"OS{i}": 100 - i for i in range(20)}
capped = _group_families(many)
check("20 families cap to 8 wedges with an 'Other'",
      len(capped) == 8 and capped[-1][0] == "Other")
check("capping preserves the grand total",
      sum(v for _, v in capped) == sum(many.values()))

print("sample is ordered unhealthy-first so a cap cannot hide a broken sensor:")
sample = sort_unhealthy_first(fleet)[:200]
check("sample still 200 rows", len(sample) == 200)
check("every unhealthy device (53) survives a 200-row cap",
      sum(1 for r in sample if r["HealthStatus"] != "Active") == 31 + 18 + 4)
check("unhealthy devices come before Active ones",
      all(r["HealthStatus"] != "Active" for r in sample[:53]))
check("Active devices fill the remainder",
      all(r["HealthStatus"] == "Active" for r in sample[53:]))
check("sort is total (no rows dropped)", len(sort_unhealthy_first(fleet)) == TOTAL)
check("unknown/missing health sorts as unhealthy, not silently trusted",
      sort_unhealthy_first([{"HealthStatus": "Active"}, {}])[0] == {})

print()
print(("FAILED %d check(s)" % fails) if fails else "All checks passed.")
sys.exit(1 if fails else 0)
