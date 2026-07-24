"""Tests for the Sentinel utilization chart's month selection.
Run: .venv/bin/python tools/test_utilization_chart_months.py

Guards the fix for the "a completed month changes between reports" bug
(Logicalis feedback, July 2026). The Past-3-Months chart used to render from a
LIVE trailing-3-month Usage query, whose oldest month loses its early days to
Sentinel's 90-day retention every time the report runs — so a finished April
fell from 520 GB to ~328 GB between the May and June reports. The chart now
prefers the FROZEN per-month total (current month live + prior months captured
from their own saved reports), falling back to the live daily bucket only for a
month with no frozen value. These tests pin that preference.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.chart_generator import _resolve_utilization_months

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


def _days(month_prefix, first_day, last_day, gb_each):
    """Build daily Usage rows for month_prefix (YYYY-MM), days first..last."""
    return [{"TimeGenerated": f"{month_prefix}-{d:02d}T00:00:00Z", "TotalGB": gb_each}
            for d in range(first_day, last_day + 1)]


# The real regression: April is retention-truncated in the LIVE daily feed
# (only 2026-04-11..30 survive => ~200 GB), but frozen history has the true 520.
live_daily = (
    _days("2026-04", 11, 30, 10.0)   # 20 days * 10 = 200 GB (April 1-10 aged out)
    + _days("2026-05", 1, 31, 7.1)   # ~220 GB
    + _days("2026-06", 1, 30, 7.58)  # ~227 GB
)
frozen = {"2026-03": 766.16, "2026-04": 520.0, "2026-05": 220.22, "2026-06": 227.43}

print("== frozen preferred over retention-truncated live ==")
months, values = _resolve_utilization_months(live_daily, "2026-06-30", frozen)
check("months are the 3 ending at end_date, in order",
      months == ["2026-04", "2026-05", "2026-06"])
by = dict(zip(months, values))
check(f"April uses FROZEN 520.0, not truncated live (~200) [got {by['2026-04']}]",
      by["2026-04"] == 520.0)
check(f"May uses frozen 220.22 [got {by['2026-05']}]", by["2026-05"] == 220.22)
check(f"June uses frozen 227.43 [got {by['2026-06']}]", by["2026-06"] == 227.43)

print("== live fallback for a month absent from frozen ==")
# Frozen has no April => April must fall back to the live daily bucket (200).
frozen_no_apr = {"2026-05": 220.22, "2026-06": 227.43}
months2, values2 = _resolve_utilization_months(live_daily, "2026-06-30", frozen_no_apr)
by2 = dict(zip(months2, values2))
check(f"April falls back to live 200.0 when unfrozen [got {by2['2026-04']}]",
      by2["2026-04"] == 200.0)
check("May still uses frozen 220.22", by2["2026-05"] == 220.22)

print("== no data is safe (no crash, zeros) ==")
months3, values3 = _resolve_utilization_months([], "2026-06-30", None)
check("three months returned", len(months3) == 3)
check("all zero when nothing supplied", values3 == [0, 0, 0])

print()
if fails:
    print(f"FAILED ({fails} check{'s' if fails != 1 else ''})")
    sys.exit(1)
print("ALL PASS")
