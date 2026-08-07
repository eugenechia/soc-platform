"""Standalone tests for escalated incident statistics (report section 1.5).
Run: python tools/test_escalated_stats.py

The central invariant under test: an UNRESOLVED escalation field must never be
reportable as "zero escalations". Those two states look identical in a bar
chart, so the data layer keeps them distinct via `escalated.available` and the
prompt renders a "pending integration" placeholder for the unavailable case.

Also covers the multi-project merge, where a customer whose second Jira project
lacks the field would otherwise get a total that silently omits it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.jira_client as jc
from tools.chart_generator import _leading_zero_note, generate_escalated_charts

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


def inc(key, severity="High", escalated=False, cj="True Positive",
        created="2026-08-04T10:00:00.000+0800", labels=None, status="Closed",
        priority="High"):
    return {"key": key, "summary": f"{key} summary", "severity": severity,
            "status": status, "priority": priority, "assignee": "analyst",
            "created": created, "updated": created, "resolved": created,
            "close_justification": cj, "labels": labels or [],
            "incident_type": "", "escalated": escalated}


# Priority deliberately diverges from severity (A-3 is High severity but Low
# priority) so a breakdown that quietly read the wrong field would fail here.
# "Pending with Customer" is the real SCDM status string — it is not literally
# "Pending", which is exactly the trap the status bucketing has to survive.
INCIDENTS = [
    inc("A-1", "Critical", escalated=True, cj="True Positive", labels=["c2"],
        priority="High"),
    inc("A-2", "High", escalated=True, cj="True Positive", labels=["c2"],
        priority="High"),
    inc("A-3", "High", escalated=True, cj="", labels=["scan"],
        priority="Low", status="Pending with Customer"),
    inc("A-4", "Medium", escalated=False, cj="Benign Positive", labels=["scan"]),
    inc("A-5", "Low", escalated=False, cj="Benign Positive", labels=["scan"]),
    inc("A-6", "Low", escalated=False, cj="", status="Open",
        created="2026-07-04T10:00:00.000+0800"),
]

# ── Availability semantics ───────────────────────────────────────────────────
print("== availability: unresolved field != zero escalations ==")

unavail = jc._compute_stats(INCIDENTS, escalation_available=False)["escalated"]
check("field unresolved -> available False", unavail["available"] is False)
check("field unresolved -> total 0", unavail["total"] == 0)
check("field unresolved -> rate is None, not 0.0",
      unavail["escalation_rate_pct"] is None)
check("field unresolved -> every breakdown empty",
      not unavail["by_status"] and not unavail["by_priority"]
      and not unavail["by_resolution"] and not unavail["monthly_trend"])

none_escalated = jc._compute_stats(
    [inc("B-1", escalated=False), inc("B-2", escalated=False)],
    escalation_available=True)["escalated"]
check("field resolved but nothing escalated -> available True",
      none_escalated["available"] is True)
check("field resolved but nothing escalated -> rate 0.0, NOT None",
      none_escalated["escalation_rate_pct"] == 0.0)

# ── Counters ─────────────────────────────────────────────────────────────────
print("\n== escalated counters ==")

esc = jc._compute_stats(INCIDENTS, escalation_available=True)["escalated"]
check("total counts only escalated incidents", esc["total"] == 3)
check("escalation rate is 3/6 = 50.0", esc["escalation_rate_pct"] == 50.0)
check("by_status splits pending from closed",
      esc["by_status"] == {"Pending": 1, "Closed": 2})
check("by_status reconciles to total",
      sum(esc["by_status"].values()) == esc["total"])
check("by_priority counts PRIORITY, not severity",
      esc["by_priority"] == {"High": 2, "Low": 1})
check("by_priority reconciles to total",
      sum(esc["by_priority"].values()) == esc["total"])
check("by_priority follows the Highest->Lowest ladder",
      list(esc["by_priority"]) == ["High", "Low"])
check("by_resolution keeps a zero False Positive category",
      esc["by_resolution"]["False Positive"] == 0)
check("by_resolution counts justifications of CLOSED escalations only",
      esc["by_resolution"]["True Positive"] == 2)
check("by_resolution carries a Pending bucket",
      esc["by_resolution"]["Pending"] == 1)
check("by_resolution reconciles to total",
      sum(esc["by_resolution"].values()) == esc["total"])
check("by_close_justification excludes the Pending bucket",
      "Pending" not in esc["by_close_justification"])
check("monthly_trend restricted to escalated", esc["monthly_trend"] == {"2026-08": 3})

full = jc._compute_stats(INCIDENTS, escalation_available=True)
check("all-incident totals unaffected by the escalated block", full["total"] == 6)
check("all-incident by_severity unaffected",
      full["by_severity"] == {"Critical": 1, "High": 2, "Medium": 1, "Low": 2})

check("blank close_justification excluded from escalated resolution counts",
      "" not in esc["by_resolution"] and "Unspecified" not in esc["by_resolution"])

zero_div = jc._compute_stats([], escalation_available=True)["escalated"]
check("no incidents at all -> rate None, no ZeroDivisionError",
      zero_div["escalation_rate_pct"] is None and zero_div["total"] == 0)

# ── Multi-project merge ──────────────────────────────────────────────────────
print("\n== multi-project merge ==")

def project(key, incidents, available):
    return {"project_key": key, "project_name": key,
            "incidents": incidents,
            "stats": jc._compute_stats(incidents, escalation_available=available)}

p_a = project("AAA", INCIDENTS, True)
p_b = project("BBB", [inc("C-1", "Critical", escalated=True, labels=["c2"])], True)

merged = jc._merge_project_results([p_a, p_b])["stats"]["escalated"]
check("both projects resolved -> merged available", merged["available"] is True)
check("escalated totals sum across projects", merged["total"] == 4)
check("merged rate uses the combined incident total (4/7)",
      merged["escalation_rate_pct"] == 57.1)
check("merged by_status sums per key",
      merged["by_status"] == {"Pending": 1, "Closed": 3})
check("merged by_priority sums and keeps ladder order",
      list(merged["by_priority"]) == ["High", "Low"])
check("merged by_resolution reconciles to merged total",
      sum(merged["by_resolution"].values()) == merged["total"])

p_c = project("CCC", [inc("D-1", escalated=False)], False)
partial = jc._merge_project_results([p_a, p_c])["stats"]["escalated"]
check("one project missing the field -> whole customer marked unavailable",
      partial["available"] is False)
check("partial merge reports 0, never a silent undercount",
      partial["total"] == 0)

single = jc._merge_project_results([p_a])["stats"]["escalated"]
check("single-project shortcut returns its block untouched", single["total"] == 3)

# ── 12-month series shape ────────────────────────────────────────────────────
print("\n== 12-month escalated series ==")

_orig = jc._fetch_month_count
jc._fetch_month_count = lambda pk, ms, me, issue_type=None, project_spec=None, \
    escalation=None: (10, 4 if escalation else 0)

import tools.jira_escalation as je
je.reset_cache()
je_orig = je.resolve_escalation_field

je.resolve_escalation_field = lambda pk, spec=None: {
    "field_id": "customfield_1", "field_name": "Escalated Incident",
    "positive_values": ("yes",), "source": "env"}
res = jc.fetch_monthly_counts_12m("P", "2026-08-31")
check("returns both series", set(res) == {"total", "escalated"})
check("12 months in each series",
      len(res["total"]) == 12 and len(res["escalated"]) == 12)
check("escalated series populated", set(res["escalated"].values()) == {4})

je.resolve_escalation_field = lambda pk, spec=None: None
res = jc.fetch_monthly_counts_12m("P", "2026-08-31")
check("unresolved field -> escalated series is None, not a dict of zeros",
      res["escalated"] is None)
check("total series still returned when escalation unresolved",
      len(res["total"]) == 12)

res = jc.fetch_monthly_counts_12m("P", "not-a-date")
check("invalid end_date returns the both-series shape, does not raise",
      res == {"total": {}, "escalated": None})

jc._fetch_month_count = _orig
je.resolve_escalation_field = je_orig

# ── Chart gating ─────────────────────────────────────────────────────────────
print("\n== chart gating ==")

check("unavailable -> no escalated charts at all",
      generate_escalated_charts({"available": False}) == {})
check("empty block -> no escalated charts", generate_escalated_charts({}) == {})

charts = generate_escalated_charts(esc, end_date="2026-08-31")
check("available -> status/priority/resolution/trend charts produced",
      set(charts) == {"escalated_status", "escalated_priority",
                      "escalated_resolution", "escalated_monthly_trend"})
check("all escalated charts are non-empty PNGs",
      all(v.startswith(b"\x89PNG") for v in charts.values()))

months = ["2025-09", "2025-10", "2025-11", "2025-12"]
check("leading zeros annotated (field added partway through the window)",
      _leading_zero_note(months, [0, 0, 3, 5])
      == "No escalations were recorded before Nov 2025.")
check("series starting at month 0 gets no note",
      _leading_zero_note(months, [2, 0, 3, 5]) == "")
check("all-zero series gets no note", _leading_zero_note(months, [0, 0, 0, 0]) == "")

print(f"\n{'FAILED: ' + str(fails) if fails else 'ALL PASSED'}")
sys.exit(1 if fails else 0)
