"""Tests for the pending-tickets-by-entity breakdown (Logicalis feedback #1).
Run: .venv/bin/python tools/test_pending_by_entity.py

Two things must hold:
  1. Entity parsing pulls the "<CODE> | LOGICALIS-..." prefix (IZ -> IZENO) and
     buckets everything else as 'Unknown' — a plain summary must NOT false-match.
  2. The by-entity breakdown RECONCILES: per-entity totals sum to the pending
     total, and the per-entity aging columns sum to the aging buckets. This is
     the whole point of the feature — the grand total must match the aging
     summary and the appendix.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.jira_client import _entity_of, _compute_incident_derived_stats

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


print("== _entity_of parsing ==")
check("prefixed -> code", _entity_of("LTW | LOGICALIS-33102 | MEDIUM | net session") == "LTW")
check("IZ normalises to IZENO", _entity_of("IZ | LOGICALIS-33098 | LOW | gworkspace") == "IZENO")
check("lowercase code upper-cased", _entity_of("lcn | LOGICALIS-5 | HIGH | x") == "LCN")
check("plain summary -> Unknown (no false match)",
      _entity_of("File shared with personal email addresses") == "Unknown")
check("quoted-word summary -> Unknown",
      _entity_of("'Kepuall' unwanted software was prevented") == "Unknown")
check("pipe without LOGICALIS- -> Unknown",
      _entity_of("URGENT | please review") == "Unknown")
check("empty -> Unknown", _entity_of("") == "Unknown")

print("== reconciliation via _compute_incident_derived_stats ==")
end = "2026-06-30"
incidents = [
    # entity, created (age vs 2026-06-30), status
    {"key": "L-1", "severity": "Medium", "status": "Open",        "created": "2026-06-28", "summary": "LTW | LOGICALIS-1 | MEDIUM | a"},   # LTW  <7d
    {"key": "L-2", "severity": "High",   "status": "In Progress", "created": "2026-06-01", "summary": "LTW | LOGICALIS-2 | HIGH | b"},     # LTW  14-30d
    {"key": "L-3", "severity": "Medium", "status": "Open",        "created": "2026-05-01", "summary": "LCN | LOGICALIS-3 | MEDIUM | c"},   # LCN  >30d
    {"key": "L-4", "severity": "Low",    "status": "Open",        "created": "2026-06-20", "summary": "IZ | LOGICALIS-4 | LOW | d"},       # IZENO 7-14d
    {"key": "L-5", "severity": "Medium", "status": "Open",        "created": "2026-06-25", "summary": "Suspicious connection blocked"},     # Unknown <7d
    {"key": "L-6", "severity": "Low",    "status": "Open",        "created": "",           "summary": "File shared with personal email"},   # Unknown, undated
    {"key": "L-7", "severity": "High",   "status": "Closed",      "created": "2026-06-10", "summary": "LTW | LOGICALIS-7 | HIGH | closed"}, # excluded
]
derived = _compute_incident_derived_stats(incidents, end)
aging = derived["pending_aging"]
by_entity = aging["by_entity"]
ent = {r["entity"]: r for r in by_entity}

check("6 pending (closed excluded)", aging["total"] == 6)
check("per-entity totals sum to pending total",
      sum(r["total"] for r in by_entity) == aging["total"])
for b in ("lt_7d", "7_to_14d", "14_to_30d", "gt_30d"):
    check(f"per-entity {b} sums to aging bucket ({aging[b]})",
          sum(r[b] for r in by_entity) == aging[b])
check("LTW total = 2", ent.get("LTW", {}).get("total") == 2)
check("IZENO present (IZ normalised) total = 1", ent.get("IZENO", {}).get("total") == 1)
check("Unknown total = 2 (unprefixed + undated)", ent.get("Unknown", {}).get("total") == 2)
check("undated Unknown counted in total but not in any aging bucket",
      ent["Unknown"]["total"] == 2 and
      sum(ent["Unknown"][b] for b in ("lt_7d", "7_to_14d", "14_to_30d", "gt_30d")) == 1)
check("Unknown sorted last", by_entity[-1]["entity"] == "Unknown")
check("entities ranked by total then name (LTW, IZENO, LCN, Unknown)",
      [r["entity"] for r in by_entity] == ["LTW", "IZENO", "LCN", "Unknown"])

print()
if fails:
    print(f"FAILED ({fails} check{'s' if fails != 1 else ''})")
    sys.exit(1)
print("ALL PASS")
