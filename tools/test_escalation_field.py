"""Standalone tests for escalation field resolution in tools/jira_escalation.py.
Run: python tools/test_escalation_field.py

The escalation field backs report section 1.5 Escalated Incidents. It is
auto-discovered by name when no override is configured, so the risk being
tested here is a WRONG field silently producing a wrong number in a
customer-facing report. The guarantees:

  * an explicit override always beats discovery
  * an ambiguous name match resolves to None (section renders "not
    configured") rather than guessing between candidates
  * a discovery outage degrades to None instead of raising
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.jira_escalation as je

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


def with_catalogue(fields):
    """Stub the Jira /field catalogue and clear the resolution cache."""
    je.reset_cache()
    je._fetch_field_catalogue = lambda project_spec: fields


def custom(fid, name, ftype="option"):
    return {"id": fid, "name": name, "custom": True, "schema": {"type": ftype}}


_orig_fetch = je._fetch_field_catalogue


def clear_env():
    os.environ.pop("JIRA_FIELD_ESCALATED", None)
    os.environ.pop("JIRA_ESCALATION_DISCOVERY", None)


# ── Precedence ───────────────────────────────────────────────────────────────
print("== resolution precedence ==")

clear_env()
with_catalogue([custom("customfield_99999", "Escalated Incident")])

spec = {"project_key": "SCDM",
        "schema": {"escalation_field": "customfield_10001"}}
res = je.resolve_escalation_field("SCDM", spec)
check("customers.json schema override wins over discovery",
      res and res["field_id"] == "customfield_10001" and res["source"] == "schema")

os.environ["JIRA_FIELD_ESCALATED"] = "customfield_20002"
res = je.resolve_escalation_field("SCDM", spec)
check("schema override still wins over the env var",
      res and res["field_id"] == "customfield_10001")

res = je.resolve_escalation_field("SCDM", {"project_key": "SCDM"})
check("env var wins over discovery when no schema override",
      res and res["field_id"] == "customfield_20002" and res["source"] == "env")

clear_env()
with_catalogue([custom("customfield_99999", "Escalated Incident")])
res = je.resolve_escalation_field("SCDM", {"project_key": "SCDM"})
check("discovery used when neither override is set",
      res and res["field_id"] == "customfield_99999" and res["source"] == "discovered")

# ── Discovery: matching ──────────────────────────────────────────────────────
print("\n== discovery matching ==")

with_catalogue([custom("customfield_1", "Escalation"),
                custom("customfield_2", "Severity")])
res = je.resolve_escalation_field("P1", None)
check("single fuzzy match resolves", res and res["field_id"] == "customfield_1")

with_catalogue([custom("customfield_1", "Escalated Incident"),
                custom("customfield_2", "Escalation Reason")])
res = je.resolve_escalation_field("P2", None)
check("two candidates: preferred exact name 'Escalated Incident' wins",
      res and res["field_id"] == "customfield_1")

with_catalogue([custom("customfield_1", "Escalation Reason"),
                custom("customfield_2", "Escalation Owner")])
res = je.resolve_escalation_field("P3", None)
check("AMBIGUOUS (no preferred exact name) resolves to None, never a guess",
      res is None)

with_catalogue([custom("customfield_1", "De-escalation Notes")])
res = je.resolve_escalation_field("P4", None)
check("'De-escalation Notes' does not match the escalation stem", res is None)

with_catalogue([custom("customfield_1", "Escalated Date", ftype="date")])
res = je.resolve_escalation_field("P5", None)
check("a date field named 'Escalated Date' is not a usable flag", res is None)

with_catalogue([{"id": "customfield_1", "name": "Escalated",
                 "custom": False, "schema": {"type": "option"}}])
res = je.resolve_escalation_field("P6", None)
check("non-custom system fields are ignored", res is None)

with_catalogue([])
check("empty catalogue resolves to None",
      je.resolve_escalation_field("P7", None) is None)

je.reset_cache()
def _boom(project_spec):
    raise RuntimeError("Jira unreachable")
je._fetch_field_catalogue = _boom
check("a discovery outage degrades to None, does not raise",
      je.resolve_escalation_field("P8", None) is None)

je.reset_cache()
je._fetch_field_catalogue = _orig_fetch
os.environ["JIRA_ESCALATION_DISCOVERY"] = "false"
check("discovery killswitch returns None without any HTTP call",
      je.resolve_escalation_field("P9", None) is None)
clear_env()

# ── Value matching ───────────────────────────────────────────────────────────
print("\n== is_escalated value matching ==")

check("single-select {'value': 'Yes'}", je.is_escalated({"value": "Yes"}) is True)
check("single-select {'value': 'No'}", je.is_escalated({"value": "No"}) is False)
check("case-insensitive 'YES'", je.is_escalated({"value": "YES"}) is True)
check("whitespace tolerated", je.is_escalated({"value": "  yes  "}) is True)
check("checkbox list [{'value': 'Yes'}]",
      je.is_escalated([{"value": "Yes"}]) is True)
check("checkbox list with no Yes", je.is_escalated([{"value": "No"}]) is False)
check("plain string 'Escalated'", je.is_escalated("Escalated") is True)
check("native bool True", je.is_escalated(True) is True)
check("None is not escalated", je.is_escalated(None) is False)
check("empty string is not escalated", je.is_escalated("") is False)
check("unrelated value is not escalated", je.is_escalated({"value": "Maybe"}) is False)
check("{'name': 'Yes'} shape also matched", je.is_escalated({"name": "Yes"}) is True)
check("custom positive vocabulary honoured",
      je.is_escalated({"value": "Escalado"}, ("escalado",)) is True)
check("default vocabulary rejected when custom list given",
      je.is_escalated({"value": "Yes"}, ("escalado",)) is False)

# ── Per-project positive-value override ──────────────────────────────────────
print("\n== positive value override ==")

clear_env()
with_catalogue([custom("customfield_1", "Escalated Incident")])
spec = {"project_key": "P10",
        "schema": {"escalation_positive_values": ["Confirmed", "Yes"]}}
res = je.resolve_escalation_field("P10", spec)
check("schema.escalation_positive_values reaches the resolution",
      res and res["positive_values"] == ("confirmed", "yes"))

je._fetch_field_catalogue = _orig_fetch
je.reset_cache()

print(f"\n{'FAILED: ' + str(fails) if fails else 'ALL PASSED'}")
sys.exit(1 if fails else 0)
