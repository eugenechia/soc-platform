"""Standalone tests for tools/jira_schema.py.  Run: python tools/test_jira_schema.py
Covers the resolver, fail-loud detector, and schema discovery. (Extraction-
integration tests live alongside the enrichment threading.)"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.jira_schema import (
    default_schema, resolve_jira_schema, detect_schema_mismatch, discover_schema,
    _DEFAULT_ENTITY_FIELDS, _DEFAULT_SEVERITY_FIELD,
)

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1

def adf(text):
    return {"type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]}

HASH_JSON = ('{"hashValue":"86efb8e9f94de2091c3e96da63e94f676bb8e536","algorithm":"SHA1","Type":"filehash"}  '
             '{"hashValue":"949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b","algorithm":"SHA256"}')

# entities in the DEFAULT SCDM field IDs (Defender JSON content)
DEFAULT_FIELDS = {
    "customfield_10082": adf(HASH_JSON),
    "customfield_10079": adf('{"address":"10.30.60.154","Type":"ip"}'),
    "customfield_10038": adf("Sev-2"),
}
# same hash content but in a NON-default field -> a mis-mapped customer
REMAPPED_FIELDS = {"customfield_20082": adf(HASH_JSON)}
REMAPPED_CUSTOMER = {"jira_projects": [
    {"project_key": "ACME", "schema": {"entity_fields": {"hash": "customfield_20082"},
                                       "severity_field": "customfield_20038",
                                       "severity_map": {"p1": "Highest"},
                                       "siem_source": "crowdstrike"}}]}

print("resolver:")
d = default_schema()
check("default source", d.source == "default")
check("default entity fields == globals", d.entity_fields == _DEFAULT_ENTITY_FIELDS)
check("default severity field", d.severity_field == _DEFAULT_SEVERITY_FIELD)
check("no customer -> default", resolve_jira_schema(None, "ACME").source == "default")
check("unmatched project -> default", resolve_jira_schema(REMAPPED_CUSTOMER, "OTHER").source == "default")

r = resolve_jira_schema(REMAPPED_CUSTOMER, "ACME")
check("override source", r.source == "customer")
check("override hash field", r.entity_fields["hash"] == "customfield_20082")
check("partial merge keeps default ip field", r.entity_fields["ip"] == _DEFAULT_ENTITY_FIELDS["ip"])
check("override severity field", r.severity_field == "customfield_20038")
check("siem_source carried", r.siem_source == "crowdstrike")

print("severity_to_priority:")
check("default sev-2 -> Medium", default_schema().severity_to_priority("Sev-2") == "Medium")
check("default critical -> Highest", default_schema().severity_to_priority("Critical") == "Highest")
check("custom p1 -> Highest (merged)", r.severity_to_priority("P1") == "Highest")
check("custom keeps defaults too", r.severity_to_priority("sev-3") == "Low")
check("empty severity -> None", default_schema().severity_to_priority("") is None)

print("detect_schema_mismatch:")
w = detect_schema_mismatch(REMAPPED_FIELDS, default_schema(), [])
check("mismatch fires when content present but 0 IOCs", w is not None and w["kind"] == "entity_fields")
check("suspect field identified", w is not None and "customfield_20082" in w["suspect_fields"])
check("no warning when IOCs present", detect_schema_mismatch(REMAPPED_FIELDS, default_schema(), [{"value": "x"}]) is None)
check("no warning on empty ticket (don't cry wolf)", detect_schema_mismatch({"customfield_10038": adf("")}, default_schema(), []) is None)
check("no warning under the correct schema", detect_schema_mismatch(REMAPPED_FIELDS, resolve_jira_schema(REMAPPED_CUSTOMER, "ACME"), [{"value": "x"}]) is None)

print("discover_schema:")
disc = discover_schema(DEFAULT_FIELDS)
sug = disc["suggested"]["entity_fields"]
check("discover suggests hash field", sug.get("hash") == "customfield_10082")
check("discover suggests ip field", sug.get("ip") == "customfield_10079")
check("discover suggests severity field", disc["suggested"]["severity_field"] == "customfield_10038")
check("discover infers defender/json source", disc["suggested"]["siem_source"] == "defender")

print("extraction threading (schema -> enrichment):")
from tools.enrichment import extract_iocs_from_entity_fields
SHA1 = "86efb8e9f94de2091c3e96da63e94f676bb8e536"
SHA256 = "949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b"
d_iocs = extract_iocs_from_entity_fields(DEFAULT_FIELDS, default_schema())
d_vals = {i["value"] for i in d_iocs}
check("default schema extracts SHA1", SHA1 in d_vals)
check("default schema extracts SHA256", SHA256 in d_vals)
check("default schema filters internal IP", "10.30.60.154" not in d_vals)
check("schema=None == default schema (SCDM unchanged)",
      {i["value"] for i in extract_iocs_from_entity_fields(DEFAULT_FIELDS)} == d_vals)
r_sch = resolve_jira_schema(REMAPPED_CUSTOMER, "ACME")
r_vals = {i["value"] for i in extract_iocs_from_entity_fields(REMAPPED_FIELDS, r_sch)}
check("remapped schema extracts hash from custom field", SHA1 in r_vals)
check("default schema extracts NOTHING from remapped field",
      extract_iocs_from_entity_fields(REMAPPED_FIELDS, default_schema()) == [])

print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
sys.exit(1 if fails else 0)
