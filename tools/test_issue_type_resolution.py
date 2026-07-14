"""Standalone tests for issue type resolution in tools/jira_client.py.
Run: python tools/test_issue_type_resolution.py

Covers the NTCJ false-zero bug (July 2026): the configured Change Request
issue type "Change" was a valid site-wide name but the project only uses
"[System] Change", so JQL returned 0 rows with no error and the report
printed zero instead of the real count. Resolution now validates the
configured name against the project's actual issue types.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.jira_client as jc

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


JSM_TYPES = ["[System] Incident", "[System] Service request",
             "[System] Change", "[System] Problem"]
PLAIN_TYPES = ["Incident", "Service Request", "Change", "Task"]

_orig_get_types = jc._get_project_issue_type_names
_orig_jira_search = jc.jira_search


def with_project_types(types):
    jc._get_project_issue_type_names = lambda pk, project_spec=None: types


print("== _resolve_issue_type_for_project ==")

with_project_types(JSM_TYPES)
check("default 'Change' resolves to '[System] Change' (NTCJ bug)",
      jc._resolve_issue_type_for_project("Change", jc._CHANGE_REQUEST_ALIASES, "NTCJ")
      == "[System] Change")
check("default 'Service Request' resolves to '[System] Service request'",
      jc._resolve_issue_type_for_project("Service Request", jc._SERVICE_REQUEST_ALIASES, "NTCJ")
      == "[System] Service request")
check("exact name passes through with canonical casing",
      jc._resolve_issue_type_for_project("[system] change", jc._CHANGE_REQUEST_ALIASES, "NTCJ")
      == "[System] Change")
check("unknown configured name falls back to alias list",
      jc._resolve_issue_type_for_project("Change Management", jc._CHANGE_REQUEST_ALIASES, "NTCJ")
      == "[System] Change")

with_project_types(PLAIN_TYPES)
check("plain-named project: 'Change' matches 'Change' unchanged",
      jc._resolve_issue_type_for_project("Change", jc._CHANGE_REQUEST_ALIASES, "PROJ")
      == "Change")
check("case-insensitive match returns project casing",
      jc._resolve_issue_type_for_project("service request", jc._SERVICE_REQUEST_ALIASES, "PROJ")
      == "Service Request")

with_project_types(["[System] Incident", "[System] Problem"])
check("type absent from project resolves to None",
      jc._resolve_issue_type_for_project("Change", jc._CHANGE_REQUEST_ALIASES, "PROJ")
      is None)

with_project_types(None)
check("createmeta unreachable: configured name passes through unvalidated",
      jc._resolve_issue_type_for_project("Change", jc._CHANGE_REQUEST_ALIASES, "PROJ")
      == "Change")


print("== fetch_change_requests uses resolution ==")

searched_jqls = []

def fake_jira_search(jql, max_results=100, next_page_token=None, project_spec=None):
    searched_jqls.append(jql)
    return {"issues": [], "isLast": True}

jc.jira_search = fake_jira_search

with_project_types(["[System] Incident", "[System] Problem"])
searched_jqls.clear()
out = jc.fetch_change_requests("PROJ", "2026-06-01", "2026-06-02")
check("no matching type: unavailable=True", out.get("unavailable") is True)
check("no matching type: Jira is never queried", len(searched_jqls) == 0)

with_project_types(JSM_TYPES)
searched_jqls.clear()
out = jc.fetch_change_requests("NTCJ", "2026-06-01", "2026-06-02")
check("resolved type appears in JQL",
      searched_jqls and all('issuetype = "[System] Change"' in q for q in searched_jqls))
check("resolved fetch: unavailable=False", out.get("unavailable") is False)


print("== _fetch_jira_by_type pagination ==")

def paged_jira_search(jql, max_results=100, next_page_token=None, project_spec=None):
    # Two pages: keys P-1..P-100, then P-101..P-150.
    if next_page_token is None:
        return {"issues": [{"key": f"P-{n}", "fields": {}} for n in range(1, 101)],
                "nextPageToken": "tok2", "isLast": False}
    return {"issues": [{"key": f"P-{n}", "fields": {}} for n in range(101, 151)],
            "isLast": True}

jc.jira_search = paged_jira_search
out = jc._fetch_jira_by_type("[System] Change", "PROJ", "2026-06-01", "2026-06-01")
check("all pages fetched (150 items across 2 pages)",
      len(out["items"]) == 150)
check("stats total matches", out["stats"].get("total") == 150)

jc.jira_search = _orig_jira_search
jc._get_project_issue_type_names = _orig_get_types

print()
if fails:
    print(f"{fails} FAILED")
    sys.exit(1)
print("ALL PASS")
