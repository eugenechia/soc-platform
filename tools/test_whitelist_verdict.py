"""Standalone tests for Improvement #3 — Confluence whitelist drives the verdict.
Run: python tools/test_whitelist_verdict.py

Covers the precision guard (whitelist_match._has_approval_keyword) and the pure
override decision (enrichment.decide_whitelist_override). No network / no Chroma."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.whitelist_match import _has_approval_keyword
from tools.enrichment import decide_whitelist_override

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1

def ioc(value, verdict):
    return {"ioc": {"value": value, "type": "ip"}, "verdict": verdict}

def wl(value, context):
    return {"ioc": value, "ioc_type": "ip", "whitelist_context": context}

print("precision guard (_has_approval_keyword):")
check("'Whitelisted IP as per customer update' -> True",
      _has_approval_keyword("Whitelisted IP address as per customer update is 1.2.3.4"))
check("'approved sender list' -> True", _has_approval_keyword("Approved sender list: 1.2.3.4"))
check("'allow-listed' -> True", _has_approval_keyword("This host is allow-listed for scanning"))
check("mere mention (incident write-up) -> False",
      not _has_approval_keyword("On 2026-05-01 the malicious IP 1.2.3.4 was seen beaconing"))
check("generic 'benign' NOT treated as approval (too generic) -> False",
      not _has_approval_keyword("traffic looked benign at first glance"))

print("decide_whitelist_override — benign override:")
# unknown IOC that IS whitelist-approved -> flips to clean (the valuable case)
v, applied, conflict = decide_whitelist_override("unknown", [ioc("1.2.3.4", "unknown")],
                                                 [wl("1.2.3.4", True)])
check("unknown + approved -> clean, applied", v == "clean" and applied and not conflict)
# clean stays clean, marked applied (whitelist confirms benign)
v, applied, conflict = decide_whitelist_override("clean", [ioc("1.2.3.4", "clean")],
                                                 [wl("1.2.3.4", True)])
check("clean + approved -> clean, applied", v == "clean" and applied)

print("decide_whitelist_override — safety (no silent suppression):")
# unknown IOC present that is NOT approved -> must NOT override
v, applied, conflict = decide_whitelist_override(
    "unknown", [ioc("1.2.3.4", "unknown"), ioc("9.9.9.9", "unknown")], [wl("1.2.3.4", True)])
check("one unapproved unknown remains -> stays unknown", v == "unknown" and not applied)
# match present but whitelist_context False (mere mention) -> ignored
v, applied, conflict = decide_whitelist_override("unknown", [ioc("1.2.3.4", "unknown")],
                                                 [wl("1.2.3.4", False)])
check("mention-only (context False) -> no override", v == "unknown" and not applied)
# no whitelist matches at all -> unchanged
v, applied, conflict = decide_whitelist_override("unknown", [ioc("1.2.3.4", "unknown")], [])
check("no matches -> unchanged", v == "unknown" and not applied)

print("decide_whitelist_override — reputation wins on conflict:")
# malicious IOC that is ALSO whitelisted -> stays malicious + conflict surfaced
v, applied, conflict = decide_whitelist_override("malicious", [ioc("1.2.3.4", "malicious")],
                                                 [wl("1.2.3.4", True)])
check("malicious + whitelisted -> stays malicious, NOT applied", v == "malicious" and not applied)
check("malicious + whitelisted -> conflict surfaced", len(conflict) == 1 and conflict[0]["ioc"] == "1.2.3.4")
# malicious IOC not whitelisted; a DIFFERENT clean IOC is whitelisted -> no false conflict
v, applied, conflict = decide_whitelist_override(
    "malicious", [ioc("1.2.3.4", "malicious"), ioc("8.8.8.8", "clean")], [wl("8.8.8.8", True)])
check("malicious(unlisted) + clean(listed) -> stays malicious, no conflict",
      v == "malicious" and not applied and not conflict)

print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
sys.exit(1 if fails else 0)
