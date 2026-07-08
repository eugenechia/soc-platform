"""Standalone tests for tools/alert_pattern_analysis.py + the ioc_history
outcome-breakdown extension.

Run:  python tools/test_alert_pattern_analysis.py

Everything is mocked — no network, no Jira. Covers the pure functions
(timing bucketing, classification, tuning heuristic), result assembly from a
canned Jira payload (incl. pagination truncation), the killswitch, prefix
parity with Phase 3, and the extended ioc_history parsing + render_line.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Clean env before import so config knobs read defaults.
for _k in list(os.environ):
    if _k.startswith("ALERT_PATTERN_") or _k.startswith("BUSINESS_HOURS_") \
            or _k.startswith("IOC_HISTORY_") or _k.startswith("JIRA_TRIAGE_"):
        del os.environ[_k]

from tools import alert_pattern_analysis as apa

fails = 0


def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


# ── _to_sgt / _bucket_timing ──────────────────────────────────────────────
print("\n_to_sgt / _bucket_timing")

# Wed 2026-07-08 10:00 SGT expressed three ways — all business hours.
wed_biz_offset = "2026-07-08T10:00:00.000+0800"     # Jira's no-colon offset
wed_biz_utc_z = "2026-07-08T02:00:00Z"              # same instant, Zulu
wed_biz_colon = "2026-07-08T10:00:00+08:00"         # colon offset
b, a = apa._bucket_timing([wed_biz_offset, wed_biz_utc_z, wed_biz_colon])
check("same instant via +0800 / Z / +08:00 all business", (b, a) == (3, 0))

# Boundaries: 09:00 SGT is in (start inclusive), 18:00 SGT is out (end exclusive).
b, a = apa._bucket_timing(["2026-07-08T09:00:00+08:00", "2026-07-08T18:00:00+08:00"])
check("09:00 in / 18:00 out boundary", (b, a) == (1, 1))

# Weekend at 10:00 SGT is after-hours by definition.
b, a = apa._bucket_timing(["2026-07-11T10:00:00+08:00", "2026-07-12T10:00:00+08:00"])
check("Sat + Sun daytime are after-hours", (b, a) == (0, 2))

# Wed 23:30 SGT — weekday but after-hours.
b, a = apa._bucket_timing(["2026-07-08T23:30:00+08:00"])
check("weekday late night is after-hours", (b, a) == (0, 1))

# UTC instant that crosses the date line into SGT business hours:
# Tue 2026-07-07 23:30Z == Wed 07:30 SGT → after-hours (before 09:00).
b, a = apa._bucket_timing(["2026-07-07T23:30:00Z"])
check("UTC→SGT day rollover respected", (b, a) == (0, 1))

# Unparseable timestamps are skipped, not guessed.
b, a = apa._bucket_timing(["not-a-date", "", "2026-07-08T10:00:00+08:00"])
check("unparseable skipped", (b, a) == (1, 0))


# ── _classify_timing ──────────────────────────────────────────────────────
print("\n_classify_timing")

check("below min sample → insufficient-sample", apa._classify_timing(3, 1) == "insufficient-sample")
check("80% business → business-hours-only", apa._classify_timing(8, 2) == "business-hours-only")
check("79% business → mixed", apa._classify_timing(79, 21) == "mixed")
check("20% business → after-hours-only", apa._classify_timing(2, 8) == "after-hours-only")
check("21% business → mixed", apa._classify_timing(21, 79) == "mixed")
check("all business → business-hours-only", apa._classify_timing(10, 0) == "business-hours-only")
check("all after → after-hours-only", apa._classify_timing(0, 10) == "after-hours-only")


# ── _tuning_signal ────────────────────────────────────────────────────────
print("\n_tuning_signal")


def _stats(total, tp, fp, timing="business-hours-only", truncated=False):
    return {"total": total, "true_positive": tp, "false_positive": fp,
            "timing_pattern": timing, "window_days": 30, "truncated": truncated}


check("below min count → None", apa._tuning_signal(_stats(9, 0, 5)) is None)
check("below min decided → None", apa._tuning_signal(_stats(20, 0, 2)) is None)
check("fp ratio below 0.9 → None", apa._tuning_signal(_stats(20, 2, 8)) is None)

t = apa._tuning_signal(_stats(20, 0, 10))
check("clean benign case recommended", t is not None and t["recommended"])
check("business-hours-only + tp==0 → strong", t["strength"] == "strong")
check("rationale mentions count + window", "20x in 30d" in t["rationale"])

t = apa._tuning_signal(_stats(20, 1, 9))  # ratio 0.9 exactly, tp present
check("ratio edge 0.9 inclusive", t is not None)
check("tp>0 → moderate even if business-only", t["strength"] == "moderate")
check("tp>0 named in rationale", "1 True-Positive" in t["rationale"])

t = apa._tuning_signal(_stats(20, 0, 10, timing="mixed"))
check("mixed timing → moderate", t["strength"] == "moderate")

t = apa._tuning_signal(_stats(200, 0, 10, truncated=True))
check("truncated renders as N+", "200+x" in t["rationale"])


# ── prefix parity with Phase 3 ────────────────────────────────────────────
print("\nprefix parity")

from tools.historical_alerts import _normalize_summary_prefix
s = "[DUPLICATE] [URGENT] Brute force attack detected on srv-dc01 from external IP"
check("same prefix helper as Phase 3 (imported, not copied)",
      apa._normalize_summary_prefix is _normalize_summary_prefix)
check("bracket noise stripped", not apa._normalize_summary_prefix(s).startswith("["))


# ── result assembly from canned payload (_analyze, mocked _search) ────────
print("\n_analyze assembly")

os.environ["JIRA_URL"] = "https://example.atlassian.net"
os.environ["ALERT_PATTERN_MAX_PAGES"] = "2"

_biz = "2026-07-08T10:00:00.000+0800"
_aft = "2026-07-08T23:00:00.000+0800"


def _issue(key, created, labels):
    return {"key": key, "fields": {"created": created, "labels": labels}}


_page1 = {
    "issues": [
        _issue("SCDM-1", _biz, ["Benign-Positive"]),
        _issue("SCDM-2", _biz, ["Benign-Positive"]),
        _issue("SCDM-3", _biz, ["True-Positive"]),
        _issue("SCDM-4", _aft, ["Unknown"]),
        _issue("SCDM-5", "2026-07-06T09:30:00.000+0800", []),
    ],
    "nextPageToken": "tok-2",
    "isLast": False,
}
_page2 = {
    "issues": [_issue("SCDM-6", _biz, ["Benign-Positive"])],
    "nextPageToken": "tok-3",   # token still present after page cap → truncated
    "isLast": False,
}
_first_ever = {"issues": [_issue("SCDM-0", "2026-03-02T09:14:03.000+0800", [])]}

_calls = []


def _fake_search(jira_url, jql, fields, max_results, next_page_token=None):
    _calls.append({"jql": jql, "fields": fields, "max": max_results, "token": next_page_token})
    if fields == "created":            # first-seen-ever probe
        return _first_ever
    return _page2 if next_page_token == "tok-2" else _page1


_orig_search = apa._search
_orig_correlate = apa._correlate_entities
apa._search = _fake_search
apa._correlate_entities = lambda *a, **kw: [
    {"value": "40.126.31.5", "type": "IP", "count": 5, "true_positive": 0,
     "false_positive": 4, "unknown": 0, "untriaged": 1,
     "historically_benign": True, "sample_tickets": ["SCDM-90"]},
]
try:
    r = apa._analyze("SCDM-100",
                     {"summary": "Brute force attack detected on srv-dc01"},
                     "SCDM", None)
    check("returns dict", isinstance(r, dict))
    check("total across pages", r["total"] == 6)
    check("truncated when token survives page cap", r["truncated"] is True)
    check("verdict counts", (r["true_positive"], r["false_positive"],
                             r["unknown"], r["untriaged"]) == (1, 3, 1, 1))
    check("timing buckets", (r["business_hours_count"], r["after_hours_count"]) == (5, 1))
    check("first_seen_ever from ASC probe", r["first_seen_ever"].startswith("2026-03-02"))
    check("first_seen_in_window is min created", r["first_seen_in_window"].startswith("2026-07-06"))
    check("entity correlation attached", r["entity_correlation"][0]["value"] == "40.126.31.5")
    check("window fetch requested created,labels", _calls[0]["fields"] == "created,labels")
    check("second page used token", _calls[1]["token"] == "tok-2")
    first_probe = [c for c in _calls if c["fields"] == "created"]
    check("first-seen probe is ASC maxResults=1",
          first_probe and first_probe[0]["max"] == 1 and "ORDER BY created ASC" in first_probe[0]["jql"])
    check("window JQL bounds by hours", "created >= -720h" in _calls[0]["jql"])

    # Short prefix → skipped entirely.
    check("short summary skipped", apa._analyze("SCDM-101", {"summary": "Alert"}, "SCDM", None) is None)
finally:
    apa._search = _orig_search
    apa._correlate_entities = _orig_correlate


# ── killswitch + timeout wrapper ──────────────────────────────────────────
print("\nkillswitch")

os.environ["ALERT_PATTERN_ANALYSIS_ENABLED"] = "false"
check("disabled → None", apa.analyze_alert_patterns("SCDM-1", {"summary": "x" * 40}, "SCDM") is None)

os.environ["ALERT_PATTERN_ANALYSIS_ENABLED"] = "true"
_orig_analyze = apa._analyze
apa._analyze = lambda *a, **kw: {"ok": True}
try:
    check("enabled → runs through thread wrapper",
          apa.analyze_alert_patterns("SCDM-1", {"summary": "x" * 40}, "SCDM") == {"ok": True})

    def _boom(*a, **kw):
        raise RuntimeError("boom")
    apa._analyze = _boom
    check("inner exception → None, never raises",
          apa.analyze_alert_patterns("SCDM-1", {"summary": "x" * 40}, "SCDM") is None)
finally:
    apa._analyze = _orig_analyze
    del os.environ["ALERT_PATTERN_ANALYSIS_ENABLED"]


# ── ioc_history outcome extension ─────────────────────────────────────────
print("\nioc_history outcomes")

from tools import ioc_history
import tools.jira_client as jira_client

_hits = {
    "issues": [
        {"key": "SCDM-10", "fields": {"labels": ["Benign-Positive"]}},
        {"key": "SCDM-11", "fields": {"labels": ["Benign-Positive"]}},
        {"key": "SCDM-12", "fields": {"labels": []}},
    ]
}
_orig_jira_search = jira_client.jira_search
jira_client.jira_search = lambda jql, max_results=100, **kw: _hits
try:
    h = ioc_history.fetch_ioc_history("198.51.100.7", exclude_ticket_key="SCDM-99",
                                      project="SCDM")
    check("fetch bypasses killswitch (IOC_HISTORY_ENABLED unset)", h is not None)
    check("count + keys preserved", h["count"] == 3 and h["tickets"][0] == "SCDM-10")
    check("outcome breakdown parsed", (h["false_positive"], h["true_positive"],
                                       h["untriaged"]) == (2, 0, 1))
    check("historically_benign: decided>=2 and tp==0", h["historically_benign"] is True)

    line = ioc_history.render_line(h)
    check("render_line includes breakdown", "2 Benign-Positive" in line)
    check("render_line flags recurring benign", "recurring benign pattern" in line)

    # A TP appearance kills the benign flag.
    _hits["issues"][0]["fields"]["labels"] = ["True-Positive"]
    h2 = ioc_history.fetch_ioc_history("198.51.100.8", exclude_ticket_key="SCDM-99",
                                       project="SCDM")
    check("tp present → not historically benign",
          h2["historically_benign"] is False and "True-Positive" in ioc_history.render_line(h2))

    # Legacy dict shape (no outcome keys) still renders the bare line.
    legacy = ioc_history.render_line({"count": 2, "tickets": ["SCDM-1", "SCDM-2"]})
    check("legacy shape renders without breakdown",
          legacy == "  Previously flagged: 2 times — SCDM-1, SCDM-2")

    # Gated wrapper still honours the killswitch.
    check("lookup_ioc_history gated when flag unset",
          ioc_history.lookup_ioc_history("198.51.100.9", project="SCDM") is None)
finally:
    jira_client.jira_search = _orig_jira_search


print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILURE(S)'}")
sys.exit(1 if fails else 0)
