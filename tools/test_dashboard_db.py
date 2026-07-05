"""Standalone tests for the L2 dashboard data layer (Stage 1).
Run: python tools/test_dashboard_db.py

Part A — parse_issue / _parse_bot_comment_text (pure, no network, no DB):
synthetic Jira search issues with ADF bot comments, covering explanation
extraction, verdict parsing, label fallback, PENDING fallback, and
first_enrichment_at selection.

Part B — metric SQL (needs Postgres): runs only when TEST_DATABASE_URL is
set; creates the table via init_db(), loads fixture rows, asserts the four
metric values, then removes the fixture rows. Skipped otherwise."""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.dashboard_sync import parse_issue, _parse_bot_comment_text

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


def adf_comment(text_parts, created):
    return {
        "created": created,
        "body": {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": t}]}
            for t in text_parts
        ]},
    }


BOT_COMMENT_TEXTS = [
    "VERDICT: TRUE-POSITIVE",
    "AUTO-TRIAGE: Assigned to GSOC for investigation.",
    "RECOMMENDED ACTION: Block the source IP at the perimeter.",
    "L1 Triage Report (Automated)",
    "IOCs (2 flagged · 3 checked) 1.2.3.4 malicious ...",
]


def issue_fixture(key="SCDM-1", labels=None, comments=None, status="Open",
                  severity="Critical", resolution=None):
    return {
        "key": key,
        "fields": {
            "summary": "Brute force attack detected",
            "status": {"name": status},
            "priority": {"name": "High"},
            "assignee": {"displayName": "GSOC Analyst", "accountId": "abc123"},
            "resolution": {"name": resolution} if resolution else None,
            "labels": labels or [],
            "created": "2026-07-01T10:00:00.000+0800",
            "customfield_10038": {"value": severity},
            "customfield_10488": {"value": "Microsoft Sentinel"},
            "comment": {"comments": comments or []},
        },
    }


print("Part A — bot-comment parsing:")

expl, verdict = _parse_bot_comment_text(" ".join(BOT_COMMENT_TEXTS))
check("verdict parsed from panel text", verdict == "TRUE-POSITIVE")
check("explanation starts at VERDICT:", expl.startswith("VERDICT: TRUE-POSITIVE"))
check("explanation includes AUTO-TRIAGE", "AUTO-TRIAGE" in expl)
check("explanation stops before report heading",
      "L1 Triage Report" not in expl and "IOCs" not in expl)
check("explanation capped at 300 chars", len(expl) <= 300)

expl, verdict = _parse_bot_comment_text("just an analyst note about VPN logins")
check("non-bot text -> empty parse", expl == "" and verdict == "")

rec = parse_issue(
    issue_fixture(comments=[
        adf_comment(["Analyst note: checking with customer"], "2026-07-01T10:02:00.000+0800"),
        adf_comment(BOT_COMMENT_TEXTS, "2026-07-01T10:05:00.000+0800"),
        adf_comment(["VERDICT: BENIGN-POSITIVE", "AUTO-TRIAGE: Whitelisted.",
                     "L1 Triage Report (Automated)"], "2026-07-01T11:00:00.000+0800"),
    ]),
    customer_id="cust1", project_key="SCDM",
)
check("latest bot comment wins for verdict", rec["verdict_label"] == "BENIGN-POSITIVE")
check("latest bot comment wins for explanation", "Whitelisted" in rec["ai_explanation"])
check("first_enrichment_at = earliest bot comment",
      rec["first_enrichment_at"] is not None
      and rec["first_enrichment_at"].hour == 10 and rec["first_enrichment_at"].minute == 5)
check("analyst comment not treated as bot",
      rec["first_enrichment_at"].minute != 2)
check("severity normalised through", rec["severity"] == "Critical")
check("source from Incident Type", rec["source"] == "Microsoft Sentinel")
check("assignee account id captured", rec["assignee_account_id"] == "abc123")
check("created_at parsed", rec["created_at"] is not None)

rec = parse_issue(issue_fixture(labels=["True-Positive"], comments=[]),
                  customer_id="cust1", project_key="SCDM")
check("no bot comment -> verdict from label", rec["verdict_label"] == "TRUE-POSITIVE")
check("no bot comment -> empty explanation", rec["ai_explanation"] == "")
check("no bot comment -> null first_enrichment_at", rec["first_enrichment_at"] is None)

rec = parse_issue(issue_fixture(labels=[], comments=[]),
                  customer_id="cust1", project_key="SCDM")
check("no comment + no label -> PENDING", rec["verdict_label"] == "PENDING")


print("Part B — metric SQL (needs TEST_DATABASE_URL):")
test_dsn = os.environ.get("TEST_DATABASE_URL", "")
if not test_dsn:
    print("  SKIP  TEST_DATABASE_URL not set — parser tests above still ran")
else:
    os.environ["DATABASE_URL"] = test_dsn
    from tools import db
    db.init_db()
    check("dashboard table created", db.dashboard_table_ok)

    now = datetime.now(timezone.utc)
    fixture_keys = []

    def row(key, status, severity, verdict, created_min_ago, enriched_min_ago=None):
        fixture_keys.append(key)
        db.upsert_dashboard_ticket({
            "ticket_key": key, "customer_id": "test-cust", "project_key": "TST",
            "summary": key, "severity": severity, "source": "Sentinel",
            "verdict_label": verdict, "priority": "High", "assignee": "",
            "assignee_account_id": "", "raw_status": status, "resolution": "",
            "ai_explanation": "", "created_at": now - timedelta(minutes=created_min_ago),
            "first_enrichment_at": (now - timedelta(minutes=enriched_min_ago))
            if enriched_min_ago is not None else None,
        })

    # 2 active (1 critical), 2 closed (1 benign) -> auto-resolved 50%
    # response times: 5 min and 15 min -> avg 600s
    row("TST-1", "Open", "Critical", "TRUE-POSITIVE", 60, 55)     # 5 min response
    row("TST-2", "In Progress", "High", "PENDING", 50)
    row("TST-3", "Closed", "Low", "BENIGN-POSITIVE", 40, 25)      # 15 min response
    row("TST-4", "Closed", "Low", "TRUE-POSITIVE", 30)

    m = db.load_dashboard_metrics("test-cust")
    check("active = 2", m["active"] == 2)
    check("critical = 1", m["critical"] == 1)
    check("avg response = 600s", m["avg_response_seconds"] is not None
          and abs(m["avg_response_seconds"] - 600) < 2)
    check("auto-resolved = 50%", m["auto_resolved_pct"] == 50.0)

    feed = db.load_dashboard_feed("test-cust", limit=10)
    check("feed newest-first", [r["ticket_key"] for r in feed[:2]] == ["TST-4", "TST-3"])
    check("feed row carries verdict", feed[0]["verdict_label"] == "TRUE-POSITIVE")

    db.touch_dashboard_ticket_after_action("TST-2", priority="Highest",
                                           bogus_column="ignored")
    check("optimistic touch updates priority",
          db.get_dashboard_ticket("TST-2")["priority"] == "Highest")

    other = db.load_dashboard_metrics("someone-else")
    check("customer scoping isolates metrics", other["active"] == 0)

    with db._conn() as con:
        con.execute("DELETE FROM dashboard_tickets WHERE customer_id = %s",
                    ("test-cust",))
    print("  (fixture rows cleaned up)")

print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
sys.exit(1 if fails else 0)
