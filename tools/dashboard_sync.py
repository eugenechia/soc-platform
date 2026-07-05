"""
Dashboard read-model sync — snapshots recent Jira tickets into the
``dashboard_tickets`` Postgres table (tools/db.py).

Read-only against Jira; the ONLY thing it writes is dashboard_tickets. It
never imports or executes the enrichment pipeline — the AI explanation is
recovered by PARSING the L1 enrichment comment that enrichment already posted
to the ticket, so a change here can never affect how tickets are triaged.

Registered in tools/scheduler.py behind DASHBOARD_ENABLED (default false):
an interval job every DASHBOARD_SYNC_INTERVAL_MIN minutes plus an immediate
startup sync (the same pattern as the RAG auto-sync).

Failure isolation: one bad project or ticket skips, never aborts the run; a
429 from Jira aborts the remaining projects for THIS cycle only (the
``updated >=`` window means the next cycle catches up).
"""
from __future__ import annotations

import logging
import os
import re
import time

logger = logging.getLogger(__name__)

# Ticket recency window for the JQL (Jira relative-date syntax, e.g. "-3d").
_SYNC_WINDOW = os.environ.get("DASHBOARD_SYNC_WINDOW", "-3d")
# Politeness delay between per-project search calls, in milliseconds.
_PROJECT_DELAY_MS = int(os.environ.get("DASHBOARD_SYNC_PROJECT_DELAY_MS", "200"))
# Hard cap on pages per project per cycle (100 issues/page).
_MAX_PAGES = int(os.environ.get("DASHBOARD_SYNC_MAX_PAGES", "5"))

# Markers identifying the L1 enrichment bot comment. Both are stable strings
# rendered by tools/enrichment.py's comment builders (verdict panel + report
# heading), so no bot account id is needed.
_BOT_HEADING = "L1 Triage Report (Automated)"
_VERDICT_RE = re.compile(r"VERDICT:\s*(TRUE-POSITIVE|BENIGN-POSITIVE|UNKNOWN)",
                         re.IGNORECASE)

_EXPLANATION_MAX_CHARS = 300


def _parse_bot_comment_text(text: str) -> tuple[str, str]:
    """Given the plaintext of one bot comment, return (explanation, verdict).

    The explanation is the verdict panel content: everything from "VERDICT:"
    up to the report heading (i.e. VERDICT / AUTO-TRIAGE / RECOMMENDED ACTION
    lines), whitespace-collapsed and capped. Either value may be ''.
    """
    if not text:
        return "", ""
    m = _VERDICT_RE.search(text)
    verdict = m.group(1).upper() if m else ""

    start = text.find("VERDICT:")
    if start < 0:
        return "", verdict
    end = text.find(_BOT_HEADING, start)
    snippet = text[start:end if end > start else start + _EXPLANATION_MAX_CHARS]
    snippet = " ".join(snippet.split()).strip()
    if len(snippet) > _EXPLANATION_MAX_CHARS:
        snippet = snippet[:_EXPLANATION_MAX_CHARS - 1].rstrip() + "…"
    return snippet, verdict


def parse_issue(issue: dict, customer_id: str, project_key: str) -> dict:
    """Map one Jira search result (with comments) to a dashboard_tickets
    record dict. Pure function — unit-tested against a captured fixture."""
    from tools.jira_client import _extract_adf_text, _normalize_severity, _parse_jira_date

    fields = issue.get("fields", {}) or {}
    status = fields.get("status") or {}
    priority = fields.get("priority") or {}
    assignee = fields.get("assignee") or {}
    resolution = fields.get("resolution") or {}

    raw_severity = (fields.get("customfield_10038") or {}).get("value", "") or \
        (priority.get("name", "") if priority else "")
    source = (fields.get("customfield_10488") or {}).get("value", "") \
        if isinstance(fields.get("customfield_10488"), dict) \
        else str(fields.get("customfield_10488") or "")

    # Scan comments for the L1 enrichment bot's report: latest bot comment
    # supplies explanation + verdict; earliest supplies first_enrichment_at.
    ai_explanation, verdict_label = "", ""
    first_enrichment_at = None
    comments = ((fields.get("comment") or {}).get("comments")) or []
    for c in comments:
        text = _extract_adf_text(c.get("body"))
        if _BOT_HEADING not in text and "VERDICT:" not in text:
            continue
        created = _parse_jira_date(c.get("created", ""))
        if created and (first_enrichment_at is None or created < first_enrichment_at):
            first_enrichment_at = created
        expl, verdict = _parse_bot_comment_text(text)
        if expl:
            ai_explanation = expl       # later comments overwrite → latest wins
        if verdict:
            verdict_label = verdict

    # Fallback when the bot hasn't commented (or parse failed): the triage
    # label enrichment applies to the ticket, else PENDING.
    if not verdict_label:
        labels_lower = {str(l).lower() for l in (fields.get("labels") or [])}
        if "true-positive" in labels_lower:
            verdict_label = "TRUE-POSITIVE"
        elif "benign-positive" in labels_lower:
            verdict_label = "BENIGN-POSITIVE"
        elif "unknown" in labels_lower:
            verdict_label = "UNKNOWN"
        else:
            verdict_label = "PENDING"

    return {
        "ticket_key": issue.get("key", ""),
        "customer_id": customer_id,
        "project_key": project_key,
        "summary": fields.get("summary", "") or "",
        "severity": _normalize_severity(raw_severity),
        "source": source or "",
        "verdict_label": verdict_label,
        "priority": priority.get("name", "") if priority else "",
        "assignee": assignee.get("displayName", "") if assignee else "",
        "assignee_account_id": assignee.get("accountId", "") if assignee else "",
        "raw_status": status.get("name", "") if status else "",
        "resolution": resolution.get("name", "") if resolution else "",
        "ai_explanation": ai_explanation,
        "created_at": _parse_jira_date(fields.get("created", "")),
        "first_enrichment_at": first_enrichment_at,
    }


def _sync_project(customer_id: str, project: dict) -> tuple[int, bool]:
    """Sync one Jira project. Returns (tickets_upserted, rate_limited)."""
    from tools.dashboard_jira import jira_search_with_comments
    from tools import db

    project_key = (project.get("project_key") or "").strip()
    if not project_key:
        return 0, False

    jql = f'project = "{project_key}" AND updated >= {_SYNC_WINDOW} ORDER BY updated DESC'
    count, next_token = 0, None
    for _page in range(_MAX_PAGES):
        result = jira_search_with_comments(jql, max_results=100,
                                           next_page_token=next_token,
                                           project_spec=project)
        if result.get("error"):
            rate_limited = result.get("status_code") == 429
            logger.warning("dashboard_sync: %s search failed (%s)%s",
                           project_key, result.get("error"),
                           " — rate limited, backing off" if rate_limited else "")
            return count, rate_limited
        for issue in result.get("issues", []):
            try:
                db.upsert_dashboard_ticket(parse_issue(issue, customer_id, project_key))
                count += 1
            except Exception:
                logger.exception("dashboard_sync: upsert failed for %s",
                                 issue.get("key", "?"))
        next_token = result.get("nextPageToken")
        if not result.get("issues") or not next_token or result.get("isLast") is True:
            break
    return count, False


def run_dashboard_sync(reason: str = "cron") -> dict:
    """Sync all customers' Jira projects into dashboard_tickets.

    Never raises — the scheduler must survive any failure here.
    """
    summary = {"customers": 0, "projects": 0, "tickets": 0, "errors": 0}
    try:
        from tools import db
        if not db.dashboard_table_ok:
            logger.warning("dashboard_sync: table unavailable — skipping run")
            return summary
        from tools.customers import load_customers
        customers = load_customers() or []

        logger.info("dashboard_sync: starting (%s), %d customer(s)",
                    reason, len(customers))
        for cust in customers:
            summary["customers"] += 1
            for project in (cust.get("jira_projects") or []):
                try:
                    count, rate_limited = _sync_project(cust.get("id", ""), project)
                    summary["projects"] += 1
                    summary["tickets"] += count
                    if rate_limited:
                        logger.warning("dashboard_sync: 429 — abandoning cycle, "
                                       "next cycle catches up")
                        return summary
                except Exception:
                    summary["errors"] += 1
                    logger.exception("dashboard_sync: project %s failed",
                                     project.get("project_key", "?"))
                if _PROJECT_DELAY_MS > 0:
                    time.sleep(_PROJECT_DELAY_MS / 1000.0)
        logger.info("dashboard_sync: done — %(tickets)d ticket(s) across "
                    "%(projects)d project(s), %(errors)d error(s)", summary)
    except Exception:
        logger.exception("dashboard_sync: run failed")
    return summary
