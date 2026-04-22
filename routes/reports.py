"""
Generate Report mode — structured, calendar-driven report generation.

This blueprint is a thin skeleton. The heavy logic (collecting data from
Jira/Splunk/Sentinel/SOCRadar, running openai-agents, building the markdown
context, persisting to SQLite) comes from SOC-Report's original `app.py`.

Migration steps:
1. Copy SOC-Report/app.py functions verbatim into this file:
      _collect_quarterly_data, _collect_report_data, _build_report_context,
      _build_unified_toc, run_report_job, _load_reports_list,
      _load_report, _get_charts_bytes, REPORT_SECTIONS, _REPORT_TAIL,
      REPORT_SYSTEM_PROMPT
2. Replace `@app.route(...)` with `@reports_bp.route(...)`.
3. Replace `app.logger` with `log = logging.getLogger(__name__)`.
4. Replace any os.environ reads for secrets with `get_secret(name)`.
5. Wire the report jobs dict to stay module-level (one scheduler replica = fine).
"""
import logging

from flask import Blueprint, render_template, session

from routes.auth import require_login

log = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/")
@require_login
def index():
    """Main Generate Report page — calendar picker, section checklist, customer dropdown."""
    return render_template(
        "reports.html",
        user=session.get("user", {}),
        active_mode="reports",
    )


# === PORT FROM SOC-Report/app.py =============================================
# Paste the following routes here, updating decorators:
#
# @reports_bp.route("/api/sections")                       -> api_sections()
# @reports_bp.route("/api/generate",    methods=["POST"])  -> generate()
# @reports_bp.route("/api/generate-poll/<job_id>")         -> generate_poll(job_id)
# @reports_bp.route("/api/reports",     methods=["GET"])   -> api_reports_list()
# @reports_bp.route("/api/reports/<rid>", methods=["GET"]) -> api_reports_get(rid)
# @reports_bp.route("/api/reports/<rid>", methods=["DELETE"]) -> api_reports_delete(rid)
#
# Functions invoked by the above stay as module-private (_collect_report_data etc.).
# =============================================================================
