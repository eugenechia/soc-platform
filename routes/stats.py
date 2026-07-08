"""
Stats page (2026-07-08) — read-only operational overview.

Login-protected (Entra session, via the global before_request guard + explicit
@require_login). Shows:
  * L1 Triage pipeline health (live Jira + LLM, cached).
  * AI & enrichment services connected, with model names.
  * L1 Triage AI feature flags (killswitches) and their ON/OFF state.
  * Per-customer L1 Triage readiness matrix.

All data comes from tools.stats_data.collect_stats(), which is failure-isolated.
"""
from flask import Blueprint, render_template, session

from routes.auth import require_login
from tools.stats_data import collect_stats

stats_bp = Blueprint("stats", __name__)


@stats_bp.route("/", methods=["GET"])
@require_login
def stats_page():
    return render_template(
        "stats.html",
        user=session.get("user", {}),
        active_mode="stats",
        stats=collect_stats(),
    )
