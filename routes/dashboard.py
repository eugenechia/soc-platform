"""
L2 Analyst Copilot Dashboard — read-only UI (Stage 2).

Serves the dashboard page plus its polling JSON endpoints. Reads ONLY the
dashboard_tickets read-model that tools/dashboard_sync.py maintains — never
Jira live, never the enrichment pipeline. Multi-tenant via ?customer_id=
(empty/"all" = every customer).

All routes sit behind Entra SSO (@require_login, plus the app-level
before_request guard). Flag-gated by DASHBOARD_ENABLED: when the flag is
off every route 404s and the nav tab is hidden, so the app behaves as if
the feature does not exist.

Routes under /dashboard/*:
  GET  /                 the dashboard UI
  GET  /api/metrics      the four metric-card values
  GET  /api/feed         recent ticket snapshots, newest first
"""
import logging
import os
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, render_template, request, session

from routes.auth import require_login

log = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)

SGT = timezone(timedelta(hours=8))

_FEED_LIMIT_DEFAULT = int(os.environ.get("DASHBOARD_FEED_LIMIT", "100"))


def _enabled() -> bool:
    return os.environ.get("DASHBOARD_ENABLED", "false").lower() == "true"


def _gate():
    """Return an error response when the dashboard is unavailable, else None."""
    if not _enabled():
        return "Not found", 404
    from tools import db
    if not db.dashboard_table_ok:
        return jsonify({"error": "dashboard storage unavailable"}), 503
    return None


def _customer_id_param() -> str | None:
    cid = (request.args.get("customer_id") or "").strip()
    return None if cid in ("", "all") else cid


def _iso_sgt(dt) -> str:
    """Render a datetime in SGT for display; '' for None."""
    if not dt:
        return ""
    try:
        if isinstance(dt, str):
            return dt
        return dt.astimezone(SGT).strftime("%Y-%m-%d %H:%M SGT")
    except Exception:
        return str(dt)


@dashboard_bp.route("/")
@require_login
def index():
    gate = _gate()
    if gate:
        return gate
    from tools.customers import load_customers
    customers = [{"id": c.get("id", ""), "name": c.get("name", "")}
                 for c in (load_customers() or []) if c.get("id")]
    customers.sort(key=lambda c: c["name"].lower())
    jira_base = os.environ.get("JIRA_URL", "").rstrip("/")
    return render_template("dashboard.html", user=session.get("user", {}),
                           active_mode="dashboard", customers=customers,
                           jira_base=jira_base)


@dashboard_bp.route("/api/metrics")
@require_login
def api_metrics():
    gate = _gate()
    if gate:
        return gate
    from tools import db
    try:
        window = int(request.args.get("window", "7"))
    except ValueError:
        window = 7
    if window not in (1, 7, 30):
        window = 7
    try:
        metrics = db.load_dashboard_metrics(_customer_id_param(), window_days=window)
    except Exception:
        log.exception("dashboard metrics query failed")
        return jsonify({"error": "metrics unavailable"}), 500
    metrics["window_days"] = window
    return jsonify(metrics)


@dashboard_bp.route("/api/feed")
@require_login
def api_feed():
    gate = _gate()
    if gate:
        return gate
    from tools import db
    try:
        limit = int(request.args.get("limit", _FEED_LIMIT_DEFAULT))
    except ValueError:
        limit = _FEED_LIMIT_DEFAULT
    try:
        rows = db.load_dashboard_feed(_customer_id_param(), limit=limit)
    except Exception:
        log.exception("dashboard feed query failed")
        return jsonify({"error": "feed unavailable"}), 500

    newest_sync = None
    for r in rows:
        for col in ("created_at", "first_enrichment_at"):
            r[col + "_display"] = _iso_sgt(r.get(col))
            r[col] = r[col].isoformat() if r.get(col) else None
        if r.get("synced_at"):
            if newest_sync is None or r["synced_at"] > newest_sync:
                newest_sync = r["synced_at"]
            r["synced_at"] = r["synced_at"].isoformat()
    return jsonify({
        "tickets": rows,
        "last_synced": newest_sync.isoformat() if newest_sync else None,
        "last_synced_display": _iso_sgt(newest_sync),
    })
