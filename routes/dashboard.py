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
  POST /api/chat         grounded copilot Q&A over the alert data
  GET  /api/volume       hourly alert counts (volume chart)
  GET  /api/search       read-model + live-Jira ticket search
  GET  /api/status       integration status + system health (sidebar)
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


@dashboard_bp.route("/api/volume")
@require_login
def api_volume():
    gate = _gate()
    if gate:
        return gate
    from tools import db
    try:
        return jsonify({"buckets": db.load_dashboard_volume(_customer_id_param(),
                                                            hours=24)})
    except Exception:
        log.exception("dashboard volume query failed")
        return jsonify({"error": "volume unavailable"}), 500


@dashboard_bp.route("/api/search")
@require_login
def api_search():
    gate = _gate()
    if gate:
        return gate
    q = (request.args.get("q") or "").strip()[:100]
    if len(q) < 2:
        return jsonify({"error": "query too short"}), 400
    customer_id = _customer_id_param()

    from tools import db
    try:
        local = db.search_dashboard_tickets(q, customer_id, limit=50)
    except Exception:
        log.exception("dashboard search (read-model) failed")
        local = []
    for r in local:
        for col in ("created_at", "first_enrichment_at"):
            r[col + "_display"] = _iso_sgt(r.get(col))
            r[col] = r[col].isoformat() if r.get(col) else None
        if r.get("synced_at"):
            r["synced_at"] = r["synced_at"].isoformat()

    # Live Jira reaches past the sync window; failure degrades to local-only.
    jira_rows: list[dict] = []
    try:
        from tools.customers import load_customers
        from tools.dashboard_jira import search_jira_text
        keys: list[str] = []
        for c in (load_customers() or []):
            if customer_id and c.get("id") != customer_id:
                continue
            for p in (c.get("jira_projects") or []):
                k = (p.get("project_key") or "").strip()
                if k and k not in keys:
                    keys.append(k)
        local_keys = {r["ticket_key"] for r in local}
        jira_rows = [r for r in search_jira_text(q, keys, max_results=20)
                     if r["ticket_key"] not in local_keys]
        for r in jira_rows:
            r["created_at_display"] = r.get("created_at", "")
    except Exception:
        log.exception("dashboard search (live Jira) failed")

    return jsonify({"query": q, "tickets": local + jira_rows,
                    "local_count": len(local), "jira_count": len(jira_rows)})


@dashboard_bp.route("/api/status")
@require_login
def api_status():
    gate = _gate()
    if gate:
        return gate
    from tools import db

    db_ok = db.dashboard_db_ok()
    last_sync = db.dashboard_last_synced()
    sync_age_s = None
    if last_sync:
        try:
            sync_age_s = int((datetime.now(timezone.utc)
                              - last_sync).total_seconds())
        except Exception:
            sync_age_s = None
    interval_min = int(os.environ.get("DASHBOARD_SYNC_INTERVAL_MIN", "5"))
    jira_ok = sync_age_s is not None and sync_age_s < interval_min * 60 * 3

    sentinel_customers = 0
    try:
        from tools.customers import load_customers
        for c in (load_customers() or []):
            if c.get("sentinel_workspaces"):
                sentinel_customers += 1
    except Exception:
        pass

    integrations = [
        {"name": "Jira", "ok": jira_ok,
         "detail": (f"synced {sync_age_s // 60}m ago" if sync_age_s is not None
                    else "no sync yet")},
        {"name": "PostgreSQL", "ok": db_ok,
         "detail": "connected" if db_ok else "unreachable"},
        {"name": "Azure OpenAI",
         "ok": bool(os.environ.get("AZURE_OPENAI_ENDPOINT")
                    or os.environ.get("OPENAI_API_KEY")),
         "detail": "configured"},
        {"name": "Microsoft Sentinel", "ok": sentinel_customers > 0,
         "detail": f"{sentinel_customers} customer(s)"},
        {"name": "Splunk", "ok": bool(os.environ.get("SPLUNK_HOST")),
         "detail": "configured" if os.environ.get("SPLUNK_HOST") else "not configured"},
        {"name": "SOCRadar", "ok": bool(os.environ.get("SOCRADAR_COMPANY_KEY")
                                        or os.environ.get("SOCRADAR_API_KEY")),
         "detail": "configured"},
    ]
    healthy = db_ok and jira_ok
    return jsonify({
        "integrations": integrations,
        "health": {
            "ok": healthy,
            "text": "All systems operational" if healthy
                    else "Degraded — check sync/database",
            "last_sync_age_s": sync_age_s,
        },
    })


@dashboard_bp.route("/api/chat", methods=["POST"])
@require_login
def api_chat():
    gate = _gate()
    if gate:
        return gate
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message") or "").strip()[:2000]
    if not message:
        return jsonify({"error": "empty message"}), 400
    history = payload.get("history")
    if not isinstance(history, list):
        history = []
    cid = (str(payload.get("customer_id") or "")).strip()
    customer_id = None if cid in ("", "all") else cid

    from tools.dashboard_chat import answer
    user = session.get("user", {})
    log.info("dashboard chat: question by %s (customer=%s)",
             user.get("email", "?"), customer_id or "all")
    reply = answer(message, history, customer_id)
    return jsonify({"reply": reply})
