"""
Admin blueprint — customers, schedules, report history.

Migration: paste these SOC-Report routes into this file with `@admin_bp.route(...)`:
  /manage-customers                → customers() page
  /report-history                  → history() page
  /schedules                       → schedules() page
  /api/customers                   → CRUD endpoints (GET/POST/PUT/DELETE + export/import)
  /api/schedules                   → CRUD endpoints (GET/POST/PUT/DELETE + run-now)
  /api/migrate                     → one-time migration helper

All `os.environ.get(...)` for secrets must be replaced with `get_secret(...)`.
"""
from flask import Blueprint, render_template, session
from routes.auth import require_login

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/customers")
@require_login
def customers():
    return render_template("customers.html", user=session.get("user", {}), active_mode="admin")


@admin_bp.route("/history")
@require_login
def history():
    return render_template("history.html", user=session.get("user", {}), active_mode="history")


@admin_bp.route("/schedules")
@require_login
def schedules():
    return render_template("schedules.html", user=session.get("user", {}), active_mode="schedules")

# TODO: port api_customers_*, api_schedules_*, api_reports_*, api_migrate
