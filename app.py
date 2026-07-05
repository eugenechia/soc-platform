"""
soc-platform — Flask entrypoint.

Responsibilities: app factory, blueprint registration, db + scheduler startup,
global auth hook. NO business logic. All feature code lives in routes/.

Run locally:      python app.py
Run in Container: gunicorn --workers 1 --threads 4 --bind 0.0.0.0:5060 app:app
(APScheduler requires --workers 1 for scheduling correctness.)
"""
import os
import logging
import secrets as pysecrets

from dotenv import load_dotenv
load_dotenv()  # must precede any tools import that reads env at module level

from flask import Flask, redirect, render_template, request, session

from tools import db
from tools import scheduler
from tools.secrets import get_secret

from routes.auth import auth_bp, require_login
from routes.reports import reports_bp
from routes.admin import admin_bp
from routes.exports import exports_bp
from routes.webhook import webhook_bp
from routes.gateway import gateway_bp
from routes.status import status_bp
from routes.dashboard import dashboard_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = get_secret("FLASK_SECRET_KEY") or pysecrets.token_hex(32)

    # Session cookie hardening — reports may contain sensitive SIEM data
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Initialise SQLite schema (idempotent)
    db.init_db()

    # Register feature blueprints
    app.register_blueprint(auth_bp,         url_prefix="/auth")
    app.register_blueprint(reports_bp,      url_prefix="/reports")
    app.register_blueprint(admin_bp,        url_prefix="/admin")
    app.register_blueprint(exports_bp,      url_prefix="/exports")
    app.register_blueprint(webhook_bp,      url_prefix="/webhook")
    app.register_blueprint(gateway_bp,      url_prefix="/api")
    app.register_blueprint(status_bp,       url_prefix="/status")
    app.register_blueprint(dashboard_bp,    url_prefix="/dashboard")

    # Templates need the flag so base.html can gate the Dashboard nav tab;
    # the dashboard routes themselves also self-gate (404 when disabled).
    @app.context_processor
    def _inject_dashboard_flag():
        return {"dashboard_enabled":
                os.environ.get("DASHBOARD_ENABLED", "false").lower() == "true"}

    # Every request requires an authenticated Entra ID session, except:
    # /auth/*    SSO flow
    # /static/*  assets
    # /webhook/* Jira webhook (secret-token auth)
    # /api/*     SIEM-facing gateway (X-Shared-Secret auth — SIEMs are unattended)
    @app.before_request
    def _enforce_login():
        if request.path.startswith(("/auth/", "/static/", "/webhook/", "/api/")):
            return
        if not session.get("user"):
            return redirect("/auth/login")

    @app.route("/")
    @require_login
    def index():
        return render_template("home.html", user=session.get("user", {}))

    # Warn loudly if gunicorn is running with multiple workers (breaks APScheduler)
    workers = int(os.environ.get("WEB_CONCURRENCY", "1"))
    if workers > 1:
        app.logger.warning(
            "WEB_CONCURRENCY=%d but APScheduler requires 1 worker. "
            "Scheduled reports may double-fire or miss. Set WEB_CONCURRENCY=1.",
            workers,
        )

    # Start the scheduler AFTER the app is fully constructed
    scheduler.init_scheduler(app)

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5060))
    # Dev-only server; production uses gunicorn (see Dockerfile CMD)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
