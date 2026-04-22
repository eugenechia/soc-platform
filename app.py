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

from flask import Flask, redirect, request, session

from tools import db
from tools import scheduler
from tools.secrets import get_secret

from routes.auth import auth_bp, require_login
from routes.reports import reports_bp
from routes.investigate import investigate_bp
from routes.admin import admin_bp
from routes.exports import exports_bp


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
    app.register_blueprint(investigate_bp,  url_prefix="/investigate")
    app.register_blueprint(admin_bp,        url_prefix="/admin")
    app.register_blueprint(exports_bp,      url_prefix="/exports")

    # Every request requires an authenticated Entra ID session, except /auth/* and /static/*
    @app.before_request
    def _enforce_login():
        if request.path.startswith(("/auth/", "/static/")):
            return
        if not session.get("user"):
            return redirect("/auth/login")

    # Root → default to Generate Report mode
    @app.route("/")
    @require_login
    def index():
        return redirect("/reports/")

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
