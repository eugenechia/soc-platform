"""Status endpoints for the home-page health tiles.

Login-protected (Entra session) — NOT under /webhook or /api, so the global
before_request hook enforces auth. Returns JSON consumed by home.html JS.
"""
from flask import Blueprint, jsonify

from routes.auth import require_login
from tools.triage_health import triage_health

status_bp = Blueprint("status", __name__)


@status_bp.route("/triage-health", methods=["GET"])
@require_login
def triage_health_endpoint():
    """L1 Triage dependency health for the home-page status tile."""
    return jsonify(triage_health())
