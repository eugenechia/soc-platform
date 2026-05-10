"""SIEM ticket gateway — /api/ingest + /api/health.

POST /api/ingest receives normalized alerts from Splunk (webhook adapter) and
Sentinel (Logic App), deduplicates by SHA-256 of `siem:rule_id|primary_entity`,
and either creates a new Jira ticket or appends a comment + bumps occurrence
count on an existing one.

Auth: X-Shared-Secret header (matches GATEWAY_SHARED_SECRET). Entra ID is
bypassed for /api/* paths in app.py's before_request hook — SIEMs are
unattended services and cannot do an interactive SSO flow.

Originally a separate Azure Function / Container App (see
Office/SOC-System/soc-ticket-gateway/). Merged into soc-platform 2026-05-05
to consolidate operations into a single Container App.
"""
import json
import logging

from flask import Blueprint, jsonify, request

from tools.gateway.dedup import dedup_key
from tools.gateway.jira import JiraClient, JiraError
from tools.gateway.schema import AlertValidationError, parse_alert
from tools.secrets import get_secret

gateway_bp = Blueprint("gateway", __name__)
log = logging.getLogger("gateway")


@gateway_bp.post("/ingest")
def ingest():
    expected_secret = get_secret("GATEWAY_SHARED_SECRET")
    if expected_secret and request.headers.get("X-Shared-Secret") != expected_secret:
        log.warning("Rejected /api/ingest request: invalid or missing X-Shared-Secret header")
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        alert = parse_alert(body)
    except AlertValidationError as e:
        log.warning("Alert validation failed: %s", e)
        return jsonify({"error": f"Invalid payload: {e}"}), 400

    key = dedup_key(alert)
    log.info("Alert received — key=%s siem=%s rule=%s entity=%s severity=%s",
             key, alert.siem, alert.rule_id, alert.primary_entity, alert.severity)

    try:
        jira = JiraClient.from_env()
        existing = jira.find_open_ticket(key)
    except JiraError as e:
        log.exception("Jira search failed")
        return jsonify({"error": str(e)}), 502

    if existing:
        try:
            new_count = jira.append_alert_occurrence(
                ticket_key=existing["key"],
                alert=alert,
                current_count=existing["occurrence_count"],
            )
        except JiraError as e:
            log.exception("Jira append failed")
            return jsonify({"error": str(e)}), 502

        log.info("DEDUP HIT — key=%s ticket=%s new_count=%d", key, existing["key"], new_count)
        return jsonify({
            "action": "deduped",
            "ticket_key": existing["key"],
            "dedup_key": key,
            "occurrence_count": new_count,
        }), 200

    try:
        new_ticket_key = jira.create_ticket(alert, dedup_key=key)
    except JiraError as e:
        log.exception("Jira create failed")
        return jsonify({"error": str(e)}), 502

    log.info("CREATED — key=%s ticket=%s", key, new_ticket_key)
    return jsonify({
        "action": "created",
        "ticket_key": new_ticket_key,
        "dedup_key": key,
    }), 201


@gateway_bp.get("/health")
def health():
    return jsonify({"status": "ok"}), 200
