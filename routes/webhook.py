"""
Jira webhook receiver for automated IOC enrichment.

Jira calls POST /webhook/jira?secret=<JIRA_WEBHOOK_SECRET> when a new issue
is created. We respond 200 immediately and process enrichment in a background
thread (same pattern as report generation).

Configure in Jira → System → Webhooks:
  URL:    https://<soc-platform-url>/webhook/jira?secret=<JIRA_WEBHOOK_SECRET>
  Events: Issue Created
  Filter: project = <JIRA_ENRICHMENT_PROJECT> (optional)
"""
import logging
import os
import threading
import uuid

from flask import Blueprint, jsonify, request

from tools.enrichment import enrich_ticket

webhook_bp = Blueprint("webhook", __name__)
logger = logging.getLogger(__name__)

_jobs: dict[str, dict] = {}


def _run_enrichment(job_id: str, ticket_key: str, summary: str, description_adf) -> None:
    try:
        result = enrich_ticket(ticket_key, summary, description_adf)
        _jobs[job_id].update({"status": "done", "result": result})
        logger.info("Enrichment %s complete: ticket=%s verdict=%s",
                    job_id, ticket_key, result.get("verdict"))
    except Exception as e:
        logger.exception("Enrichment %s failed for %s: %s", job_id, ticket_key, e)
        _jobs[job_id].update({"status": "error", "error": str(e)})


@webhook_bp.route("/jira", methods=["POST"])
def jira_webhook():
    """Receive a Jira issue_created webhook and queue IOC enrichment."""
    webhook_secret = os.environ.get("JIRA_WEBHOOK_SECRET", "")
    if webhook_secret:
        provided = request.args.get("secret", "")
        if provided != webhook_secret:
            logger.warning("Jira webhook: invalid secret from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    event = payload.get("webhookEvent", "")

    if event and event != "jira:issue_created":
        return jsonify({"status": "ignored", "reason": f"event '{event}' not processed"}), 200

    issue = payload.get("issue", {})
    fields = issue.get("fields", {})
    ticket_key = issue.get("key", "")

    if not ticket_key:
        logger.warning("Jira webhook: missing issue key in payload")
        return jsonify({"status": "ignored", "reason": "no issue key"}), 200

    enrichment_project = os.environ.get("JIRA_ENRICHMENT_PROJECT", "")
    if enrichment_project:
        project_key = ticket_key.split("-")[0]
        if project_key != enrichment_project:
            return jsonify({"status": "ignored", "reason": "project not monitored"}), 200

    summary = fields.get("summary", "")
    description_adf = fields.get("description")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status": "queued",
        "ticket": ticket_key,
        "result": None,
        "error": None,
    }

    threading.Thread(
        target=_run_enrichment,
        args=(job_id, ticket_key, summary, description_adf),
        daemon=True,
    ).start()

    logger.info("Jira webhook: queued enrichment job %s for ticket %s", job_id, ticket_key)
    return jsonify({"status": "queued", "job_id": job_id, "ticket": ticket_key}), 200


@webhook_bp.route("/jira/jobs/<job_id>", methods=["GET"])
def enrichment_job_status(job_id: str):
    """Poll enrichment job status. Returns job dict or 404."""
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify(job), 200
