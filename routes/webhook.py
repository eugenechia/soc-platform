"""
Jira webhook receiver for automated IOC enrichment.

Jira calls POST /webhook/jira?secret=<JIRA_WEBHOOK_SECRET> when a new issue
is created. We respond 200 immediately and process enrichment in a background
thread (same pattern as report generation).

The thread polls the Jira REST API every WEBHOOK_FETCH_DELAY_SECONDS (default 5)
until any Sentinel-style entity custom field becomes populated, or until
WEBHOOK_FETCH_MAX_WAIT_SECONDS (default 60) total elapses. This adaptive wait
handles the gap between issue_created firing and Service Desk request-form
field merging, which has been observed to take 30+ seconds in the SCDM
project. Tickets created programmatically (e.g. by soc-ticket-gateway) where
fields are populated atomically will trigger after the first poll.

Once entity fields are detected, the thread sleeps an additional
WEBHOOK_FETCH_STABILIZATION_SECONDS (default 30) and re-fetches the issue.
Service Desk merges entity fields in waves — the IP may appear first, then
Host/DNS/Hash arrive 20-30s later. The stabilization sleep lets later waves
land before we run the pipeline, so the comment captures all IOCs.

After the wait (or timeout), the latest fields are passed to enrich_ticket()
which produces the comment. Even on timeout we still run the pipeline — that
posts a "No IOCs found" comment, which is a useful signal.

Configure in Jira → System → Webhooks:
  URL:    https://<soc-platform-url>/webhook/jira?secret=<JIRA_WEBHOOK_SECRET>
  Events: Issue Created
  Filter: project = <JIRA_ENRICHMENT_PROJECT> (optional)
"""
import logging
import os
import threading
import time
import uuid

from flask import Blueprint, jsonify, request

from tools.dedup_jira import (
    append_occurrence,
    find_strict_duplicate,
    mark_as_duplicate,
    write_dedup_key,
)
from tools.enrichment import enrich_ticket, has_entity_data, set_priority, assign_jira_ticket
from tools.gateway.dedup import derive_key_from_ticket
from tools.jira_client import fetch_issue_by_key, severity_to_priority
from tools.secrets import get_secret
from tools.triage import TRIAGE_CONFIDENCE_THRESHOLD, triage_priority

webhook_bp = Blueprint("webhook", __name__)
logger = logging.getLogger(__name__)

_jobs: dict[str, dict] = {}


def _run_enrichment(job_id: str, ticket_key: str) -> None:
    """Background worker. Polls the Jira API until entity fields are populated
    (or the max wait expires), then runs the enrichment pipeline once."""
    try:
        poll_interval = int(os.environ.get("WEBHOOK_FETCH_DELAY_SECONDS", "5"))
        max_wait = int(os.environ.get("WEBHOOK_FETCH_MAX_WAIT_SECONDS", "60"))
        stabilization = int(os.environ.get("WEBHOOK_FETCH_STABILIZATION_SECONDS", "30"))
        elapsed = 0
        last_issue = None

        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval

            issue = fetch_issue_by_key(ticket_key)
            if not issue or "fields" not in issue:
                logger.warning(
                    "Enrichment %s: poll %ds — fetch failed for %s, will retry",
                    job_id, elapsed, ticket_key,
                )
                continue

            last_issue = issue
            if has_entity_data(issue["fields"]):
                logger.info(
                    "Enrichment %s: entity fields detected after %ds — sleeping %ds for stabilization",
                    job_id, elapsed, stabilization,
                )
                if stabilization > 0:
                    time.sleep(stabilization)
                final = fetch_issue_by_key(ticket_key)
                if final and "fields" in final:
                    last_issue = final
                    logger.info(
                        "Enrichment %s: post-stabilization fetch complete — proceeding",
                        job_id,
                    )
                else:
                    logger.warning(
                        "Enrichment %s: post-stabilization fetch failed — using pre-stabilization snapshot",
                        job_id,
                    )
                break
            logger.info(
                "Enrichment %s: poll %ds — entity fields still empty for %s",
                job_id, elapsed, ticket_key,
            )
        else:
            logger.warning(
                "Enrichment %s: timeout after %ds — proceeding with whatever data is available for %s",
                job_id, max_wait, ticket_key,
            )

        if last_issue is None or "fields" not in last_issue:
            msg = f"failed to fetch issue {ticket_key} from Jira API after {elapsed}s"
            logger.error("Enrichment %s: %s", job_id, msg)
            _jobs[job_id].update({"status": "error", "error": msg})
            return

        # Dedup MUST run on polled (fully populated) data, not the webhook payload.
        # The Sentinel Logic App writes Incident ID / entity fields asynchronously,
        # so the webhook payload often arrives before the description is populated —
        # which would cause derive_key_from_ticket() to fall through to the Tier-3
        # fuzzy fallback and produce a key that bears no relation to the actual
        # incident. Running here, after polling, guarantees Tier 1/2 see real data.
        dedup_result = None
        if os.environ.get("DEDUP_WEBHOOK_ENABLED", "true").lower() == "true":
            try:
                dedup_result = _apply_dedup_if_strict_match(ticket_key, last_issue["fields"])
            except Exception as e:
                logger.exception("Dedup check failed for %s; falling through to triage: %s",
                                 ticket_key, e)

        if dedup_result and dedup_result.get("action") == "closed":
            # Ticket was just closed as a duplicate — skip L1 Triage. Enriching a
            # closed ticket adds noise the analyst will never review.
            logger.info("Enrichment %s: skipping L1 Triage for %s (closed as duplicate of %s)",
                        job_id, ticket_key, dedup_result["original"])
            _jobs[job_id].update({"status": "done", "result": dedup_result})
            return

        # ── Phase 1: Triage Foundation ───────────────────────────────────────
        # Runs before enrichment so the priority/assignee are correct by the
        # time the IOC pipeline kicks in. Each step is independently failure-
        # tolerant — a hiccup here must not block enrichment.
        _run_triage_foundation(job_id, ticket_key, last_issue["fields"])

        result = enrich_ticket(ticket_key, last_issue["fields"])
        _jobs[job_id].update({"status": "done", "result": result})
        logger.info("Enrichment %s complete: ticket=%s verdict=%s",
                    job_id, ticket_key, result.get("verdict"))
    except Exception as e:
        logger.exception("Enrichment %s failed for %s: %s", job_id, ticket_key, e)
        _jobs[job_id].update({"status": "error", "error": str(e)})


def _run_triage_foundation(job_id: str, ticket_key: str, fields: dict) -> None:
    """Phase 1 pre-enrichment steps. Each step logs and continues on failure
    so the downstream enrichment pipeline always runs.

      1. Severity sync — read the SIEM severity custom field (default
         customfield_10038) and set the Jira priority to match.
      2. GSOC auto-assign — assign the ticket to JIRA_GSOC_ACCOUNT_ID if set.
      3. LLM Triage — ask the model whether the actual impact warrants a
         different priority than the severity-mapped baseline; override only
         if confidence ≥ TRIAGE_CONFIDENCE_THRESHOLD AND recommendation
         differs from baseline.
    """
    # ── 1. Severity sync ────────────────────────────────────────────────
    severity_field_id = os.environ.get("JIRA_FIELD_SEVERITY", "customfield_10038")
    raw = fields.get(severity_field_id) or {}
    severity = (raw.get("value", "") if isinstance(raw, dict) else str(raw or "")).strip()
    baseline_priority = severity_to_priority(severity)
    if baseline_priority:
        set_priority(ticket_key, baseline_priority)
        logger.info("Triage %s: severity sync — '%s' → priority '%s' for %s",
                    job_id, severity, baseline_priority, ticket_key)
    else:
        logger.info("Triage %s: priority sync skipped for %s — unknown severity %r",
                    job_id, ticket_key, severity)

    # ── 2. GSOC auto-assign ─────────────────────────────────────────────
    gsoc_id = get_secret("JIRA_GSOC_ACCOUNT_ID")
    if gsoc_id:
        assign_jira_ticket(ticket_key, gsoc_id)
        logger.info("Triage %s: assigned %s to GSOC (%s)", job_id, ticket_key, gsoc_id)
    else:
        logger.info("Triage %s: GSOC assign skipped for %s — JIRA_GSOC_ACCOUNT_ID not set",
                    job_id, ticket_key)

    # ── 3. LLM Triage priority override ─────────────────────────────────
    rec = triage_priority(ticket_key, fields, severity, baseline_priority)
    if not rec:
        logger.info("Triage %s: LLM rec unavailable for %s — keeping baseline",
                    job_id, ticket_key)
        return

    if rec["confidence"] < TRIAGE_CONFIDENCE_THRESHOLD:
        logger.info("Triage %s: override rejected for %s — confidence %.2f < %.2f",
                    job_id, ticket_key, rec["confidence"], TRIAGE_CONFIDENCE_THRESHOLD)
        return

    if rec["recommended_priority"] == baseline_priority:
        logger.info("Triage %s: LLM agrees with baseline (%s) for %s",
                    job_id, baseline_priority, ticket_key)
        return

    if set_priority(ticket_key, rec["recommended_priority"]):
        logger.info("Triage %s: override accepted for %s — %s → %s (confidence %.2f). Rationale: %s",
                    job_id, ticket_key, baseline_priority or "(none)",
                    rec["recommended_priority"], rec["confidence"], rec["rationale"][:200])


def _apply_dedup_if_strict_match(ticket_key: str, fields: dict) -> dict | None:
    """Post-creation dedup side effects.

    1. Determine the dedup key — read from cf_10125 if already populated
       (gateway path), or derive from ticket fields (Sentinel Logic App path).
    2. Write the derived key to cf_10125 so future searches can find this ticket.
    3. Search for an OLDER open ticket within 24h that strictly matches
       (same summary + same five typed entity fields).
    4. If strict match → mark this ticket as duplicate (prefix summary,
       comment-link, close with resolution=Duplicate) and bump occurrence
       count + last seen on the original.

    Returns a dict with action="closed" on dedup hit so the caller can skip
    L1 Triage (no point enriching a ticket we just closed). Returns None when
    no dedup action was taken — caller proceeds with normal triage.
    """
    dedup_field = os.environ.get("JIRA_FIELD_SOURCE_ALERT_ID", "customfield_10125")
    existing_key_value = fields.get(dedup_field)

    if existing_key_value:
        dedup_key = str(existing_key_value)
        logger.info("Webhook dedup: %s already carries key %s (gateway-created)",
                    ticket_key, dedup_key)
    else:
        dedup_key = derive_key_from_ticket(fields)
        if not dedup_key:
            logger.info("Webhook dedup: no signal in %s — skipping dedup", ticket_key)
            return None
        logger.info("Webhook dedup: derived key %s for %s", dedup_key, ticket_key)
        write_dedup_key(ticket_key, dedup_key)

    match = find_strict_duplicate(dedup_key, current_key=ticket_key, current_fields=fields)
    if not match:
        logger.info("Webhook dedup: no strict duplicate within 24h for %s (key=%s) — "
                    "proceeding to triage as standalone ticket",
                    ticket_key, dedup_key)
        return None

    original_key = match["key"]
    current_count = match["occurrence_count"]
    original_labels = match.get("labels") or []
    last_seen = fields.get("created", "")

    new_count = append_occurrence(original_key, current_count, ticket_key, last_seen)
    closed_ok = mark_as_duplicate(ticket_key, original_key, original_labels)

    logger.info("Webhook dedup STRICT MATCH: %s closed as duplicate of %s; "
                "original count=%s; close_ok=%s",
                ticket_key, original_key, new_count, closed_ok)
    return {
        "action": "closed",
        "original": original_key,
        "dedup_key": dedup_key,
        "occurrence_count": new_count,
    }


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
    ticket_key = issue.get("key", "")

    if not ticket_key:
        logger.warning("Jira webhook: missing issue key in payload")
        return jsonify({"status": "ignored", "reason": "no issue key"}), 200

    enrichment_projects_raw = os.environ.get("JIRA_ENRICHMENT_PROJECT", "")
    if enrichment_projects_raw:
        allowed = {p.strip().upper() for p in enrichment_projects_raw.split(",") if p.strip()}
        project_key = ticket_key.split("-")[0].upper()
        if project_key not in allowed:
            return jsonify({"status": "ignored", "reason": "project not monitored"}), 200

    # Note: dedup runs INSIDE _run_enrichment after polling completes, not here.
    # Running synchronously off the webhook payload was racy because the Sentinel
    # Logic App writes the Incident ID and entity fields asynchronously, often
    # arriving 20-30s after issue_created fires. Webhook-time derivation would
    # see an empty description, fall through to the Tier-3 fuzzy fallback, and
    # produce a key unrelated to the real incident. Kill switch
    # DEDUP_WEBHOOK_ENABLED is checked inside _run_enrichment now.

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status": "queued",
        "ticket": ticket_key,
        "result": None,
        "error": None,
    }

    threading.Thread(
        target=_run_enrichment,
        args=(job_id, ticket_key),
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
