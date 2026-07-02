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

from tools.jira_schema import resolve_jira_schema, default_schema
from tools.dedup_jira import (
    append_occurrence,
    find_strict_duplicate,
    mark_as_duplicate,
    write_dedup_key,
)
from tools.customers import find_customer_by_jira_project
from tools.enrichment import enrich_ticket, has_entity_data, set_priority, assign_jira_ticket
from tools.gateway.dedup import derive_key_from_ticket
from tools.historical_alerts import query_similar_alerts
from tools.jira_client import fetch_issue_by_key, severity_to_priority
from tools.rag_retrieval import retrieve_customer_context
from tools.secrets import get_secret
from tools.triage import TRIAGE_CONFIDENCE_THRESHOLD, triage_priority

webhook_bp = Blueprint("webhook", __name__)
logger = logging.getLogger(__name__)

_jobs: dict[str, dict] = {}


def _run_enrichment(job_id: str, ticket_key: str) -> None:
    """Background worker. Polls the Jira API until entity fields are populated
    (or the max wait expires), then runs the enrichment pipeline once."""
    try:
        # Resolve the customer + per-customer Jira schema ONCE, up front. Entity
        # field IDs and severity mapping vary per customer; a project with no
        # customer record (or no schema override) resolves to the global defaults
        # (SCDM behaviour). project_key needs no Jira fetch.
        project_key = ticket_key.split("-")[0]
        try:
            customer = find_customer_by_jira_project(project_key)
        except Exception as _cust_err:
            logger.warning("Enrichment %s: customer lookup raised (%s); using default schema: %s",
                           job_id, type(_cust_err).__name__, _cust_err)
            customer = None
        schema = resolve_jira_schema(customer, project_key)

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
            if has_entity_data(issue["fields"], schema):
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

        # ── Phase 3: Historical Alert Correlation ───────────────────────────
        # Looks up similar alerts in the past 24h (same Jira project + matching
        # summary prefix). Failure-safe — returns None on any error. The result
        # feeds both the Phase 1 LLM Triage call (de-escalation evidence) and
        # the enrichment comment (Similar Alerts section).
        historical = None
        try:
            project_key = ticket_key.split("-")[0]
            summary = (last_issue["fields"].get("summary") or "")
            historical = query_similar_alerts(ticket_key, summary, project_key)
        except Exception as e:
            logger.warning("Enrichment %s: historical lookup raised (%s); continuing without it: %s",
                           job_id, type(e).__name__, e)

        # ── Phase 4: RAG Customer Context retrieval ─────────────────────────
        # Vector search over indexed knowledge documents (HRT/HVT lists,
        # Escalation Matrix, Whitelists, Asset Inventory, etc.) for snippets
        # relevant to this ticket's summary + IOCs. Killswitch defaults OFF
        # (RAG_LOOKUP_ENABLED=false). Hard 5s timeout. Returns None on ANY
        # failure mode (disabled, timeout, embed error, store error, no
        # chunks above threshold) — pipeline always continues.
        #
        # Phase 4 MVP: RAG context is surfaced to the analyst in the
        # enrichment comment only, NOT fed into the LLM Triage prompt.
        # Mitigates the prior failure mode where bad retrievals confused
        # the LLM and degraded priority decisions. LLM integration is a
        # future opt-in (Phase 4c) contingent on retrieval quality.
        #
        # Phase 4b-rev (2026-06-15): retrieval is strictly customer-scoped.
        # Resolve the customer from the ticket's project key BEFORE the call;
        # tickets whose project key matches no customer get no Customer
        # Context section (silent skip).
        # rag_info: shape {pages_searched: int, status: "matched"|"no_matches",
        #                  chunks: list[dict]} OR None to suppress the section.
        # We only build rag_info when the customer was resolved AND has at
        # least one Confluence page registered AND retrieval actually ran
        # (statuses "matched" / "no_matches"). Every other status — disabled,
        # error, no_customer, no_query — is silent in the comment.
        rag_info = None
        try:
            summary_text = (last_issue["fields"].get("summary") or "")
            query = summary_text[:500]
            project_key = ticket_key.split("-")[0]
            customer = find_customer_by_jira_project(project_key)
            customer_id = (customer or {}).get("id") or ""
            pages_count = len((customer or {}).get("confluence_pages") or [])
            if not customer_id:
                logger.info("Enrichment %s: no customer matched project_key=%s — "
                            "skipping RAG retrieval", job_id, project_key)
            elif pages_count == 0:
                logger.info("Enrichment %s: customer %s has no Confluence pages — "
                            "skipping RAG retrieval", job_id, customer_id)
            else:
                retrieval = retrieve_customer_context(query, customer_id=customer_id)
                status = (retrieval or {}).get("status") or "error"
                if status in ("matched", "no_matches"):
                    rag_info = {
                        "pages_searched": pages_count,
                        "status": status,
                        "chunks": list((retrieval or {}).get("chunks") or []),
                    }
        except Exception as e:
            logger.warning("Enrichment %s: RAG retrieval orchestrator raised (%s); continuing without it: %s",
                           job_id, type(e).__name__, e)

        # ── Phase 1: Triage Foundation ───────────────────────────────────────
        # Runs before enrichment so the priority/assignee are correct by the
        # time the IOC pipeline kicks in. Each step is independently failure-
        # tolerant — a hiccup here must not block enrichment.
        #
        # Phase 4c (2026-06-15): customer-scoped RAG context can now reach the
        # LLM Triage prompt, gated by:
        #   - RAG_TO_LLM_PROMPT_ENABLED (default false — code ships dark)
        #   - RAG_PROMPT_MIN_SCORE (default 0.7 — stricter than the comment's
        #     RAG_MIN_SCORE so noise that's safe to show analysts doesn't reach
        #     the model's priority reasoning).
        # We filter the SAME chunks already retrieved (no second retrieval).
        chunks_for_prompt: list[dict] = []
        try:
            if rag_info and os.environ.get("RAG_TO_LLM_PROMPT_ENABLED", "false").strip().lower() == "true":
                try:
                    prompt_threshold = float(os.environ.get("RAG_PROMPT_MIN_SCORE", "0.7"))
                except (TypeError, ValueError):
                    prompt_threshold = 0.7
                chunks_for_prompt = [
                    c for c in (rag_info.get("chunks") or [])
                    if float(c.get("score") or 0.0) >= prompt_threshold
                ]
                if chunks_for_prompt:
                    logger.info("Enrichment %s: passing %d RAG chunk(s) to LLM Triage prompt (>= %.2f)",
                                job_id, len(chunks_for_prompt), prompt_threshold)
        except Exception as e:
            logger.warning("Enrichment %s: RAG-to-prompt gate raised (%s); continuing without prompt chunks: %s",
                           job_id, type(e).__name__, e)
            chunks_for_prompt = []

        _run_triage_foundation(job_id, ticket_key, last_issue["fields"], historical, chunks_for_prompt, schema)

        # ── Phase 5: AI-driven KQL expansion ─────────────────────────────────
        # Runs AFTER Phase 1 (so the triage call doesn't pay for KQL latency,
        # which can be up to 60s) and BEFORE enrich_ticket so the rendered
        # comment includes the Sentinel Evidence block. Killswitch defaults
        # OFF — code ships dark. Hot path: bounded by KQL_EXPANSION_TIMEOUT_S
        # and KQL_EXPANSION_MAX_ITERATIONS; failure-isolated (never raises;
        # None return = skip the section).
        kql_evidence = None
        try:
            from tools.kql_expansion import expand_with_kql
            summary_text = (last_issue["fields"].get("summary") or "")
            description_text = ""
            try:
                from tools.jira_client import _extract_adf_text
                description_text = _extract_adf_text(last_issue["fields"].get("description")) or ""
            except Exception:
                description_text = ""
            # Reuse the IOCs the enrichment pipeline will extract anyway —
            # better than duplicating regex/entity extraction here.
            iocs_for_kql: list[dict] = []
            try:
                from tools.enrichment import extract_iocs_from_entity_fields
                iocs_for_kql = list(extract_iocs_from_entity_fields(last_issue["fields"], schema) or [])
            except Exception as _ioc_err:
                logger.warning("Enrichment %s: IOC extraction for KQL failed (%s); continuing with empty IOC list",
                               job_id, _ioc_err)
            kql_evidence = expand_with_kql(
                customer=customer if 'customer' in locals() else None,
                ticket_key=ticket_key,
                ticket_summary=summary_text,
                ticket_description=description_text,
                iocs=iocs_for_kql,
            )
        except Exception as e:
            logger.warning("Enrichment %s: KQL expansion orchestrator raised (%s); continuing without it: %s",
                           job_id, type(e).__name__, e)
            kql_evidence = None

        result = enrich_ticket(ticket_key, last_issue["fields"], historical, rag_info, kql_evidence, schema)
        _jobs[job_id].update({"status": "done", "result": result})
        logger.info("Enrichment %s complete: ticket=%s verdict=%s",
                    job_id, ticket_key, result.get("verdict"))
    except Exception as e:
        logger.exception("Enrichment %s failed for %s: %s", job_id, ticket_key, e)
        _jobs[job_id].update({"status": "error", "error": str(e)})


def _run_triage_foundation(job_id: str, ticket_key: str, fields: dict,
                           historical: dict | None = None,
                           rag_chunks_for_prompt: list[dict] | None = None,
                           schema=None) -> None:
    """Phase 1 pre-enrichment steps. Each step logs and continues on failure
    so the downstream enrichment pipeline always runs.

      1. Severity sync — read the SIEM severity custom field (default
         customfield_10038) and set the Jira priority to match.
      2. GSOC auto-assign — assign the ticket to JIRA_GSOC_ACCOUNT_ID if set.
      3. LLM Triage — ask the model whether the actual impact warrants a
         different priority than the severity-mapped baseline; override only
         if confidence ≥ TRIAGE_CONFIDENCE_THRESHOLD AND recommendation
         differs from baseline.

    Phase 3 (2026-06-13): optional `historical` arg (precomputed by the
    caller) is passed through to triage_priority() so the LLM sees the
    same-rule FP/TP distribution as de-escalation evidence.

    Phase 4c (2026-06-15): optional `rag_chunks_for_prompt` arg — list of
    chunks already filtered against `RAG_PROMPT_MIN_SCORE` and gated by
    `RAG_TO_LLM_PROMPT_ENABLED` by the caller. Passed through to
    triage_priority() so customer-specific HVT/whitelist/asset-inventory
    context can influence the priority recommendation. Empty list or None
    suppresses the block entirely (no behavioural change from Phase 4b).
    """
    # ── 1. Severity sync ────────────────────────────────────────────────
    sch = schema or default_schema()
    severity_field_id = sch.severity_field
    raw = fields.get(severity_field_id) or {}
    severity = (raw.get("value", "") if isinstance(raw, dict) else str(raw or "")).strip()
    baseline_priority = sch.severity_to_priority(severity)
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
    rec = triage_priority(ticket_key, fields, severity, baseline_priority,
                          historical, rag_chunks_for_prompt)
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


def _handle_issue_updated(payload: dict):
    """Phase 7 (2026-06-16) — capture L2 decisions from label changes.

    When the analyst adds a 'True-Positive' / 'Benign-Positive' / 'Unknown'
    label to a ticket, we log an immutable decision row to data/
    triage_decisions.jsonl. Used by future few-shot triage prompts and
    auto-close FP (sub-features 2 + 3, deferred). Failure-isolated:
    bad payloads / disabled killswitch → 200 ignored, never raises.
    """
    if os.environ.get("DECISION_CAPTURE_ENABLED", "false").lower() != "true":
        return jsonify({"status": "ignored", "reason": "decision capture disabled"}), 200

    issue = payload.get("issue", {}) or {}
    ticket_key = issue.get("key", "")
    if not ticket_key:
        return jsonify({"status": "ignored", "reason": "no issue key"}), 200

    changelog = payload.get("changelog", {}) or {}
    items = changelog.get("items", []) or []
    label_changes = [i for i in items if (i.get("field") or "").lower() == "labels"]
    if not label_changes:
        return jsonify({"status": "ignored", "reason": "no label change"}), 200

    # Determine which triage label was newly added.
    _ML  = os.environ.get("JIRA_TRIAGE_MALICIOUS_LABEL", "True-Positive")
    _CL  = os.environ.get("JIRA_TRIAGE_CLEAN_LABEL",     "Benign-Positive")
    _UL  = os.environ.get("JIRA_TRIAGE_UNKNOWN_LABEL",   "Unknown")
    triage_labels = {_ML, _CL, _UL}

    added_triage_label = None
    platform_verdict = "unknown"
    for chg in label_changes:
        # Jira sends `toString` and `fromString` as space-separated label lists.
        before = set((chg.get("fromString") or "").split())
        after  = set((chg.get("toString")   or "").split())
        new_labels = after - before
        for lbl in new_labels:
            if lbl in triage_labels:
                added_triage_label = lbl
                break
        # Detect what the platform had labelled before (so we know what the
        # platform's original verdict was for the few-shot loop).
        for lbl in before & triage_labels:
            if   lbl == _ML: platform_verdict = "malicious"
            elif lbl == _CL: platform_verdict = "benign"
            elif lbl == _UL: platform_verdict = "unknown"
        if added_triage_label:
            break

    if not added_triage_label:
        return jsonify({"status": "ignored", "reason": "no triage-label addition"}), 200

    # The L2 decision is the newly-added triage label.
    fields = issue.get("fields", {}) or {}
    summary = fields.get("summary") or ""
    # Re-use Phase 3's rule-prefix derivation so this decision is keyed
    # the same way historical_alerts groups similar tickets.
    rule_prefix = summary[: int(os.environ.get("HISTORICAL_LOOKUP_SUMMARY_PREFIX_LEN", "60"))]

    project_key = (issue.get("fields", {}).get("project", {}) or {}).get("key", "") \
                  or ticket_key.split("-")[0]

    # Customer resolution (best-effort, never blocks the record write).
    customer_id = ""
    try:
        from tools.customers import find_customer_by_jira_project
        cust = find_customer_by_jira_project(project_key)
        customer_id = (cust or {}).get("id", "")
    except Exception:
        pass

    try:
        from tools.decisions import record_decision
        record_decision(
            ticket_key=ticket_key,
            project_key=project_key,
            customer_id=customer_id,
            rule_prefix=rule_prefix,
            l2_label=added_triage_label,
            platform_verdict=platform_verdict,
        )
    except Exception:
        logger.exception("Phase 7 record_decision dispatch failed for %s", ticket_key)
        return jsonify({"status": "error", "reason": "record_decision failed"}), 200

    return jsonify({
        "status": "recorded",
        "ticket": ticket_key,
        "l2_label": added_triage_label,
        "platform_verdict": platform_verdict,
    }), 200


@webhook_bp.route("/jira", methods=["POST"])
def jira_webhook():
    """Receive a Jira issue_created webhook and queue IOC enrichment.

    Phase 7 (2026-06-16) — also accepts issue_updated events and dispatches
    them to _handle_issue_updated() for decision capture. Same URL keeps
    Jira webhook config simple.
    """
    webhook_secret = os.environ.get("JIRA_WEBHOOK_SECRET", "")
    if webhook_secret:
        provided = request.args.get("secret", "")
        if provided != webhook_secret:
            logger.warning("Jira webhook: invalid secret from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    event = payload.get("webhookEvent", "")

    # Phase 7 (2026-06-16) — handle issue_updated events for L2 decision
    # capture. Same endpoint as issue_created to keep the Jira webhook config
    # simple (one URL handles everything).
    if event == "jira:issue_updated":
        return _handle_issue_updated(payload)

    if event and event != "jira:issue_created":
        return jsonify({"status": "ignored", "reason": f"event '{event}' not processed"}), 200

    issue = payload.get("issue", {})
    ticket_key = issue.get("key", "")

    if not ticket_key:
        logger.warning("Jira webhook: missing issue key in payload")
        return jsonify({"status": "ignored", "reason": "no issue key"}), 200

    # Fail-closed allowlist: only projects explicitly listed in
    # JIRA_ENRICHMENT_PROJECT are enriched. An empty/unset allowlist denies ALL
    # tickets (rather than the old fail-open behaviour of processing everything),
    # so a blank or dropped env var can never silently open enrichment to every
    # customer project.
    allowed = {p.strip().upper()
               for p in os.environ.get("JIRA_ENRICHMENT_PROJECT", "").split(",")
               if p.strip()}
    project_key = ticket_key.split("-")[0].upper()
    if not allowed:
        logger.warning(
            "JIRA_ENRICHMENT_PROJECT is empty — denying enrichment for %s "
            "(fail-closed). Set the allowlist to enable processing.", ticket_key)
        return jsonify({"status": "ignored", "reason": "no project allowlist configured"}), 200
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
