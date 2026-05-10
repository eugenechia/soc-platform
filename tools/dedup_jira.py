"""Jira helpers for the post-creation dedup branch in routes/webhook.py.

The webhook handler treats a new Jira ticket as a *strict duplicate* only when
ALL of the following hold:

  1. dedup-key custom field equal (cf_10125)
  2. summary equal (trimmed, case-sensitive)
  3. all five typed entity fields equal raw-string
       (Host / IP / DNS / URL / FileHash entities)
  4. old ticket created within the last 24h (JQL `created >= -1d`)
  5. old ticket has no resolution (still open)

A "loose" match (only the dedup key matches but criteria 2-4 fail) is treated
as a recurrence — every Sentinel rule fires on a schedule, and a fire on a
different day with different scope is a different incident worth its own
ticket. Loose matches receive normal L1 Triage and no special marker.

On strict match, the duplicate ticket is AUTO-CLOSED:
  - Summary prefixed with the configured tag (default `[Duplicate]`) so
    analysts can spot duplicates at a glance in any list view. We use the
    summary rather than a Jira label because labels are reserved for other
    workflow purposes (e.g. `Potential-TP` from L1 Triage).
  - Comment linking to the original ticket.
  - Transition to Canceled with resolution = Duplicate.
The original ticket gets its Occurrence Count bumped + Last Seen updated +
a `[Dedup append]` comment, but its summary and status are untouched.

All helpers return bool/None on failure rather than raising, so the webhook
handler can fall through to L1 Triage if dedup itself breaks.
"""
import base64
import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


def _jira_url() -> str:
    return (os.environ.get("JIRA_URL") or "").rstrip("/")


def _jira_headers() -> dict:
    email = os.environ.get("JIRA_EMAIL", "")
    from tools.secrets import get_secret
    token = get_secret("JIRA_API_TOKEN") or os.environ.get("JIRA_API_TOKEN", "")
    if not email or not token:
        return {}
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _project_key() -> str:
    return os.environ.get("JIRA_PROJECT_KEY", "SCDM")


def _dedup_key_field() -> str:
    return os.environ.get("JIRA_FIELD_SOURCE_ALERT_ID", "customfield_10125")


def _occurrence_field() -> str:
    return os.environ.get("JIRA_FIELD_OCCURRENCE_COUNT", "customfield_11589")


def _last_seen_field() -> str:
    return os.environ.get("JIRA_FIELD_LAST_SEEN", "customfield_11590")


def _duplicate_summary_prefix() -> str:
    """Tag prepended to the duplicate ticket's summary."""
    return os.environ.get("JIRA_DUPLICATE_SUMMARY_PREFIX", "[DUPLICATE]")


# ── Close-as-duplicate workflow fields (SCDM-specific defaults) ──────────────
# The SCDM workflow's `Close` transition (id=181) requires three custom fields
# to be set BEFORE the transition fires, plus a non-empty Labels field. Setting
# Resolution Category=Duplicate is the SCDM-native way to mark a closed ticket
# as a duplicate; we use that instead of the standard Jira `resolution` field
# (which the SCDM workflow doesn't expose on the Close transition).

def _close_transition_id() -> str:
    return os.environ.get("JIRA_CLOSE_TRANSITION_ID", "181")


def _close_justification_field() -> str:
    return os.environ.get("JIRA_FIELD_CLOSE_JUSTIFICATION", "customfield_10057")


def _close_justification_value() -> str:
    """Picked from: False Positive | True Positive | Benign Positive
    | False Negative | True Negative | Other Comments. 'Other Comments' is the
    least-misleading default for an unreviewed auto-closed duplicate."""
    return os.environ.get("JIRA_CLOSE_JUSTIFICATION_VALUE", "Other Comments")


def _resolution_summary_field() -> str:
    return os.environ.get("JIRA_FIELD_RESOLUTION_SUMMARY", "customfield_10127")


def _resolution_category_field() -> str:
    return os.environ.get("JIRA_FIELD_RESOLUTION_CATEGORY", "customfield_10521")


def _resolution_category_value() -> str:
    """Picked from: Duplicate | Escalated | Known Issue | Misrouted."""
    return os.environ.get("JIRA_RESOLUTION_CATEGORY_VALUE", "Duplicate")


def _label_to_remove_on_close() -> str:
    """Analyst-facing label stripped on close — currently only used by the
    duplicate-close path's `compute_labels` strategy when the original ticket
    has no labels and a fallback is needed. Default value left set so
    downstream code paths (e.g. future close-path additions) can rely on it."""
    return os.environ.get("JIRA_LABEL_REMOVE_ON_CLOSE", "IOC_Detection")


# Five typed entity fields a Sentinel Logic App-created ticket carries. All five
# must match raw-string for two tickets to be considered strictly the same incident.
_ENTITY_FIELDS = [
    "customfield_10078",  # Host Entities
    "customfield_10079",  # IP Entities
    "customfield_10080",  # DNS Entities
    "customfield_10081",  # URL Entities
    "customfield_10082",  # FileHash Entities
]


def _entity_field_value(field_value) -> str:
    """Normalise an entity-field value to a comparable string.

    Sentinel's Logic App is deterministic — repeated fires of the same incident
    emit byte-for-byte identical strings. Just compare raw, trimmed.
    """
    if field_value is None:
        return ""
    return str(field_value).strip()


def _is_strict_match(new_fields: dict, old_fields: dict) -> bool:
    """Strict duplicate definition: same summary + same five typed entity fields."""
    if (new_fields.get("summary") or "").strip() != (old_fields.get("summary") or "").strip():
        return False
    for fid in _ENTITY_FIELDS:
        if _entity_field_value(new_fields.get(fid)) != _entity_field_value(old_fields.get(fid)):
            return False
    return True


def write_dedup_key(ticket_key: str, dedup_key: str) -> bool:
    """Write the derived dedup key to customfield_10125 on a freshly-created ticket."""
    base = _jira_url()
    if not base:
        logger.warning("JIRA_URL not set — cannot write dedup key to %s", ticket_key)
        return False
    try:
        r = httpx.put(
            f"{base}/rest/api/3/issue/{ticket_key}",
            headers=_jira_headers(),
            json={"fields": {_dedup_key_field(): dedup_key}},
            timeout=30,
        )
        if r.status_code >= 400:
            logger.error("write_dedup_key %s HTTP %s: %s",
                         ticket_key, r.status_code, r.text[:300])
            return False
        logger.info("Wrote dedup key %s to %s", dedup_key, ticket_key)
        return True
    except Exception as e:
        logger.error("write_dedup_key %s failed: %s", ticket_key, e)
        return False


def find_strict_duplicate(dedup_key: str, current_key: str,
                          current_fields: dict) -> Optional[dict]:
    """Search for the OLDEST open ticket within 24h that strictly matches.

    Returns {"key": ..., "occurrence_count": int, "labels": [...]}
    on hit, None otherwise. `labels` carries the original ticket's analyst-facing
    labels so the caller can copy them onto the duplicate at close time.
    """
    base = _jira_url()
    if not base:
        return None

    field_num = _dedup_key_field().replace("customfield_", "")
    # statusCategory != Done excludes both Closed and Canceled tickets
    # (more reliable than `resolution is EMPTY` because the SCDM Close
    # transition doesn't always populate the standard resolution field).
    jql = (
        f"project = {_project_key()} "
        f'AND cf[{field_num}] = "{dedup_key}" '
        f"AND created >= -1d "
        f'AND statusCategory != "Done" '
        f"AND key != {current_key} "
        f"ORDER BY created ASC"
    )
    fields_to_fetch = ["summary", "labels", _occurrence_field()] + _ENTITY_FIELDS

    try:
        r = httpx.post(
            f"{base}/rest/api/3/search/jql",
            headers=_jira_headers(),
            json={"jql": jql, "maxResults": 50, "fields": fields_to_fetch},
            timeout=30,
        )
        if r.status_code >= 400:
            logger.error("find_strict_duplicate HTTP %s: %s", r.status_code, r.text[:300])
            return None
        candidates = r.json().get("issues") or []
    except Exception as e:
        logger.error("find_strict_duplicate failed: %s", e)
        return None

    for candidate in candidates:
        cand_fields = candidate.get("fields", {}) or {}
        if _is_strict_match(current_fields, cand_fields):
            count = cand_fields.get(_occurrence_field())
            return {
                "key": candidate["key"],
                "occurrence_count": int(count) if count else 1,
                "labels": list(cand_fields.get("labels") or []),
            }
    if candidates:
        logger.info(
            "find_strict_duplicate: %d dedup-key match(es) within 24h but none strict-matched %s",
            len(candidates), current_key,
        )
    return None


def append_occurrence(original_key: str, current_count: int,
                      duplicate_key: str, last_seen: str) -> Optional[int]:
    """Bump occurrence count + update Last Seen + add a [Dedup append] comment on the original."""
    base = _jira_url()
    if not base:
        return None

    new_count = current_count + 1
    headers = _jira_headers()

    comment_body = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [
                    {"type": "text", "text": "[Dedup append] Strict duplicate detected: "},
                    {"type": "text", "text": duplicate_key, "marks": [{
                        "type": "link",
                        "attrs": {"href": f"{base}/browse/{duplicate_key}"}}]},
                ]},
                {"type": "paragraph", "content": [
                    {"type": "text", "text": f"Seen at: {last_seen}"}]},
                {"type": "paragraph", "content": [
                    {"type": "text", "text": f"Occurrence count: {new_count}"}]},
            ],
        }
    }

    try:
        r = httpx.post(
            f"{base}/rest/api/3/issue/{original_key}/comment",
            headers=headers, json=comment_body, timeout=30,
        )
        if r.status_code >= 400:
            logger.error("append_occurrence comment %s HTTP %s: %s",
                         original_key, r.status_code, r.text[:300])

        r = httpx.put(
            f"{base}/rest/api/3/issue/{original_key}",
            headers=headers,
            json={"fields": {
                _occurrence_field(): new_count,
                _last_seen_field(): last_seen,
            }},
            timeout=30,
        )
        if r.status_code >= 400:
            logger.error("append_occurrence bump %s HTTP %s: %s",
                         original_key, r.status_code, r.text[:300])
            return None
        logger.info("Bumped %s occurrence_count to %d (from duplicate %s)",
                    original_key, new_count, duplicate_key)
        return new_count
    except Exception as e:
        logger.error("append_occurrence %s failed: %s", original_key, e)
        return None


def _close_with_resolution(
    ticket_key: str,
    summary_prefix: str,
    resolution_summary_text: str,
    resolution_category_value: str,
    compute_labels,
    comment_adf: dict,
    log_label: str,
) -> bool:
    """Atomic SCDM-Close workflow used by both dedup and tuning-suppression.

    `compute_labels(current_labels: list[str]) -> list[str]` is a callable
    that decides what labels the closed ticket should carry. The dedup path
    overrides with the *original* ticket's labels (so duplicates inherit the
    parent's labelling); the tuning-suppression path filters the malicious
    label out and adds a system marker.

    Steps (all idempotent):
      1. GET current summary + labels.
      2. PUT { summary (prefixed if not already),
              labels (= compute_labels(current_labels)),
              Close Justification, Resolution Summary,
              Resolution Category } in one request.
      3. POST `comment_adf` as a comment.
      4. POST the Close transition (id from `_close_transition_id()`).
    """
    base = _jira_url()
    if not base:
        return False
    headers = _jira_headers()

    try:
        r = httpx.get(
            f"{base}/rest/api/3/issue/{ticket_key}?fields=summary,labels",
            headers=headers, timeout=30,
        )
        if r.status_code >= 400:
            logger.error("%s GET %s HTTP %s", log_label, ticket_key, r.status_code)
            return False
        f = r.json().get("fields", {})
        current_summary = (f.get("summary") or "").strip()
        current_labels = f.get("labels") or []
    except Exception as e:
        logger.error("%s GET %s failed: %s", log_label, ticket_key, e)
        return False

    new_summary = (current_summary if current_summary.startswith(summary_prefix)
                   else f"{summary_prefix} {current_summary}".strip())
    new_labels = compute_labels(current_labels)
    if not new_labels:
        # Close transition validator requires non-empty Labels. Fall back to a
        # neutral marker rather than failing the close.
        logger.warning("%s: %s would close with empty labels — adding fallback marker",
                       log_label, ticket_key)
        new_labels = ["auto-closed"]

    fields_payload = {
        "summary": new_summary,
        "labels": new_labels,
        _close_justification_field(): {"value": _close_justification_value()},
        _resolution_summary_field(): {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": resolution_summary_text}
            ]}],
        },
        _resolution_category_field(): {"value": resolution_category_value},
    }
    try:
        r = httpx.put(
            f"{base}/rest/api/3/issue/{ticket_key}",
            headers=headers, json={"fields": fields_payload}, timeout=30,
        )
        if r.status_code >= 400:
            logger.error("%s PUT fields %s HTTP %s: %s",
                         log_label, ticket_key, r.status_code, r.text[:500])
            return False
    except Exception as e:
        logger.error("%s PUT fields %s failed: %s", log_label, ticket_key, e)
        return False

    try:
        r = httpx.post(
            f"{base}/rest/api/3/issue/{ticket_key}/comment",
            headers=headers, json={"body": comment_adf}, timeout=30,
        )
        if r.status_code >= 400:
            logger.error("%s comment %s HTTP %s: %s",
                         log_label, ticket_key, r.status_code, r.text[:300])
    except Exception as e:
        logger.error("%s comment %s failed: %s", log_label, ticket_key, e)

    try:
        r = httpx.post(
            f"{base}/rest/api/3/issue/{ticket_key}/transitions",
            headers=headers,
            json={"transition": {"id": _close_transition_id()}},
            timeout=30,
        )
        if r.status_code >= 400:
            logger.error("%s transition %s HTTP %s: %s",
                         log_label, ticket_key, r.status_code, r.text[:500])
            return False
    except Exception as e:
        logger.error("%s transition %s failed: %s", log_label, ticket_key, e)
        return False

    logger.info("%s: closed %s (Resolution Category=%s, labels=%s)",
                log_label, ticket_key, resolution_category_value, new_labels)
    return True


def mark_as_duplicate(
    duplicate_key: str,
    original_key: str,
    original_labels: Optional[list] = None,
) -> bool:
    """Auto-close `duplicate_key` as a strict duplicate of `original_key`.

    Per SOC SOP, the duplicate ticket inherits the original's labels exactly
    (rather than carrying its own L1 Triage labels), so analyst label-based
    filters group the two together. `original_labels` is the labels list
    fetched by `find_strict_duplicate`; pass [] if the original was
    unlabelled (caller responsibility — None is treated the same).

    Resolution Summary text is "This is a duplicate of {original_key}." per
    SOC SOP. Close Justification stays at the global default "Other Comments"."""
    base = _jira_url()
    if not base:
        return False
    resolution_summary_text = f"This is a duplicate of {original_key}."

    comment_adf = {
        "type": "doc", "version": 1,
        "content": [{"type": "paragraph", "content": [
            {"type": "text", "text": "Strict duplicate of "},
            {"type": "text", "text": original_key, "marks": [{
                "type": "link",
                "attrs": {"href": f"{base}/browse/{original_key}"}}]},
            {"type": "text", "text": " — same summary, same entities, fired within "
                                      "24h. Closed automatically by SOC Platform dedup."},
        ]}],
    }

    inherited = list(original_labels or [])

    def use_original_labels(_current_labels):
        return inherited

    return _close_with_resolution(
        ticket_key=duplicate_key,
        summary_prefix=_duplicate_summary_prefix(),
        resolution_summary_text=resolution_summary_text,
        resolution_category_value=_resolution_category_value(),
        compute_labels=use_original_labels,
        comment_adf=comment_adf,
        log_label="mark_as_duplicate",
    )
