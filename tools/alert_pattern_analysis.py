"""
Alert Pattern Analysis (30d) — L1 Triage historical pattern & tuning signals.

Extends Phase 3 (``tools.historical_alerts``, 24h similar-alert counts) with a
30-day view of the same rule identity, answering four analyst questions:

  1. Entity correlation — have this ticket's IOCs/hostnames appeared in prior
     incidents, and did those close True-Positive or Benign-Positive?
  2. Frequency — how often has this alert type fired in the past 30 days,
     and when was its first occurrence ever?
  3. Timing — does it fire only during business hours (tuning candidate) or
     after-hours (more suspicious)? Business hours are SGT, env-configurable.
  4. Tuning — deterministic recommendation when high-frequency + historically
     benign, so the SOC can finetune noisy rules.

Rule identity is the same summary-prefix signal as Phase 3 (helpers imported
from ``tools.historical_alerts`` so the 24h and 30d blocks can never disagree
on what "similar" means). Entity correlation reuses the gate-free
``tools.ioc_history.fetch_ioc_history`` entry point and shares its cache.

Design constraints (house pattern):
- Killswitch ``ALERT_PATTERN_ANALYSIS_ENABLED=false`` by default — ships dark.
- Whole analysis runs in a daemon thread with a hard wall-clock cap
  (``ALERT_PATTERN_TIMEOUT_S``, default 20s) — a slow Jira can never stall
  triage.
- Function never raises; ``None`` return = feature silently absent.
- Comment rendering works off the master flag alone; feeding the LLM Triage
  prompt requires the separate ``ALERT_PATTERN_TO_LLM_PROMPT_ENABLED`` flag
  (same conservative ladder as RAG Phase 4 → 4c).
"""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta, timezone

import httpx

from tools.historical_alerts import (
    _categorise,
    _jira_headers,
    _jql_escape,
    _label_names,
    _normalize_summary_prefix,
)

logger = logging.getLogger(__name__)

_DEFAULT_WINDOW_DAYS = 30
_DEFAULT_MAX_PAGES = 2
_DEFAULT_TIMEOUT_S = 20.0
_DEFAULT_IOC_BUDGET = 5
_DEFAULT_MIN_SAMPLE = 5
_DEFAULT_TIMING_THRESHOLD = 0.8
_DEFAULT_BUSINESS_START = 9
_DEFAULT_BUSINESS_END = 18
_DEFAULT_TUNING_MIN_COUNT = 10
_DEFAULT_TUNING_MIN_DECIDED = 3
_DEFAULT_TUNING_FP_RATIO = 0.9

_PAGE_SIZE = 100

# Fallback when zoneinfo can't resolve Asia/Singapore (no DST there anyway).
_SGT_FIXED = timezone(timedelta(hours=8))


# ── Config knobs ──────────────────────────────────────────────────────────

def _enabled() -> bool:
    return os.environ.get("ALERT_PATTERN_ANALYSIS_ENABLED", "false").strip().lower() == "true"


def _int_env(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _window_days() -> int:
    return _int_env("ALERT_PATTERN_WINDOW_DAYS", _DEFAULT_WINDOW_DAYS, minimum=1)


def _max_pages() -> int:
    return _int_env("ALERT_PATTERN_MAX_PAGES", _DEFAULT_MAX_PAGES, minimum=1)


def _timeout_s() -> float:
    return _float_env("ALERT_PATTERN_TIMEOUT_S", _DEFAULT_TIMEOUT_S)


def _first_seen_enabled() -> bool:
    return os.environ.get("ALERT_PATTERN_FIRST_SEEN_ENABLED", "true").strip().lower() != "false"


def _ioc_budget() -> int:
    return _int_env("ALERT_PATTERN_IOC_BUDGET", _DEFAULT_IOC_BUDGET)


def _min_sample() -> int:
    return _int_env("ALERT_PATTERN_MIN_SAMPLE", _DEFAULT_MIN_SAMPLE, minimum=1)


def _timing_threshold() -> float:
    return _float_env("ALERT_PATTERN_TIMING_THRESHOLD", _DEFAULT_TIMING_THRESHOLD)


def _business_hours() -> tuple[int, int]:
    return (
        _int_env("BUSINESS_HOURS_START", _DEFAULT_BUSINESS_START),
        _int_env("BUSINESS_HOURS_END", _DEFAULT_BUSINESS_END),
    )


def _tuning_min_count() -> int:
    return _int_env("ALERT_PATTERN_TUNING_MIN_COUNT", _DEFAULT_TUNING_MIN_COUNT, minimum=1)


def _tuning_min_decided() -> int:
    return _int_env("ALERT_PATTERN_TUNING_MIN_DECIDED", _DEFAULT_TUNING_MIN_DECIDED, minimum=1)


def _tuning_fp_ratio() -> float:
    return _float_env("ALERT_PATTERN_TUNING_FP_RATIO", _DEFAULT_TUNING_FP_RATIO)


# ── Pure helpers (unit-tested, no network) ────────────────────────────────

def _to_sgt(created_iso: str) -> datetime | None:
    """Parse a Jira ISO-8601 timestamp (handles trailing 'Z' and offsets like
    +0000 / +08:00) and convert to SGT. Returns None when unparseable —
    callers skip the sample rather than guess."""
    raw = (created_iso or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    # Jira commonly emits "+0000" (no colon), which fromisoformat rejects on
    # some Python versions — normalise to "+00:00".
    if len(raw) >= 5 and raw[-5] in "+-" and raw[-4:].isdigit():
        raw = raw[:-2] + ":" + raw[-2:]
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        from zoneinfo import ZoneInfo
        return dt.astimezone(ZoneInfo("Asia/Singapore"))
    except Exception:
        return dt.astimezone(_SGT_FIXED)


def _bucket_timing(created_iso_list: list[str]) -> tuple[int, int]:
    """Split timestamps into (business_hours, after_hours) counts in SGT.
    Business = Mon-Fri, BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END.
    Weekends are after-hours by definition. Unparseable timestamps are
    excluded from both buckets."""
    start, end = _business_hours()
    business = after = 0
    for iso in created_iso_list:
        local = _to_sgt(iso)
        if local is None:
            continue
        if local.weekday() < 5 and start <= local.hour < end:
            business += 1
        else:
            after += 1
    return business, after


def _classify_timing(business: int, after: int) -> str:
    n = business + after
    if n < _min_sample():
        return "insufficient-sample"
    threshold = _timing_threshold()
    if business / n >= threshold:
        return "business-hours-only"
    if after / n >= threshold:
        return "after-hours-only"
    return "mixed"


def _tuning_signal(stats: dict) -> dict | None:
    """Deterministic tuning recommendation. Untriaged siblings count toward
    frequency (total) but not the FP ratio — pending tickets are not evidence
    of benignity. Any True-Positive among decided outcomes is named in the
    rationale so the analyst sees the counter-evidence."""
    total = int(stats.get("total") or 0)
    tp = int(stats.get("true_positive") or 0)
    fp = int(stats.get("false_positive") or 0)
    decided = tp + fp
    if total < _tuning_min_count() or decided < _tuning_min_decided():
        return None
    fp_ratio = fp / decided
    if fp_ratio < _tuning_fp_ratio():
        return None

    timing = stats.get("timing_pattern") or ""
    strength = "strong" if (timing == "business-hours-only" and tp == 0) else "moderate"
    window = stats.get("window_days") or _window_days()
    total_str = f"{total}+" if stats.get("truncated") else str(total)

    parts = [
        f"Fired {total_str}x in {window}d",
        f"{fp} of {decided} decided outcomes Benign-Positive ({fp_ratio:.0%})",
    ]
    if timing == "business-hours-only":
        parts.append("business-hours-only pattern")
    rationale = ", ".join(parts) + " — recommend rule finetuning to reduce noise."
    if tp > 0:
        rationale += (
            f" NOTE: {tp} True-Positive among decided outcomes — review those before tuning."
        )
    return {"recommended": True, "strength": strength, "rationale": rationale}


# ── Jira fetches ──────────────────────────────────────────────────────────

def _rule_jql(prefix: str, ticket_key: str, project_key: str, window_hours: int | None) -> str:
    escaped = _jql_escape(prefix)
    parts = [
        f'project = "{project_key}"',
        f'key != "{ticket_key}"',
    ]
    if window_hours is not None:
        parts.append(f"created >= -{window_hours}h")
    parts.append(f'summary ~ "\\"{escaped}\\""')
    order = "DESC" if window_hours is not None else "ASC"
    return " AND ".join(parts) + f" ORDER BY created {order}"


def _search(jira_url: str, jql: str, fields: str, max_results: int,
            next_page_token: str | None = None) -> dict | None:
    params: dict = {"jql": jql, "fields": fields, "maxResults": max_results}
    if next_page_token:
        params["nextPageToken"] = next_page_token
    r = httpx.get(
        f"{jira_url}/rest/api/3/search/jql",
        headers=_jira_headers(),
        params=params,
        timeout=15,
    )
    if r.status_code >= 400:
        logger.warning("Alert pattern JQL HTTP %s: %s", r.status_code, r.text[:200])
        return None
    return r.json() or {}


def _fetch_window_pages(jira_url: str, jql: str) -> tuple[list[dict], bool]:
    """Fetch up to _max_pages() of siblings. Returns (issues, truncated)."""
    issues: list[dict] = []
    token: str | None = None
    for _ in range(_max_pages()):
        data = _search(jira_url, jql, "created,labels", _PAGE_SIZE, token)
        if data is None:
            break
        issues.extend(data.get("issues") or [])
        token = data.get("nextPageToken")
        if not token or data.get("isLast"):
            token = None if data.get("isLast") else token
            if not token:
                break
    return issues, bool(token)


def _fetch_first_seen_ever(jira_url: str, prefix: str, ticket_key: str,
                           project_key: str) -> str:
    """One cheap unbounded query: oldest ticket ever with this rule prefix.
    Returns "" on any failure — caller falls back to first_seen_in_window."""
    if not _first_seen_enabled():
        return ""
    try:
        jql = _rule_jql(prefix, ticket_key, project_key, window_hours=None)
        data = _search(jira_url, jql, "created", 1)
        issues = (data or {}).get("issues") or []
        if issues:
            return ((issues[0].get("fields") or {}).get("created") or "").strip()
    except Exception as e:
        logger.warning("Alert pattern first-seen lookup failed (%s): %s",
                       type(e).__name__, e)
    return ""


# ── Entity correlation ────────────────────────────────────────────────────

def _correlate_entities(ticket_key: str, fields: dict, project_key: str,
                        schema) -> list[dict]:
    """Per-IOC prior-incident lookup with TP/FP outcome breakdown. Reuses the
    gate-free ioc_history fetch (shares its 60s cache with Phase 5b rendering,
    so overlapping IOCs cost no duplicate JQL calls). IOCs with no prior
    appearances are dropped to keep prompt + comment signal-dense."""
    try:
        from tools.enrichment import extract_iocs_from_entity_fields
        from tools.ioc_history import fetch_ioc_history
        iocs = extract_iocs_from_entity_fields(fields, schema) or []
    except Exception as e:
        logger.warning("Alert pattern entity extraction failed (%s): %s",
                       type(e).__name__, e)
        return []

    correlated: list[dict] = []
    for ioc in iocs[:_ioc_budget()]:
        value = (ioc.get("value") or "").strip()
        if not value:
            continue
        try:
            history = fetch_ioc_history(value, exclude_ticket_key=ticket_key,
                                        project=project_key)
        except Exception as e:
            logger.warning("Alert pattern IOC lookup failed for %r (%s): %s",
                           value, type(e).__name__, e)
            continue
        if not history or not history.get("count"):
            continue
        correlated.append({
            "value": value,
            "type": (ioc.get("type") or "").upper(),
            "count": int(history.get("count") or 0),
            "true_positive": int(history.get("true_positive") or 0),
            "false_positive": int(history.get("false_positive") or 0),
            "unknown": int(history.get("unknown") or 0),
            "untriaged": int(history.get("untriaged") or 0),
            "historically_benign": bool(history.get("historically_benign")),
            "sample_tickets": list(history.get("tickets") or [])[:5],
        })
    return correlated


# ── Core analysis (runs inside the timeout thread) ────────────────────────

def _analyze(ticket_key: str, fields: dict, project_key: str, schema) -> dict | None:
    jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
    if not jira_url:
        logger.warning("Alert pattern analysis: JIRA_URL not set — skipping %s", ticket_key)
        return None

    summary = (fields.get("summary") or "").strip()
    prefix = _normalize_summary_prefix(summary)
    if len(prefix) < 10:
        logger.info("Alert pattern analysis: prefix too short (%d chars) for %s — skipping",
                    len(prefix), ticket_key)
        return None

    days = _window_days()
    jql = _rule_jql(prefix, ticket_key, project_key, window_hours=days * 24)
    issues, truncated = _fetch_window_pages(jira_url, jql)

    label_map = _label_names()
    counts = {"tp": 0, "fp": 0, "unknown": 0, "untriaged": 0}
    created_list: list[str] = []
    for issue in issues:
        f = issue.get("fields") or {}
        counts[_categorise(f.get("labels") or [], label_map)] += 1
        created = (f.get("created") or "").strip()
        if created:
            created_list.append(created)

    business, after = _bucket_timing(created_list)
    sample = business + after
    first_in_window = min(created_list) if created_list else ""
    first_ever = _fetch_first_seen_ever(jira_url, prefix, ticket_key, project_key)

    result = {
        "window_days": days,
        "rule_prefix": prefix,
        "total": len(issues),
        "truncated": truncated,
        "true_positive": counts["tp"],
        "false_positive": counts["fp"],
        "unknown": counts["unknown"],
        "untriaged": counts["untriaged"],
        "first_seen_ever": first_ever,
        "first_seen_in_window": first_in_window,
        "business_hours_count": business,
        "after_hours_count": after,
        "business_hours_share": (business / sample) if sample else 0.0,
        "timing_pattern": _classify_timing(business, after),
        "entity_correlation": _correlate_entities(ticket_key, fields, project_key, schema),
    }
    result["tuning"] = _tuning_signal(result)

    logger.info(
        "Alert pattern analysis %s: %d%s alerts in %dd (TP=%d FP=%d U=%d untriaged=%d), "
        "timing=%s (%d biz/%d after), entities=%d, tuning=%s",
        ticket_key, result["total"], "+" if truncated else "", days,
        counts["tp"], counts["fp"], counts["unknown"], counts["untriaged"],
        result["timing_pattern"], business, after,
        len(result["entity_correlation"]),
        (result["tuning"] or {}).get("strength") or "no",
    )
    return result


# ── Public entry ──────────────────────────────────────────────────────────

def analyze_alert_patterns(ticket_key: str, fields: dict, project_key: str,
                           schema=None) -> dict | None:
    """30-day pattern analysis for a freshly-enriched ticket. Returns the
    stats dict or None (disabled / skipped / any error / timeout). MUST NOT
    raise — the whole body runs in a daemon thread behind a hard timeout."""
    if not _enabled():
        return None

    result_box: dict = {"value": None, "done": False}

    def _target():
        try:
            result_box["value"] = _analyze(ticket_key, fields, project_key, schema)
        except Exception as e:
            logger.warning("Alert pattern analysis failed for %s (%s): %s",
                           ticket_key, type(e).__name__, e)
        finally:
            result_box["done"] = True

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=_timeout_s())
    if not result_box["done"]:
        logger.warning("Alert pattern analysis: timeout (%.1fs) for %s",
                       _timeout_s(), ticket_key)
        return None
    return result_box["value"]
