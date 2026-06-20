"""
Phase 7 — Decision capture (2026-06-16).

Append-only log of L2 analyst decisions on triage tickets. When the analyst
adds a 'True-Positive' or 'False-Positive' label to a ticket that the
platform previously labelled 'Unknown' / 'Malicious' / 'Clean', a row is
appended to ``data/triage_decisions.jsonl``.

Storage choice: JSONL on Azure Files. Append-only writes are safe over SMB
because each write is one-line + flush — no record-locking required. Reads
filter the entire file in memory; acceptable at expected scale (well under
100k decisions for the foreseeable future).

Consumers:
- Auto-close FP (Phase 7 sub-feature 3, this commit) — when L2 confirms FP
  on a ticket the platform also called clean, transition the ticket closed.
- Few-shot retrieval at LLM triage time (Phase 7 sub-feature 2) — DEFERRED.
  Needs weeks of accumulated data to be useful; ship the collector now,
  turn on the consumer later.
- Future analytics dashboards — out of scope here.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

SGT = timezone(timedelta(hours=8))

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECISIONS_FILE = os.path.join(_BASE_DIR, "data", "triage_decisions.jsonl")

_write_lock = threading.Lock()


def record_decision(*, ticket_key: str, project_key: str, customer_id: str,
                    rule_prefix: str, l2_label: str,
                    platform_verdict: str,
                    decided_at: datetime | None = None) -> bool:
    """Append a decision row. Returns True on success, False on any error.

    Never raises — caller can fire-and-forget from the webhook handler.
    """
    if os.environ.get("DECISION_CAPTURE_ENABLED", "false").lower() != "true":
        return False
    try:
        os.makedirs(os.path.dirname(DECISIONS_FILE), exist_ok=True)
        row = {
            "ticket_key": ticket_key,
            "project_key": project_key,
            "customer_id": customer_id,
            "rule_prefix": rule_prefix or "",
            "l2_label": l2_label,           # "True-Positive" | "False-Positive" | "Unknown"
            "platform_verdict": platform_verdict,  # what the platform originally decided
            "decided_at": (decided_at or datetime.now(SGT)).isoformat(timespec="seconds"),
        }
        line = json.dumps(row, ensure_ascii=False) + "\n"
        with _write_lock:
            with open(DECISIONS_FILE, "a") as f:
                f.write(line)
                f.flush()
        logger.info("Recorded decision %s: %s (platform said %s)",
                    ticket_key, l2_label, platform_verdict)
        return True
    except Exception:
        logger.exception("record_decision failed for %s", ticket_key)
        return False


def list_decisions(*, customer_id: str | None = None,
                   rule_prefix: str | None = None,
                   limit: int = 20) -> list[dict]:
    """Read decisions from the JSONL log, newest first. Optional filters."""
    if not os.path.exists(DECISIONS_FILE):
        return []
    out: list[dict] = []
    try:
        with open(DECISIONS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if customer_id and row.get("customer_id") != customer_id:
                    continue
                if rule_prefix and row.get("rule_prefix") != rule_prefix:
                    continue
                out.append(row)
    except Exception:
        logger.exception("list_decisions read failed")
        return []
    out.sort(key=lambda r: r.get("decided_at", ""), reverse=True)
    return out[:limit]
