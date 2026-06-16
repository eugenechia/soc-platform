"""
Backup workflow for SOC-Platform.

Writes periodic snapshots of:
  * the Postgres database (via ``pg_dump --format=custom``)
  * ``data/customers.json`` (atomic file copy)

to the Azure Files mount at ``/app/data/backups``. Retention defaults to 30
days. Triggered nightly by APScheduler at 02:00 SGT; also exposed via
``/admin/api/backup/run-now`` for manual use.

Layout::

    /app/data/backups/
        db/
            socplatform-YYYY-MM-DD-HHMMSS.dump
            ...
        customers/
            customers-YYYY-MM-DD-HHMMSS.json
            ...

Failure isolation
-----------------

``run_nightly_backup()`` runs each step independently. A failed DB dump does
NOT block the customers snapshot and vice versa — the next nightly run
retries everything from scratch. The backup workflow must never be the cause
of an app outage.

Encryption
----------

Azure Files is encrypted at rest with Microsoft-managed keys. We do NOT add
app-level encryption. The connection-string secret inside the dump is the
only sensitive payload; treat the share's access controls as the security
boundary.
"""
import os
import logging
import shutil
import subprocess
import threading
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BACKUP_DIR = os.environ.get("BACKUP_DIR", os.path.join(_BASE_DIR, "data", "backups"))
DB_BACKUP_DIR = os.path.join(BACKUP_DIR, "db")
CUSTOMERS_BACKUP_DIR = os.path.join(BACKUP_DIR, "customers")

CUSTOMERS_FILE = os.path.join(_BASE_DIR, "data", "customers.json")

RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", "30"))
BACKUP_HOUR = int(os.environ.get("BACKUP_SCHEDULE_HOUR", "2"))  # SGT
BACKUP_TIMEOUT_S = int(os.environ.get("BACKUP_TIMEOUT_S", "300"))

SGT = timezone(timedelta(hours=8))

_lock = threading.Lock()
_last_manual_run: datetime | None = None
_MANUAL_MIN_INTERVAL = timedelta(minutes=5)


def _ensure_dirs() -> None:
    os.makedirs(DB_BACKUP_DIR, exist_ok=True)
    os.makedirs(CUSTOMERS_BACKUP_DIR, exist_ok=True)


def dump_database() -> dict:
    """Run pg_dump against ``DATABASE_URL`` and write a custom-format dump.

    Returns ``{path, size_bytes, dumped_at, elapsed_seconds}``. Raises if
    pg_dump exits non-zero or times out; the orchestrator catches and
    surfaces the error without aborting later steps.
    """
    _ensure_dirs()
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL not set — cannot dump database")

    started = datetime.now(SGT)
    ts = started.strftime("%Y-%m-%d-%H%M%S")
    out_path = os.path.join(DB_BACKUP_DIR, f"socplatform-{ts}.dump")

    cmd = [
        "pg_dump",
        "--dbname", dsn,
        "--format", "custom",
        "--no-owner",
        "--no-privileges",
        "--file", out_path,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=BACKUP_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        logger.error("pg_dump timed out after %ds", BACKUP_TIMEOUT_S)
        _safe_remove(out_path)
        raise

    if result.returncode != 0:
        logger.error("pg_dump failed (rc=%d): %s", result.returncode, result.stderr[:500])
        _safe_remove(out_path)
        raise RuntimeError(f"pg_dump failed with exit code {result.returncode}")

    size = os.path.getsize(out_path)
    elapsed = (datetime.now(SGT) - started).total_seconds()
    logger.info("DB dump complete: %s (%d bytes, %.2fs)", out_path, size, elapsed)
    return {
        "path": out_path,
        "size_bytes": size,
        "dumped_at": started.isoformat(timespec="seconds"),
        "elapsed_seconds": elapsed,
    }


def snapshot_customers() -> dict:
    """Atomically copy ``data/customers.json`` to ``customers/customers-<ts>.json``."""
    _ensure_dirs()
    if not os.path.exists(CUSTOMERS_FILE):
        raise RuntimeError(f"customers.json not found at {CUSTOMERS_FILE}")

    started = datetime.now(SGT)
    ts = started.strftime("%Y-%m-%d-%H%M%S")
    out_path = os.path.join(CUSTOMERS_BACKUP_DIR, f"customers-{ts}.json")

    tmp_path = out_path + ".tmp"
    # shutil.copy (not copy2) deliberately — copy2 preserves the source mtime,
    # which would make the snapshot's mtime equal customers.json's last-edit
    # time. We want the mtime to reflect snapshot CREATION so the UI freshness
    # pill correctly says "just now".
    shutil.copy(CUSTOMERS_FILE, tmp_path)
    os.replace(tmp_path, out_path)

    size = os.path.getsize(out_path)
    logger.info("Customers snapshot complete: %s (%d bytes)", out_path, size)
    return {
        "path": out_path,
        "size_bytes": size,
        "snapshotted_at": started.isoformat(timespec="seconds"),
    }


def prune_old_backups() -> int:
    """Delete backup files older than ``RETENTION_DAYS``. Returns count deleted."""
    _ensure_dirs()
    cutoff_ts = (datetime.now(SGT) - timedelta(days=RETENTION_DAYS)).timestamp()
    deleted = 0
    for d in (DB_BACKUP_DIR, CUSTOMERS_BACKUP_DIR):
        for fname in os.listdir(d):
            path = os.path.join(d, fname)
            if not os.path.isfile(path):
                continue
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if mtime < cutoff_ts:
                try:
                    os.remove(path)
                    deleted += 1
                    logger.info("Pruned old backup: %s", path)
                except OSError as e:
                    logger.warning("Failed to prune %s: %s", path, e)
    return deleted


def run_nightly_backup(*, manual: bool = False) -> dict:
    """Orchestrator: dump DB + snapshot customers + prune old.

    ``manual=True`` enforces a 5-minute minimum interval between manual runs
    so a runaway "Run now" button doesn't flood pg_dump invocations.

    Returns::

        {
          "db":        dict | None,        # dump_database() result, None on failure
          "customers": dict | None,        # snapshot_customers() result, None on failure
          "pruned":    int,                # files removed by retention
          "errors":    list[str],          # per-step error messages
          "status":    backup_status() dict
        }

    If the lock is already held (a backup is already running), returns the
    current status with ``in_progress=True`` and skips this invocation.
    """
    global _last_manual_run

    if not _lock.acquire(blocking=False):
        logger.info("Backup already in progress; ignoring duplicate trigger")
        status = backup_status()
        status["in_progress"] = True
        return status

    try:
        if manual:
            now = datetime.now(SGT)
            if _last_manual_run and (now - _last_manual_run) < _MANUAL_MIN_INTERVAL:
                wait = (_MANUAL_MIN_INTERVAL - (now - _last_manual_run)).total_seconds()
                logger.info("Manual backup rate-limited; %ds remaining", int(wait))
                status = backup_status()
                status["rate_limited"] = True
                status["retry_after_seconds"] = int(wait)
                return status
            _last_manual_run = now

        result: dict = {"db": None, "customers": None, "pruned": 0, "errors": []}

        try:
            result["db"] = dump_database()
        except Exception as e:
            logger.exception("dump_database failed")
            result["errors"].append(f"db: {e}")

        try:
            result["customers"] = snapshot_customers()
        except Exception as e:
            logger.exception("snapshot_customers failed")
            result["errors"].append(f"customers: {e}")

        try:
            result["pruned"] = prune_old_backups()
        except Exception as e:
            logger.exception("prune_old_backups failed")
            result["errors"].append(f"prune: {e}")

        result["status"] = backup_status()
        return result
    finally:
        _lock.release()


def backup_status() -> dict:
    """Return summary for the admin UI freshness indicator.

    Includes the SGT timestamp of the newest file in each backup dir, current
    file count, size of newest, and the next scheduled run time. ``last_at``
    is None if no backups exist yet. Safe to call concurrently with a running
    backup — only reads filesystem state.
    """
    next_at = _next_scheduled_at()
    db_info = _newest_file_info(DB_BACKUP_DIR)
    db_info["next_at"] = next_at
    customers_info = _newest_file_info(CUSTOMERS_BACKUP_DIR)
    customers_info["next_at"] = next_at
    return {
        "db": db_info,
        "customers": customers_info,
        "retention_days": RETENTION_DAYS,
        "backup_dir": BACKUP_DIR,
    }


def _newest_file_info(directory: str) -> dict:
    if not os.path.isdir(directory):
        return {"last_at": None, "size_bytes": 0, "count": 0}
    files = [
        os.path.join(directory, f) for f in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, f)) and not f.endswith(".tmp")
    ]
    if not files:
        return {"last_at": None, "size_bytes": 0, "count": 0}
    newest = max(files, key=os.path.getmtime)
    return {
        "last_at": datetime.fromtimestamp(os.path.getmtime(newest), SGT).isoformat(timespec="seconds"),
        "size_bytes": os.path.getsize(newest),
        "count": len(files),
    }


def _next_scheduled_at() -> str:
    now = datetime.now(SGT)
    next_dt = now.replace(hour=BACKUP_HOUR, minute=0, second=0, microsecond=0)
    if next_dt <= now:
        next_dt += timedelta(days=1)
    return next_dt.isoformat(timespec="seconds")


def _safe_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
