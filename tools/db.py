"""
SQLite persistence layer for SOC-Report.

Provides:
  - reports table: historical report storage (replaces flat JSON reads)
  - schedules table: recurring schedule configuration

Flat JSON files in data/reports/ continue to be written in parallel so the
ZIP backup/import feature remains intact. This module owns all read paths.
"""
import os
import json
import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

_DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "soc_platform.db"),
)

_REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "reports"
)


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    """Create tables if they do not exist. Called once at app startup.

    Also runs idempotent ALTER TABLE migrations for columns added after the
    initial schema (see ``_migrate_columns`` below). New deployments and
    long-running ones converge on the same schema.
    """
    with _conn() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS reports (
                id            TEXT PRIMARY KEY,
                customer_id   TEXT NOT NULL DEFAULT '',
                customer_name TEXT NOT NULL,
                report_type   TEXT NOT NULL DEFAULT '',
                start_date    TEXT NOT NULL DEFAULT '',
                end_date      TEXT NOT NULL DEFAULT '',
                generated_at  TEXT NOT NULL,
                markdown      TEXT NOT NULL DEFAULT '',
                stats_json    TEXT,
                charts_b64    TEXT,
                sections_json TEXT,
                logo_path     TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS schedules (
                id               TEXT PRIMARY KEY,
                customer_id      TEXT NOT NULL,
                frequency        TEXT NOT NULL,
                day_of_month     INTEGER,
                day_of_week      INTEGER,
                sections_json    TEXT,
                use_sentinel     INTEGER DEFAULT 0,
                use_splunk       INTEGER DEFAULT 0,
                use_socradar     INTEGER DEFAULT 0,
                email_recipients TEXT DEFAULT '',
                enabled          INTEGER DEFAULT 1,
                last_run         TEXT,
                created_at       TEXT
            );
        """)
        _migrate_columns(con)
    logger.info("Database initialised at %s", _DB_PATH)


def _migrate_columns(con: sqlite3.Connection) -> None:
    """Idempotent column additions for live DBs.

    SQLite's ALTER TABLE only supports ADD COLUMN (no IF NOT EXISTS), so we
    introspect PRAGMA table_info and only issue ADDs for columns that are
    actually missing. Safe to call at every startup.

    Phase C (2026-06): adds ``aggregation_mode`` + ``workspace_name`` to
    reports, ``aggregation_mode`` to schedules. Existing rows take the
    column default ('merged' / '').
    """
    def existing_cols(table: str) -> set:
        rows = con.execute(f"PRAGMA table_info({table})").fetchall()
        return {r[1] for r in rows}  # row[1] = column name

    additions = [
        ("reports",   "aggregation_mode", "TEXT DEFAULT 'merged'"),
        ("reports",   "workspace_name",   "TEXT DEFAULT ''"),
        ("schedules", "aggregation_mode", "TEXT DEFAULT 'merged'"),
    ]
    for table, col, decl in additions:
        if col not in existing_cols(table):
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            logger.info("Migrated: added %s.%s", table, col)


# ── Reports ──────────────────────────────────────────────────────────────────

def save_report(report_dict: dict) -> None:
    """Upsert a report record. Accepts the same dict shape as _save_report() writes to JSON."""
    import base64
    charts_b64_raw = report_dict.get("charts_b64")
    if not charts_b64_raw and "charts" in report_dict:
        # In-memory job: charts are raw bytes — encode them
        charts_b64_raw = {}
        for name, png in (report_dict.get("charts") or {}).items():
            if png:
                charts_b64_raw[name] = base64.b64encode(png).decode()

    data = report_dict.get("data") or {}
    stats = data.get("stats") or {}

    with _conn() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO reports
              (id, customer_id, customer_name, report_type, start_date, end_date,
               generated_at, markdown, stats_json, charts_b64, sections_json, logo_path,
               aggregation_mode, workspace_name)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                report_dict.get("id", ""),
                report_dict.get("customer_id", ""),
                report_dict.get("customer_name", ""),
                report_dict.get("report_type", ""),
                report_dict.get("start_date", ""),
                report_dict.get("end_date", ""),
                report_dict.get("generated_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                report_dict.get("markdown", ""),
                json.dumps(stats) if stats else None,
                json.dumps(charts_b64_raw) if charts_b64_raw else None,
                json.dumps(report_dict.get("sections", [])),
                report_dict.get("customer_logo", report_dict.get("logo_path", "")),
                report_dict.get("aggregation_mode", "merged"),
                report_dict.get("workspace_name", ""),
            )
        )


def load_report(report_id: str) -> dict | None:
    """Load a full report record. Returns dict in the same shape as the flat JSON files."""
    with _conn() as con:
        row = con.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not row:
        return None
    return _row_to_report(dict(row))


def load_reports_list(customer_id: str | None = None,
                      start_date: str | None = None,
                      end_date: str | None = None,
                      report_type: str | None = None) -> list[dict]:
    """Return report metadata rows, newest first. Supports optional filters."""
    clauses = []
    params: list = []
    if customer_id:
        clauses.append("customer_id = ?")
        params.append(customer_id)
    if report_type:
        clauses.append("report_type = ?")
        params.append(report_type)
    if start_date:
        clauses.append("start_date >= ?")
        params.append(start_date)
    if end_date:
        clauses.append("end_date <= ?")
        params.append(end_date)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, customer_name, report_type, start_date, end_date, generated_at
        FROM reports
        {where}
        ORDER BY generated_at DESC
    """
    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def delete_report(report_id: str) -> None:
    with _conn() as con:
        con.execute("DELETE FROM reports WHERE id = ?", (report_id,))


def _row_to_report(row: dict) -> dict:
    """Convert a SQLite row dict to the same shape the flat JSON files use."""
    charts_b64 = {}
    if row.get("charts_b64"):
        try:
            charts_b64 = json.loads(row["charts_b64"])
        except Exception:
            pass

    stats = {}
    if row.get("stats_json"):
        try:
            stats = json.loads(row["stats_json"])
        except Exception:
            pass

    sections = []
    if row.get("sections_json"):
        try:
            sections = json.loads(row["sections_json"])
        except Exception:
            pass

    return {
        "id": row["id"],
        "customer_name": row["customer_name"],
        "customer_id": row.get("customer_id", ""),
        "report_type": row["report_type"],
        "start_date": row["start_date"],
        "end_date": row["end_date"],
        "generated_at": row["generated_at"],
        "markdown": row["markdown"],
        "charts_b64": charts_b64,
        "sections": sections,
        "customer_logo": row.get("logo_path", ""),
        "aggregation_mode": row.get("aggregation_mode", "merged") or "merged",
        "workspace_name":   row.get("workspace_name", "") or "",
        # data key is not stored in DB (too large / not needed for exports)
        "data": {"stats": stats},
    }


# ── Migration ─────────────────────────────────────────────────────────────────

def migrate_from_json() -> int:
    """
    One-time import of all existing flat JSON report files into SQLite.
    Returns the number of records imported.
    """
    if not os.path.exists(_REPORTS_DIR):
        return 0

    imported = 0
    with _conn() as con:
        existing_ids = {r[0] for r in con.execute("SELECT id FROM reports").fetchall()}

    for fname in os.listdir(_REPORTS_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(_REPORTS_DIR, fname)
        try:
            with open(fpath, "r") as f:
                report = json.load(f)
            if report.get("id") in existing_ids:
                continue
            save_report(report)
            imported += 1
        except Exception as e:
            logger.warning("migrate_from_json: skipping %s — %s", fname, e)

    logger.info("migrate_from_json: imported %d records", imported)
    return imported


# ── Schedules ─────────────────────────────────────────────────────────────────

def save_schedule(schedule: dict) -> None:
    """Upsert a schedule record."""
    with _conn() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO schedules
              (id, customer_id, frequency, day_of_month, day_of_week,
               sections_json, use_sentinel, use_splunk, use_socradar,
               email_recipients, enabled, last_run, created_at,
               aggregation_mode)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                schedule["id"],
                schedule["customer_id"],
                schedule["frequency"],
                schedule.get("day_of_month"),
                schedule.get("day_of_week"),
                json.dumps(schedule.get("sections", [])),
                1 if schedule.get("use_sentinel") else 0,
                1 if schedule.get("use_splunk") else 0,
                1 if schedule.get("use_socradar") else 0,
                schedule.get("email_recipients", ""),
                1 if schedule.get("enabled", True) else 0,
                schedule.get("last_run"),
                schedule.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                schedule.get("aggregation_mode", "merged") or "merged",
            )
        )


def load_schedules(enabled_only: bool = False) -> list[dict]:
    where = "WHERE enabled = 1" if enabled_only else ""
    with _conn() as con:
        rows = con.execute(
            f"SELECT * FROM schedules {where} ORDER BY created_at DESC"
        ).fetchall()
    return [_row_to_schedule(dict(r)) for r in rows]


def load_schedule(schedule_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    return _row_to_schedule(dict(row)) if row else None


def delete_schedule(schedule_id: str) -> None:
    with _conn() as con:
        con.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))


def update_schedule_last_run(schedule_id: str, dt: str) -> None:
    with _conn() as con:
        con.execute("UPDATE schedules SET last_run = ? WHERE id = ?", (dt, schedule_id))


def _row_to_schedule(row: dict) -> dict:
    sections = []
    if row.get("sections_json"):
        try:
            sections = json.loads(row["sections_json"])
        except Exception:
            pass
    return {
        "id": row["id"],
        "customer_id": row["customer_id"],
        "frequency": row["frequency"],
        "day_of_month": row.get("day_of_month"),
        "day_of_week": row.get("day_of_week"),
        "sections": sections,
        "use_sentinel": bool(row.get("use_sentinel")),
        "use_splunk": bool(row.get("use_splunk")),
        "use_socradar": bool(row.get("use_socradar")),
        "email_recipients": row.get("email_recipients", ""),
        "enabled": bool(row.get("enabled", 1)),
        "last_run": row.get("last_run"),
        "created_at": row.get("created_at"),
        "aggregation_mode": row.get("aggregation_mode", "merged") or "merged",
    }
