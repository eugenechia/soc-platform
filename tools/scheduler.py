"""
APScheduler-based recurring report scheduler.

Checks every 5 minutes for schedules that are due to run, fires off a
report job, and emails the PDF + DOCX to the configured recipients.

Important: Requires Gunicorn --workers 1 (this module uses in-process state).
"""
import os
import logging
import smtplib
import threading
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

logger = logging.getLogger(__name__)

_scheduler = None

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)


def init_scheduler(app) -> None:
    """
    Initialise and start the APScheduler BackgroundScheduler.
    Call once at app startup, after db.init_db().
    """
    global _scheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        logger.warning("APScheduler not installed — scheduled reports disabled.")
        return

    _scheduler = BackgroundScheduler(daemon=True)
    # Check for due schedules every 5 minutes
    _scheduler.add_job(
        lambda: _check_due_schedules(app),
        trigger="interval",
        minutes=5,
        id="check_schedules",
        replace_existing=True,
    )

    # D1 nightly backup — dumps Postgres + customers.json to /app/data/backups
    # Killswitch via BACKUP_ENABLED env (default true). Runs at BACKUP_SCHEDULE_HOUR
    # SGT (default 02:00). misfire_grace_time=3600 covers cases where the container
    # was restarting at fire moment so we don't silently skip a night.
    if os.environ.get("BACKUP_ENABLED", "true").lower() == "true":
        try:
            from tools import backup as _backup
            backup_hour = int(os.environ.get("BACKUP_SCHEDULE_HOUR", "2"))
            _scheduler.add_job(
                _backup.run_nightly_backup,
                trigger="cron",
                hour=backup_hour,
                minute=0,
                timezone="Asia/Singapore",
                id="nightly_backup",
                replace_existing=True,
                misfire_grace_time=3600,
            )
            logger.info("Nightly backup job registered for %02d:00 SGT.", backup_hour)
        except Exception:
            logger.exception("Failed to register nightly_backup job — scheduler still starting")

    # Phase 5d (2026-06-16) — daily Confluence RAG re-sync. The Chroma vector
    # store lives on ephemeral /tmp/rag (SQLite + SMB don't mix), so it is
    # wiped on every container restart. A daily cron keeps customer Confluence
    # content fresh; an immediate-on-startup sync (below, after start())
    # repopulates /tmp/rag before any webhook traffic arrives. Killswitch
    # RAG_AUTO_SYNC_ENABLED defaults true — sync is maintenance work that
    # should just run.
    _rag_auto_sync_enabled = os.environ.get("RAG_AUTO_SYNC_ENABLED", "true").lower() == "true"
    if _rag_auto_sync_enabled:
        try:
            from tools.rag_auto_sync import sync_all_customers
            rag_sync_hour = int(os.environ.get("RAG_AUTO_SYNC_HOUR", "3"))
            _scheduler.add_job(
                lambda: sync_all_customers(reason="cron"),
                trigger="cron",
                hour=rag_sync_hour,
                minute=0,
                timezone="Asia/Singapore",
                id="rag_auto_sync",
                replace_existing=True,
                misfire_grace_time=3600,
            )
            logger.info("RAG auto-sync job registered for %02d:00 SGT.", rag_sync_hour)
        except Exception:
            logger.exception("Failed to register rag_auto_sync job — scheduler still starting")
    else:
        logger.info("RAG auto-sync disabled via RAG_AUTO_SYNC_ENABLED env var.")

    _scheduler.start()
    logger.info("Scheduler started — checking every 5 minutes for due reports.")

    # Phase 5d — immediate-on-startup RAG sync. Container restart wipes
    # /tmp/rag, so the Chroma store is empty until the first sync. Fired in a
    # background thread so app startup isn't blocked.
    if _rag_auto_sync_enabled and os.environ.get("RAG_AUTO_SYNC_ON_STARTUP", "true").lower() == "true":
        def _initial_rag_sync():
            try:
                from tools.rag_auto_sync import sync_all_customers
                logger.info("RAG auto-sync: firing initial sync on startup")
                sync_all_customers(reason="startup")
            except Exception:
                logger.exception("Initial RAG sync failed at startup")
        threading.Thread(target=_initial_rag_sync, daemon=True).start()


def _check_due_schedules(app) -> None:
    """Called by APScheduler every 5 minutes. Runs any overdue schedules."""
    import tools.db as db

    with app.app_context():
        schedules = db.load_schedules(enabled_only=True)
        now = datetime.now()

        for schedule in schedules:
            if _is_due(schedule, now):
                logger.info("Schedule %s is due — firing report job.", schedule["id"])
                _fire_schedule(app, schedule, now)


def _is_due(schedule: dict, now: datetime) -> bool:
    """
    Return True if the schedule should run now based on frequency and last_run.

    monthly: runs on day_of_month each month (defaults to 1st).
             If the target day has already passed this month and no run has
             happened yet for the current month, a catch-up fire is issued
             on the next 5-minute poll — guarantees container restarts
             across the fire moment don't silently drop a month's report.
    weekly:  runs on day_of_week each week (0=Mon … 6=Sun).
             Same catch-up semantics within the current calendar week.

    last_run is the only de-duplication signal, so the calling code must
    update it *before* (or atomically with) firing the report — otherwise
    a slow report run that overlaps the next 5-min poll could double-fire.
    See _fire_schedule() in this module: it writes last_run via
    db.update_schedule_last_run() prior to spawning the report thread.
    """
    frequency = schedule.get("frequency", "monthly")
    last_run_str = schedule.get("last_run")
    last_run = _parse_dt(last_run_str) if last_run_str else None

    if frequency == "monthly":
        target_day = schedule.get("day_of_month") or 1
        # Already fired this calendar month? Done.
        if last_run and last_run.year == now.year and last_run.month == now.month:
            return False
        # On-time fire — exactly the target day this month.
        if now.day == target_day:
            return True
        # Catch-up fire — target day has passed this month and we never ran.
        # Skips months where the schedule was created after the target day:
        # if the schedule was created today (now.day=15) targeting day 1, we
        # would NOT fire retroactively for "this month" because a fresh
        # schedule with no last_run shouldn't fire until next month. The
        # `created_at < first_of_this_month` check enforces that.
        if now.day > target_day:
            created_at = _parse_dt(schedule.get("created_at", "")) if schedule.get("created_at") else None
            first_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            if created_at and created_at < first_of_month:
                return True
            # No created_at field — be permissive (legacy schedules).
            if not created_at:
                return True
        return False

    elif frequency == "weekly":
        target_dow = schedule.get("day_of_week")
        if target_dow is None:
            target_dow = 0
        # Already fired this week? Done.
        if last_run and (now - last_run) < timedelta(days=6):
            return False
        # On-time fire.
        if now.weekday() == target_dow:
            return True
        # Catch-up: target day-of-week has passed this calendar week
        # (Mon-Sun) and we never ran.
        days_since_monday = now.weekday()
        start_of_week = (now - timedelta(days=days_since_monday)).replace(
            hour=0, minute=0, second=0, microsecond=0,
        )
        if now.weekday() > target_dow:
            created_at = _parse_dt(schedule.get("created_at", "")) if schedule.get("created_at") else None
            if not created_at or created_at < start_of_week:
                return True
        return False

    return False


def _parse_dt(dt_str: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue
    return None


def _fire_schedule(app, schedule: dict, now: datetime) -> None:
    """Kick off a report job for the schedule in a background thread."""
    import uuid
    import tools.db as db

    customers = _load_customers(app)
    customer = next((c for c in customers if c["id"] == schedule["customer_id"]), None)
    if not customer:
        logger.error("Schedule %s: customer %s not found, skipping.",
                     schedule["id"], schedule["customer_id"])
        return

    # Compute date range: previous full month for monthly, previous week for weekly
    if schedule.get("frequency") == "monthly":
        first_of_this_month = now.replace(day=1)
        last_month_end = first_of_this_month - timedelta(days=1)
        start_date = last_month_end.replace(day=1).strftime("%Y-%m-%d")
        end_date = last_month_end.strftime("%Y-%m-%d")
    else:
        week_start = now - timedelta(days=now.weekday())
        end_date = (week_start - timedelta(days=1)).strftime("%Y-%m-%d")
        start_date = (week_start - timedelta(days=7)).strftime("%Y-%m-%d")

    job_id = str(uuid.uuid4())
    config = {
        "customer_name": customer["name"],
        "customer_id": customer["id"],
        "jira_project_key": customer.get("jira_project_key", ""),
        "report_type": "Monthly SOC Report" if schedule.get("frequency") == "monthly" else "SOC Report",
        "start_date": start_date,
        "end_date": end_date,
        "sections": schedule.get("sections") or customer.get("default_sections", []),
        "customer_logo": customer.get("logo", ""),
        "csv_path": "",
        "use_sentinel": schedule.get("use_sentinel", False),
        "use_splunk": schedule.get("use_splunk", False),
        "use_socradar": schedule.get("use_socradar", False),
        # Phase C — "merged" (default, single roll-up report) vs
        # "per_workspace" (one report per workspace, run sequentially by
        # run_report_job's fan-out block in routes/reports.py).
        "aggregation_mode": schedule.get("aggregation_mode", "merged") or "merged",
        "_schedule_id": schedule["id"],
        "_email_recipients": schedule.get("email_recipients", ""),
    }

    # Register job in the global jobs dict via app import
    from app import jobs, run_report_job
    jobs[job_id] = {"status": "running", "text": "", "data": None, "error": None, "config": config}

    def _run():
        run_report_job(job_id, config)
        _on_job_complete(app, job_id, schedule)

    threading.Thread(target=_run, daemon=True).start()

    # Mark last_run immediately so a second check within the same minute doesn't re-fire
    db.update_schedule_last_run(schedule["id"], now.strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("Schedule %s fired job %s for %s (%s to %s).",
                schedule["id"], job_id[:8], customer["name"], start_date, end_date)


def _on_job_complete(app, job_id: str, schedule: dict) -> None:
    """Called after the report job finishes. Sends email if recipients configured."""
    from app import jobs
    job = jobs.get(job_id, {})
    if job.get("status") != "done":
        logger.warning("Scheduled job %s did not complete successfully — no email sent.", job_id[:8])
        return

    recipients_str = schedule.get("email_recipients", "")
    if not recipients_str:
        return

    recipients = [r.strip() for r in recipients_str.split(",") if r.strip()]
    if not recipients:
        return

    _send_report_email(app, job_id, job, schedule, recipients)


def _send_report_email(app, job_id: str, job: dict, schedule: dict, recipients: list[str]) -> None:
    """Generate PDF + DOCX and email them as attachments."""
    if not SMTP_HOST:
        logger.warning("SMTP_HOST not configured — skipping scheduled report email.")
        return

    from export.pdf_export import generate_pdf
    from export.docx_export import generate_docx
    from app import _get_charts_bytes

    config = job.get("config", {})
    markdown = job.get("text", "")
    customer_name = config.get("customer_name", "Client")
    report_date = f"{config.get('start_date', '')} to {config.get('end_date', '')}"
    logo = config.get("customer_logo", "")
    logo_path = None
    if logo:
        import os as _os
        base = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        candidate = _os.path.join(base, logo)
        if _os.path.exists(candidate):
            logo_path = candidate

    charts = _get_charts_bytes(job)

    try:
        pdf_bytes = generate_pdf(markdown, customer_name, report_date, logo_path, charts)
    except Exception as e:
        logger.error("Scheduled email: PDF generation failed: %s", e)
        pdf_bytes = None

    try:
        docx_bytes = generate_docx(markdown, customer_name, report_date, logo_path, charts)
    except Exception as e:
        logger.error("Scheduled email: DOCX generation failed: %s", e)
        docx_bytes = None

    if not pdf_bytes and not docx_bytes:
        logger.error("Scheduled email: both PDF and DOCX generation failed — aborting email.")
        return

    # Build email
    subject = f"GSOC Monthly Report — {customer_name} ({report_date})"
    msg = MIMEMultipart()
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    body = (
        f"Please find attached the GSOC Monthly Report for {customer_name}.\n\n"
        f"Report period: {report_date}\n\n"
        "This is an automated report generated by the Logicalis GSOC Report Portal.\n\n"
        "Regards,\nLogicalis GSOC"
    )
    msg.attach(MIMEText(body, "plain"))

    safe_name = customer_name.lower().replace(" ", "-")

    if pdf_bytes:
        part = MIMEBase("application", "pdf")
        part.set_payload(pdf_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment",
                        filename=f"GSOC-Report-{safe_name}.pdf")
        msg.attach(part)

    if docx_bytes:
        part = MIMEBase("application", "vnd.openxmlformats-officedocument.wordprocessingml.document")
        part.set_payload(docx_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment",
                        filename=f"GSOC-Report-{safe_name}.docx")
        msg.attach(part)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if SMTP_USER and SMTP_PASS:
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_FROM, recipients, msg.as_string())
        logger.info("Scheduled report email sent to %s for job %s.", recipients, job_id[:8])
    except Exception as e:
        logger.error("Failed to send scheduled report email: %s", e)


def _load_customers(app) -> list:
    """Load customers from customers.json."""
    import json as _json
    customers_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "customers.json"
    )
    if not os.path.exists(customers_file):
        return []
    with open(customers_file, "r") as f:
        return _json.load(f)
