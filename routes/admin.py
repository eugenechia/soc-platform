"""
Admin blueprint — customers, schedules, report history.
"""
import os
import json
import uuid
import zipfile
from datetime import datetime
from io import BytesIO

from flask import Blueprint, render_template, session, request, jsonify, send_file

from routes.auth import require_login
import tools.db as db

log = __import__("logging").getLogger(__name__)

admin_bp = Blueprint("admin", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
CUSTOMERS_FILE = os.path.join(DATA_DIR, "customers.json")
LOGOS_DIR = os.path.join(DATA_DIR, "logos")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")

os.makedirs(LOGOS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


# ── Customer helpers ───────────────────────────────────────────────────────────

def _load_customers() -> list:
    if not os.path.exists(CUSTOMERS_FILE):
        return []
    with open(CUSTOMERS_FILE) as f:
        return json.load(f)


def _save_customers(customers: list):
    os.makedirs(os.path.dirname(CUSTOMERS_FILE), exist_ok=True)
    with open(CUSTOMERS_FILE, "w") as f:
        json.dump(customers, f, indent=2)


# ── Pages ──────────────────────────────────────────────────────────────────────

@admin_bp.route("/customers")
@require_login
def customers():
    return render_template("customers.html", user=session.get("user", {}), active_mode="admin")


@admin_bp.route("/history")
@require_login
def history():
    return render_template("history.html", user=session.get("user", {}), active_mode="history")


@admin_bp.route("/schedules")
@require_login
def schedules():
    return render_template("schedules.html", user=session.get("user", {}), active_mode="schedules")


# ── Logo serving ───────────────────────────────────────────────────────────────

@admin_bp.route("/data/logos/<filename>")
@require_login
def serve_logo(filename):
    from flask import send_from_directory
    return send_from_directory(LOGOS_DIR, filename)


# ── Customer API ───────────────────────────────────────────────────────────────

@admin_bp.route("/api/customers", methods=["GET"])
@require_login
def api_customers_list():
    return jsonify(_load_customers())


@admin_bp.route("/api/customers", methods=["POST"])
@require_login
def api_customers_create():
    name = request.form.get("name", "").strip()
    short_name = request.form.get("short_name", "").strip()
    jira_project_key = request.form.get("jira_project_key", "").strip()
    industry = request.form.get("industry", "").strip()
    default_sections = request.form.getlist("default_sections")

    if not name or not short_name:
        return jsonify({"error": "Name and short name are required."}), 400

    customers = _load_customers()
    cid = short_name.lower().replace(" ", "-")
    if any(c["id"] == cid for c in customers):
        return jsonify({"error": "A customer with this short name already exists."}), 409

    logo_path = ""
    logo_file = request.files.get("logo")
    if logo_file and logo_file.filename:
        ext = os.path.splitext(logo_file.filename)[1].lower()
        if ext not in (".png", ".jpg", ".jpeg", ".webp"):
            return jsonify({"error": "Logo must be PNG, JPG, or WebP."}), 400
        logo_filename = f"{cid}{ext}"
        logo_file.save(os.path.join(LOGOS_DIR, logo_filename))
        logo_path = f"data/logos/{logo_filename}"

    customer = {
        "id": cid,
        "name": name,
        "short_name": short_name,
        "jira_project_key": jira_project_key,
        "industry": industry,
        "logo": logo_path,
        "default_sections": default_sections or [
            "introduction", "incident_overview", "incident_severity",
            "incident_status", "incident_details", "pending_tickets",
            "monitoring_scope", "recommendations"
        ],
        "created_at": datetime.now().strftime("%Y-%m-%d"),
    }
    customers.append(customer)
    _save_customers(customers)
    return jsonify(customer), 201


@admin_bp.route("/api/customers/<cid>", methods=["PUT"])
@require_login
def api_customers_update(cid):
    customers = _load_customers()
    customer = next((c for c in customers if c["id"] == cid), None)
    if not customer:
        return jsonify({"error": "Customer not found."}), 404

    if request.content_type and "multipart/form-data" in request.content_type:
        for key in ("name", "short_name", "jira_project_key"):
            val = request.form.get(key, "").strip()
            if val:
                customer[key] = val
        industry_val = request.form.get("industry", None)
        if industry_val is not None:
            customer["industry"] = industry_val.strip()
        default_sections = request.form.getlist("default_sections")
        if default_sections:
            customer["default_sections"] = default_sections
        logo_file = request.files.get("logo")
        if logo_file and logo_file.filename:
            ext = os.path.splitext(logo_file.filename)[1].lower()
            if ext not in (".png", ".jpg", ".jpeg", ".webp"):
                return jsonify({"error": "Logo must be PNG, JPG, or WebP."}), 400
            logo_filename = f"{cid}{ext}"
            logo_file.save(os.path.join(LOGOS_DIR, logo_filename))
            customer["logo"] = f"data/logos/{logo_filename}"
    else:
        data = request.json or {}
        for key in ("name", "short_name", "jira_project_key", "industry", "default_sections"):
            if key in data:
                customer[key] = data[key]

    _save_customers(customers)
    return jsonify(customer)


@admin_bp.route("/api/customers/<cid>", methods=["DELETE"])
@require_login
def api_customers_delete(cid):
    customers = _load_customers()
    customer = next((c for c in customers if c["id"] == cid), None)
    if not customer:
        return jsonify({"error": "Customer not found."}), 404

    if customer.get("logo"):
        logo_full = os.path.join(BASE_DIR, customer["logo"])
        if os.path.exists(logo_full):
            os.remove(logo_full)

    _save_customers([c for c in customers if c["id"] != cid])
    return jsonify({"ok": True})


@admin_bp.route("/api/customers/export")
@require_login
def api_customers_export():
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(CUSTOMERS_FILE):
            zf.write(CUSTOMERS_FILE, "customers.json")
        if os.path.exists(LOGOS_DIR):
            for fname in os.listdir(LOGOS_DIR):
                fpath = os.path.join(LOGOS_DIR, fname)
                if os.path.isfile(fpath):
                    zf.write(fpath, f"logos/{fname}")
        if os.path.exists(REPORTS_DIR):
            for fname in os.listdir(REPORTS_DIR):
                if fname.endswith(".json"):
                    zf.write(os.path.join(REPORTS_DIR, fname), f"reports/{fname}")
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name="soc-platform-backup.zip")


@admin_bp.route("/api/customers/import", methods=["POST"])
@require_login
def api_customers_import():
    zfile = request.files.get("backup")
    if not zfile:
        return jsonify({"error": "No backup file provided."}), 400

    buf = BytesIO(zfile.read())
    with zipfile.ZipFile(buf, "r") as zf:
        names = zf.namelist()
        if "customers.json" in names:
            with zf.open("customers.json") as f:
                _save_customers(json.load(f))
        for name in names:
            if name.startswith("logos/") and not name.endswith("/"):
                target = os.path.join(LOGOS_DIR, os.path.basename(name))
                with zf.open(name) as src, open(target, "wb") as dst:
                    dst.write(src.read())
            if name.startswith("reports/") and name.endswith(".json"):
                target = os.path.join(REPORTS_DIR, os.path.basename(name))
                with zf.open(name) as src, open(target, "wb") as dst:
                    dst.write(src.read())

    from routes.reports import _load_reports_list
    return jsonify({"ok": True, "customers": len(_load_customers()),
                    "reports": len(_load_reports_list())})


# ── Schedule API ───────────────────────────────────────────────────────────────

@admin_bp.route("/api/schedules", methods=["GET"])
@require_login
def api_schedules_list():
    return jsonify(db.load_schedules())


@admin_bp.route("/api/schedules", methods=["POST"])
@require_login
def api_schedules_create():
    data = request.json or {}
    customer_id = data.get("customer_id", "").strip()
    if not customer_id:
        return jsonify({"error": "customer_id is required."}), 400

    schedule = {
        "id": str(uuid.uuid4()),
        "customer_id": customer_id,
        "frequency": data.get("frequency", "monthly"),
        "day_of_month": data.get("day_of_month", 1),
        "day_of_week": data.get("day_of_week"),
        "sections": data.get("sections", []),
        "use_sentinel": bool(data.get("use_sentinel", False)),
        "use_splunk": bool(data.get("use_splunk", False)),
        "use_socradar": bool(data.get("use_socradar", False)),
        "email_recipients": data.get("email_recipients", ""),
        "enabled": bool(data.get("enabled", True)),
        "last_run": None,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    db.save_schedule(schedule)
    return jsonify(schedule), 201


@admin_bp.route("/api/schedules/<schedule_id>", methods=["PUT"])
@require_login
def api_schedules_update(schedule_id):
    existing = db.load_schedule(schedule_id)
    if not existing:
        return jsonify({"error": "Schedule not found."}), 404
    data = request.json or {}
    for key in ("frequency", "day_of_month", "day_of_week", "sections",
                "use_sentinel", "use_splunk", "use_socradar", "email_recipients", "enabled"):
        if key in data:
            existing[key] = data[key]
    db.save_schedule(existing)
    return jsonify(existing)


@admin_bp.route("/api/schedules/<schedule_id>", methods=["DELETE"])
@require_login
def api_schedules_delete(schedule_id):
    if not db.load_schedule(schedule_id):
        return jsonify({"error": "Schedule not found."}), 404
    db.delete_schedule(schedule_id)
    return jsonify({"ok": True})


@admin_bp.route("/api/schedules/<schedule_id>/run-now", methods=["POST"])
@require_login
def api_schedules_run_now(schedule_id):
    schedule = db.load_schedule(schedule_id)
    if not schedule:
        return jsonify({"error": "Schedule not found."}), 404
    from tools.scheduler import _fire_schedule
    from flask import current_app
    _fire_schedule(current_app._get_current_object(), schedule, datetime.now())
    return jsonify({"ok": True, "message": "Schedule fired manually."})


# ── Migration helper ───────────────────────────────────────────────────────────

@admin_bp.route("/api/migrate", methods=["POST"])
@require_login
def api_migrate():
    try:
        count = db.migrate_from_json()
        return jsonify({"ok": True, "imported": count})
    except Exception as e:
        log.error(f"Migration failed: {e}")
        return jsonify({"error": str(e)}), 500
