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
from tools.customers import (
    load_customers as _load_customers,
    save_customers as _save_customers,
    CUSTOMERS_FILE,
)
from tools.secrets import set_kv_secret

log = __import__("logging").getLogger(__name__)

admin_bp = Blueprint("admin", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOGOS_DIR = os.path.join(DATA_DIR, "logos")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")

os.makedirs(LOGOS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def _customer_secret_kv_name(customer_id: str) -> str:
    """Deterministic KV name for a customer's primary Sentinel client secret.

    Retained for backwards compatibility with single-workspace records. New
    multi-workspace records use :func:`_workspace_secret_kv_name` which
    namespaces by workspace slug.
    """
    return f"customer-{customer_id}-sentinel-client-secret"


def _workspace_secret_kv_name(customer_id: str, workspace_name: str, kind: str = "sentinel") -> str:
    """Deterministic KV name for a per-workspace client secret.

    ``customer-{cid}-{kind}-{workspace-slug}-secret`` — e.g.
    ``customer-logicalis-asia-sentinel-malaysia-secret``. Slugged so that
    workspace renames don't accidentally collide.
    """
    import re
    slug = re.sub(r"[^a-z0-9]+", "-", (workspace_name or "").lower()).strip("-") or "ws"
    return f"customer-{customer_id}-{kind}-{slug}-secret"


def _parse_workspaces_json(raw: str) -> list[dict]:
    """Parse and validate the ``sentinel_workspaces_json`` (or
    ``defender_workspaces_json``) form field.

    Accepts an empty/missing string and returns ``[]``. Strict-validates
    each element to be a dict with the required keys; raises ValueError
    on malformed input so the route returns 400 instead of silently
    persisting garbage.
    """
    if not raw or not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"workspaces JSON is malformed: {e}")
    if not isinstance(parsed, list):
        raise ValueError("workspaces JSON must be a list of workspace objects")
    out: list[dict] = []
    for i, w in enumerate(parsed):
        if not isinstance(w, dict):
            raise ValueError(f"workspaces[{i}] must be an object")
        out.append({
            "name":          (w.get("name") or "").strip() or f"Workspace {i + 1}",
            "workspace_id":  (w.get("workspace_id") or "").strip(),
            "tenant_id":     (w.get("tenant_id") or "").strip(),
            "client_id":     (w.get("client_id") or "").strip(),
            # client_secret is the raw value; keep it in-memory only until
            # we write to KV — it's never persisted on the customer record.
            "client_secret": w.get("client_secret") or "",
            # client_secret_kv_name on the input is optional; if present, the
            # caller is using the rotation-by-name path instead of providing
            # a raw secret. We preserve it verbatim.
            "client_secret_kv_name": (w.get("client_secret_kv_name") or "").strip(),
        })
    return out


def _persist_workspace_secrets(customer_id: str, workspaces: list[dict],
                               kind: str = "sentinel") -> list[dict]:
    """For each workspace dict with a non-empty client_secret, write the
    value to Key Vault and rewrite the dict to carry only the kv_name
    reference. Workspaces with an empty client_secret keep their existing
    client_secret_kv_name (rotation semantics: empty means "leave KV alone").

    Returns the cleaned list ready for persistence on the customer record.
    Raises RuntimeError on KV write failure so the calling route returns
    500 rather than silently storing dangling references.
    """
    cleaned: list[dict] = []
    for w in workspaces:
        secret = w.pop("client_secret", "")
        kv_name = w.get("client_secret_kv_name", "") or _workspace_secret_kv_name(
            customer_id, w.get("name", ""), kind=kind,
        )
        if secret:
            try:
                set_kv_secret(kv_name, secret)
            except Exception as e:
                log.error("Failed to write %s secret for %s/%s: %s",
                          kind, customer_id, w.get("name"), e)
                raise RuntimeError(
                    f"Could not save {kind} client secret to Key Vault: {e}"
                ) from e
        w["client_secret_kv_name"] = kv_name
        cleaned.append(w)
    return cleaned


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
    jira_request_type = request.form.get("jira_request_type", "Report an Incident").strip()
    jira_incident_issuetype = request.form.get("jira_incident_issuetype", "").strip()
    jira_service_request_issuetype = request.form.get("jira_service_request_issuetype", "").strip()
    jira_change_request_issuetype = request.form.get("jira_change_request_issuetype", "").strip()
    industry = request.form.get("industry", "").strip()
    sentinel_workspace_id = request.form.get("sentinel_workspace_id", "").strip()
    sentinel_tenant_id = request.form.get("sentinel_tenant_id", "").strip()
    sentinel_client_id = request.form.get("sentinel_client_id", "").strip()
    sentinel_client_secret = request.form.get("sentinel_client_secret", "").strip()
    # Multi-workspace input — JSON-encoded list of workspace objects. When
    # present and non-empty, takes precedence over the legacy 4 flat fields.
    sentinel_workspaces_json = request.form.get("sentinel_workspaces_json", "")
    defender_workspaces_json = request.form.get("defender_workspaces_json", "")
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

    # Resolve sentinel_workspaces list. Priority: JSON array (multi-workspace
    # form path) → legacy 4 flat fields (single-workspace fallback).
    try:
        sentinel_workspaces = _parse_workspaces_json(sentinel_workspaces_json)
        defender_workspaces = _parse_workspaces_json(defender_workspaces_json)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    kv_name = ""
    if sentinel_workspaces:
        try:
            sentinel_workspaces = _persist_workspace_secrets(cid, sentinel_workspaces, kind="sentinel")
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 500
    elif sentinel_client_secret or any([sentinel_workspace_id, sentinel_tenant_id, sentinel_client_id]):
        # Legacy single-workspace path — collapse into a one-element array
        # under the canonical schema. Operators upgrading the customer record
        # can keep using the existing single-row form fields; the multi-ws
        # editor is a superset.
        if sentinel_client_secret:
            kv_name = _customer_secret_kv_name(cid)
            try:
                set_kv_secret(kv_name, sentinel_client_secret)
            except Exception as e:
                log.error("Failed to write Sentinel client secret to KV for %s: %s", cid, e)
                return jsonify({"error": f"Could not save client secret to Key Vault: {e}"}), 500
        sentinel_workspaces = [{
            "name":          name or "Primary",
            "workspace_id":  sentinel_workspace_id,
            "tenant_id":     sentinel_tenant_id,
            "client_id":     sentinel_client_id,
            "client_secret_kv_name": kv_name,
        }]

    if defender_workspaces:
        try:
            defender_workspaces = _persist_workspace_secrets(cid, defender_workspaces, kind="defender")
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 500

    customer = {
        "id": cid,
        "name": name,
        "short_name": short_name,
        "jira_project_key": jira_project_key,
        "jira_request_type": jira_request_type or "Report an Incident",
        "jira_incident_issuetype": jira_incident_issuetype or "[System] Incident",
        "jira_service_request_issuetype": jira_service_request_issuetype or "Service Request",
        "jira_change_request_issuetype": jira_change_request_issuetype or "Change",
        "industry": industry,
        # Phase C — canonical multi-workspace fields. Empty list is OK; the
        # client will refuse to fetch but the record is still valid.
        "sentinel_workspaces": sentinel_workspaces,
        "defender_workspaces": defender_workspaces,
        # Legacy flat fields kept on the record for backwards-compat with
        # any out-of-tree consumers reading customers.json. The normalize
        # layer in tools/customers.py treats sentinel_workspaces as
        # authoritative when present.
        "sentinel_workspace_id": sentinel_workspace_id,
        "sentinel_tenant_id": sentinel_tenant_id,
        "sentinel_client_id": sentinel_client_id,
        "sentinel_client_secret_kv_name": kv_name,
        "logo": logo_path,
        "default_sections": default_sections or [
            "introduction", "incident_overview", "incident_severity",
            "incident_status", "incident_details",
            "service_requests", "change_requests",
            "pending_tickets", "monitoring_scope", "recommendations",
            "industry_threat_intel"
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
        jira_request_type_val = request.form.get("jira_request_type", None)
        if jira_request_type_val is not None:
            customer["jira_request_type"] = jira_request_type_val.strip() or "Report an Incident"
        incident_issuetype_val = request.form.get("jira_incident_issuetype", None)
        if incident_issuetype_val is not None:
            customer["jira_incident_issuetype"] = incident_issuetype_val.strip() or "[System] Incident"
        sr_issuetype_val = request.form.get("jira_service_request_issuetype", None)
        if sr_issuetype_val is not None:
            customer["jira_service_request_issuetype"] = sr_issuetype_val.strip() or "Service Request"
        cr_issuetype_val = request.form.get("jira_change_request_issuetype", None)
        if cr_issuetype_val is not None:
            customer["jira_change_request_issuetype"] = cr_issuetype_val.strip() or "Change"
        industry_val = request.form.get("industry", None)
        if industry_val is not None:
            customer["industry"] = industry_val.strip()
        sentinel_workspace_id_val = request.form.get("sentinel_workspace_id", None)
        if sentinel_workspace_id_val is not None:
            customer["sentinel_workspace_id"] = sentinel_workspace_id_val.strip()
        sentinel_tenant_id_val = request.form.get("sentinel_tenant_id", None)
        if sentinel_tenant_id_val is not None:
            customer["sentinel_tenant_id"] = sentinel_tenant_id_val.strip()
        sentinel_client_id_val = request.form.get("sentinel_client_id", None)
        if sentinel_client_id_val is not None:
            customer["sentinel_client_id"] = sentinel_client_id_val.strip()
        # Client secret: rotation semantics — empty input means "leave KV value alone".
        # Non-empty input writes the new value to KV under a deterministic name and
        # records the reference on the customer record.
        sentinel_client_secret_val = request.form.get("sentinel_client_secret", "").strip()
        if sentinel_client_secret_val:
            kv_name = _customer_secret_kv_name(cid)
            try:
                set_kv_secret(kv_name, sentinel_client_secret_val)
            except Exception as e:
                log.error("Failed to update Sentinel client secret in KV for %s: %s", cid, e)
                return jsonify({"error": f"Could not save client secret to Key Vault: {e}"}), 500
            customer["sentinel_client_secret_kv_name"] = kv_name
        # Multi-workspace JSON path (form-data variant)
        sentinel_workspaces_json = request.form.get("sentinel_workspaces_json", "")
        defender_workspaces_json = request.form.get("defender_workspaces_json", "")
        if sentinel_workspaces_json:
            try:
                new_workspaces = _parse_workspaces_json(sentinel_workspaces_json)
                customer["sentinel_workspaces"] = _persist_workspace_secrets(
                    cid, new_workspaces, kind="sentinel",
                )
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
            except RuntimeError as e:
                return jsonify({"error": str(e)}), 500
        if defender_workspaces_json:
            try:
                new_d = _parse_workspaces_json(defender_workspaces_json)
                customer["defender_workspaces"] = _persist_workspace_secrets(
                    cid, new_d, kind="defender",
                )
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
            except RuntimeError as e:
                return jsonify({"error": str(e)}), 500
        if request.form.get("default_sections_submitted"):
            customer["default_sections"] = request.form.getlist("default_sections")
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
        for key in ("name", "short_name", "jira_project_key", "jira_request_type",
                    "jira_incident_issuetype",
                    "jira_service_request_issuetype", "jira_change_request_issuetype",
                    "industry", "sentinel_workspace_id", "sentinel_tenant_id",
                    "sentinel_client_id", "default_sections"):
            if key in data:
                customer[key] = data[key]
        # JSON path also supports rotating the secret. The KV reference name is
        # derived deterministically — clients only send the raw value.
        if "sentinel_client_secret" in data and data["sentinel_client_secret"]:
            kv_name = _customer_secret_kv_name(cid)
            try:
                set_kv_secret(kv_name, data["sentinel_client_secret"])
            except Exception as e:
                log.error("Failed to update Sentinel client secret in KV for %s: %s", cid, e)
                return jsonify({"error": f"Could not save client secret to Key Vault: {e}"}), 500
            customer["sentinel_client_secret_kv_name"] = kv_name

        # Multi-workspace JSON path: replaces sentinel_workspaces wholesale.
        # Callers wanting to add/remove one workspace should fetch the
        # current list, mutate, and PUT the full array — this matches the
        # "REST PUT" idempotent-replacement semantic.
        if "sentinel_workspaces" in data and isinstance(data["sentinel_workspaces"], list):
            try:
                new_workspaces = _parse_workspaces_json(json.dumps(data["sentinel_workspaces"]))
                customer["sentinel_workspaces"] = _persist_workspace_secrets(
                    cid, new_workspaces, kind="sentinel",
                )
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
            except RuntimeError as e:
                return jsonify({"error": str(e)}), 500
        if "defender_workspaces" in data and isinstance(data["defender_workspaces"], list):
            try:
                new_d = _parse_workspaces_json(json.dumps(data["defender_workspaces"]))
                customer["defender_workspaces"] = _persist_workspace_secrets(
                    cid, new_d, kind="defender",
                )
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
            except RuntimeError as e:
                return jsonify({"error": str(e)}), 500

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
        # Phase C — "merged" (single rollup) | "per_workspace" (N reports per
        # multi-workspace customer). Validated to those two values only.
        "aggregation_mode": (data.get("aggregation_mode") or "merged").strip()
            if (data.get("aggregation_mode") or "merged").strip() in ("merged", "per_workspace")
            else "merged",
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
                "use_sentinel", "use_splunk", "use_socradar", "email_recipients",
                "enabled", "aggregation_mode"):
        if key in data:
            existing[key] = data[key]
    # Normalise aggregation_mode to the two valid values.
    if existing.get("aggregation_mode") not in ("merged", "per_workspace"):
        existing["aggregation_mode"] = "merged"
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
