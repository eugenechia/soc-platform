"""
Admin blueprint — customers, schedules, report history.
"""
import os
import re
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
                               kind: str = "sentinel",
                               secret_field: str = "client_secret",
                               kv_field: str = "client_secret_kv_name") -> list[dict]:
    """For each entry with a non-empty secret, write the value to Key Vault
    and rewrite the dict to carry only the kv_name reference. Entries with
    an empty secret keep their existing kv_name (rotation semantics: empty
    means "leave KV alone").

    ``secret_field`` / ``kv_field`` let this function serve both the
    Sentinel/Defender workspace flow (``client_secret`` /
    ``client_secret_kv_name``) and the multi-Jira-project flow
    (``api_token`` / ``api_token_kv_name``). The KV name is derived
    deterministically via :func:`_workspace_secret_kv_name` which already
    accepts a ``kind`` discriminator.

    Returns the cleaned list ready for persistence on the customer record.
    Raises RuntimeError on KV write failure so the calling route returns
    500 rather than silently storing dangling references.
    """
    cleaned: list[dict] = []
    for w in workspaces:
        secret = w.pop(secret_field, "")
        kv_name = w.get(kv_field, "") or _workspace_secret_kv_name(
            customer_id, w.get("name", ""), kind=kind,
        )
        if secret:
            try:
                set_kv_secret(kv_name, secret)
            except Exception as e:
                log.error("Failed to write %s secret for %s/%s: %s",
                          kind, customer_id, w.get("name"), e)
                raise RuntimeError(
                    f"Could not save {kind} {secret_field} to Key Vault: {e}"
                ) from e
        w[kv_field] = kv_name
        cleaned.append(w)
    return cleaned


def _parse_jira_projects_json(raw: str) -> list[dict]:
    """Parse and validate the ``jira_projects_json`` form field. Returns
    [] on empty input; raises ValueError on malformed JSON or missing
    required keys (``name`` + ``project_key``).

    Optional fields: ``base_url`` / ``email`` / ``api_token`` /
    ``api_token_kv_name``. Blank values trigger env-var fallback in
    :func:`tools.jira_client._resolve_jira_auth` so single-instance
    multi-project customers (the common case) need only fill in
    ``name`` + ``project_key``.
    """
    if not raw or not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"jira_projects JSON is malformed: {e}")
    if not isinstance(parsed, list):
        raise ValueError("jira_projects JSON must be a list of project objects")
    out: list[dict] = []
    for i, p in enumerate(parsed):
        if not isinstance(p, dict):
            raise ValueError(f"jira_projects[{i}] must be an object")
        proj_key = (p.get("project_key") or "").strip()
        if not proj_key:
            raise ValueError(f"jira_projects[{i}] missing required 'project_key'")
        out.append({
            "name":              (p.get("name") or "").strip() or f"Project {i + 1}",
            "project_key":       proj_key,
            "base_url":          (p.get("base_url") or "").strip(),
            "email":             (p.get("email") or "").strip(),
            # api_token is the raw value; kept in-memory only until we
            # write to KV — never persisted on the customer record.
            "api_token":         p.get("api_token") or "",
            "api_token_kv_name": (p.get("api_token_kv_name") or "").strip(),
        })
    return out


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


# ── Phase 4: RAG knowledge store admin ───────────────────────────────────────

@admin_bp.route("/rag")
@require_login
def rag_page():
    """Lightweight admin page for the Phase 4 RAG store. Shows chunk count
    + persist dir + a re-ingest button. JSON API below does the actual work
    so this page is a thin HTML wrapper."""
    from tools.rag_store import collection_stats
    stats = collection_stats()
    docs_dir = os.environ.get("RAG_DOCS_DIR", "/app/data/rag_docs")
    enabled = os.environ.get("RAG_LOOKUP_ENABLED", "false").strip().lower() == "true"
    return render_template(
        "rag.html",
        user=session.get("user", {}),
        active_mode="admin",
        stats=stats,
        docs_dir=docs_dir,
        enabled=enabled,
    )


@admin_bp.route("/api/rag/stats", methods=["GET"])
@require_login
def api_rag_stats():
    from tools.rag_store import collection_stats
    return jsonify(collection_stats())


@admin_bp.route("/api/rag/reingest", methods=["POST"])
@require_login
def api_rag_reingest():
    """Trigger a synchronous re-ingest of RAG_DOCS_DIR. Returns the summary
    dict. Body may include {"source": "<bucket>", "dry_run": false}.
    Synchronous because the dataset is small (analyst-authored markdown);
    if it ever becomes too slow we can move to a background thread the same
    way enrichment is queued."""
    from tools.rag_ingest import ingest
    payload = request.get_json(silent=True) or {}
    source = (payload.get("source") or "").strip() or None
    dry_run = bool(payload.get("dry_run", False))
    try:
        summary = ingest(source_filter=source, dry_run=dry_run)
        return jsonify({"status": "ok", "summary": summary})
    except Exception as e:
        log.exception("RAG re-ingest failed: %s", e)
        return jsonify({"status": "error", "error": f"{type(e).__name__}: {e}"}), 500


# ── Phase 4b-rev: per-customer Confluence sources ────────────────────────────
# Confluence pages now live on the customer record (under `confluence_pages`).
# The /admin/rag page no longer has a global Confluence card — manage pages
# from the customer Edit modal at /admin/customers.

@admin_bp.route("/api/customers/<cid>/confluence/pages", methods=["GET"])
@require_login
def api_customer_confluence_pages_list(cid: str):
    from tools.rag_confluence_ingest import load_pages_for_customer
    from tools.customers import get_customer
    if not get_customer(cid):
        return jsonify({"status": "error", "error": "customer not found"}), 404
    return jsonify({"pages": load_pages_for_customer(cid)})


@admin_bp.route("/api/customers/<cid>/confluence/pages", methods=["POST"])
@require_login
def api_customer_confluence_pages_add(cid: str):
    """Register a Confluence page on a customer. Body: {"url": "..."}.
    Fetches title + space from Confluence so the table can show real metadata."""
    from tools.rag_confluence_ingest import add_page
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"status": "error", "error": "url is required"}), 400
    result = add_page(cid, url)
    if "error" in result:
        status = 404 if "not found" in result["error"] else 400
        return jsonify({"status": "error", "error": result["error"]}), status
    return jsonify({"status": "ok", "entry": result})


@admin_bp.route("/api/customers/<cid>/confluence/pages/<page_id>", methods=["DELETE"])
@require_login
def api_customer_confluence_pages_remove(cid: str, page_id: str):
    from tools.rag_confluence_ingest import remove_page
    removed = remove_page(cid, page_id)
    if not removed:
        return jsonify({"status": "error", "error": "page not found"}), 404
    return jsonify({"status": "ok", "removed": page_id})


@admin_bp.route("/api/customers/<cid>/confluence/sync", methods=["POST"])
@require_login
def api_customer_confluence_sync(cid: str):
    """Sync every Confluence page registered on this customer. Synchronous;
    returns the summary so the UI can refresh without a second round-trip."""
    from tools.rag_confluence_ingest import sync_for_customer
    try:
        summary = sync_for_customer(cid)
        if "error" in summary:
            return jsonify({"status": "error", "error": summary["error"]}), 404
        return jsonify({"status": "ok", "summary": summary})
    except Exception as e:
        log.exception("Confluence sync for customer=%s failed: %s", cid, e)
        return jsonify({"status": "error", "error": f"{type(e).__name__}: {e}"}), 500


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
    org_profile = request.form.get("org_profile", "").strip()
    sentinel_workspace_id = request.form.get("sentinel_workspace_id", "").strip()
    sentinel_tenant_id = request.form.get("sentinel_tenant_id", "").strip()
    sentinel_client_id = request.form.get("sentinel_client_id", "").strip()
    sentinel_client_secret = request.form.get("sentinel_client_secret", "").strip()
    # Multi-workspace input — JSON-encoded list of workspace objects. When
    # present and non-empty, takes precedence over the legacy 4 flat fields.
    sentinel_workspaces_json = request.form.get("sentinel_workspaces_json", "")
    defender_workspaces_json = request.form.get("defender_workspaces_json", "")
    # Multi-Jira-project input — same pattern as workspaces. When non-empty
    # the wrapped list replaces the legacy single jira_project_key field.
    jira_projects_json = request.form.get("jira_projects_json", "")
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
        jira_projects = _parse_jira_projects_json(jira_projects_json)
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

    if jira_projects:
        try:
            jira_projects = _persist_workspace_secrets(
                cid, jira_projects, kind="jira",
                secret_field="api_token", kv_field="api_token_kv_name",
            )
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
        "org_profile": org_profile,
        # Phase C — canonical multi-workspace fields. Empty list is OK; the
        # client will refuse to fetch but the record is still valid.
        "sentinel_workspaces": sentinel_workspaces,
        "defender_workspaces": defender_workspaces,
        # Multi-Jira-project field. When empty, _normalize_customer auto-wraps
        # the legacy jira_project_key above into a single-element list at
        # load time.
        "jira_projects": jira_projects,
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
            "pending_tickets", "monitoring_scope",
            "trends_insights", "recommendations", "posture_improvements",
            "appendix",
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
        org_profile_val = request.form.get("org_profile", None)
        if org_profile_val is not None:
            customer["org_profile"] = org_profile_val.strip()
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
        jira_projects_json = request.form.get("jira_projects_json", "")
        if jira_projects_json:
            try:
                new_projects = _parse_jira_projects_json(jira_projects_json)
                customer["jira_projects"] = _persist_workspace_secrets(
                    cid, new_projects, kind="jira",
                    secret_field="api_token", kv_field="api_token_kv_name",
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
        if "jira_projects" in data and isinstance(data["jira_projects"], list):
            try:
                new_projects = _parse_jira_projects_json(json.dumps(data["jira_projects"]))
                customer["jira_projects"] = _persist_workspace_secrets(
                    cid, new_projects, kind="jira",
                    secret_field="api_token", kv_field="api_token_kv_name",
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
        "use_jira": bool(data.get("use_jira", True)),
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
                "use_jira", "use_sentinel", "use_splunk", "use_socradar",
                "email_recipients", "enabled", "aggregation_mode"):
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


# ── Advisory feeds (§1.15 Threat Analytics + §1.17 IOC Update + Critical CVEs) ──
#
# Per-customer advisory JSON files live in `data/{customer-slug}/`. Until this
# admin UI existed, analysts had to edit those files directly on the Azure
# Files share via Storage Explorer / portal. This blueprint gives them a
# proper CRUD surface so the data-entry workflow doesn't depend on knowing
# the filesystem layout. Both advisory types are managed in one place because
# they typically get updated together at the end of each reporting period.

from tools.customer_advisories import (
    customer_slug as _customer_slug,
    load_threat_analytics_advisories,
    load_ioc_advisories,
)


def _advisory_dir(customer_name: str) -> str | None:
    slug = _customer_slug(customer_name)
    if not slug:
        return None
    return os.path.join(DATA_DIR, slug)


def _read_advisory_file(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Failed to read advisory file %s: %s", path, exc)
        return []


def _write_advisory_file(path: str, rows: list) -> None:
    """Atomically write rows to path as a pretty-printed JSON list.

    Atomic = write to .tmp then rename. Prevents a half-written file if the
    container is killed mid-write; Azure Files honours rename as a metadata
    op so the swap is observed atomically by anything reading the canonical
    path.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


_THREAT_ANALYTICS_FIELDS = ("threat", "report_type", "published", "hunting_result")
_IOC_FIELDS = ("advisory", "date", "hunt_outcome")


def _coerce_threat_analytics_row(row: dict) -> dict | None:
    if not isinstance(row, dict):
        return None
    threat = (row.get("threat") or "").strip()
    if not threat:
        return None  # threat name is the only required field
    return {
        "threat": threat,
        "report_type": (row.get("report_type") or "").strip(),
        "published": (row.get("published") or "").strip(),
        "hunting_result": (row.get("hunting_result") or "").strip(),
    }


def _coerce_ioc_row(row: dict) -> dict | None:
    if not isinstance(row, dict):
        return None
    advisory = (row.get("advisory") or "").strip()
    if not advisory:
        return None
    return {
        "advisory": advisory,
        "date": (row.get("date") or "").strip(),
        "hunt_outcome": (row.get("hunt_outcome") or "").strip(),
    }


@admin_bp.route("/advisories")
@require_login
def advisories_page():
    return render_template("advisories.html", active_mode="advisories")


@admin_bp.route("/api/advisories")
@require_login
def api_advisories_list():
    """Return every customer plus row counts for both advisory types so the
    admin landing page can show "5 threat analytics, 2 IOC" badges without
    requiring N round-trips."""
    customers = _load_customers()
    out = []
    for c in customers:
        name = c.get("name", "")
        d = _advisory_dir(name)
        ta_count = ioc_count = 0
        if d:
            ta_count = len(_read_advisory_file(os.path.join(d, "threat_analytics_advisories.json")))
            ioc_count = len(_read_advisory_file(os.path.join(d, "ioc_advisories.json")))
        out.append({
            "id": c.get("id", ""),
            "name": name,
            "short_name": c.get("short_name", ""),
            "slug": _customer_slug(name),
            "threat_analytics_count": ta_count,
            "ioc_count": ioc_count,
        })
    return jsonify(out)


@admin_bp.route("/api/advisories/<customer_id>")
@require_login
def api_advisories_get(customer_id):
    """Return both advisory lists for a single customer. Empty lists when the
    files don't exist yet (customer never had an advisory entered)."""
    customer = next((c for c in _load_customers() if c.get("id") == customer_id), None)
    if not customer:
        return jsonify({"error": "Customer not found."}), 404
    d = _advisory_dir(customer.get("name", ""))
    if not d:
        return jsonify({"error": "Customer has no resolvable slug."}), 400
    return jsonify({
        "customer_id": customer_id,
        "customer_name": customer.get("name", ""),
        "slug": _customer_slug(customer.get("name", "")),
        "threat_analytics": _read_advisory_file(os.path.join(d, "threat_analytics_advisories.json")),
        "ioc": _read_advisory_file(os.path.join(d, "ioc_advisories.json")),
    })


@admin_bp.route("/api/advisories/<customer_id>/upload", methods=["POST"])
@require_login
def api_advisories_upload(customer_id):
    """Accept a single uploaded file (.msg / .eml / .pdf / .docx / .txt /
    .html / .md), persist it under data/{slug}/uploads/, extract text, run
    the LLM extractor, and return the candidate advisory rows for the
    analyst to review in the modal.

    The persisted file gives an audit trail — if the AI misses something the
    analyst can re-open the source. The rows are NOT added to the advisory
    file here; the frontend gets the candidates, the analyst confirms what
    to keep, then triggers the existing PUT /api/advisories/<id> to save.
    """
    from tools.advisory_extractor import (
        SUPPORTED_EXTENSIONS, is_supported, extract_text,
        extract_advisories_with_ai,
    )

    customer = next((c for c in _load_customers() if c.get("id") == customer_id), None)
    if not customer:
        return jsonify({"error": "Customer not found."}), 404
    d = _advisory_dir(customer.get("name", ""))
    if not d:
        return jsonify({"error": "Customer has no resolvable slug."}), 400

    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify({"error": "No file uploaded."}), 400
    filename = upload.filename
    if not is_supported(filename):
        return jsonify({
            "error": (
                f"Unsupported file type. Allowed: "
                f"{', '.join(sorted('.' + ext for ext in SUPPORTED_EXTENSIONS))}"
            ),
        }), 400

    data = upload.read()
    if not data:
        return jsonify({"error": "Uploaded file is empty."}), 400
    # 25 MB hard cap. A typical advisory PDF is ~500 KB; .msg with embedded
    # images can be a few MB. 25 MB catches the absurd-mistake bucket
    # (someone uploaded a backup zip) without hurting legitimate use.
    if len(data) > 25 * 1024 * 1024:
        return jsonify({"error": "File exceeds 25 MB limit."}), 400

    # Persist the original under data/{slug}/uploads/{timestamp}-{safename}
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", filename)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    uploads_dir = os.path.join(d, "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    saved_path = os.path.join(uploads_dir, f"{timestamp}-{safe_name}")
    try:
        with open(saved_path, "wb") as f:
            f.write(data)
    except OSError as exc:
        log.error("Failed to persist uploaded file %s: %s", saved_path, exc)
        # Non-fatal — keep going so the user at least gets extraction
        # results even if the audit-trail copy didn't save.
        saved_path = None

    # Extract text + run AI extractor.
    try:
        text = extract_text(data, filename)
    except Exception as exc:
        log.error("Text extraction failed for %s: %s", filename, exc, exc_info=True)
        return jsonify({"error": f"Could not extract text from file: {exc}"}), 422

    if not text.strip():
        return jsonify({
            "ok": True,
            "filename": filename,
            "stored_at": os.path.basename(saved_path) if saved_path else None,
            "extracted_text_length": 0,
            "candidates": [],
            "warning": "No text was extracted from the file.",
        })

    candidates = extract_advisories_with_ai(text)
    return jsonify({
        "ok": True,
        "filename": filename,
        "stored_at": os.path.basename(saved_path) if saved_path else None,
        "extracted_text_length": len(text),
        "candidates": candidates,
    })


@admin_bp.route("/api/advisories/<customer_id>", methods=["PUT"])
@require_login
def api_advisories_save(customer_id):
    """Replace both advisory lists for a customer.

    The frontend always sends the full state of both tables. Server validates
    + coerces (drops rows missing the required primary field) and writes
    atomically. Returns the cleaned payload so the UI can reflect any rows
    that were dropped server-side.
    """
    customer = next((c for c in _load_customers() if c.get("id") == customer_id), None)
    if not customer:
        return jsonify({"error": "Customer not found."}), 404
    d = _advisory_dir(customer.get("name", ""))
    if not d:
        return jsonify({"error": "Customer has no resolvable slug."}), 400

    body = request.get_json(silent=True) or {}
    ta_raw = body.get("threat_analytics") or []
    ioc_raw = body.get("ioc") or []
    if not isinstance(ta_raw, list) or not isinstance(ioc_raw, list):
        return jsonify({"error": "threat_analytics and ioc must be arrays."}), 400

    ta_clean = [r for r in (_coerce_threat_analytics_row(r) for r in ta_raw) if r]
    ioc_clean = [r for r in (_coerce_ioc_row(r) for r in ioc_raw) if r]

    try:
        _write_advisory_file(os.path.join(d, "threat_analytics_advisories.json"), ta_clean)
        _write_advisory_file(os.path.join(d, "ioc_advisories.json"), ioc_clean)
    except Exception as e:
        log.error("Advisory save failed for customer %s: %s", customer_id, e)
        return jsonify({"error": f"Save failed: {e}"}), 500

    return jsonify({
        "ok": True,
        "threat_analytics": ta_clean,
        "ioc": ioc_clean,
        "dropped_threat_analytics": len(ta_raw) - len(ta_clean),
        "dropped_ioc": len(ioc_raw) - len(ioc_clean),
    })


# ── Backup status + manual trigger (D1, 2026-06-16) ─────────────────────────

@admin_bp.route("/api/backup/status", methods=["GET"])
@require_login
def api_backup_status():
    """Return last/next backup timestamps + file counts for the UI freshness pill."""
    from tools import backup as _backup
    return jsonify(_backup.backup_status())


@admin_bp.route("/api/backup/run-now", methods=["POST"])
@require_login
def api_backup_run_now():
    """Trigger a manual backup. Rate-limited to once per 5 minutes."""
    from tools import backup as _backup
    return jsonify(_backup.run_nightly_backup(manual=True))
