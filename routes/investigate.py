"""
Investigate mode — interactive streaming LLM with SOCRadar MCP + Tavily tools.

Ported from SOCRadar AI Analyst's app.py, with ONE critical behavioural change:
OAuth state (client_id, code_verifier, access_token) is stored per-user in
session["socradar"], not in a module-level dict. This is the fix for the
multi-user bug where all concurrent users shared one SOCRadar token.

Routes exposed under /investigate/*:
  GET  /                    the Investigate UI
  POST /query               kick off a streaming LLM job
  GET  /query-poll/<jid>    poll for job text / status
  GET  /oauth/start         begin SOCRadar MCP OAuth (per-user PKCE)
  GET  /oauth/callback      exchange auth code for access token
  GET  /oauth/logout        revoke this user's SOCRadar session
  GET  /auth-status         JSON: is this user authed to SOCRadar?
"""
import base64
import hashlib
import logging
import secrets as pysecrets
import threading
import uuid
from urllib.parse import urlencode

import httpx
from flask import Blueprint, jsonify, redirect, render_template, request, session

import os

from routes.auth import require_login
from tools.secrets import get_secret
from tools.socradar_mcp import build_mcp_tools, register_dynamic_client
from tools.tavily_client import fetch_web_context

log = logging.getLogger(__name__)

investigate_bp = Blueprint("investigate", __name__)

_INVESTIGATE_MODEL = os.environ.get("INVESTIGATE_MODEL", "gpt-5.2")

# Investigate jobs live in-process. Single-replica Container App means this is
# acceptable; we just accept that jobs in flight during a restart are lost.
_jobs: dict[str, dict] = {}
_JOB_TIMEOUT = 300  # 5 minutes


# ── System prompt + templates (lifted verbatim from SOCRadar app) ──────────────

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst with access to SOCRadar threat intelligence via MCP tools, plus optional web intelligence context.

Guidelines:
- For entity-specific queries (IP, domain, CVE, email, company name), use SOCRadar tools. They are authoritative for these lookups.
- For broad threat landscape questions (threat actor profiles, regional trends, TTP/IOC surveys): if Web Intelligence Context is provided in the message, synthesise EXCLUSIVELY from that context — do NOT call any SOCRadar tools. If no web context is provided, make at most 2 SOCRadar tool calls and summarise concisely.
- Never fabricate threat intelligence. Only report what tools or provided context explicitly confirms.
- Structure responses with sections: Summary, Findings, Risk Assessment, Recommendations."""

PROMPT_TEMPLATES = {
    "check_ip":             {"prompt": "Investigate IP address {entity} using SOCRadar. Check reputation, geolocation, associated threats, and IOC history.", "needs_entity": True},
    "lookup_cve":           {"prompt": "Look up vulnerability {entity} via SOCRadar. Retrieve CVSS, EPSS, affected products, exploit availability, threat actor links, and remediations.", "needs_entity": True},
    "investigate_domain":   {"prompt": "Investigate domain {entity} via SOCRadar. Check for phishing, malware hosting, reputation, WHOIS, DNS, SSL, and threat actor activity.", "needs_entity": True},
    "credential_exposure":  {"prompt": "Check credential exposures linked to {entity} via SOCRadar. Search breach data, stealer logs, and dark web for compromised accounts.", "needs_entity": True},
    "ransomware_check":     {"prompt": "Check ransomware activity related to {entity}. Retrieve victim lists, active groups targeting this sector, IOCs, and current threat level.", "needs_entity": True},
    "open_incidents":       {"prompt": "List all currently open SOCRadar security incidents for my organisation with severity, status, and summary.", "needs_entity": False},
    "digital_footprint":    {"prompt": "Provide a comprehensive digital footprint summary for my organisation via SOCRadar: assets, risk scores, exposures.", "needs_entity": False},
    "impersonating_domains":{"prompt": "Find all domains impersonating my organisation's brand via SOCRadar. Include status, detection source, and recommended action.", "needs_entity": False},
}


# ── Page ────────────────────────────────────────────────────────────────────────

@investigate_bp.route("/")
@require_login
def index():
    # embed=1: rendered inside the L2 dashboard's chat panel iframe — the
    # template hides its own page header (the dashboard provides the chrome).
    return render_template("investigate.html", user=session.get("user", {}),
                           embed=request.args.get("embed") == "1")


# ── Query endpoints ─────────────────────────────────────────────────────────────

@investigate_bp.route("/query", methods=["POST"])
@require_login
def query():
    socradar = session.get("socradar") or {}
    if not socradar.get("access_token"):
        return jsonify({"error": "Not authenticated to SOCRadar. Connect first."}), 401

    data = request.get_json() or {}
    entity = (data.get("entity") or "").strip()
    template = (data.get("template") or "").strip()
    freeform = (data.get("freeform") or "").strip()

    if template and template in PROMPT_TEMPLATES:
        cfg = PROMPT_TEMPLATES[template]
        if cfg["needs_entity"] and not entity:
            return jsonify({"error": "An entity (IP, domain, email, CVE, or company name) is required."}), 400
        user_message = cfg["prompt"].format(entity=entity) if cfg["needs_entity"] else cfg["prompt"]
    elif freeform:
        user_message = freeform
        web_ctx = fetch_web_context(freeform)
        if web_ctx:
            user_message = f"{web_ctx}\nUser Query: {freeform}"
    else:
        return jsonify({"error": "No valid query provided."}), 400

    mcp_tools = build_mcp_tools(socradar["access_token"])

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "running", "text": "", "error": None, "user": session["user"]["email"]}
    threading.Thread(
        target=_run_streaming_job,
        args=(job_id, user_message, mcp_tools),
        daemon=True,
    ).start()
    log.info("Investigate job %s started for %s", job_id[:8], session["user"]["email"])
    return jsonify({"job_id": job_id})


@investigate_bp.route("/query-poll/<job_id>")
@require_login
def query_poll(job_id):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job."}), 404
    # Scope jobs to the user who created them — prevents cross-user leakage
    if job.get("user") != session["user"]["email"]:
        return jsonify({"error": "Forbidden."}), 403
    return jsonify({
        "status": job["status"],
        "text":   job["text"],
        "error":  job["error"],
    })


def _run_streaming_job(job_id: str, user_message: str, mcp_tools: list) -> None:
    """Background streaming call to OpenAI Responses API with SOCRadar MCP tools."""
    from openai import OpenAI

    def _timeout():
        j = _jobs.get(job_id)
        if j and j["status"] == "running":
            j["status"] = "error"
            j["error"] = "Request timed out after 5 minutes."
            log.warning("Job %s timed out", job_id[:8])

    timer = threading.Timer(_JOB_TIMEOUT, _timeout)
    timer.daemon = True
    timer.start()

    try:
        client = OpenAI(api_key=get_secret("OPENAI_API_KEY"))
        stream = client.responses.create(
            model=_INVESTIGATE_MODEL,
            instructions=SYSTEM_PROMPT,
            input=[{"role": "user", "content": user_message}],
            tools=mcp_tools,
            stream=True,
        )
        for event in stream:
            if _jobs[job_id]["status"] != "running":
                break
            if event.type == "response.output_text.delta":
                _jobs[job_id]["text"] += event.delta
        if _jobs[job_id]["status"] == "running":
            _jobs[job_id]["status"] = "done"
            log.info("Job %s done, %d chars", job_id[:8], len(_jobs[job_id]["text"]))
    except Exception as e:
        log.exception("Job %s failed", job_id[:8])
        if _jobs[job_id]["status"] == "running":
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(e)
    finally:
        timer.cancel()


# ── SOCRadar MCP OAuth (per-user) ───────────────────────────────────────────────
# All per-user state lives in session["socradar"]; nothing at module level.

@investigate_bp.route("/oauth/start")
@require_login
def oauth_start():
    socradar = session.setdefault("socradar", {})

    if not socradar.get("client_id"):
        try:
            socradar["client_id"] = register_dynamic_client()
        except Exception as e:
            log.error("SOCRadar dynamic client registration failed: %s", e)
            return f"Client registration failed: {e}", 500

    # PKCE: fresh verifier + state per OAuth start
    code_verifier = pysecrets.token_urlsafe(64)
    state = pysecrets.token_urlsafe(32)
    socradar["code_verifier"] = code_verifier
    socradar["state"] = state
    session["socradar"] = socradar  # ensure persistence (Flask session is copy-on-write)

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    mcp_base = get_secret("SOCRADAR_MCP_URL") or "https://mcp.socradar.com"
    params = {
        "client_id":             socradar["client_id"],
        "redirect_uri":          get_secret("SOCRADAR_REDIRECT_URI"),
        "response_type":         "code",
        "scope":                 "tools:read tools:execute",
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
        "state":                 state,
    }
    return redirect(f"{mcp_base.rstrip('/')}/authorize?{urlencode(params)}")


@investigate_bp.route("/oauth/callback")
@require_login
def oauth_callback():
    socradar = session.get("socradar") or {}

    if request.args.get("error"):
        return f"SOCRadar OAuth error: {request.args.get('error_description', request.args['error'])}", 400

    if request.args.get("state") != socradar.get("state"):
        log.warning("OAuth state mismatch for %s", session["user"]["email"])
        return "OAuth state mismatch.", 400

    code = request.args.get("code")
    if not code:
        return "Missing auth code.", 400

    mcp_base = get_secret("SOCRADAR_MCP_URL") or "https://mcp.socradar.com"
    try:
        with httpx.Client(timeout=15) as http:
            resp = http.post(
                f"{mcp_base.rstrip('/')}/token",
                data={
                    "grant_type":    "authorization_code",
                    "code":          code,
                    "redirect_uri":  get_secret("SOCRADAR_REDIRECT_URI"),
                    "client_id":     socradar["client_id"],
                    "code_verifier": socradar["code_verifier"],
                },
            )
            resp.raise_for_status()
            socradar["access_token"] = resp.json().get("access_token")
    except Exception as e:
        log.error("Token exchange failed for %s: %s", session["user"]["email"], e)
        return f"Token exchange failed: {e}", 500

    # Wipe transient PKCE values — only keep what's needed for subsequent calls
    socradar.pop("state", None)
    socradar.pop("code_verifier", None)
    session["socradar"] = socradar
    log.info("SOCRadar MCP connected for %s", session["user"]["email"])
    return redirect("/investigate/")


@investigate_bp.route("/oauth/logout")
@require_login
def oauth_logout():
    session.pop("socradar", None)
    return redirect("/investigate/")


@investigate_bp.route("/auth-status")
@require_login
def auth_status():
    token = (session.get("socradar") or {}).get("access_token")
    return jsonify({"authenticated": bool(token)})
