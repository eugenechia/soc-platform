"""
Entra ID (Azure AD) authentication via MSAL.

Replaces SOC-Report's shared-password auth AND SOCRadar AI Analyst's module-level
state. Group membership is enforced on every request (via @app.before_request),
not just at login, so a user removed from the security group loses access on their
next click, no logout needed.

Environment / Key Vault keys consumed:
  ENTRA_TENANT_ID
  ENTRA_CLIENT_ID
  ENTRA_CLIENT_SECRET     (Key Vault in Azure)
  ENTRA_REDIRECT_URI      (e.g. https://<app>.azurecontainerapps.io/auth/callback)
  ENTRA_ALLOWED_GROUP_ID  (Azure AD security group GUID)
"""
from functools import wraps
import logging

import msal
from flask import Blueprint, redirect, request, session, url_for

from tools.secrets import get_secret

log = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)

_SCOPES = ["User.Read"]


def _msal_app() -> msal.ConfidentialClientApplication:
    """Build the MSAL client on every request.
    Cheap (no network), and avoids stale state across process restarts."""
    tenant_id = get_secret("ENTRA_TENANT_ID")
    client_id = get_secret("ENTRA_CLIENT_ID")
    client_secret = get_secret("ENTRA_CLIENT_SECRET")
    return msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )


def require_login(fn):
    """Decorator for routes that need an authenticated user in session."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/auth/login")
        return fn(*args, **kwargs)
    return wrapper


@auth_bp.route("/login")
def login():
    flow = _msal_app().initiate_auth_code_flow(
        _SCOPES,
        redirect_uri=get_secret("ENTRA_REDIRECT_URI"),
    )
    session["auth_flow"] = flow
    return redirect(flow["auth_uri"])


@auth_bp.route("/callback")
def callback():
    flow = session.pop("auth_flow", {})
    if not flow:
        return redirect("/auth/login")
    try:
        result = _msal_app().acquire_token_by_auth_code_flow(flow, request.args)
    except ValueError as e:
        log.error("Entra auth_code_flow error: %s", e)
        return redirect("/auth/login")

    if "error" in result:
        log.error("Entra token error: %s", result)
        return (f"Authentication failed: {result.get('error_description', result['error'])}", 400)

    claims = result.get("id_token_claims", {})

    allowed_group = get_secret("ENTRA_ALLOWED_GROUP_ID")
    if allowed_group and allowed_group not in (claims.get("groups") or []):
        log.warning(
            "Access denied for %s — not in group %s",
            claims.get("preferred_username"), allowed_group,
        )
        return (
            "<html><body style='font-family:sans-serif;padding:60px;text-align:center'>"
            "<h2 style='color:#c00'>Access Denied</h2>"
            "<p>Your account is not authorised to use this application.</p>"
            "<p><a href='/auth/logout'>Sign out</a></p>"
            "</body></html>"
        ), 403

    session["user"] = {
        "name":  claims.get("name", ""),
        "email": claims.get("preferred_username", ""),
        "oid":   claims.get("oid", ""),
        "groups": claims.get("groups", []),
    }
    log.info("Login: %s", session["user"]["email"])
    return redirect("/")


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    email = (session.get("user") or {}).get("email", "")
    session.clear()  # clear ALL session state, including SOCRadar MCP OAuth tokens
    log.info("Logout: %s", email)

    tenant_id = get_secret("ENTRA_TENANT_ID")
    redirect_uri = get_secret("ENTRA_REDIRECT_URI")
    post_logout = redirect_uri.replace("/auth/callback", "/")
    return redirect(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={post_logout}"
    )


@auth_bp.route("/status")
def status():
    """Lightweight JSON endpoint the UI can poll to detect session expiry."""
    user = session.get("user")
    if not user:
        return {"authenticated": False}, 200
    return {
        "authenticated": True,
        "email": user.get("email"),
        "name":  user.get("name"),
    }
