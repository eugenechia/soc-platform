"""
SOCRadar MCP (Model Context Protocol) client.

This is the INTERACTIVE integration path — used by routes/investigate.py to let
the LLM autonomously call SOCRadar tools during a user session. Authenticates
via OAuth 2.1 PKCE with dynamic client registration.

For scheduled / unattended report generation (Generate Report mode), use
tools/socradar_rest.py instead — it uses a static API key.
"""
import logging

import httpx

from tools.secrets import get_secret

log = logging.getLogger(__name__)


def _mcp_base() -> str:
    return (get_secret("SOCRADAR_MCP_URL") or "https://mcp.socradar.com").rstrip("/")


def register_dynamic_client() -> str:
    """Register this app with the SOCRadar MCP server and return the client_id.
    Called once per process lifetime (per session, in practice)."""
    redirect_uri = get_secret("SOCRADAR_REDIRECT_URI")
    with httpx.Client(timeout=15) as http:
        resp = http.post(
            f"{_mcp_base()}/register",
            json={
                "client_name": "soc-platform",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "tools:read tools:execute",
            },
        )
        resp.raise_for_status()
        client_id = resp.json()["client_id"]
    log.info("Registered SOCRadar MCP dynamic client: %s", client_id)
    return client_id


def build_mcp_tools(access_token: str) -> list[dict]:
    """Build the OpenAI Responses API tools list for this user's SOCRadar session."""
    return [
        {
            "type":             "mcp",
            "server_url":       _mcp_base(),
            "server_label":     "socradar",
            "headers":          {"Authorization": f"Bearer {access_token}"},
            "require_approval": "never",
        }
    ]
