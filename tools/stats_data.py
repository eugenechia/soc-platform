"""
Stats page data (2026-07-08).

Assembles the read-only "Stats" view:
  1. AI & enrichment services that are connected (with model names / detail).
  2. L1 Triage AI feature flags (the killswitches) and whether each is ON.
  3. Per-customer L1 Triage readiness matrix (allowlist / Sentinel / Confluence /
     entity-field-mapping health).

Everything here is derived from config (env + Key Vault via get_secret) and the
customer records — no external calls except the cached L1 pipeline health probe.
Every section is failure-isolated: a broken piece degrades to an empty/false
value rather than raising, so the page always renders.
"""
from __future__ import annotations

import logging
import os

from tools.secrets import get_secret

logger = logging.getLogger(__name__)


def _has_secret(name: str) -> bool:
    try:
        return bool(get_secret(name))
    except Exception:
        return False


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _allowlist() -> set[str]:
    return {p.strip().upper()
            for p in _env("JIRA_ENRICHMENT_PROJECT").split(",") if p.strip()}


# ── 1. AI & enrichment services ─────────────────────────────────────────────────

def _ai_services(sentinel_customers: int) -> list[dict]:
    """Each item: {name, category, ok, detail}. ``ok`` = configured/connected."""
    services: list[dict] = []

    # Triage LLM
    azure_llm = bool(_env("AZURE_OPENAI_ENDPOINT")) and _has_secret("AZURE_OPENAI_API_KEY")
    public_llm = _has_secret("OPENAI_API_KEY")
    if azure_llm:
        model = _env("AZURE_OPENAI_DEPLOYMENT") or "gpt-4.1"
        services.append({"name": "Triage LLM", "category": "AI",
                         "ok": True, "detail": f"Azure OpenAI · {model}"})
    elif public_llm:
        model = _env("OPENAI_MODEL") or "gpt-5.2"
        services.append({"name": "Triage LLM", "category": "AI",
                         "ok": True, "detail": f"OpenAI · {model}"})
    else:
        services.append({"name": "Triage LLM", "category": "AI",
                         "ok": False, "detail": "not configured"})

    # Embeddings (RAG customer context)
    embed_model = _env("AZURE_OPENAI_EMBEDDING_DEPLOYMENT") or _env("OPENAI_EMBEDDING_MODEL")
    embed_ok = bool(embed_model) and (_has_secret("AZURE_OPENAI_API_KEY") or _has_secret("OPENAI_API_KEY"))
    services.append({"name": "Embeddings (RAG)", "category": "AI", "ok": embed_ok,
                     "detail": (embed_model or "not configured") if embed_ok else "not configured"})

    # Web research (Tavily) — powers command-line analysis + IOC insights
    tav = _has_secret("TAVILY_API_KEY")
    services.append({"name": "Web Research (Tavily)", "category": "AI", "ok": tav,
                     "detail": "connected" if tav else "not configured"})

    # Threat-intel enrichment
    vt = _has_secret("VT_API_KEY")
    services.append({"name": "VirusTotal", "category": "Threat Intel", "ok": vt,
                     "detail": "connected" if vt else "not configured"})
    ab = _has_secret("ABUSEIPDB_API_KEY")
    services.append({"name": "AbuseIPDB", "category": "Threat Intel", "ok": ab,
                     "detail": "connected" if ab else "not configured"})
    sr = _has_secret("SOCRADAR_COMPANY_KEY") or _has_secret("SOCRADAR_IOC_ENRICHMENT_KEY")
    services.append({"name": "SOCRadar", "category": "Threat Intel", "ok": sr,
                     "detail": "connected" if sr else "not configured"})

    # SIEM / XDR
    services.append({"name": "Microsoft Sentinel", "category": "SIEM/XDR",
                     "ok": sentinel_customers > 0,
                     "detail": f"{sentinel_customers} customer(s)" if sentinel_customers
                               else "no workspace configured"})
    defender = (_has_secret("DEFENDER_CLIENT_ID") and _has_secret("DEFENDER_CLIENT_SECRET")
                and _has_secret("DEFENDER_TENANT_ID"))
    services.append({"name": "Microsoft Defender", "category": "SIEM/XDR", "ok": defender,
                     "detail": "connected" if defender else "not configured"})

    # Knowledge source
    conf = _has_secret("CONFLUENCE_API_TOKEN") and bool(_env("CONFLUENCE_BASE_URL"))
    services.append({"name": "Confluence (RAG source)", "category": "Knowledge", "ok": conf,
                     "detail": "connected" if conf else "not configured"})

    # Ticketing
    jira = bool(_env("JIRA_URL")) and _has_secret("JIRA_EMAIL") and _has_secret("JIRA_API_TOKEN")
    services.append({"name": "Jira", "category": "Ticketing", "ok": jira,
                     "detail": "configured" if jira else "not configured"})

    return services


# ── 2. L1 Triage AI feature flags ───────────────────────────────────────────────

# (label, env var, default-on?). Default-on flags are ON unless explicitly "false".
_FEATURE_FLAGS = [
    ("Command-Line Analysis", "CMDLINE_ANALYSIS_ENABLED", False),
    ("Security Code Decoder", "CODE_EXPLAIN_ENABLED", False),
    ("MITRE ATT&CK Mapping", "MITRE_MAPPING_ENABLED", True),
    ("IOC Web Insights", "IOC_INSIGHTS_ENABLED", False),
    ("Historical Correlation", "HISTORICAL_LOOKUP_ENABLED", False),
    ("RAG Customer Context", "RAG_LOOKUP_ENABLED", False),
    ("Whitelist-Driven Verdict", "WHITELIST_VERDICT_OVERRIDE_ENABLED", False),
    ("Known-Activity Advisory", "KNOWN_ACTIVITY_ADVISORY_ENABLED", False),
    ("KQL Expansion", "KQL_EXPANSION_ENABLED", False),
    ("Rich (ADF) Comments", "COMMENT_ADF_ENABLED", False),
]


def _feature_flags() -> list[dict]:
    flags = []
    for label, env, default_on in _FEATURE_FLAGS:
        raw = _env(env).lower()
        on = (raw != "false") if default_on else (raw == "true")
        flags.append({"label": label, "env": env, "on": on})
    return flags


# ── 3. Per-customer L1 readiness ────────────────────────────────────────────────

def _customer_projects(cust: dict) -> list[str]:
    keys = [str((jp or {}).get("project_key", "")).strip()
            for jp in (cust.get("jira_projects") or [])]
    keys = [k for k in keys if k]
    if not keys and cust.get("jira_project_key"):
        keys = [str(cust["jira_project_key"]).strip()]
    return keys


def _customer_readiness() -> tuple[list[dict], int]:
    """Return (rows, sentinel_customer_count)."""
    try:
        from tools.customers import load_customers
        customers = load_customers()
    except Exception:
        logger.exception("stats: load_customers failed")
        return [], 0

    try:
        from tools.triage_health import schema_mismatches
        mismatch_by_project = {m["project"].upper(): m for m in schema_mismatches()}
    except Exception:
        mismatch_by_project = {}

    allow = _allowlist()
    rows: list[dict] = []
    sentinel_count = 0

    for c in customers:
        projects = _customer_projects(c)
        workspaces = c.get("sentinel_workspaces") or []
        if workspaces:
            sentinel_count += 1
        conf_pages = c.get("confluence_pages") or []
        has_sentinel = bool(workspaces)
        has_rag = len(conf_pages) > 0

        # Tier mirrors tools.triage_health exactly so this matrix and the
        # home-page tile never disagree: a customer is "triaged" when it has a
        # project key that is in the enrichment allowlist (empty allowlist == all
        # in scope, matching triage_health's definition).
        triaged = bool(projects) and (not allow or any(pk.upper() in allow for pk in projects))
        if not triaged:
            tier = "inactive"
        elif has_sentinel and has_rag:
            tier = "active"
        else:
            tier = "limited"

        mismatch = next((mismatch_by_project[pk.upper()] for pk in projects
                         if pk.upper() in mismatch_by_project), None)

        rows.append({
            "name": c.get("name") or c.get("id") or "—",
            "projects": projects,
            "tier": tier,
            "on_allowlist": triaged,
            "has_sentinel": has_sentinel,
            "sentinel_count": len(workspaces),
            "confluence_pages": len(conf_pages),
            "mapping_flag": mismatch,   # None, or {detail, count, ...}
            "ready": triaged,           # enrichment only runs for allowlisted projects
        })

    # Ready customers first, then by name; within ready, active before limited.
    _tier_rank = {"active": 0, "limited": 1, "inactive": 2}
    rows.sort(key=lambda r: (_tier_rank.get(r["tier"], 3), r["name"].lower()))
    return rows, sentinel_count


# ── Public entry ────────────────────────────────────────────────────────────────

def collect_stats() -> dict:
    """Assemble the full Stats context. Never raises."""
    customers, sentinel_count = _customer_readiness()
    try:
        from tools.triage_health import triage_health
        pipeline = triage_health()
    except Exception:
        logger.exception("stats: triage_health failed")
        pipeline = {"status": "unknown", "checks": []}

    ready_count = sum(1 for c in customers if c["ready"])
    return {
        "pipeline": pipeline,
        "ai_services": _ai_services(sentinel_count),
        "feature_flags": _feature_flags(),
        "customers": customers,
        "summary": {
            "total_customers": len(customers),
            "ready_customers": ready_count,
            "sentinel_customers": sentinel_count,
        },
    }
