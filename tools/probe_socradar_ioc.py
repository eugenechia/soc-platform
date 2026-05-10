"""
One-shot probe to settle which SOCRadar API key authorises per-IOC reputation
lookups via the documented ThreatFusion endpoint:

    GET https://platform.socradar.com/api/threat/analysis?key=<KEY>&entity=<value>

Auth is by `key=` query parameter (NOT the `Api-Key` header we use for
/company/{id}/incidents/v4 — different endpoints, different auth methods).

Run locally:
    cd Office/SOC-System/soc-platform
    SOCRADAR_THREAT_ANALYSIS_KEY=0716de5a... \\
    SOCRADAR_IOC_ENRICHMENT_KEY=61252f95... \\
    SOCRADAR_THREAT_INVESTIGATING_KEY=26cd0938... \\
    python -m tools.probe_socradar_ioc

For each candidate key the script:
  1. Calls /api/threat/analysis/check/auth?key=… (cheap auth probe).
  2. If auth passes, calls /api/threat/analysis?key=…&entity=<TEST_IP> against
     a known-bad IP from the March IOC Update feed (185.156.73.62, honeypot
     tagged at 100% confidence in last month's report).
  3. Prints HTTP status + first 600 chars of the response body.

No keys are read from secrets.get_secret() and no values are written to disk.
The script reads strictly from os.environ so the keys never leave the shell.
"""

import os
import sys
import json
import textwrap

import httpx

BASE = "https://platform.socradar.com/api"
TEST_IP = "185.156.73.62"  # honeypot IOC from March 2026 report — public knowledge

CANDIDATE_KEYS = [
    ("Threat Analysis",     "SOCRADAR_THREAT_ANALYSIS_KEY"),
    ("IOC Enrichment",      "SOCRADAR_IOC_ENRICHMENT_KEY"),
    ("Threat Investigating", "SOCRADAR_THREAT_INVESTIGATING_KEY"),
    # Including the Company key as a control — we EXPECT this to fail on
    # /threat/analysis. If it succeeds, our mental model is wrong.
    ("Company (control)",   "SOCRADAR_COMPANY_KEY"),
]


def _truncate(s: str, n: int = 600) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


def _label_status(status: int) -> str:
    if 200 <= status < 300:
        return "✓ OK"
    if status in (401, 403):
        return "✗ AUTH DENIED"
    if status == 404:
        return "✗ NOT FOUND"
    return f"✗ {status}"


def _probe(label: str, key: str) -> None:
    masked = (key[:8] + "…" + key[-4:]) if key and len(key) > 12 else "<unset>"
    print(f"\n=== {label}  key={masked} ===")
    if not key:
        print("  SKIP: env var not set")
        return

    # 1. Auth check — cheapest, just verifies the key is valid for this endpoint.
    try:
        r = httpx.get(f"{BASE}/threat/analysis/check/auth",
                      params={"key": key}, timeout=20)
        print(f"  [auth-check]  HTTP {r.status_code}  {_label_status(r.status_code)}")
        print("    body: " + _truncate(r.text, 300))
    except Exception as e:
        print(f"  [auth-check]  ERROR: {type(e).__name__}: {e}")
        return

    # 2. Real lookup — only run if auth check looked promising.
    if r.status_code >= 400:
        print(f"  [lookup]      SKIPPED (auth-check failed)")
        return

    try:
        r2 = httpx.get(f"{BASE}/threat/analysis",
                       params={"key": key, "entity": TEST_IP}, timeout=30)
        print(f"  [lookup IP]   HTTP {r2.status_code}  {_label_status(r2.status_code)}")
        body = r2.text
        # Try to pretty-print JSON if it parses
        try:
            parsed = r2.json()
            body = json.dumps(parsed, indent=2)
        except Exception:
            pass
        print("    body: " + _truncate(body, 800))
    except Exception as e:
        print(f"  [lookup IP]   ERROR: {type(e).__name__}: {e}")


def main() -> int:
    print(textwrap.dedent(f"""\
        SOCRadar IOC Enrichment Probe
        Endpoint:  GET {BASE}/threat/analysis
        Test IP:   {TEST_IP}  (honeypot from March 2026 IOC feed)
    """))
    for label, env_name in CANDIDATE_KEYS:
        _probe(label, os.environ.get(env_name, ""))
    print("\nDone. Whichever key returned HTTP 200 above is the one to wire into check_ioc().")
    return 0


if __name__ == "__main__":
    sys.exit(main())
