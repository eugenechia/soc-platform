"""Standalone tests for tools/cmdline_analysis.py.

Mocked mode (default):  python tools/test_cmdline_analysis.py
    Patches the Sentinel fetch + Tavily + LLM calls and asserts the orchestration
    logic — killswitch, empty-fetch skip, verdict validation, markdown strip,
    fail-silent per command line.

Live mode:              python tools/test_cmdline_analysis.py --live
    Runs a REAL Tavily search + LLM verdict against a known-malicious encoded
    PowerShell command line and a benign one, to eyeball quality. Needs
    TAVILY_API_KEY + an LLM the box can actually reach (Azure OpenAI is VNet-only
    in prod — locally, point at public OpenAI).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import cmdline_analysis as ca


def _cmd(command_line, image, verdict_hint="", alert="Suspicious process"):
    return {"command_line": command_line, "image": image, "parent_image": "explorer.exe",
            "parent_command_line": "", "alert_name": alert, "provider": "MDATP"}


def _run_live():
    os.environ["CMDLINE_ANALYSIS_ENABLED"] = "true"
    samples = [
        _cmd("powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAKAAnAGgAdAB0AHAAOgAvAC8AYQAnACkA",
             "powershell.exe", alert="Suspicious PowerShell command line"),
        _cmd('"Acrobat.exe" "C:\\Users\\j\\Downloads\\Invoice.pdf"', "Acrobat.exe",
             alert="Adobe Reader child process blocked"),
    ]
    ca.fetch_command_lines = lambda c, t, f: samples  # bypass Sentinel
    import tools.cmdline_source as src
    src.fetch_command_lines = lambda c, t, f: samples
    print("LIVE run — hitting real Tavily + LLM...\n")
    out = ca.analyze_ticket_command_lines({"id": "x"}, "LIVE-1", {"customfield_10071": 1})
    for it in (out or {}).get("items", []):
        print(f"  [{it['verdict']}] {it['image']}\n    {it['analysis']}\n")
    if not out:
        print("  (nothing returned — check API reachability)")


def _run_mocked():
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS " if cond else "  FAIL ") + name)
        if not cond:
            fails += 1

    import tools.cmdline_source as src

    web_calls = []

    def fake_web(query):
        web_calls.append(query)
        return "[Web] Source: microsoft.com — known malware installer.\n---"

    # LLM returns valid JSON with a proper verdict; also exercises markdown strip.
    async def fake_llm(image, command_line, parent_image, alert_name, web_context):
        return ca._parse_verdict(
            '{"verdict": "malicious", "analysis": "**Encoded** hidden PowerShell payload (microsoft.com)."}')

    ca._web_search = fake_web
    ca._call_llm = fake_llm

    # killswitch
    print("killswitch:")
    os.environ["CMDLINE_ANALYSIS_ENABLED"] = "false"
    src.fetch_command_lines = lambda c, t, f: [_cmd("powershell -enc AAAA", "powershell.exe")]
    check("off -> None, no web calls",
          ca.analyze_ticket_command_lines({"id": "x"}, "T", {}) is None and not web_calls)

    os.environ["CMDLINE_ANALYSIS_ENABLED"] = "true"

    # empty fetch -> None
    print("empty fetch:")
    src.fetch_command_lines = lambda c, t, f: []
    check("no command lines -> None", ca.analyze_ticket_command_lines({"id": "x"}, "T", {}) is None)

    # happy path: verdict + markdown strip
    print("happy path:")
    src.fetch_command_lines = lambda c, t, f: [_cmd("powershell -nop -enc AAAA", "powershell.exe")]
    out = ca.analyze_ticket_command_lines({"id": "x"}, "T", {})
    items = (out or {}).get("items", [])
    check("one analysed item returned", len(items) == 1)
    check("verdict validated to Malicious", items and items[0]["verdict"] == "Malicious")
    check("markdown stripped from analysis", items and "**" not in items[0]["analysis"])
    check("web research was called", len(web_calls) >= 1)

    # verdict validation: bogus verdict -> Inconclusive
    print("verdict validation:")
    v, _ = ca._parse_verdict('{"verdict": "TotallyEvil", "analysis": "x"}')
    check("unknown verdict -> Inconclusive", v == "Inconclusive")
    v2, a2 = ca._parse_verdict('not json at all')
    check("non-JSON -> Inconclusive, no crash", v2 == "Inconclusive")
    v3, _ = ca._parse_verdict('{"verdict":"legitimate","analysis":"ok"}')
    check("case-insensitive verdict normalised to Legitimate", v3 == "Legitimate")

    # privacy sanitizers (doctrine 2026-07-08): no client-identifying tokens
    # in public web queries.
    print("web-query privacy sanitizers:")
    q = ca._build_query({"image": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\evil.exe",
                         "alert_name": ""})
    check("full-path image -> basename only", '"evil.exe"' in q)
    check("username never reaches the query", "jsmith" not in q)
    q2 = ca._build_query({"image": "svchost.exe",
                          "alert_name": "Suspicious activity on 'SRV-FIN-01.corp.local'"})
    check("quoted hostname rejected from family hint", "SRV-FIN-01" not in q2 and "corp.local" not in q2)
    q3 = ca._build_query({"image": "gt.exe", "alert_name": "'Kepuall' unwanted software was detected"})
    check("legit family hint still passes (regression)", "Kepuall" in q3)
    q4 = ca._build_query({"image": "svchost.exe",
                          "alert_name": "Anomalous sign-in for 'jsmith@client.com'"})
    check("quoted UPN rejected from family hint", "jsmith" not in q4)
    check("raw command line never appears in any web call",
          all("-enc" not in c and "AAAA" not in c for c in web_calls))

    # fail-silent: LLM raises on one item -> that item omitted, no crash
    print("fail-silent per command line:")
    async def boom(*a, **k):
        raise RuntimeError("LLM down")
    ca._call_llm = boom
    src.fetch_command_lines = lambda c, t, f: [_cmd("powershell -enc AAAA", "powershell.exe")]
    check("LLM failure -> None (item dropped, no raise)",
          ca.analyze_ticket_command_lines({"id": "x"}, "T", {}) is None)

    print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
    return fails


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--live":
        _run_live()
    else:
        sys.exit(1 if _run_mocked() else 0)
