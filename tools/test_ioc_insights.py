"""Standalone tests for tools/ioc_insights.py.

Mocked mode (default):  python tools/test_ioc_insights.py
    Patches the Tavily + LLM calls and asserts the orchestration logic —
    killswitch, malicious-only filter, per-ticket cap, honest-null, markdown strip.

Live mode:              python tools/test_ioc_insights.py --live [ioc_value] [ioc_type]
    Runs a REAL Tavily search + LLM summary against a known indicator and prints
    the grounded insight, to eyeball quality. Needs TAVILY_API_KEY + Azure OpenAI
    to resolve. Defaults to the EICAR test-file SHA-256 (safe, heavily documented).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import ioc_insights


def _mk(value, ioc_type, verdict="malicious"):
    return {
        "ioc": {"value": value, "type": ioc_type},
        "verdict": verdict,
        "virustotal": {"malicious_count": 5, "total_engines": 70},
        "abuseipdb": {"confidence_score": 88} if ioc_type == "ip" else None,
        "socradar": {"verdict": "malicious", "categories": ["Malware", "C2"]},
    }


def _run_live():
    value = sys.argv[2] if len(sys.argv) > 2 else \
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    ioc_type = sys.argv[3] if len(sys.argv) > 3 else "hash"
    os.environ["IOC_INSIGHTS_ENABLED"] = "true"
    print(f"LIVE run — IOC {value} ({ioc_type})")
    print("Querying Tavily + LLM (this hits real APIs)...\n")
    out = ioc_insights.fetch_insights_for_malicious([_mk(value, ioc_type)])
    if not out:
        print("  (no insight returned — check TAVILY_API_KEY / Azure OpenAI resolution)")
        return
    for v, text in out.items():
        print(f"  [{v}]\n    {text}\n")


def _run_mocked():
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS " if cond else "  FAIL ") + name)
        if not cond:
            fails += 1

    # --- patch the two external calls -------------------------------------------
    web_calls = []

    def fake_web(query):
        web_calls.append(query)
        return ("[Web Intelligence Context]\n"
                "Source 1: ThreatFox (https://threatfox.abuse.ch/ioc/123)\n"
                "Listed as AsyncRAT C2, first seen June 2026\n---")

    async def fake_llm(value, ioc_type, verdict_summary, vendor_facts, web_context):
        return "**Associated** with AsyncRAT commodity RAT; active C2 (threatfox.abuse.ch)."

    ioc_insights._web_search = fake_web
    ioc_insights._call_llm = fake_llm

    print("killswitch:")
    os.environ["IOC_INSIGHTS_ENABLED"] = "false"
    check("off -> empty dict, no web calls",
          ioc_insights.fetch_insights_for_malicious([_mk("1.2.3.4", "ip")]) == {} and not web_calls)

    os.environ["IOC_INSIGHTS_ENABLED"] = "true"

    print("malicious-only filter:")
    mixed = [_mk("1.2.3.4", "ip", "malicious"),
             _mk("8.8.8.8", "ip", "clean"),
             _mk("9.9.9.9", "ip", "unknown")]
    out = ioc_insights.fetch_insights_for_malicious(mixed)
    check("only the malicious IOC is researched", set(out.keys()) == {"1.2.3.4"})
    check("clean/unknown never hit the web", all("8.8.8.8" not in q and "9.9.9.9" not in q for q in web_calls))

    print("markdown stripped + returned:")
    check("insight present for malicious IOC", bool(out.get("1.2.3.4")))
    check("no markdown bold markers", "**" not in out.get("1.2.3.4", "**"))

    print("per-ticket cap:")
    web_calls.clear()
    many = [_mk(f"10.0.0.{i}", "ip", "malicious") for i in range(5)]
    out = ioc_insights.fetch_insights_for_malicious(many, max_iocs=2)
    check("cap=2 -> only 2 researched", len(out) == 2)
    check("cap=2 -> only 2 web searches", len(web_calls) == 2)

    print("honest-null when BOTH web and vendor facts empty:")
    ioc_insights._web_search = lambda q: None  # Tavily returned nothing
    bare = {"ioc": {"value": "5.5.5.5", "type": "ip"}, "verdict": "malicious",
            "virustotal": {"malicious_count": 3, "total_engines": 70},  # no owner/network
            "abuseipdb": None, "socradar": None}                        # no facts
    out = ioc_insights.fetch_insights_for_malicious([bare])
    check("empty web + empty facts -> _NO_CONTEXT literal", out.get("5.5.5.5") == ioc_insights._NO_CONTEXT)
    print("vendor facts alone (no web) still produce an insight:")
    ioc_insights._web_search = lambda q: None  # no web, but socradar categories present
    out = ioc_insights.fetch_insights_for_malicious([_mk("6.6.6.6", "ip", "malicious")])
    check("facts present + no web -> LLM called, insight returned",
          bool(out.get("6.6.6.6")) and out.get("6.6.6.6") != ioc_insights._NO_CONTEXT)

    print("empty input:")
    ioc_insights._web_search = fake_web
    check("no malicious IOCs -> empty dict",
          ioc_insights.fetch_insights_for_malicious([_mk("1.1.1.1", "ip", "clean")]) == {})

    print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    if "--live" in sys.argv:
        _run_live()
    else:
        _run_mocked()
