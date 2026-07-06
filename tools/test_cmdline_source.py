"""Standalone unit tests for tools/cmdline_source.py — no network.

    python tools/test_cmdline_source.py

Covers the deterministic pieces that matter for correctness/safety:
- SecurityAlert.Entities parsing (Process entity CommandLine + ImageFile + parent).
- Incident-number resolution is KQL-injection-safe (bare integers only).
- Device-name resolution is KQL-string-safe (rejects quotes/spaces/control chars).
- Dedupe + LOLBin-first ranking within the per-ticket cap.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import cmdline_source as cs


def _run():
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS " if cond else "  FAIL ") + name)
        if not cond:
            fails += 1

    # ── entity parsing ──────────────────────────────────────────────────────────
    print("SecurityAlert.Entities parsing:")
    entities = json.dumps([
        {"Type": "host", "HostName": "vn82hcmhc0177"},
        {"Type": "process", "CommandLine": '"Gt.exe" --softname=WeChat',
         "ImageFile": {"Name": "Gt.exe"},
         "ParentProcess": {"CommandLine": "installer.exe /q",
                           "ImageFile": {"Name": "installer.exe"}}},
        {"Type": "account", "Name": "jsmith"},
    ])
    procs = cs._parse_entities(entities)
    check("one process entity extracted", len(procs) == 1)
    check("command line captured", procs and procs[0]["command_line"] == '"Gt.exe" --softname=WeChat')
    check("image name captured", procs and procs[0]["image"] == "Gt.exe")
    check("parent image captured", procs and procs[0]["parent_image"] == "installer.exe")
    check("parent command line captured", procs and procs[0]["parent_command_line"] == "installer.exe /q")

    print("parsing is fail-silent on junk:")
    check("non-JSON -> []", cs._parse_entities("not json") == [])
    check("None -> []", cs._parse_entities(None) == [])
    check("dict (not list) -> []", cs._parse_entities('{"CommandLine":"x"}') == [])
    check("process without CommandLine skipped",
          cs._parse_entities(json.dumps([{"Type": "process", "ImageFile": {"Name": "x.exe"}}])) == [])
    check("camelCase commandLine also captured",
          cs._parse_entities(json.dumps([{"commandLine": "a.exe -x"}]))[0]["command_line"] == "a.exe -x")

    # ── incident-number resolution (KQL-injection safety) ───────────────────────
    print("incident-number resolution is KQL-safe:")
    check("bare integer accepted", cs._resolve_incident_number({"customfield_10071": 228509}) == "228509")
    check("string integer accepted", cs._resolve_incident_number({"customfield_10071": "228509"}) == "228509")
    check("injection payload rejected",
          cs._resolve_incident_number({"customfield_10071": "1; drop table x"}) is None)
    check("non-numeric rejected", cs._resolve_incident_number({"customfield_10071": "INC-5"}) is None)
    check("missing field -> None", cs._resolve_incident_number({}) is None)

    # ── device-name resolution (KQL-string safety) ──────────────────────────────
    print("device-name resolution is KQL-safe:")
    check("plain hostname accepted",
          cs._resolve_device_name({"customfield_10078": '{"hostName":"vn82hcmhc0177"}'}) == "vn82hcmhc0177")
    check("hostname from larger blob",
          cs._resolve_device_name({"customfield_10078": '{"dnsDomain":"x","hostName":"host-01.corp","osFamily":"Windows"}'}) == "host-01.corp")
    check("quote-injection hostname rejected",
          cs._resolve_device_name({"customfield_10078": '{"hostName":"a\\" or Entities has \\"b"}'}) is None)
    check("missing host field -> None", cs._resolve_device_name({}) is None)

    # ── dedupe + LOLBin-first ranking ───────────────────────────────────────────
    print("dedupe + LOLBin-first ranking:")
    rows = [{"AlertName": "A", "ProviderName": "MDATP"},
            {"AlertName": "B", "ProviderName": "MDATP"}]
    parsed = [
        [{"command_line": '"Gt.exe" --x', "image": "Gt.exe", "parent_image": "", "parent_command_line": ""},
         {"command_line": '"Gt.exe" --x', "image": "Gt.exe", "parent_image": "", "parent_command_line": ""}],  # dup
        [{"command_line": "powershell.exe -enc AAAA", "image": "powershell.exe",
          "parent_image": "", "parent_command_line": ""}],
    ]
    merged = cs._dedupe_and_rank(rows, parsed)
    check("duplicate command line collapsed", len(merged) == 2)
    check("LOLBin (powershell) ranked first", merged[0]["image"] == "powershell.exe")
    check("alert metadata attached", merged[0]["alert_name"] in ("A", "B"))

    print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
    return fails


if __name__ == "__main__":
    sys.exit(1 if _run() else 0)
