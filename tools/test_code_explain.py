"""Standalone tests for tools/code_explain.py — no network.

    python tools/test_code_explain.py

Covers extraction precision (the whole point of #5) + deterministic decode:
- Codes decode ONLY with an explicit context marker (never a bare number).
- Event IDs decode only if in the curated security set.
- Logon Type / NTSTATUS / Kerberos decode from the dictionary.
- Killswitch off / no codes -> None.
- Unknown marker-qualified NTSTATUS is surfaced as an LLM candidate (meaning None).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import code_explain as ce


def _run():
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS " if cond else "  FAIL ") + name)
        if not cond:
            fails += 1

    print("extraction precision (context marker required):")
    # A bare 4625 with NO marker must NOT decode.
    check("bare number not decoded", ce.extract_codes("the count was 4625 items") == [])
    # With a marker, a curated Event ID decodes.
    ev = ce.extract_codes("Event ID 4625 observed on host")
    check("marked Event ID 4625 decoded", any(c["kind"] == "event_id" and c["code"] == "4625" for c in ev))
    # A marked but NON-curated Event ID (e.g. 9999) must NOT decode.
    check("marked non-curated Event ID ignored",
          ce.extract_codes("Event ID 9999 whatever") == [])

    print("logon type / ntstatus / kerberos decode:")
    lt = ce.extract_codes("Logon Type: 3 from 10.0.0.5")
    check("Logon Type 3 -> Network", lt and "Network" in lt[0]["meaning"])
    ns = ce.extract_codes("Sub Status: 0xC000006A")
    check("NTSTATUS 0xC000006A -> wrong password",
          ns and ns[0]["kind"] == "ntstatus" and "password is wrong" in ns[0]["meaning"])
    nb = ce.extract_codes("failure reason 0xC0000234 seen")
    check("bare KNOWN NTSTATUS 0xC0000234 -> locked out",
          any(c["code"] == "0xC0000234" and "locked out" in (c["meaning"] or "") for c in nb))
    kb = ce.extract_codes("Kerberos Failure Code: 0x18")
    check("Kerberos 0x18 -> pre-auth failed",
          kb and kb[0]["kind"] == "kerberos" and "Pre-authentication" in kb[0]["meaning"])

    print("doctrine knowledge (2026-07-08):")
    dc = ce.extract_codes("Event ID 4662 on the domain controller")
    check("4662 -> DCSync pattern", dc and "DCSync" in dc[0]["meaning"])
    pth = ce.extract_codes("Logon Type: 9 observed")
    check("Logon Type 9 -> pass-the-hash note", pth and "pass-the-hash" in pth[0]["meaning"])
    krb = ce.extract_codes("Event ID: 4769 burst")
    check("4769 -> Kerberoasting note", krb and "Kerberoasting" in krb[0]["meaning"])
    # Regression vs the encryption-type/failure-code trap: Kerberos FAILURE
    # code 0x17 is "password expired", NOT Kerberoasting.
    k17 = ce.extract_codes("Kerberos Failure Code: 0x17")
    check("Kerberos failure 0x17 still password-expired",
          k17 and "password has expired" in k17[0]["meaning"] and "Kerberoast" not in k17[0]["meaning"])

    print("Entra ID ResultTypes (curated, marker-gated):")
    en = ce.extract_codes("Sign-in failed, ResultType: 500121 repeated")
    check("ResultType 500121 -> MFA fatigue",
          en and en[0]["kind"] == "entra_result" and "MFA" in en[0]["meaning"])
    check("bare 500121 without marker not decoded",
          ce.extract_codes("value 500121 in payload") == [])
    check("non-curated Entra code not decoded (never an LLM candidate)",
          ce.extract_codes("ResultType: 999999") == [])
    ec = ce.extract_codes("error code 50126 for user sign-in")
    check("error code 50126 -> invalid credentials",
          ec and ec[0]["kind"] == "entra_result" and "Invalid username or password" in ec[0]["meaning"])

    print("unknown marker-qualified code -> LLM candidate (meaning None):")
    unk = ce.extract_codes("Sub Status: 0xC0009999")
    check("unknown sub-status surfaced with meaning None",
          unk and unk[0]["code"] == "0xC0009999" and unk[0]["meaning"] is None)

    print("dedupe:")
    dup = ce.extract_codes("Event ID 4625 ... later Event ID: 4625 again")
    check("same code collapsed", len([c for c in dup if c["code"] == "4625"]) == 1)

    print("explain_ticket_codes orchestration:")
    os.environ["CODE_EXPLAIN_ENABLED"] = "false"
    check("killswitch off -> None",
          ce.explain_ticket_codes({"summary": "Event ID 4625 Logon Type 3"}) is None)
    os.environ["CODE_EXPLAIN_ENABLED"] = "true"
    check("no codes in ticket -> None",
          ce.explain_ticket_codes({"summary": "powershell.exe observed"}) is None)
    out = ce.explain_ticket_codes({"summary": "An account failed to log on. Event ID 4625, Logon Type 3, Sub Status 0xC000006A"})
    items = (out or {}).get("items", [])
    check("three known codes decoded from dictionary (no LLM needed)", len(items) == 3)
    check("all dictionary-sourced", all(i["source"] == "dictionary" for i in items))
    check("extra_texts scanned too",
          bool((ce.explain_ticket_codes({}, extra_texts=["Logon Type: 10"]) or {}).get("items")))

    print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
    return fails


if __name__ == "__main__":
    sys.exit(1 if _run() else 0)
