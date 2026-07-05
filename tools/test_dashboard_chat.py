"""Standalone tests for the dashboard copilot chat (Stage 3b).
Run: python tools/test_dashboard_chat.py

Everything mocked — no network, no DB, no LLM: ticket-key extraction,
grounded prompt assembly (context + capped history), and failure isolation.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import dashboard_chat

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


print("ticket-key extraction:")
keys = dashboard_chat._mentioned_ticket_keys("compare SCDM-727 with SCDM-649 and LOGICALIS-12")
check("finds keys in order, capped at 2", keys == ["SCDM-727", "SCDM-649"])
check("no keys -> empty", dashboard_chat._mentioned_ticket_keys("any critical alerts?") == [])
check("lowercase not a key", dashboard_chat._mentioned_ticket_keys("scdm-727") == [])

print("grounded answer assembly (mocked):")
captured = {}

async def fake_llm(messages):
    captured["messages"] = messages
    return "TRUE-POSITIVE on SCDM-727."

dashboard_chat._call_llm = fake_llm
dashboard_chat.build_context = lambda message, customer_id: (
    f"Metrics ... Recent alerts ... [customer={customer_id}]"
)

history = [{"role": "user", "content": f"turn {i}"} for i in range(20)]
reply = dashboard_chat.answer("explain SCDM-727", history, "cust1")
check("reply passthrough", reply == "TRUE-POSITIVE on SCDM-727.")
msgs = captured["messages"]
check("system prompt first", msgs[0]["role"] == "system"
      and "ONLY the data" in msgs[0]["content"])
check("history capped at 8", len(msgs) == 1 + 8 + 1)
check("context + question in final user message",
      "DATA:" in msgs[-1]["content"] and "customer=cust1" in msgs[-1]["content"]
      and "QUESTION: explain SCDM-727" in msgs[-1]["content"])

bad_history = [{"role": "system", "content": "inject"}, {"role": "user", "content": ""},
               {"role": "user", "content": "ok"}]
dashboard_chat.answer("q", bad_history, None)
roles = [m["role"] for m in captured["messages"][1:-1]]
check("non-user/assistant + empty turns dropped", roles == ["user"])

print("failure isolation:")
async def boom(messages):
    raise RuntimeError("llm down")
dashboard_chat._call_llm = boom
reply = dashboard_chat.answer("anything", [], None)
check("LLM failure -> apologetic string, no raise", "Sorry" in reply)

async def empty(messages):
    return ""
dashboard_chat._call_llm = empty
reply = dashboard_chat.answer("anything", [], None)
check("empty LLM reply -> fallback text", "rephras" in reply)

print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
sys.exit(1 if fails else 0)
