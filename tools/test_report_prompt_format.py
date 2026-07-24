"""Guard test for the report prompt's str.format() safety.
Run: python tools/test_report_prompt_format.py

Why this exists (July 2026 prod outage):
    routes/reports.py builds the LLM prompt with
    ``REPORT_SYSTEM_PROMPT.format(customer_name=..., data_json=..., ...)``.
    The prompt is a large hand-authored string, so any literal brace that is
    meant as example/doc text (e.g. ``[{HealthStatus, Count}]``) MUST be
    escaped as ``{{...}}``. Commit a3ec425 added an unescaped ``{HealthStatus,
    Count}`` to section 1.13's instructions; every report generation after that
    deploy died with ``KeyError('HealthStatus, Count')`` before producing any
    output. The same failure class applies to ``_REPORT_TAIL.format(...)``.

    This test formats both strings with the exact keyword arguments their real
    call sites pass. An unescaped brace (or a placeholder with no matching
    kwarg) makes .format() raise, so the test fails BEFORE the change ever
    reaches production instead of after.

The prompt and its call sites are read straight from routes/reports.py via the
``ast`` module, so this test pulls in none of the Flask / Azure runtime deps
that importing the module would.
"""
import ast
import os
import sys

REPORTS_PY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "routes", "reports.py",
)

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


def _load():
    """Return (module_tree, source). Parsed once, shared by the helpers."""
    with open(REPORTS_PY, "r") as f:
        src = f.read()
    return ast.parse(src), src


def _string_const_named(tree, var_name):
    """The literal string assigned to a module-level ``var_name = "..."``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == var_name:
                    return ast.literal_eval(node.value)
    return None


def _format_kwargs_for(tree, var_name):
    """Keyword names passed to ``<var_name>.format(...)``. Lets the test learn
    the valid placeholder set from the real call site instead of hard-coding
    it, so a newly-added *legitimate* placeholder doesn't cause a false fail."""
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == var_name):
            return [kw.arg for kw in node.keywords if kw.arg]
    return None


def _try_format(template, kwargs):
    """(ok, error_string). Never raises."""
    try:
        template.format(**{k: "x" for k in kwargs})
        return True, ""
    except Exception as e:  # KeyError / IndexError / ValueError from bad braces
        return False, f"{type(e).__name__}({e})"


tree, _src = _load()

print("== REPORT_SYSTEM_PROMPT ==")
prompt = _string_const_named(tree, "REPORT_SYSTEM_PROMPT")
prompt_kwargs = _format_kwargs_for(tree, "REPORT_SYSTEM_PROMPT")
check("REPORT_SYSTEM_PROMPT literal found", prompt is not None)
check("its .format() call site found", bool(prompt_kwargs))
if prompt is not None and prompt_kwargs:
    ok, err = _try_format(prompt, prompt_kwargs)
    check("prompt.format(**call-site kwargs) succeeds — no unescaped braces"
          + ("" if ok else f"  [{err}]"), ok)

print("== _REPORT_TAIL ==")
tail = _string_const_named(tree, "_REPORT_TAIL")
tail_kwargs = _format_kwargs_for(tree, "_REPORT_TAIL")
check("_REPORT_TAIL literal found", tail is not None)
check("its .format() call site found", bool(tail_kwargs))
if tail is not None and tail_kwargs:
    ok, err = _try_format(tail, tail_kwargs)
    check("_REPORT_TAIL.format(**call-site kwargs) succeeds"
          + ("" if ok else f"  [{err}]"), ok)

print()
if fails:
    print(f"FAILED ({fails} check{'s' if fails != 1 else ''})")
    sys.exit(1)
print("ALL PASS")
