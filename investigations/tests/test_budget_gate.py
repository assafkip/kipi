"""Deterministic in-flight tool-call budget (RULE-114, cap the function not the time): a
PreToolUse hook charges every tool call against a per-run cap and denies once it's exceeded.
A circuit-breaker for a pass that loops without finishing — the between-pass cost cap can't
see inside one pass, and a cut-off pass reports cost_usd=0.

Run: .venv/bin/python -m investigations.tests.test_budget_gate
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

from investigations.agent import budget


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_charge_allows_up_to_cap_then_denies():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "b.json")
        budget.write_budget(path, 3)
        verdicts = [budget.check_and_charge(path)[0] for _ in range(4)]
        _check("first 3 calls allowed, 4th denied (cap=3)", verdicts == [True, True, True, False])
        _, count, cap = budget.check_and_charge(path)
        _check("count keeps climbing past the cap", count == 5 and cap == 3)


def test_no_budget_file_is_unbudgeted():
    cap0_allow, _, cap = budget.check_and_charge("/nonexistent/path/b.json")
    _check("unreadable budget file → allow (fail open), cap 0", cap0_allow is True and cap == 0)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "b.json")
        budget.write_budget(path, 0)  # cap 0 = unbudgeted
        allow, _, _ = budget.check_and_charge(path)
        _check("cap 0 → always allow (deep/unbounded runs)", allow is True)


def test_deny_message_is_actionable():
    msg = budget.deny_message(151, 150)
    _check("deny message names the counts", "151" in msg and "150" in msg)
    _check("deny message tells the agent to emit findings + leads",
           "findings" in msg.lower() and "lead" in msg.lower())


def test_hook_script_end_to_end():
    """The actual PreToolUse hook (budget_hook.py) as a subprocess: allows until the cap,
    then denies; and is a no-op when no budget env is set (deep is unbudgeted)."""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    hook = os.path.join(root, "investigations", "agent", "budget_hook.py")
    event = json.dumps({"tool_name": "mcp__kipi-osint__whois_lookup", "tool_input": {"target": "x.com"}})
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "b.json"
        budget.write_budget(str(path), 2)
        env = {**os.environ, "KIPI_BUDGET_FILE": str(path)}
        outs = [subprocess.run(["python3", hook], input=event, env=env,
                               capture_output=True, text=True).stdout for _ in range(3)]
        _check("hook allows the first 2 calls (no output)", outs[0].strip() == "" and outs[1].strip() == "")
        _check("hook DENIES the 3rd call (over cap)", '"deny"' in outs[2] and "budget" in outs[2].lower())
        env_no = {k: v for k, v in os.environ.items() if k != "KIPI_BUDGET_FILE"}
        r = subprocess.run(["python3", hook], input=event, env=env_no, capture_output=True, text=True)
        _check("no budget env → no-op (deep is unbudgeted)", r.stdout.strip() == "")


def test_guard_settings_wires_budget_hook():
    from investigations.agent import investigator as inv
    sp, rp, bp = inv._build_guard_settings(["trumpstake.us"], tool_budget=50)
    try:
        cfg = json.load(open(sp))
        hooks = cfg["hooks"]["PreToolUse"]
        cmds = " ".join(h["hooks"][0]["command"] for h in hooks)
        _check("both scope + budget hooks wired", "scope_hook.py" in cmds and "budget_hook.py" in cmds)
        _check("budget hook matcher counts every tool (.*)",
               any(h["matcher"] == ".*" for h in hooks))
        _check("budget file written with the cap", bp and json.load(open(bp))["cap"] == 50)
    finally:
        for p in (sp, rp, bp):
            if p and os.path.exists(p):
                os.remove(p)
    # No budget requested → no budget hook, budget_path None (back-compat / deep path)
    sp2, rp2, bp2 = inv._build_guard_settings(["trumpstake.us"], tool_budget=None)
    try:
        cfg2 = json.load(open(sp2))
        cmds2 = " ".join(h["hooks"][0]["command"] for h in cfg2["hooks"]["PreToolUse"])
        _check("no tool_budget → scope hook only, no budget hook",
               "scope_hook.py" in cmds2 and "budget_hook.py" not in cmds2 and bp2 is None)
    finally:
        for p in (sp2, rp2):
            if p and os.path.exists(p):
                os.remove(p)


def main():
    test_charge_allows_up_to_cap_then_denies()
    test_no_budget_file_is_unbudgeted()
    test_deny_message_is_actionable()
    test_hook_script_end_to_end()
    test_guard_settings_wires_budget_hook()
    print("\nPASS: test_budget_gate")


if __name__ == "__main__":
    main()
