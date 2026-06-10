"""PreToolUse hook: charge one tool call against the run's tool-call budget and DENY once
the cap is exceeded (RULE-114, in-flight bound). Wired into the cold bounded launch via
--settings alongside scope_hook.py; reads the budget file from $KIPI_BUDGET_FILE. Deep /
unbounded runs don't set that env var, so the hook is a no-op there.

Fails OPEN on any error (allow) — a budget hook must never be the thing that breaks a run.

Run by claude as: python3 <abs path>/budget_hook.py   (stdin = PreToolUse JSON)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _allow():
    sys.exit(0)  # no output = allow


def main():
    budget_path = os.environ.get("KIPI_BUDGET_FILE")
    if not budget_path or not os.path.exists(budget_path):
        _allow()
    try:
        from investigations.agent import budget
        json.load(sys.stdin)  # consume the event (we charge per call, not per target)
        allow, count, cap = budget.check_and_charge(budget_path)
        reason = budget.deny_message(count, cap)
    except Exception:
        _allow()  # fail open — never break the agent on a hook error
    if allow:
        _allow()
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))
    sys.exit(0)


if __name__ == "__main__":
    main()
