"""PreToolUse hook: deny the case agent from INVESTIGATING a target not in the case roster
(RULE-112, leads-first). Wired into the cold `claude -p` launch via --settings; reads the
roster from the file at $KIPI_SCOPE_ROSTER (one entity per line). Deep runs don't set that
env var, so the hook is a no-op there (chase freely).

Fails OPEN on any error (allow) — a scope hook must never be the thing that breaks a run.

Run by claude as: python3 <abs path>/scope_hook.py   (stdin = PreToolUse JSON)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _allow():
    sys.exit(0)  # no output = allow


def main():
    roster_path = os.environ.get("KIPI_SCOPE_ROSTER")
    if not roster_path or not os.path.exists(roster_path):
        _allow()
    try:
        from investigations.agent import scope
        event = json.load(sys.stdin)
        roster = scope.normalize_roster(open(roster_path).read().splitlines())
        allow, reason = scope.gate(event.get("tool_name", ""), event.get("tool_input", {}) or {}, roster)
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
