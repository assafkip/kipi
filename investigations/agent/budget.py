"""Deterministic in-flight tool-call budget (RULE-114, "cap the function, not the time").

The cold case run already has two bounds: a per-pass TIMEOUT (a generous circuit-breaker)
and a between-pass USD COST CAP. Neither bounds a SINGLE pass IN-FLIGHT — a pass that loops
on tools without finishing burns cost the between-pass check only sees AFTER the pass ends
(and a cut-off pass reports cost_usd=0, so the meter never catches it). This caps the one
quantity the hook can observe deterministically per call: the number of tool calls. It is a
circuit-breaker, not the control — the agent concludes well under the cap on a normal run.

Pure + dependency-free (json + os only) so the PreToolUse hook subprocess can import it.
A budget file is one JSON object {"cap": int, "count": int}; each tool call charges 1.
"""
from __future__ import annotations

import json
import os


def read_state(path: str) -> tuple[int, int]:
    """(cap, count) from the budget file. (0, 0) if unreadable → caller treats cap 0 as
    'no budget' and allows (fail open)."""
    try:
        with open(path) as f:
            data = json.load(f)
        return int(data.get("cap", 0)), int(data.get("count", 0))
    except Exception:
        return 0, 0


def check_and_charge(path: str) -> tuple[bool, int, int]:
    """Charge one tool call against the budget file and return (allow, count, cap).
    allow is False once the charged count EXCEEDS the cap. cap <= 0 → unbudgeted → always
    allow (and don't bother writing). Single-writer per run (one budget file per _run_agent
    subprocess), and an agent's tool calls are sequential, so a plain read-modify-write is
    race-free here."""
    cap, count = read_state(path)
    if cap <= 0:
        return True, count, cap
    count += 1
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"cap": cap, "count": count}, f)
        os.replace(tmp, path)
    except Exception:
        # Can't persist the charge — fail open rather than wedge the run on a disk error.
        return True, count, cap
    return count <= cap, count, cap


def deny_message(count: int, cap: int) -> str:
    return (f"tool budget exhausted: {count} of {cap} tool calls used this run. STOP "
            "investigating and emit your findings JSON NOW — the run is being bounded "
            "(RULE-114, cap the function not the time). Surface any entity you have not "
            "reached yet as a LEAD in recommended_pivots; the analyst expands the rest.")


def write_budget(path: str, cap: int) -> None:
    """Initialise a budget file with a fresh count. Called per run by the agent launcher."""
    with open(path, "w") as f:
        json.dump({"cap": int(cap), "count": 0}, f)
