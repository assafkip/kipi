"""4pa-04 — replace the 4-subprocess crew with in-session warm fan-out.

The cold crew fans each target into 4 metered `claude -p` subprocesses (one per
ROLE_AGENT). Under KIPI_WARM_SESSION the same roles run as warm turns on the ONE
per-case session — ZERO new subprocesses, same merged-output shape.

Deterministic + offline: the warm runner is stubbed; the cold _run_agent is
patched to a counter that proves it is NEVER called (== zero claude -p spawns).

Run: .venv/bin/python -m investigations.tests.test_insession_fanout
"""
import os
import json
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.agent import investigator


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _canned_role_result(task, case, timeout=600, cancel=None):
    # One finding per role keyed off the role word in the task, so the merge has content.
    role = "infra" if "INFRASTRUCTURE" in task else "page" if "live site" in task else \
           "reputation" if "REPUTATION" in task else "attribution"
    return {"ok": True, "raw": {"total_cost_usd": 0.0}, "events": [], "steps": [],
            "capped": False, "cancelled": False, "stderr_tail": "", "returncode": 0,
            "result_text": json.dumps({
                "findings": [{"entity": f"{role}-finding.com", "entity_type": "domain",
                              "claim": f"{role} hit", "provenance": "tool",
                              "confidence": "low", "unvalidated": True}],
                "summary": f"{role} done"})}


def test_warm_crew_spawns_zero_subprocesses():
    mp = _MP()
    cold_calls = {"n": 0}

    def _cold_counter(*a, **k):
        cold_calls["n"] += 1
        raise AssertionError("cold _run_agent (claude -p) called under warm fan-out")

    warm_calls = {"n": 0}

    def _warm_counter(task, case, timeout=600, cancel=None):
        warm_calls["n"] += 1
        return _canned_role_result(task, case, timeout, cancel)

    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            tgt = db.upsert_entity(conn, "target-x.com", "domain", rid)
            db.add_mention(conn, tgt, rid, "target-x.com", "seed")

        mp.setattr(os, "environ", {**os.environ, "KIPI_WARM_SESSION": "1"})
        # Explicit opt-in over the conftest warm-unavailable guard (runner
        # faked below, so this stays offline).
        mp.setattr(investigator, "warm_run_available", lambda: True)
        mp.setattr(investigator, "_run_agent", _cold_counter)
        mp.setattr(investigator, "_run_agent_warm", _warm_counter)
        try:
            with db.connect(dbp) as conn:
                res = investigator.investigate_entity_crew(conn, "target-x.com", "cx")
        finally:
            mp.undo()

    n_roles = len(investigator.ROLE_AGENTS)
    _check("zero claude -p subprocesses spawned for the warm crew", cold_calls["n"] == 0)
    _check("each role ran as a warm turn (in-session fan-out)", warm_calls["n"] == n_roles)
    # Same merged-output shape as the cold crew.
    _check("crew returned ok", res.get("ok"))
    for key in ("entity", "case", "findings", "cost_usd", "crew"):
        _check(f"merged output keeps '{key}'", key in res)
    _check("all roles represented in the merge", len(res["crew"]) == n_roles)
    _check("merged findings landed", res["findings"] >= 1)


def main():
    test_warm_crew_spawns_zero_subprocesses()
    print("PASS test_insession_fanout: warm crew runs roles in-session (zero claude -p "
          "subprocesses), same merged-output shape as the cold 4-subprocess crew")


if __name__ == "__main__":
    main()
