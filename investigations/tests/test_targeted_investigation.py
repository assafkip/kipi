"""PRD-07: run the full agent on an analyst-chosen set of nodes (multi-select), no
planner. Verifies investigate_selected dispatches exactly the chosen targets, dedups,
caps, emits the progress marker, and never invokes the planner.

Run: .venv/bin/python -m investigations.tests.test_targeted_investigation
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.agent import swarm


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def _fake_one(entity, case, max_turns, on_event=None):
    return {"ok": True, "entity": entity, "findings": 1, "promoted": 1}


def _planner_must_not_run(*a, **k):
    raise AssertionError("planner was called — selected runs must skip planning")


def test_selected_set_dispatches_exactly(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        calls = []
        mp.setattr(swarm, "_investigate_one",
                   lambda e, c, m, on_event=None: (calls.append(e) or _fake_one(e, c, m)))
        mp.setattr(swarm, "plan_investigation", _planner_must_not_run)
        events = []
        with db.connect(dbp) as conn:
            res = swarm.investigate_selected(conn, "cx", ["Alice", "bob", "Alice ", " "],
                                             on_event=events.append)
        _check("dedup + blank-strip → 2 targets", res["targets"] == 2)
        _check("dispatched exactly the 2 unique targets", sorted(calls) == ["Alice", "bob"])
        _check("findings summed from the set", res["findings"] == 2)
        _check("emitted the 'picked N' progress marker",
               any(e.startswith("picked 2 target(s)") for e in events))


def test_selected_set_caps(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        calls = []
        mp.setattr(swarm, "_investigate_one",
                   lambda e, c, m, on_event=None: (calls.append(e) or _fake_one(e, c, m)))
        mp.setattr(swarm, "plan_investigation", _planner_must_not_run)
        many = [f"node{i}" for i in range(20)]
        with db.connect(dbp) as conn:
            res = swarm.investigate_selected(conn, "cx", many)
        _check("caps the dispatched set at DEFAULT_LIMIT",
               res["targets"] == swarm.DEFAULT_LIMIT and len(calls) == swarm.DEFAULT_LIMIT)


def test_empty_selection_is_safe(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        mp.setattr(swarm, "plan_investigation", _planner_must_not_run)
        with db.connect(dbp) as conn:
            res = swarm.investigate_selected(conn, "cx", ["  ", ""])
        _check("empty selection → ok, 0 targets, no planner", res["ok"] and res["targets"] == 0)


def main():
    for fn in (test_selected_set_dispatches_exactly, test_selected_set_caps,
               test_empty_selection_is_safe):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_targeted_investigation")


if __name__ == "__main__":
    main()
