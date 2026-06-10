"""Schema handling on Process (founder decision 2026-06-10: no human approval
step — the tool auto-models the case schema inline).

Two invariants:
  - an existing PROPOSED schema is AUTO-APPROVED and reused, never re-discovered
    (the old "stuck at 0% re-running discover_schema" bug must not return);
  - Process never returns needs_approval — it runs straight through.

Run: .venv/bin/python -m investigations.tests.test_process_schema_gate
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations import understand as understand_mod
from investigations.webapp import app as app_module
from investigations.tests.test_understand import CRYPTO_SCHEMA


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


def _seed_case_with_proposed_schema(db_path: Path):
    db.init_db(db_path)
    with db.connect(db_path) as conn:
        conn.execute("INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?,?)",
                     ("cat-flower", "Cat Flower"))
        db.insert_report(conn, "r.md", "h1", "markdown", "body", "cat-flower", "x")
        understand_mod.save_schema(conn, "cat-flower", CRYPTO_SCHEMA, status="proposed")
        conn.commit()


def test_existing_schema_is_auto_approved_not_rediscovered(mp):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        _seed_case_with_proposed_schema(db_path)

        orig_connect = db.connect
        mp.setattr(app_module.db, "connect",
                   lambda migrate=True, db_path=db_path: orig_connect(db_path=db_path, migrate=migrate))

        # Tripwire: discovery must NOT run when a schema already exists.
        called = {"discover": 0}
        def boom(conn, case):
            called["discover"] += 1
            raise AssertionError("discover_schema must not run for an existing schema")
        mp.setattr(understand_mod, "discover_schema", boom)

        # The gate auto-approves the existing proposed schema and returns None
        # (no needs_approval), without re-discovering.
        gate = app_module._schema_gate("cat-flower", "tester")
        _check("gate returns None (no approval step)", gate is None)
        _check("discover_schema was NOT called", called["discover"] == 0)
        with db.connect(db_path) as conn:
            _check("schema is now approved",
                   understand_mod.approved_schema(conn, "cat-flower") is not None)


def test_process_never_returns_needs_approval(mp):
    # The HTTP Process path must not bounce to /schema anymore.
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        _seed_case_with_proposed_schema(db_path)
        orig_connect = db.connect
        mp.setattr(app_module.db, "connect",
                   lambda migrate=True, db_path=db_path: orig_connect(db_path=db_path, migrate=migrate))
        # Stub the heavy pipeline so we only exercise the gate/dispatch, not LLM steps.
        mp.setattr(app_module, "_process_case",
                   lambda case, analyst, on_step=None, on_progress=None: {"ok": True, "case": case})
        app_module._PROCESS_JOBS.clear()
        client = TestClient(app_module.app)
        r = client.post("/api/process",
                        headers={"cookie": f"{app_module.CASE_COOKIE}=cat-flower"})
        _check("POST does not return needs_approval", r.json().get("status") != "needs_approval")


def main():
    mp = _MP()
    try:
        test_existing_schema_is_auto_approved_not_rediscovered(mp)
        mp.undo(); mp = _MP()
        test_process_never_returns_needs_approval(mp)
    finally:
        mp.undo()
    print("\nPASS: test_process_schema_gate")


if __name__ == "__main__":
    main()
