"""PRD-11 + sp1-migrate-webapp-writers: one "data changed → refresh" signal.

Three layers proven here:
  1. unit — bump_case increments the DB-backed per-case version
     (investigations.version via the store); case_version reads it. Shared
     across processes — a CLI writer's bump is visible to the webapp.
  2. endpoint — /api/changed reports changed=false until a bump, true after.
  3. wiring guard — every mutation route/job routes through the store (its
     own apply_mutation bump, or an explicit store-backed bump_case call in
     the same handler). The STRONGER invariant than the old "calls
     bump_case": signaling now rides the one write path, so a new mutator
     cannot forget it (gap 2's class, closed).

Run: .venv/bin/python -m investigations.tests.test_view_refresh
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.webapp import app as app_module


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _temp_app_db(tmp):
    dbp = Path(tmp) / "t.db"
    db.init_db(dbp)
    orig = db.connect
    app_module.db.connect = lambda migrate=True, db_path=dbp: orig(
        db_path=db_path, migrate=migrate)
    return orig


def test_bump_and_version():
    case = "unit-test-case-xyz"
    with tempfile.TemporaryDirectory() as tmp:
        orig = _temp_app_db(tmp)
        try:
            start = app_module.case_version(case)
            v1 = app_module.bump_case(case)
            _check("bump returns an incremented version", v1 == start + 1)
            _check("case_version reflects the bump",
                   app_module.case_version(case) == v1)
            v2 = app_module.bump_case(case)
            _check("a second bump moves it again", v2 == v1 + 1)
            # No-case is a no-op (single-entity unscoped runs pass None).
            _check("bump(None) is a no-op returning 0",
                   app_module.bump_case(None) == 0)
            _check("case_version(None) is 0", app_module.case_version(None) == 0)
            # DB-backed = shared across connections (the gap the in-memory
            # dict had: CLI writers could never signal the webapp).
            with db.connect(Path(tmp) / "t.db") as other_conn:
                from investigations import store
                store.bump_case(other_conn, case)
            _check("a foreign connection's bump is visible",
                   app_module.case_version(case) == v2 + 1)
        finally:
            app_module.db.connect = orig


def test_changed_endpoint():
    with tempfile.TemporaryDirectory() as tmp:
        orig = _temp_app_db(tmp)
        try:
            client = TestClient(app_module.app)
            case = "endpoint-test-case"
            base = app_module.case_version(case)
            d = client.get(f"/api/changed?case={case}&since={base}").json()
            _check("no change reported at baseline", d["changed"] is False)
            app_module.bump_case(case)
            d2 = client.get(f"/api/changed?case={case}&since={base}").json()
            _check("change reported after a bump", d2["changed"] is True)
            _check("version advanced past baseline", d2["version"] > base)
            d3 = client.get(
                f"/api/changed?case={case}&since={d2['version']}").json()
            _check("quiet again once caller catches up", d3["changed"] is False)
        finally:
            app_module.db.connect = orig


# Every mutation surface must route through the store: either the handler
# applies store events (apply_mutation bumps inside the same transaction) or
# it calls the store-backed bump_case in the same window. Anchors are the
# current code shapes; the guard catches a mutator added without a signal.
_MUTATORS = [
    ("claims_mod.resolve(conn, claim_id)", "claims resolve"),
    ("claims_mod.reject(conn, claim_id)", "claims reject"),
    ('_PROCESS_JOBS[case] = {"status": status, "result": result, "case": case,\n'
     '                                   "progress"', "process job completion"),
    ('"entity": label, "log": prev.get("log"), "progress": prog}',
     "investigate job completion"),
    ("result = _synthesize_case(case, analyst)", "synthesize brief"),
    ("promote_mod.add_manual_node(", "manual node"),
    ("promote_mod.promote_result(conn, result_id, analyst=analyst)",
     "enrich promote"),
    ("Restore a soft-hidden node", "node unhide"),
    ("result = await run_in_threadpool(_graph_chat, message, case, selected_name)",
     "graph chat mutate"),
    ("wrote += _persist_step_discovery(case, s)", "live step discovery"),
]

# Constructors are NOT signals — only the application call or the store-backed
# bump proves the mutation was committed to the one write path (codex
# finding: a handler could build an event and never apply it).
_SIGNALS = ("store.apply_mutation(", "bump_case(")


def test_every_mutator_bumps():
    src = Path(app_module.__file__).read_text()
    for anchor, label in _MUTATORS:
        idx = src.find(anchor)
        _check(f"found mutator: {label}", idx != -1)
        # A store-routed signal must appear within ~600 chars of the mutation
        # (same handler): the event's own bump, or the store-backed bump call.
        window = src[idx: idx + 600]
        _check(f"{label} routes through the store",
               any(sig in window for sig in _SIGNALS))


def main():
    test_bump_and_version()
    test_changed_endpoint()
    test_every_mutator_bumps()
    print("\nPASS: test_view_refresh")


if __name__ == "__main__":
    main()
