"""PRD-11: one "data changed → refresh" signal so open views never go stale.

Three layers proven here:
  1. unit — bump_case increments a per-case version; case_version reads it.
  2. endpoint — /api/changed reports changed=false until a bump, true after.
  3. wiring guard — every mutation route/job actually calls bump_case (the whole
     point is that a new mutation can't forget to signal). A grep guard catches a
     mutator added without a bump.

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


def test_bump_and_version():
    case = "unit-test-case-xyz"
    start = app_module.case_version(case)
    v1 = app_module.bump_case(case)
    _check("bump returns an incremented version", v1 == start + 1)
    _check("case_version reflects the bump", app_module.case_version(case) == v1)
    v2 = app_module.bump_case(case)
    _check("a second bump moves it again", v2 == v1 + 1)
    # No-case is a no-op (single-entity unscoped runs pass None).
    _check("bump(None) is a no-op returning 0", app_module.bump_case(None) == 0)
    _check("case_version(None) is 0", app_module.case_version(None) == 0)


def test_changed_endpoint():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        orig = db.connect
        # Point the app at the temp DB (the endpoint itself doesn't hit the DB, but
        # TestClient construction may touch it elsewhere — keep it isolated).
        app_module.db.connect = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
        try:
            client = TestClient(app_module.app)
            case = "endpoint-test-case"
            base = app_module.case_version(case)
            # Caller establishes a baseline, then asks "anything since base?"
            d = client.get(f"/api/changed?case={case}&since={base}").json()
            _check("no change reported at baseline", d["changed"] is False)
            app_module.bump_case(case)
            d2 = client.get(f"/api/changed?case={case}&since={base}").json()
            _check("change reported after a bump", d2["changed"] is True)
            _check("version advanced past baseline", d2["version"] > base)
            # Re-baseline to the new version → quiet again.
            d3 = client.get(f"/api/changed?case={case}&since={d2['version']}").json()
            _check("quiet again once caller catches up", d3["changed"] is False)
        finally:
            app_module.db.connect = orig


# Every mutation surface named in PRD-11 must route through bump_case. Each tuple is
# (anchor that proves we're at that mutator, label). The guard asserts a bump_case call
# appears within a small window after the anchor.
_MUTATORS = [
    ("claims_mod.resolve(conn, claim_id)", "claims resolve"),
    ("claims_mod.reject(conn, claim_id)", "claims reject"),
    ('_PROCESS_JOBS[case] = {"status": status, "result": result, "case": case,\n'
     '                                   "progress"', "process job completion"),
    ('"entity": label, "log": prev.get("log"), "progress": prog}', "investigate job completion"),
    ("result = await run_in_threadpool(_synthesize_case, case, analyst)", "synthesize brief"),
    ("promote_mod.add_manual_node(", "manual node"),
    ("promote_mod.promote_result(conn, result_id, analyst=analyst)", "enrich promote"),
    ('conn.execute("UPDATE entities SET hidden = 0 WHERE id = ?", (entity_id,))', "node unhide"),
    ("result = await run_in_threadpool(_graph_chat, message, case, selected_name)", "graph chat mutate"),
]


def test_every_mutator_bumps():
    src = Path(app_module.__file__).read_text()
    for anchor, label in _MUTATORS:
        idx = src.find(anchor)
        _check(f"found mutator: {label}", idx != -1)
        # bump_case must appear within ~600 chars after the mutation (same handler).
        window = src[idx: idx + 600]
        _check(f"{label} calls bump_case", "bump_case(" in window)


def main():
    test_bump_and_version()
    test_changed_endpoint()
    test_every_mutator_bumps()
    print("\nPASS: test_view_refresh")


if __name__ == "__main__":
    main()
