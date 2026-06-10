"""Process pipeline reports live per-step progress: the job seeds a pending
checklist, flips each step running -> ok/skipped as it executes, and the panel
reads it off /api/process/status.

Run: .venv/bin/python -m investigations.tests.test_process_progress
"""
from investigations.webapp import app as app_module


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_step_keys_match_pipeline():
    # The progress manifest keys must match the _step() names the pipeline calls,
    # or the bar would show steps that never move. Guard against drift.
    keys = {k for k, _ in app_module.PROCESS_STEPS}
    expected = {"reextract", "consolidate", "typing", "correlate",
                "cross_domain", "analyze", "graph_metrics", "synthesize", "dossiers"}
    _check("PROCESS_STEPS keys match the pipeline steps", keys == expected)


def test_progress_updates_live_and_final():
    case = "test-prog-case"
    orig = app_module._process_case
    mid_snapshot = {}

    def fake(c, analyst, on_step=None, on_progress=None):
        on_step("reextract", "running"); on_step("reextract", "ok")
        on_step("consolidate", "running"); on_step("consolidate", "skipped")
        on_step("typing", "running")  # leave running -> simulates mid-flight
        # Snapshot what the status endpoint would return RIGHT NOW.
        prog = app_module._PROCESS_JOBS[c]["progress"]
        mid_snapshot.update({s["key"]: s["status"] for s in prog["steps"]})
        on_step("typing", "ok")
        return {"ok": True, "case": c, "steps": {}}

    app_module._process_case = fake
    try:
        app_module._process_case_job(case, "tester")
        job = app_module._PROCESS_JOBS[case]
        prog = job["progress"]
        st = {s["key"]: s["status"] for s in prog["steps"]}
        _check("mid-run snapshot saw reextract done", mid_snapshot.get("reextract") == "ok")
        _check("mid-run snapshot saw typing running", mid_snapshot.get("typing") == "running")
        _check("final status is done", job["status"] == "done")
        _check("reextract ok in final", st["reextract"] == "ok")
        _check("consolidate skipped in final", st["consolidate"] == "skipped")
        _check("typing ok in final", st["typing"] == "ok")
        _check("untouched step stays pending", st["dossiers"] == "pending")
        _check("total reflects manifest length", prog["total"] == len(app_module.PROCESS_STEPS))
    finally:
        app_module._process_case = orig
        app_module._PROCESS_JOBS.pop(case, None)


if __name__ == "__main__":
    test_step_keys_match_pipeline()
    test_progress_updates_live_and_final()
    print("\nPASS: test_process_progress")
