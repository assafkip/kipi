"""Process runs as a BACKGROUND job: POST returns instantly, status polls to done.

This is the fix for "Process stops working when I change tab" — the job lives on
the server, not the HTTP request, so navigating away never kills it.

Run: .venv/bin/python -m investigations.tests.test_process_job
"""
import time

from starlette.testclient import TestClient

from investigations.webapp import app as app_module


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


def test_background_process_flow(mp):
    # Stub the heavy pipeline with a short sleep so the test is fast but still
    # proves the POST returns BEFORE the job finishes.
    def fake_process(case, analyst, on_step=None, on_progress=None):
        time.sleep(0.6)
        return {"ok": True, "case": case, "steps": {"x": "ok"}}
    mp.setattr(app_module, "_process_case", fake_process)
    # This test exercises the background-JOB mechanics, not the schema gate — open it.
    mp.setattr(app_module, "_schema_gate", lambda case, analyst: None)
    app_module._PROCESS_JOBS.clear()

    client = TestClient(app_module.app)
    client.cookies.set(app_module.CASE_COOKIE, "tab-test-case")

    t0 = time.time()
    r = client.post("/api/process")
    elapsed = time.time() - t0
    _check("POST returns quickly (did not block on the 0.6s job)", elapsed < 0.4)
    _check("POST reports the job started", r.json().get("status") == "started")

    # Immediately after, status is 'running' (job still in flight).
    s1 = client.get("/api/process/status").json()
    _check("status is running while the job runs", s1.get("status") == "running")

    # Simulate the user switching tabs: just wait, then poll again. The job keeps
    # going server-side regardless.
    deadline = time.time() + 5
    final = s1
    while time.time() < deadline:
        final = client.get("/api/process/status").json()
        if final.get("status") != "running":
            break
        time.sleep(0.2)
    _check("job completed server-side (survives 'leaving the page')", final.get("status") == "done")
    _check("result is available on poll", final.get("result", {}).get("ok") is True)


def main():
    mp = _MP()
    try:
        test_background_process_flow(mp)
    finally:
        mp.undo()
    print("\nPASS: test_process_job")


if __name__ == "__main__":
    main()
