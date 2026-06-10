"""Streaming + Stop for the chat-led investigator.

prd-chat-stream-control / issue-chat-stream-control. Offline + deterministic: a
fake SDK client drives _collect; the warm loop is faked at the /api/chat layer.

Run: .venv/bin/python3 -m investigations.tests.test_chat_stream

Asserts every acceptance criterion:
  - on_step fires once per NEWLY-appended step through WarmSession.ask/_collect
    (text + tool_use append; a tool_result mutates the pending step, no re-emit)
  - cooperative cancel: a set cancel Event makes _collect break, set capped, call
    _safe_interrupt, and return the accumulated partial
  - /api/chat warm path returns mode:job; the job records live steps then ends
    with the reply persisted (poll /api/chat/status)
  - /api/chat/stop sets the cancel and the partial is salvaged + persisted (stopped)
"""
import asyncio
import tempfile
import time
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.webapp import app as app_module
from investigations.agent import investigator as inv
from investigations.agent import warm_session as ws
from investigations.agent.warm_session import WarmSession


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


# --- fake SDK message blocks / client (duck-typed, mirrors test_warm_session) ----
class _Text:
    def __init__(self, text): self.text = text


class _ToolUse:
    def __init__(self, name, id): self.name = name; self.id = id; self.input = {}
    text = None


class _ToolResult:
    def __init__(self, tool_use_id, content):
        self.tool_use_id = tool_use_id; self.content = content
    text = None
    name = None


class _Msg:
    def __init__(self, blocks): self.content = blocks


class _Result:
    is_result = True
    content = []


class FakeClient:
    def __init__(self, messages):
        self._messages = messages
        self.interrupted = False

    async def connect(self): pass
    async def disconnect(self): pass
    async def query(self, task): pass
    async def interrupt(self): self.interrupted = True

    def receive_response(self):
        async def gen():
            for m in self._messages:
                yield m
        return gen()


def test_on_step_emits_each_new_step():
    msgs = [
        _Msg([_Text("thinking about it"), _ToolUse("dns_lookup", "t1")]),
        _Msg([_ToolResult("t1", "1.2.3.4")]),   # mutates pending step, no new append
        _Result(),
    ]
    session = WarmSession("case-x", FakeClient(msgs))
    seen = []
    out = asyncio.run(session.ask("go", on_step=seen.append))
    _check("on_step fired once per new step (reasoning + tool, not the result-fill)",
           len(seen) == 2)
    _check("first emitted step is the reasoning text", seen[0].get("type") == "reasoning")
    _check("second emitted step is the tool call", seen[1].get("type") == "tool")
    _check("tool step's result was filled in place (same dict)", seen[1].get("result") is not None)
    _check("turn returned ok with both steps", out["ok"] and len(out["steps"]) == 2)


def test_cooperative_cancel_salvages_partial():
    import threading
    # Pre-set cancel → _collect breaks on the first loop check, before consuming.
    cancel = threading.Event(); cancel.set()
    fake = FakeClient([_Msg([_Text("should not be reached")]), _Result()])
    session = WarmSession("case-c", fake)
    out = asyncio.run(session.ask("go", cancel=cancel))
    _check("cancelled turn is capped", out["capped"] is True)
    _check("cancelled turn returns a (partial) result dict", out["ok"] is True)
    _check("cancelled turn salvaged no steps (broke immediately)", out["steps"] == [])
    _check("_safe_interrupt was called on cancel", fake.interrupted is True)


def test_cancel_mid_await_salvages_streamed_steps():
    """Stop pressed WHILE _collect awaits the next message must still return the
    steps already streamed (the finding-1 race fix: cooperative cancel re-checks
    mid-await; no hard future-cancel pre-empts the partial)."""
    import threading

    class BlockingClient(FakeClient):
        def receive_response(self):
            async def gen():
                yield _Msg([_Text("first thought"), _ToolUse("dns_lookup", "t1")])
                await asyncio.sleep(5)   # stream stalls — Stop must break the await
                yield _Result()
            return gen()

    cancel = threading.Event()
    session = WarmSession("case-m", BlockingClient([]))

    async def run():
        loop = asyncio.get_event_loop()
        loop.call_later(0.2, cancel.set)   # Stop fires during the stalled await
        return await session.ask("go", cancel=cancel)

    out = asyncio.run(run())
    _check("mid-await cancel is capped", out["capped"] is True)
    _check("mid-await cancel salvaged the already-streamed steps", len(out["steps"]) == 2)
    _check("mid-await cancel returned the partial text", "first thought" in out["result_text"])


# --- /api/chat job integration ---------------------------------------------------
_ORIG = {"warm": inv.warm_run_available, "warm_loop": ws.run_turn_on_warm_loop,
         "connect": db.connect}


def _restore():
    inv.warm_run_available = _ORIG["warm"]
    ws.run_turn_on_warm_loop = _ORIG["warm_loop"]
    app_module.db.connect = _ORIG["connect"]
    app_module._CHAT_JOBS.clear(); app_module._CHAT_CANCEL.clear()


def _client(dbp):
    orig = _ORIG["connect"]
    app_module.db.connect = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
    app_module._CHAT_JOBS.clear(); app_module._CHAT_CANCEL.clear()
    return TestClient(app_module.app)


def _poll(client, case, tries=200):
    for _ in range(tries):
        job = client.get("/api/chat/status", params={"case": case}).json()
        if job.get("status") in ("done", "stopped", "error", "idle"):
            return job
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_chat_job_streams_and_persists():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True

            def fake_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                # stream two live steps, then return the final reply
                if on_step:
                    on_step({"type": "tool", "tool": "dns_lookup", "text": "lookup", "result": "ok"})
                    on_step({"type": "reasoning", "text": "found the IP"})
                return {"ok": True, "result_text": "done: 1 IP", "tools": ["dns_lookup"],
                        "steps": [{"n": 1, "type": "tool"}], "capped": False}
            ws.run_turn_on_warm_loop = fake_warm

            r = client.post("/api/chat", json={"case": "case-j", "message": "dig in"})
            _check("warm path returns mode:job/started", r.json() == {"mode": "job", "status": "started"})
            job = _poll(client, "case-j")
            _check("job ended done", job["status"] == "done")
            _check("job reply present", job["reply"] == "done: 1 IP")
            _check("job streamed live steps", len(job.get("steps") or []) >= 1)
            with _ORIG["connect"](dbp) as conn:
                rows = db.get_chat_turns(conn, "case-j")
            _check("analyst + agent persisted", [x["role"] for x in rows] == ["analyst", "agent"])
            _check("agent turn holds the reply", rows[1]["text"] == "done: 1 IP")
        finally:
            _restore()


def test_stop_salvages_partial():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True

            def slow_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                # run until the analyst Stops, then salvage the partial (cooperative)
                for _ in range(500):
                    if cancel is not None and cancel.is_set():
                        break
                    time.sleep(0.01)
                return {"ok": True, "result_text": "partial work so far",
                        "tools": [], "steps": [], "capped": True}
            ws.run_turn_on_warm_loop = slow_warm

            r = client.post("/api/chat", json={"case": "case-s", "message": "long run"})
            _check("job started", r.json()["status"] == "started")
            # let it spin, then Stop
            time.sleep(0.1)
            stop = client.post("/api/chat/stop", json={"case": "case-s"}).json()
            _check("stop acknowledged a running job", stop["ok"] is True)
            job = _poll(client, "case-s")
            _check("stopped job status", job["status"] == "stopped")
            _check("partial salvaged into the reply", job["reply"] == "partial work so far")
            with _ORIG["connect"](dbp) as conn:
                rows = db.get_chat_turns(conn, "case-s")
            _check("stopped turn still persisted analyst + agent",
                   [x["role"] for x in rows] == ["analyst", "agent"])
        finally:
            _restore()


def main():
    test_on_step_emits_each_new_step()
    test_cooperative_cancel_salvages_partial()
    test_cancel_mid_await_salvages_streamed_steps()
    test_chat_job_streams_and_persists()
    test_stop_salvages_partial()
    print("\nALL PASS: test_chat_stream")


if __name__ == "__main__":
    main()
