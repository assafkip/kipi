"""UI -> chat memory bridge: canvas actions feed the chat agent's next turn.

prd-chat-ui-memory-bridge / issue-chat-ui-memory-bridge. Offline + deterministic:
the warm turn is faked; the high-water mark is reset per test.

Run: .venv/bin/python3 -m investigations.tests.test_ui_memory_bridge

Asserts every acceptance criterion:
  - role constants have the exact expected string values
  - record_ui_event writes a ui_event turn for a case; no-op (no raise) on blank
  - _consume_ui_events returns ui_events past the mark, advances it (no repeat),
    and a later event is still picked up (high-water mark, not dropped)
  - a UI mutation endpoint (/api/node/{id}/unhide) records to the active case
  - /api/chat prepends un-consumed UI events to the warm task ONCE; the next turn
    has no prefix; an event recorded between turns is injected on the next turn
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.webapp import app as app_module
from investigations.agent import investigator as inv
from investigations.agent import warm_session as ws

_ORIG = {"warm": inv.warm_run_available, "warm_loop": ws.run_turn_on_warm_loop,
         "connect": db.connect}


def _restore():
    inv.warm_run_available = _ORIG["warm"]
    ws.run_turn_on_warm_loop = _ORIG["warm_loop"]
    app_module.db.connect = _ORIG["connect"]
    app_module._UI_SEEN.clear()
    app_module._CHAT_JOBS.clear(); app_module._CHAT_CANCEL.clear()


def _poll(client, case, timeout=20.0):
    """Wait for the warm chat job (async) to finish, so captured tasks are set.
    Wall-clock deadline (not a fixed iteration count) so it doesn't flake when the
    background thread is starved under full-suite CPU load."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get("/api/chat/status", params={"case": case}).json()
        if job.get("status") in ("done", "stopped", "error", "idle"):
            return job
        time.sleep(0.05)
    raise AssertionError("chat job did not finish")


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _client(dbp):
    orig = _ORIG["connect"]
    app_module.db.connect = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
    app_module._UI_SEEN.clear()
    app_module._CHAT_JOBS.clear(); app_module._CHAT_CANCEL.clear()
    return TestClient(app_module.app)


def test_role_constants():
    _check("ROLE_ANALYST", app_module.ROLE_ANALYST == "analyst")
    _check("ROLE_AGENT", app_module.ROLE_AGENT == "agent")
    _check("ROLE_UI_EVENT", app_module.ROLE_UI_EVENT == "ui_event")
    _check("ROLE_SYSTEM", app_module.ROLE_SYSTEM == "system")


def test_record_and_consume():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        orig = _ORIG["connect"]
        app_module.db.connect = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
        app_module._UI_SEEN.clear()
        try:
            # blank case is a no-op, never raises
            app_module.record_ui_event("", "should not persist")
            app_module.record_ui_event(None, "should not persist")
            with db.connect(dbp) as conn:
                _check("blank case wrote nothing", db.get_chat_turns(conn, "") == [])

            app_module.record_ui_event("case-c", "added node a.com")
            app_module.record_ui_event("case-c", "launched an investigation on b.com")
            with db.connect(dbp) as conn:
                rows = db.get_chat_turns(conn, "case-c")
                _check("two ui_event turns recorded",
                       [r["role"] for r in rows] == ["ui_event", "ui_event"])
                peek = app_module._peek_ui_events(conn, "case-c")
            _check("peek returns both un-seen events",
                   [r["text"] for r in peek] == ["added node a.com", "launched an investigation on b.com"])
            # peek alone does NOT consume (the agent hasn't received them yet)
            with db.connect(dbp) as conn:
                _check("peek is side-effect-free (still unseen)",
                       len(app_module._peek_ui_events(conn, "case-c")) == 2)
            # advance only after the agent received them
            app_module._advance_ui_mark("case-c", peek[-1]["id"])
            with db.connect(dbp) as conn:
                _check("after advance, nothing unseen", app_module._peek_ui_events(conn, "case-c") == [])

            # an event recorded later is still picked up (high-water mark, not dropped)
            app_module.record_ui_event("case-c", "promoted finding x")
            with db.connect(dbp) as conn:
                later = app_module._peek_ui_events(conn, "case-c")
            _check("later event picked up on next peek",
                   [r["text"] for r in later] == ["promoted finding x"])
        finally:
            _restore()


def test_unhide_endpoint_records_event():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rep = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-ui", "x")
            eid = db.upsert_entity(conn, "ghost.com", "domain", rep)
            conn.execute("UPDATE entities SET hidden = 1 WHERE id = ?", (eid,))
            conn.commit()
        client = _client(dbp)
        try:
            client.cookies.set(app_module.CASE_COOKIE, "case-ui")
            r = client.post(f"/api/node/{eid}/unhide")
            _check("unhide ok", r.status_code == 200 and r.json().get("ok"))
            with db.connect(dbp) as conn:
                evs = [t for t in db.get_chat_turns(conn, "case-ui") if t["role"] == "ui_event"]
            _check("unhide recorded a ui_event for the active case", len(evs) == 1)
            _check("ui_event names the restored node", "ghost.com" in evs[0]["text"])
        finally:
            _restore()


def test_chat_injects_ui_events_once():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True
            tasks = []

            # warm /api/chat is now a background job (prd-chat-stream-control); the
            # fake captures the task it received, and we poll the job to completion
            # before asserting (and before the next turn starts).
            def fake_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                tasks.append(task)
                return {"ok": True, "result_text": "ack", "tools": [], "steps": [], "capped": False}
            ws.run_turn_on_warm_loop = fake_warm

            def chat(msg):
                client.post("/api/chat", json={"case": "case-z", "message": msg})
                _poll(client, "case-z")

            # analyst did something on the canvas, then chats
            app_module.record_ui_event("case-z", "added node evil.com")
            chat("what did i just add?")
            _check("first warm task carries the UI event",
                   "added node evil.com" in tasks[0] and "what did i just add?" in tasks[0])

            # next turn with no new UI action: no prefix (consumed). The task always
            # carries the findings contract suffix (issue warm-lands-findings), so the
            # message leads it — assert no UI prefix was prepended, not byte-equality.
            chat("anything else?")
            _check("second warm task has no UI prefix",
                   "Since your last reply" not in tasks[1] and tasks[1].startswith("anything else?"))

            # a UI action between turns is injected on the following turn (not dropped)
            app_module.record_ui_event("case-z", "promoted finding wallet-1")
            chat("ok")
            _check("a between-turns UI event is injected next turn",
                   "promoted finding wallet-1" in tasks[2])

            # a FAILED warm turn must NOT consume the UI event — it re-injects next time
            app_module.record_ui_event("case-z", "added node retry.com")

            def fail_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                tasks.append(task)
                return {"ok": False, "error": "boom"}
            ws.run_turn_on_warm_loop = fail_warm
            chat("go")
            _check("failed turn still carried the prefix", "added node retry.com" in tasks[3])
            ws.run_turn_on_warm_loop = fake_warm  # warm recovers
            chat("again")
            _check("event re-injected after a failed turn (not consumed on failure)",
                   "added node retry.com" in tasks[4])
        finally:
            _restore()


def main():
    test_role_constants()
    test_record_and_consume()
    test_unhide_endpoint_records_event()
    test_chat_injects_ui_events_once()
    print("\nALL PASS: test_ui_memory_bridge")


if __name__ == "__main__":
    main()
