"""One chat, every capability: a plain QUESTION routes to grounded Q&A (ask_mod),
an action phrasing routes to the investigator/router. Folds the retired "Ask the
case" box into /api/chat (founder: one chat that has everything).

Offline + deterministic: ask_mod.answer and the warm/router paths are faked.

Run: .venv/bin/python3 -m investigations.tests.test_chat_ask_routing
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.webapp import app as app_module
from investigations.agent import investigator as inv
from investigations.agent import warm_session as ws

_ORIG = {
    "warm": inv.warm_run_available,
    "warm_loop": ws.run_turn_on_warm_loop,
    "answer": app_module.ask_mod.answer,
    "graph_chat": app_module._graph_chat,
    "connect": db.connect,
}


def _restore():
    inv.warm_run_available = _ORIG["warm"]
    ws.run_turn_on_warm_loop = _ORIG["warm_loop"]
    app_module.ask_mod.answer = _ORIG["answer"]
    app_module._graph_chat = _ORIG["graph_chat"]
    app_module.db.connect = _ORIG["connect"]


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _client(dbp):
    orig = _ORIG["connect"]
    app_module.db.connect = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
    return TestClient(app_module.app)


def _turns(dbp, case):
    with _ORIG["connect"](dbp) as conn:
        return db.get_chat_turns(conn, case)


def _drain(client, case, tries=100):
    """Wait for a warm chat job to reach a terminal state so its background thread
    finishes before the temp DB is torn down (no thread-vs-cleanup race)."""
    import time
    for _ in range(tries):
        if client.get("/api/chat/status", params={"case": case}).json().get("status") in (
                "done", "stopped", "error", "idle"):
            return
        time.sleep(0.02)


def test_question_routes_to_grounded_ask_when_no_warm():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False  # no warm agent → grounded Q&A answers
            asked = {}

            def fake_answer(conn, case, question, full=False):
                asked["q"] = question; asked["case"] = case
                return {"answer": "Trumpfundus is run by X.", "grounded": True,
                        "sources": [{"report": "r1", "snippet": "..."}],
                        "coverage": {"mode": "full", "passages_total": 3}}
            app_module.ask_mod.answer = fake_answer

            r = client.post("/api/chat", json={"case": "case-q",
                                               "message": "who runs trumpfundus.com?"})
            _check("question returns 200 sync", r.status_code == 200 and r.json()["mode"] == "sync")
            body = r.json()
            _check("grounded answer returned as the reply", body["reply"] == "Trumpfundus is run by X.")
            _check("sources passed through", body["sources"] and body["grounded"] is True)
            _check("ask_mod got the question + case", asked["q"] == "who runs trumpfundus.com?" and asked["case"] == "case-q")

            rows = _turns(dbp, "case-q")
            _check("question persists analyst+agent turns", [x["role"] for x in rows] == ["analyst", "agent"])
            _check("agent turn holds the grounded answer", rows[1]["text"] == "Trumpfundus is run by X.")
        finally:
            _restore()


def test_question_goes_to_warm_agent_when_live():
    # When the warm investigator is live it handles questions too (it has session/graph
    # context the report-only answerer lacks). The grounded Q&A must NOT fire.
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True
            # Fake the warm loop so no real agent thread spawns (hermetic).
            ws.run_turn_on_warm_loop = lambda *a, **k: {
                "ok": True, "result_text": "you added evil.com", "tools": [], "steps": [], "capped": False}
            ask_called = {"v": False}
            app_module.ask_mod.answer = lambda *a, **k: ask_called.__setitem__("v", True) or {"answer": "x"}

            r = client.post("/api/chat", json={"case": "case-warmq",
                                               "message": "what did i just add?"})
            _check("warm path takes the question (mode:job)", r.json().get("mode") == "job")
            _check("grounded Q&A NOT used when warm is live", ask_called["v"] is False)
            _drain(client, "case-warmq")  # let the warm job finish before teardown
        finally:
            _restore()


def test_action_phrasing_bypasses_ask():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False  # force the router fallback path
            ask_called = {"v": False}
            app_module.ask_mod.answer = lambda *a, **k: ask_called.__setitem__("v", True) or {"answer": "x"}
            app_module._graph_chat = lambda m, c, s: {"reply": f"router:{m}", "deltas": {}}

            r = client.post("/api/chat", json={"case": "case-a", "message": "dig into trumpfundus.com"})
            body = r.json()
            _check("action phrasing did NOT hit grounded Q&A", ask_called["v"] is False)
            _check("action phrasing reached the router", body["reply"] == "router:dig into trumpfundus.com")
        finally:
            _restore()


def test_modal_command_question_goes_to_agent():
    # 'can you investigate X?' ends with '?' but is an ACTION — the action guard wins so
    # it reaches the investigator, not the report-grounded answerer.
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False
            ask_called = {"v": False}
            app_module.ask_mod.answer = lambda *a, **k: ask_called.__setitem__("v", True) or {"answer": "x"}
            app_module._graph_chat = lambda m, c, s: {"reply": "router", "deltas": {}}

            client.post("/api/chat", json={"case": "case-m", "message": "can you investigate example_channel?"})
            _check("modal command-question bypassed grounded Q&A", ask_called["v"] is False)
        finally:
            _restore()


def main():
    test_question_routes_to_grounded_ask_when_no_warm()
    test_question_goes_to_warm_agent_when_live()
    test_action_phrasing_bypasses_ask()
    test_modal_command_question_goes_to_agent()
    print("\nALL PASS: test_chat_ask_routing")


if __name__ == "__main__":
    main()
