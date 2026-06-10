"""Chat can START a brand-new investigation (founder pick: create + run fused).

Offline + deterministic: graph_chat.interpret and _start_investigate_job are both
faked, so no SDK/LLM/network and no real agent thread spawns.

Run: .venv/bin/python3 -m investigations.tests.test_chat_new_case

Asserts the create+run behavior wired into POST /api/chat:
  - no case open + an investigate-shaped intent with a target → creates the case,
    switches to it (cookie), fires the investigator, persists both turns to the NEW
    case, returns action {type:new_case, slug, ran:true}
  - no case open + new_case intent, no target → creates + switches only (ran:false)
  - case OPEN + an explicit "new case on X" phrasing → forks a SECOND case
  - case OPEN + a normal in-case turn (no new-case phrasing) → does NOT classify or
    fork; falls through to the regular chat path (stays in the current case)
  - no case + a non-start intent (help) → 400 nudge, nothing persisted

Monkeypatched globals are restored after every test (order-independent).
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.webapp import app as app_module
from investigations.webapp import graph_chat
from investigations.agent import investigator as inv

_ORIG = {
    "warm": inv.warm_run_available,
    "interpret": graph_chat.interpret,
    "start_job": app_module._start_investigate_job,
    "graph_chat": app_module._graph_chat,
    "connect": db.connect,
}


def _restore():
    inv.warm_run_available = _ORIG["warm"]
    graph_chat.interpret = _ORIG["interpret"]
    app_module._start_investigate_job = _ORIG["start_job"]
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


def _fake_interpret(result):
    """Return an interpret() stand-in that always yields `result` (records the call)."""
    calls = []

    def fake(message, selected_name):
        calls.append(message)
        return result
    return fake, calls


def test_no_case_investigate_target_creates_and_runs():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False
            graph_chat.interpret, _ = _fake_interpret(
                {"intent": "investigate", "args": {"target": "trumpfundus.com"}})
            started = []
            app_module._start_investigate_job = lambda case, entity, analyst, deep=False: (
                started.append((case, entity, deep)) or True)

            # No case cookie at all → the route classifies up front.
            r = client.post("/api/chat", json={"message": "investigate the trumpfundus scam"})
            _check("create+run returns 200", r.status_code == 200)
            body = r.json()
            slug = body["action"]["slug"]
            _check("action is new_case", body["action"]["type"] == "new_case")
            _check("slug derived from the target", slug == "trumpfundus-com")
            _check("ran=true (investigator fired)", body["action"]["ran"] is True)
            _check("investigator started on the target in the new case",
                   started == [(slug, "trumpfundus.com", False)])
            _check("reply names the case + the run",
                   slug in body["reply"] and "trumpfundus.com" in body["reply"])

            rows = _turns(dbp, slug)
            _check("two turns persisted to the NEW case", len(rows) == 2)
            _check("analyst turn first, verbatim",
                   rows[0]["role"] == "analyst" and rows[0]["text"] == "investigate the trumpfundus scam")
            _check("agent turn second", rows[1]["role"] == "agent")

            # The case row exists and the cookie now points to it.
            with _ORIG["connect"](dbp) as conn:
                exists = conn.execute("SELECT 1 FROM investigations WHERE slug = ?", (slug,)).fetchone()
            _check("case row created", exists is not None)
            _check("case cookie switched to the new case", client.cookies.get("case") == slug)
        finally:
            _restore()


def test_no_case_new_case_no_target_switch_only():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False
            graph_chat.interpret, _ = _fake_interpret(
                {"intent": "new_case", "args": {"name": "case-b leak"}})
            started = []
            app_module._start_investigate_job = lambda *a, **k: started.append(a) or True

            r = client.post("/api/chat", json={"message": "open a new case on the case-b leak"})
            body = r.json()
            _check("switch-only ran=false", body["action"]["ran"] is False)
            _check("no investigator started without a target", started == [])
            _check("slug from the name", body["action"]["slug"] == "case-b-leak")
            _check("reply tells the analyst what to do next",
                   "investigate" in body["reply"].lower() or "evidence" in body["reply"].lower())
        finally:
            _restore()


def test_case_open_explicit_new_case_forks_second():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False
            graph_chat.interpret, calls = _fake_interpret(
                {"intent": "new_case", "args": {"name": "examplering", "target": "t.me/examplering"}})
            started = []
            app_module._start_investigate_job = lambda case, entity, analyst, deep=False: (
                started.append((case, entity)) or True)

            # A case IS open; the explicit "new case" phrasing matches the regex → classify.
            r = client.post("/api/chat", json={"case": "existing-case",
                                               "message": "start a new investigation into examplering"})
            body = r.json()
            _check("interpret was consulted (regex matched)", len(calls) == 1)
            _check("forked a second case", body["action"]["slug"] == "examplering")
            _check("run fired on the new case's target", started == [("examplering", "t.me/examplering")])
        finally:
            _restore()


def test_case_open_normal_turn_does_not_fork_or_classify():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False
            # If the route classifies on a normal in-case turn, this fake fires and the
            # assert below catches it. A normal turn must NOT touch interpret.
            graph_chat.interpret, calls = _fake_interpret({"intent": "new_case", "args": {"name": "x"}})
            app_module._graph_chat = lambda m, c, s: {"reply": f"router:{m}", "deltas": {}}

            r = client.post("/api/chat", json={"case": "case-stay", "message": "dig into x.com"})
            body = r.json()
            _check("no up-front classify on a normal in-case turn", calls == [])
            _check("stayed in the current case (router fallback ran)",
                   body["reply"] == "router:dig into x.com")
            rows = _turns(dbp, "case-stay")
            _check("turns persisted to the SAME case", len(rows) == 2)
        finally:
            _restore()


def test_no_case_non_start_intent_400_no_persist():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False
            graph_chat.interpret, _ = _fake_interpret({"intent": "help", "args": {}})

            r = client.post("/api/chat", json={"message": "what can you do"})
            _check("non-start intent with no case → 400", r.status_code == 400)
            _check("nudge tells the analyst to open a case",
                   "case" in r.json()["reply"].lower())
            with _ORIG["connect"](dbp) as conn:
                n = conn.execute("SELECT COUNT(*) FROM chat_turns").fetchone()[0]
            _check("nothing persisted on the nudge path", n == 0)
        finally:
            _restore()


def main():
    test_no_case_investigate_target_creates_and_runs()
    test_no_case_new_case_no_target_switch_only()
    test_case_open_explicit_new_case_forks_second()
    test_case_open_normal_turn_does_not_fork_or_classify()
    test_no_case_non_start_intent_400_no_persist()
    print("\nALL PASS: test_chat_new_case")


if __name__ == "__main__":
    main()
