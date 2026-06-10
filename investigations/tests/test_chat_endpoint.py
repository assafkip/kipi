"""Conversational /api/chat endpoint + /api/chat/transcript (chat-led spine).

prd-chat-led-endpoint / issue-chat-led-endpoint. Offline + deterministic: the
warm turn and the graph_chat router are both faked, so no SDK/LLM/network.

Run: .venv/bin/python3 -m investigations.tests.test_chat_endpoint

Asserts every acceptance criterion:
  - POST /api/chat persists analyst THEN agent turn, in order
  - warm path: invoked with the analyst message; dict result persisted
  - warm ok=false / raised: a usable failure message persists, never a 500
  - fallback path: persists both turns; returns reply+deltas+action (investigate
    launch preserved); forwards selected_name to the router
  - blank/None case returns 400 BEFORE any persist (no 500, no orphan turn)
  - GET /api/chat/transcript round-trips persisted turns, parsing non-null
    deltas/steps JSON back to objects (guards the module-level json import)

Monkeypatched module globals are restored after every test so a same-process run
is order-independent.
"""
import json
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
    "graph_chat": app_module._graph_chat,
    "connect": db.connect,
}


def _restore():
    inv.warm_run_available = _ORIG["warm"]
    ws.run_turn_on_warm_loop = _ORIG["warm_loop"]
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


def _poll(client, case, timeout=20.0):
    """Poll /api/chat/status until the warm job reaches a terminal state. Uses a
    wall-clock deadline (not a fixed iteration count) so it doesn't flake when the
    background thread is starved under full-suite CPU load."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get("/api/chat/status", params={"case": case}).json()
        if job.get("status") in ("done", "stopped", "error", "idle"):
            return job
        time.sleep(0.05)
    raise AssertionError("chat job did not finish")


def test_fallback_path_persists_and_preserves_action():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False  # force the router fallback
            seen = {}

            def fake_graph_chat(message, case, selected):
                seen["message"] = message
                seen["selected"] = selected
                return {"reply": f"router saw {message}", "deltas": {"focus_id": "9"},
                        "action": {"type": "investigate", "entity": "x.com"}}
            app_module._graph_chat = fake_graph_chat

            r = client.post("/api/chat", json={"case": "case-fb", "message": "investigate x.com",
                                               "selected_name": "node-7"})
            assert r.status_code == 200, r.status_code
            body = r.json()
            _check("fallback returns the router reply", body["reply"] == "router saw investigate x.com")
            _check("fallback preserves action (investigate launch)",
                   body["action"] == {"type": "investigate", "entity": "x.com"})
            _check("fallback returns deltas", body["deltas"] == {"focus_id": "9"})
            _check("selected_name forwarded to router", seen["selected"] == "node-7")

            rows = _turns(dbp, "case-fb")
            _check("two turns persisted", len(rows) == 2)
            _check("analyst turn first", rows[0]["role"] == "analyst" and rows[0]["text"] == "investigate x.com")
            _check("agent turn second", rows[1]["role"] == "agent" and rows[1]["text"] == "router saw investigate x.com")
        finally:
            _restore()


def test_warm_path_persists_burst():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True
            got = {}

            def fake_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                got["task"] = task
                return {"ok": True, "result_text": "ran dns_lookup; found 2 IPs",
                        "tools": ["dns_lookup"], "steps": [{"n": 1, "type": "tool"}], "capped": False}
            ws.run_turn_on_warm_loop = fake_warm

            r = client.post("/api/chat", json={"case": "case-w", "message": "dig into trumpstake.us"})
            _check("warm path returns mode:job started", r.json().get("mode") == "job")
            job = _poll(client, "case-w")
            # The task STARTS WITH the analyst message; the findings contract (issue
            # warm-lands-findings) is appended after so the turn also lands findings.
            _check("warm turn invoked with the analyst message",
                   got["task"].startswith("dig into trumpstake.us"))
            _check("warm job done", job["status"] == "done")
            _check("warm reply returned", job["reply"] == "ran dns_lookup; found 2 IPs")

            rows = _turns(dbp, "case-w")
            _check("warm persisted analyst+agent", [x["role"] for x in rows] == ["analyst", "agent"])
            _check("agent turn holds the burst reply", rows[1]["text"] == "ran dns_lookup; found 2 IPs")

            # The warm turn persisted a non-null step_trail_json; the transcript
            # route must parse it (guards the module-level json import).
            tr = client.get("/api/chat/transcript", params={"case": "case-w"}).json()
            agent_turn = [t for t in tr if t["role"] == "agent"][0]
            _check("transcript parses non-null steps back to a list",
                   agent_turn["steps"] == [{"n": 1, "type": "tool"}])
        finally:
            _restore()


def test_warm_failure_persists_usable_message():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True
            ws.run_turn_on_warm_loop = lambda *a, **k: {"ok": False, "error": "boom"}

            client.post("/api/chat", json={"case": "case-fail", "message": "go"})
            job = _poll(client, "case-fail")
            # A warm failure now falls back to the deterministic router (issue
            # chat-primary-fallback) — a usable, non-empty reply, not a dead 'try again'.
            _check("ok=false yields a usable router reply", bool(job["reply"]))
            rows = _turns(dbp, "case-fail")
            _check("failure still persists a non-empty agent turn", rows[1]["text"] == job["reply"])

            # And a raised exception must not break the chat either — the job ends error.
            def boom(*a, **k):
                raise RuntimeError("wedged")
            ws.run_turn_on_warm_loop = boom
            r2 = client.post("/api/chat", json={"case": "case-fail", "message": "again"})
            _check("a raised warm turn returns 200 (job)", r2.status_code == 200)
            job2 = _poll(client, "case-fail")
            # _run_chat_turn catches the raise and falls back to the router, so the job
            # finishes cleanly with a usable reply (never wedged/running, never a 500).
            _check("raised warm turn finishes with a usable reply",
                   job2["status"] in ("done", "error") and bool(job2.get("reply")))
        finally:
            _restore()


def test_blank_case_400_before_persist():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False
            # No case in body, no case cookie -> _active_case is None.
            r = client.post("/api/chat", json={"message": "hello"})
            _check("blank case returns 400", r.status_code == 400)
            with _ORIG["connect"](dbp) as conn:
                n = conn.execute("SELECT COUNT(*) FROM chat_turns").fetchone()[0]
            _check("no turn persisted on blank case (no 500, no orphan)", n == 0)
        finally:
            _restore()


def test_ordering_and_transcript_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: False
            # Non-empty deltas -> deltas_json non-null -> exercises json.loads on read.
            app_module._graph_chat = lambda m, c, s: {
                "reply": f"re:{m}", "deltas": {"focus_id": "5", "add_nodes": [{"data": {"id": "5"}}]}}

            client.post("/api/chat", json={"case": "case-seq", "message": "one"})
            client.post("/api/chat", json={"case": "case-seq", "message": "two"})

            tr = client.get("/api/chat/transcript", params={"case": "case-seq"}).json()
            texts = [t["text"] for t in tr]
            _check("transcript round-trips in order",
                   texts == ["one", "re:one", "two", "re:two"])
            _check("transcript roles correct",
                   [t["role"] for t in tr] == ["analyst", "agent", "analyst", "agent"])
            _check("transcript carries created_at", all(t["created_at"] for t in tr))
            # The agent turns carried non-null deltas; they must parse back to objects.
            agent_deltas = [t["deltas"] for t in tr if t["role"] == "agent"]
            _check("transcript parses non-null deltas back to objects",
                   all(d == {"focus_id": "5", "add_nodes": [{"data": {"id": "5"}}]} for d in agent_deltas))

            # Blank case transcript is an empty list, never an error.
            empty = client.get("/api/chat/transcript", params={"case": ""}).json()
            _check("blank-case transcript is []", empty == [])
        finally:
            _restore()


def test_redirect_reaches_running_turn():
    # POST /api/chat/redirect drops a NEW instruction into the live warm turn: the
    # same RedirectBox the job runs with receives it. No-op when nothing is running
    # or the message is empty.
    import time, threading
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True
            seen = {}
            started = threading.Event()

            def fake_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                started.set()
                steer = None
                for _ in range(300):  # wait up to ~3s for the analyst's steer
                    if redirect is not None:
                        steer = redirect.take()
                        if steer:
                            break
                    time.sleep(0.01)
                seen["task"] = task; seen["steer"] = steer
                return {"ok": True, "result_text": f"{task} -> {steer}",
                        "tools": [], "steps": [], "capped": False, "redirected": bool(steer)}
            ws.run_turn_on_warm_loop = fake_warm

            # No running turn → redirect is a no-op.
            r0 = client.post("/api/chat/redirect", json={"case": "case-r", "message": "pivot"})
            _check("redirect with no running turn → ok:false", r0.json()["ok"] is False)

            # Start a turn, wait for the job thread to enter the warm fake, then steer it.
            client.post("/api/chat", json={"case": "case-r", "message": "start dns"})
            _check("warm job started", started.wait(2))
            r1 = client.post("/api/chat/redirect", json={"case": "case-r", "message": "now whois"})
            _check("redirect on a running turn → ok:true", r1.json()["ok"] is True)

            # Empty instruction is a no-op (checked before the running test).
            r2 = client.post("/api/chat/redirect", json={"case": "case-r", "message": "   "})
            _check("empty redirect → ok:false", r2.json()["ok"] is False)

            job = _poll(client, "case-r")
            _check("the live warm turn received the steer", seen["steer"] == "now whois")
            _check("job completed", job["status"] == "done")
        finally:
            _restore()


def test_selections_feed_ui_memory():
    # Client-batched node-selections ride along with the message and flow through the
    # SAME ui-event memory bridge: they're recorded as ui_event turns and folded into
    # the warm turn's task prefix. Duplicates within one batch collapse.
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True
            got = {}

            def fake_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                got["task"] = task
                return {"ok": True, "result_text": "ok", "tools": [], "steps": [], "capped": False}
            ws.run_turn_on_warm_loop = fake_warm

            client.post("/api/chat", json={"case": "case-sel", "message": "compare these",
                                           "selections": ["alpha.com", "beta.com", "alpha.com"]})
            _poll(client, "case-sel")
            _check("selections folded into the warm task prefix",
                   "viewed node alpha.com" in got["task"] and "viewed node beta.com" in got["task"])
            _check("duplicate selection deduped within the batch", got["task"].count("alpha.com") == 1)

            rows = _turns(dbp, "case-sel")
            ui = [r for r in rows if r["role"] == "ui_event"]
            _check("selections persisted as ui_event turns", len(ui) == 2)
        finally:
            _restore()


def test_sse_streams_steps_and_done():
    # GET /api/chat/stream pushes a `step` event per new step and a final `done` event
    # (status + reply), so the client opens one connection instead of polling.
    import time
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            inv.warm_run_available = lambda: True

            def fake_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                if on_step:
                    on_step({"tool": "dns_lookup", "text": "looked up x"})
                    time.sleep(0.3)
                    on_step({"tool": "whois", "text": "whois x"})
                return {"ok": True, "result_text": "found it", "tools": ["dns_lookup", "whois"],
                        "steps": [], "capped": False}
            ws.run_turn_on_warm_loop = fake_warm

            client.post("/api/chat", json={"case": "case-sse", "message": "go"})
            events = []
            with client.stream("GET", "/api/chat/stream", params={"case": "case-sse"}) as r:
                cur = None
                for line in r.iter_lines():
                    if line.startswith("event:"):
                        cur = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        events.append((cur, line.split(":", 1)[1].strip()))
                        if cur == "done":
                            break
            kinds = [k for k, _ in events]
            _check("SSE emitted at least one step event", "step" in kinds)
            _check("SSE ended with a done event", kinds[-1] == "done")
            done_data = json.loads([d for k, d in events if k == "done"][-1])
            _check("done event carries the final reply", done_data.get("reply") == "found it")
            _check("done event reports terminal status", done_data.get("status") == "done")
        finally:
            _restore()


def test_sse_step_seq_survives_cap_eviction():
    # Codex P2 regression: the live step list is front-trimmed at _CHAT_STEP_MAX. The
    # SSE stream tracks progress by a monotonic per-step `seq`, NOT list index — so it
    # keeps emitting after the cap (index slicing would stall). Drive >cap steps and
    # assert the trimmed list's seqs are strictly increasing and counted past the cap.
    import time
    orig_cap = app_module._CHAT_STEP_MAX
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        client = _client(dbp)
        try:
            app_module._CHAT_STEP_MAX = 3
            inv.warm_run_available = lambda: True
            n_steps = 7

            def fake_warm(case, task, timeout=None, cancel=None, on_step=None, redirect=None):
                if on_step:
                    for i in range(n_steps):
                        on_step({"tool": f"t{i}", "text": f"step {i}"})
                return {"ok": True, "result_text": "done", "tools": [], "steps": [], "capped": False}
            ws.run_turn_on_warm_loop = fake_warm

            client.post("/api/chat", json={"case": "case-cap", "message": "go"})
            _poll(client, "case-cap")
            with app_module._CHAT_LOCK:
                steps = list(app_module._CHAT_JOBS.get("case-cap", {}).get("steps") or [])
            seqs = [s.get("seq") for s in steps]
            _check("live step list trimmed to the cap", len(steps) == 3)
            _check("every live step carries a seq", all(isinstance(x, int) for x in seqs))
            _check("seqs strictly increasing after eviction", seqs == sorted(seqs) and len(set(seqs)) == len(seqs))
            _check("seq counted past the cap (not reset by trim)", max(seqs) == n_steps)
        finally:
            app_module._CHAT_STEP_MAX = orig_cap
            _restore()


def main():
    test_fallback_path_persists_and_preserves_action()
    test_warm_path_persists_burst()
    test_warm_failure_persists_usable_message()
    test_blank_case_400_before_persist()
    test_ordering_and_transcript_roundtrip()
    test_redirect_reaches_running_turn()
    test_selections_feed_ui_memory()
    test_sse_streams_steps_and_done()
    test_sse_step_seq_survives_cap_eviction()
    print("\nALL PASS: test_chat_endpoint")


if __name__ == "__main__":
    main()
