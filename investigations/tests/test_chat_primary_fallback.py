"""Chat-primary + guaranteed graceful router fallback (issue chat-primary-fallback).

When the warm investigator turn raises or fails to boot, /api/chat must still return a
usable response via the deterministic router — never a 500, never a dead 'try again'.
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.agent import investigator as inv
from investigations.agent import warm_session as ws
from investigations.webapp import app as app_module

_ORIG_CONNECT = db.connect


def _client(monkeypatch, dbp):
    db.init_db(dbp)
    import functools
    bound = functools.partial(_ORIG_CONNECT, dbp)
    monkeypatch.setattr(app_module.db, "connect", bound)
    monkeypatch.setattr(db, "connect", bound)
    with _ORIG_CONNECT(dbp) as conn:
        conn.execute("INSERT INTO investigations (slug, status) VALUES ('case-f','active')")
        conn.commit()
    return TestClient(app_module.app)


def _poll(client, case, tries=100):
    for _ in range(tries):
        job = client.get("/api/chat/status", params={"case": case}).json()
        if job.get("status") in ("done", "stopped", "error", "idle"):
            return job
    return {"status": "timeout"}


def test_warm_raise_falls_back_to_router_not_500(monkeypatch):
    dbp = Path(tempfile.mkdtemp()) / "f.db"
    client = _client(monkeypatch, dbp)
    monkeypatch.setattr(inv, "warm_run_available", lambda: True)

    def _boom(*a, **k):
        raise RuntimeError("warm wedged")
    monkeypatch.setattr(ws, "run_turn_on_warm_loop", _boom)
    # A distinctive router reply proves the fallback routed through _graph_chat.
    monkeypatch.setattr(app_module, "_graph_chat",
                        lambda message, case, selected: {"reply": "ROUTER-ANSWER", "deltas": {}})

    r = client.post("/api/chat", json={"case": "case-f", "message": "who runs trumpfundus.com?"})
    assert r.status_code == 200
    job = _poll(client, "case-f")
    assert job["status"] in ("done", "error")
    assert job["reply"] == "ROUTER-ANSWER"  # fell back to the router, not a dead 'try again'


def test_warm_ok_false_also_falls_back_to_router(monkeypatch):
    dbp = Path(tempfile.mkdtemp()) / "f2.db"
    client = _client(monkeypatch, dbp)
    monkeypatch.setattr(inv, "warm_run_available", lambda: True)
    monkeypatch.setattr(ws, "run_turn_on_warm_loop",
                        lambda *a, **k: {"ok": False, "error": "model error"})
    monkeypatch.setattr(app_module, "_graph_chat",
                        lambda message, case, selected: {"reply": "ROUTER-ANSWER", "deltas": {}})

    r = client.post("/api/chat", json={"case": "case-f", "message": "go"})
    assert r.status_code == 200
    job = _poll(client, "case-f")
    assert job["reply"] == "ROUTER-ANSWER"


def test_fallback_deltas_trigger_graph_refresh(monkeypatch):
    """A router fallback that MUTATED the graph (deltas) must flag graph_touched so open
    views refresh (Codex review). Calls _run_chat_turn directly to read graph_touched."""
    dbp = Path(tempfile.mkdtemp()) / "f3.db"
    _client(monkeypatch, dbp)  # wires db.connect to the temp db + seeds case-f
    monkeypatch.setattr(inv, "warm_run_available", lambda: True)
    monkeypatch.setattr(ws, "run_turn_on_warm_loop",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("wedged")))
    monkeypatch.setattr(app_module, "_graph_chat",
                        lambda message, case, selected: {
                            "reply": "added it", "deltas": {"add_nodes": [{"data": {"id": "1"}}]}})
    result = app_module._run_chat_turn("case-f", "add a node x", None)
    assert result["graph_touched"] is True
    assert result["deltas"] == {"add_nodes": [{"data": {"id": "1"}}]}
