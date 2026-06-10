"""4pa-02 — the warm session lands findings to the DB; graph + /cross-case +
dossier routes serve unchanged.

Two things proven:
  (1) SEAM: with KIPI_WARM_SESSION on, investigate_entity routes through the warm
      runner (NOT the cold claude -p subprocess), and its output flows through the
      SAME land_findings pipeline → the graph route returns the new node, and
      /cross-case + the dossier route still serve their shapes.
  (2) RUNTIME GUARD: warm turns run on ONE persistent loop. asyncio.run-per-turn
      would orphan the warm client (cold). This guard fails if that regresses.

Offline + deterministic: the warm runner is stubbed at the investigate_entity
seam (no live SDK); the runtime guard uses a fake client. The grader is NOT
re-tested here — we assert the integration boundary, not promotion internals.

Run: .venv/bin/python -m investigations.tests.test_warm_lands_to_graph
"""
import asyncio
import json
import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from investigations.storage import db
from investigations.agent import investigator
from investigations.webapp import app as app_module


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


# Canned warm run: a corroborated domain finding (dns + whois both surface it) so it
# lands AND promotes through the real pipeline — proving warm output reaches the graph.
_WARM_DOMAIN = "warm-evil-test.com"
_WARM_RESULT_TEXT = json.dumps({
    "findings": [{
        "entity": _WARM_DOMAIN, "entity_type": "domain",
        "claim": "payout domain wired into the scam page",
        "provenance": "dns_lookup", "confidence": "high",
        "url": f"http://{_WARM_DOMAIN}",
    }],
    "summary": "warm run", "negatives": [], "recommended_pivots": [],
})
_WARM_STEPS = [
    {"type": "tool", "n": 1, "tool": "mcp__kipi-osint__dns_lookup",
     "input": {"domain": _WARM_DOMAIN}, "result": f"A {_WARM_DOMAIN} -> 5.6.7.8"},
    {"type": "tool", "n": 2, "tool": "mcp__kipi-osint__whois_lookup",
     "input": {"domain": _WARM_DOMAIN}, "result": f"registrant record for {_WARM_DOMAIN}"},
]


def _canned_warm_run(task, case, timeout=600, cancel=None):
    return {"ok": True, "result_text": _WARM_RESULT_TEXT, "raw": {}, "events": [],
            "steps": _WARM_STEPS, "capped": False, "cancelled": False,
            "stderr_tail": "", "returncode": 0}


def _cold_must_not_run(*a, **k):
    raise AssertionError("cold _run_agent was called under KIPI_WARM_SESSION — warm not routed")


def test_warm_lands_and_routes_serve():
    mp = _MP()
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        # Seed a case + target entity so investigate_entity has context.
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            tgt = db.upsert_entity(conn, "trump-2026.io", "domain", rid)
            db.add_mention(conn, tgt, rid, "trump-2026.io", "seed context")

        # Point the webapp at the temp DB (routes call db.connect() with no arg).
        _orig_connect = db.connect
        mp.setattr(db, "connect", lambda db_path=None, migrate=True: _orig_connect(dbp, migrate=migrate))
        # Warm ON; warm runner stubbed; cold path forbidden.
        mp.setattr(os, "environ", {**os.environ, "KIPI_WARM_SESSION": "1"})
        mp.setattr(investigator, "_run_agent_warm", _canned_warm_run)
        mp.setattr(investigator, "_run_agent", _cold_must_not_run)

        try:
            with db.connect(dbp) as conn:
                res = investigator.investigate_entity(conn, "trump-2026.io", "cx")
            _check("warm run reported ok", res.get("ok"))

            # (a) lands via land_findings under an 'agent' run.
            with db.connect(dbp) as conn:
                agent_runs = conn.execute(
                    "SELECT COUNT(*) c FROM enrichment_runs WHERE provider_slug='agent'").fetchone()["c"]
                node = conn.execute(
                    "SELECT id FROM entities WHERE canonical_name=?", (_WARM_DOMAIN,)).fetchone()
            _check("warm findings landed under an agent run", agent_runs >= 1)
            _check("corroborated warm finding promoted to a graph node", node is not None)

            client = TestClient(app_module.app)
            # (b) /api/graph returns the new node (DB-decoupled read path).
            g = client.get("/api/graph?show_all=true&meaningful_only=false&min_score=0")
            _check("/api/graph 200", g.status_code == 200)
            # Nodes are cytoscape-shaped: {"data": {"label": ..., "full_name": ...}}.
            names = {(n.get("data") or {}).get("full_name") or (n.get("data") or {}).get("label")
                     for n in g.json().get("nodes", [])}
            _check("graph returns the warm-landed node", _WARM_DOMAIN in names)

            # (c) /cross-case still serves its shape.
            cc = client.get("/cross-case")
            _check("/cross-case 200", cc.status_code == 200)

            # (d) dossier route still serves its shape.
            dr = client.post(f"/api/entity/{tgt}/dossier", json={"body": "analyst note"})
            _check("dossier route 200", dr.status_code == 200)
            _check("dossier route returns its shape", dr.json().get("ok") is True)
        finally:
            mp.undo()


class _Result:
    is_result = True
    content = []


def test_warm_turns_share_one_loop():
    """RUNTIME GUARD: every warm turn runs on the SAME persistent loop. If someone
    reverts to asyncio.run-per-turn, the loop ids diverge and this fails."""
    from investigations.agent import warm_session as ws

    loops_seen = []

    class _LoopCapturingClient:
        def __init__(self, case_slug): self.case_slug = case_slug
        async def connect(self): pass
        async def query(self, prompt, session_id="default"):
            loops_seen.append(id(asyncio.get_running_loop()))
        async def receive_response(self):
            yield _Result()
        async def disconnect(self): pass

    saved = ws._DEFAULT_MANAGER
    ws._DEFAULT_MANAGER = ws.WarmSessionManager(client_factory=lambda c: _LoopCapturingClient(c))
    try:
        ws.run_turn_on_warm_loop("case-loop", "turn 1", timeout=10)
        ws.run_turn_on_warm_loop("case-loop", "turn 2", timeout=10)
    finally:
        ws._DEFAULT_MANAGER = saved

    _check("both warm turns executed", len(loops_seen) == 2)
    _check("warm turns ran on the SAME persistent loop (not asyncio.run-per-turn)",
           loops_seen[0] == loops_seen[1] == ws.warm_loop_id())


def main():
    test_warm_lands_and_routes_serve()
    test_warm_turns_share_one_loop()
    print("PASS test_warm_lands_to_graph: warm output lands via land_findings, "
          "/api/graph returns the node, /cross-case + dossier serve unchanged, "
          "and warm turns share one persistent loop")


if __name__ == "__main__":
    main()
