"""Persona-driven whole-case investigator: the agent drives its own paths.

Run: .venv/bin/python -m investigations.tests.test_persona_investigator

The agent run (`claude`) is stubbed — these prove the DOCTRINE, the TASK assembly,
the LANDING of findings, and the WIRING (web deep path → agentic run), not a live
investigation.
"""
import json
import tempfile
import inspect
from pathlib import Path

import pytest

from investigations.storage import db
from investigations.agent import investigator
from investigations.webapp import app as app_module


@pytest.fixture(autouse=True)
def _force_cold_path(monkeypatch):
    """Mock the cold _run_agent path: warm is default-on, so without pinning it off the
    real warm agent boots (hangs on MCP) and bypasses the mocks. Warm path is covered in
    test_warm_*.py."""
    monkeypatch.setattr(investigator, "warm_run_available", lambda: False)


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


def test_case_persona_doctrine():
    p = investigator.CASE_PERSONA.lower()
    _check("persona tells the agent to DRIVE its own paths",
           "drive it yourself" in p or "drive your own paths" in p)
    _check("has the recursive completeness engine", "recursive completeness" in p)
    _check("has the 3-pass / plateau stopping rule", "plateau" in p and "3 full passes" in p)
    _check("never-retry / switch-tools doctrine",
           "never retry the same" in p and "switch" in p)
    _check("pivots wallets (assets beyond domains)", "wallet" in p)
    _check("pivots affiliate / ref IDs", "affiliate" in p and "ref" in p)
    _check("recovers silently — no 'got stuck' message", "got stuck" in p)


def test_run_agent_accepts_persona():
    sig = inspect.signature(investigator._run_agent)
    _check("_run_agent has a persona param", "persona" in sig.parameters)
    _check("persona defaults to None (→ per-target persona)",
           sig.parameters["persona"].default is None)


def test_case_task_carries_goal_and_roster():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            db.upsert_entity(conn, "trump-2026.io", "domain", r)
            e = db.upsert_entity(conn, "trump-2026.io", "domain", r)
            db.add_mention(conn, e, r, "trump-2026.io", "c")
            db.set_objective(conn, "cx", "map the related scam domains and wallets")
            conn.commit()
            task = investigator._build_case_task(conn, "cx")
            _check("task carries the case goal", "map the related scam domains and wallets" in task)
            _check("task carries the entity roster", "trump-2026.io" in task)
            _check("task names Phase 0 tool status", "TOOLS LIVE THIS RUN" in task)


_FAKE_FINDINGS = json.dumps({
    "findings": [
        {"entity": "trump-2026.com", "entity_type": "domain", "claim": "sibling scam kit",
         "confidence": "high", "provenance": "crtsh: trump-2026.com", "unvalidated": False},
        {"entity": "0xDEADBEEF", "entity_type": "wallet", "claim": "receives victim funds",
         "confidence": "medium", "provenance": "web_search", "unvalidated": False},
    ],
    "relationships": [{"src": "trump-2026.io", "dst": "0xDEADBEEF", "rel_type": "drains_to",
                       "direction": "src_to_dst", "confidence": "medium", "provenance": "page read"}],
    "same_as": [], "negatives": [],
    "recommended_pivots": [{"entity": "0xDEADBEEF", "why": "trace the cashout"}],
    "assessment": {"attributed_actor": "trump scam crew", "best_judgment": "linked network",
                   "overall_confidence": "medium", "collection_gaps": "exchange KYC"},
    "summary": "Mapped 2 siblings + a wallet.",
})


def test_agentic_run_lands_findings(mp):
    # Stub the live agent — return our findings JSON. Prove the whole-case run lands
    # them as an agent run + result rows (entity_id=None on the run; per-finding entities).
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            e = db.upsert_entity(conn, "trump-2026.io", "domain", r)
            db.add_mention(conn, e, r, "trump-2026.io", "c")
            db.set_objective(conn, "cx", "map the network")
            conn.commit()

            mp.setattr(investigator, "_run_agent",
                       lambda *a, **k: {"ok": True, "result_text": _FAKE_FINDINGS,
                                        "raw": {"total_cost_usd": 0.12, "num_turns": 7},
                                        "events": [], "steps": [], "capped": False})
            events = []
            res = investigator.investigate_case_agentic(conn, "cx", on_event=events.append)

            _check("run reports ok + agentic", res.get("ok") and res.get("agentic"))
            _check("counted both findings", res.get("findings") == 2)
            runs = conn.execute(
                "SELECT id, entity_id FROM enrichment_runs WHERE provider_slug='agent' "
                "AND investigation='cx'").fetchall()
            _check("one agent run record written, case-scoped (no single entity_id)",
                   len(runs) == 1 and runs[0]["entity_id"] is None)
            n_results = conn.execute(
                "SELECT COUNT(*) FROM enrichment_results WHERE run_id=?", (runs[0]["id"],)).fetchone()[0]
            _check("both findings landed as result rows", n_results == 2)
            _check("streamed a completion line", any("case mapped" in e for e in events))
            # Fields the post-run recap block renders:
            _check("returns assessment for the recap",
                   bool((res.get("assessment") or {}).get("best_judgment")))
            _check("returns next-move pivots for the recap",
                   len(res.get("recommended_pivots") or []) == 1)


def test_agentic_stop_keeps_findings(mp):
    # Analyst hit Stop mid-run: the agent is killed, _run_agent salvages what it emitted,
    # and investigate_case_agentic LANDS it + flags stopped (not error, not discarded).
    import threading
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            e = db.upsert_entity(conn, "trump-2026.io", "domain", r)
            db.add_mention(conn, e, r, "trump-2026.io", "c")
            conn.commit()
            ev = threading.Event(); ev.set()
            mp.setattr(investigator, "_run_agent",
                       lambda *a, **k: {"ok": True, "result_text": _FAKE_FINDINGS,
                                        "raw": {"total_cost_usd": 0.05, "num_turns": 3},
                                        "events": [{}], "steps": [], "capped": True, "cancelled": True})
            res = investigator.investigate_case_agentic(conn, "cx", cancel=ev)
            _check("run is flagged stopped (not error)", res.get("stopped") is True and res.get("ok"))
            _check("stopped run KEPT its salvaged findings", res.get("findings") == 2)


def test_stop_endpoint_signals_cancel():
    import threading
    from starlette.testclient import TestClient
    c = TestClient(app_module.app)
    c.cookies.set("case", "cx")
    key = app_module._investigate_key("cx")
    ev = threading.Event()
    with app_module._INVESTIGATE_LOCK:
        app_module._INVESTIGATE_JOBS[key] = {"status": "running", "case": "cx"}
        app_module._INVESTIGATE_CANCEL[key] = ev
    try:
        r = c.post("/api/investigate/stop")
        _check("stop returns ok while running", r.status_code == 200 and r.json().get("ok"))
        _check("stop set the cancel event", ev.is_set())
    finally:
        with app_module._INVESTIGATE_LOCK:
            app_module._INVESTIGATE_JOBS.pop(key, None)
            app_module._INVESTIGATE_CANCEL.pop(key, None)
    r2 = c.post("/api/investigate/stop")
    _check("stop with no run in progress → 400", r2.status_code == 400)


def test_web_path_routing_is_analyst_driven(mp):
    # The wiring (founder 2026-06-05, revises 2026-06-03; replay D4): both modes use ONE
    # agent (no fan-out). The DEFAULT is investigate_case_agentic(max_passes=1) — one
    # bounded pass; deep=True re-seeds multi-pass. The old per-entity volley→crew fan-out
    # is no longer the default.
    from investigations.agent import swarm
    called = {"agentic": 0, "shallow": 0, "deep_loop": 0, "passes": []}
    def _agentic(conn, case, on_event=None, max_passes=1, **k):
        called["agentic"] += 1; called["passes"].append(max_passes); return {"ok": True}
    mp.setattr(investigator, "investigate_case_agentic", _agentic)
    mp.setattr(swarm, "investigate_case",
               lambda conn, case, on_event=None, **k: called.__setitem__("shallow", called["shallow"] + 1) or {"ok": True})
    mp.setattr(swarm, "deep_investigate",
               lambda *a, **k: called.__setitem__("deep_loop", called["deep_loop"] + 1) or {"ok": True})
    import contextlib
    @contextlib.contextmanager
    def _noconn(*a, **k):
        yield None
    mp.setattr(app_module.db, "connect", _noconn)
    app_module._investigate_swarm("cx", shallow=False)                 # default
    _check("default → ONE bounded agent (no fan-out), not the volley",
           called["agentic"] == 1 and called["shallow"] == 0)
    _check("default loops to completeness (CASE_MAX_PASSES backstop, not a single hop)",
           called["passes"] == [investigator.CASE_MAX_PASSES])
    app_module._investigate_swarm("cx", shallow=False, deep=True)      # opt-in: deep multi-pass
    _check("deep=True → multi-pass agentic (CASE_MAX_PASSES)",
           called["agentic"] == 2 and called["passes"][-1] == investigator.CASE_MAX_PASSES)
    _check("the old Python deep_investigate loop is NOT used", called["deep_loop"] == 0)


def test_full_job_chain_wired(mp):
    # End-to-end wiring (minus HTTP/threading): _investigate_job → _investigate_swarm
    # → investigate_case_agentic → land_findings. Proves the chain the /api/investigate
    # route dispatches into is actually connected.
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        orig = db.connect
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            e = db.upsert_entity(conn, "trump-2026.io", "domain", r)
            db.add_mention(conn, e, r, "trump-2026.io", "c")
            db.set_objective(conn, "cx", "map the network")
            conn.commit()
        # Point every module's db.connect at the temp DB + stub the live agent.
        patched = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
        mp.setattr(app_module.db, "connect", patched)
        mp.setattr(investigator, "_run_agent",
                   lambda *a, **k: {"ok": True, "result_text": _FAKE_FINDINGS,
                                    "raw": {"total_cost_usd": 0.1, "num_turns": 5},
                                    "events": [], "steps": [], "capped": False})
        # Run the whole-case DEEP job synchronously (deep → persona coordinator, the
        # 4_points engine). This is what the route's thread calls.
        app_module._investigate_job(None, "cx", "ally", shallow=False, deep=True)
        job = app_module._INVESTIGATE_JOBS.get(app_module._investigate_key("cx"))
        _check("job finished done", job and job.get("status") == "done")
        _check("job result is the agentic run", job["result"].get("agentic") is True)
        with orig(db_path=dbp) as conn:
            runs = conn.execute("SELECT entity_id FROM enrichment_runs WHERE provider_slug='agent' "
                                "AND investigation='cx'").fetchall()
            # The deep persona engine lands one CASE-LEVEL run (entity_id NULL) per pass.
            _check("agentic case-level run(s) landed via the job chain",
                   len(runs) >= 1 and all(r["entity_id"] is None for r in runs))


def test_land_pass_salvages_capped_run(mp):
    """A capped run (timeout/cancel/kill) whose final text has NO findings JSON must
    reconstruct from the tool trail via _salvage_from_trail — not land zero (durability:
    no termination path drops work). A clean run with findings does NOT salvage."""
    salvage_calls = {"n": 0}
    mp.setattr(investigator, "_salvage_from_trail",
               lambda steps, text: salvage_calls.__setitem__("n", salvage_calls["n"] + 1) or
               {"findings": [{"entity": "evil.com", "entity_type": "domain",
                              "claim": "rescued from trail", "confidence": "medium"}],
                "summary": "reconstructed"})
    mp.setattr(investigator, "_build_process", lambda *a, **k: {"cost_usd": 0.0})
    mp.setattr(investigator, "land_findings", lambda *a, **k: {"results": 1, "promoted": 0})

    capped = {"result_text": "I was mid-investigation when cut off (no JSON).",
              "capped": True, "raw": {},
              "steps": [{"n": 1, "type": "tool", "tool": "whois_lookup",
                         "input": "target=evil.com", "result": "registrar X"}]}
    parsed, _ = investigator._land_pass(None, "c", "task", capped)
    _check("capped + no findings → trail salvage invoked", salvage_calls["n"] == 1)
    _check("salvaged findings are used (work not lost)",
           [f["entity"] for f in parsed.get("findings", [])] == ["evil.com"])

    salvage_calls["n"] = 0
    clean = {"result_text": '{"findings":[{"entity":"a.com","entity_type":"domain",'
             '"claim":"y","confidence":"high"}]}', "capped": False, "raw": {}, "steps": []}
    investigator._land_pass(None, "c", "task", clean)
    _check("clean run with findings → NO salvage", salvage_calls["n"] == 0)


def test_bounded_persona_aligns_with_hook():
    """The BOUNDED persona must tell the agent off-case = a lead, don't retry refused tools,
    conclude — so the prompt cooperates with the scope hook instead of fighting it. The deep
    persona keeps the chase. Both keep the full investigator base."""
    bp, dp = investigator.CASE_PERSONA_BOUNDED, investigator.CASE_PERSONA
    _check("bounded persona has the leads-first override", "BOUNDED RUN" in bp and "is a LEAD" in bp)
    _check("bounded persona says don't retry a refused target", "retrying a refused" in bp.lower())
    _check("bounded persona says CONCLUDE, not map the wider network", "CONCLUDE" in bp)
    _check("deep persona does NOT carry the bounded override", "BOUNDED RUN" not in dp)
    _check("both keep the full investigator base", "Senior Staff Investigator" in bp and "Senior Staff Investigator" in dp)


def main():
    test_case_persona_doctrine()
    test_bounded_persona_aligns_with_hook()
    test_run_agent_accepts_persona()
    test_case_task_carries_goal_and_roster()
    test_stop_endpoint_signals_cancel()
    for fn in (test_agentic_run_lands_findings, test_agentic_stop_keeps_findings,
               test_land_pass_salvages_capped_run,
               test_web_path_routing_is_analyst_driven, test_full_job_chain_wired):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_persona_investigator")


if __name__ == "__main__":
    main()
