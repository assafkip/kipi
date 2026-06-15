"""PRD-09: the investigator off the leash. The whole-case run chases leads round after
round until the trail goes cold (loop-until-dry) or a budget ceiling — with a real
per-target turn budget. Tests the loop control deterministically (agents mocked).

Run: .venv/bin/python -m investigations.tests.test_depth_engine
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.agent import swarm
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


def _fake_volley(rounds_seen):
    def vol(conn, case, targets, **k):
        rounds_seen.append(list(targets))
        return [{"ok": True, "entity": t, "findings": 1, "promoted": 1} for t in targets]
    return vol


def test_bounded_depth_defaults():
    # Deeper than the old single-volley (10 turns / 1 round), but HARD-bounded so a run
    # can't surprise-bill. The dollar cap is the real ceiling.
    _check("per-target turns deeper than old 10", swarm.DEEP_TURNS >= 16)
    _check("loops more than once", swarm.MAX_ROUNDS >= 2)
    _check("entity budget bounded", 8 <= swarm.DEEP_ENTITY_BUDGET <= 30)
    _check("a dollar cost cap exists", swarm.DEEP_COST_CAP_USD > 0)
    from investigations.agent import investigator
    import inspect
    sig = inspect.signature(investigator.investigate_entity)
    _check("investigate_entity turns deeper than old 12",
           sig.parameters["max_turns"].default >= 16)


def _cost_volley(per_target):
    def vol(conn, case, targets, **k):
        return [{"ok": True, "entity": t, "findings": 1, "promoted": 1, "cost_usd": per_target} for t in targets]
    return vol


def test_cost_cap_bounds_scope_and_finishes(mp):
    # The $ cap becomes a TARGET budget UP FRONT: the run commits to a scope it can
    # finish (stop='budget'), not a death mid-investigation. cap $2.7 / est $0.9 ≈ 3.
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        orig = db.connect
        mp.setattr(swarm.db, "connect", lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
        mp.setattr(swarm, "plan_investigation", lambda conn, case, limit=12: (["seed1"], {"source": "t"}))
        mp.setattr(swarm, "volley", _cost_volley(0.5))
        c = {"i": 1}
        mp.setattr(swarm, "_uninvestigated_targets",
                   lambda conn, case, seen, limit: (c.__setitem__("i", c["i"] + 1) or [f"pivot{c['i']}"]))
        events = []
        with db.connect(dbp) as conn:
            res = swarm.deep_investigate(conn, "cx", cost_cap=2.7, budget=99, rounds=10, on_event=events.append)
        _check("scope bounded to ~cap/est targets", res["targets"] <= 4)
        _check("finished its planned scope cleanly (no mid-run death)", res["stop"] == "budget")
        _check("told you the estimate up front", any("est ~$" in e for e in events))


def test_runaway_backstop(mp):
    # If real per-target cost runs FAR over the estimate, a backstop catches it.
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        orig = db.connect
        mp.setattr(swarm.db, "connect", lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
        mp.setattr(swarm, "plan_investigation", lambda conn, case, limit=12: (["seed1"], {"source": "t"}))
        mp.setattr(swarm, "volley", _cost_volley(5.0))   # way over the $0.9 estimate
        c = {"i": 1}
        mp.setattr(swarm, "_uninvestigated_targets",
                   lambda conn, case, seen, limit: (c.__setitem__("i", c["i"] + 1) or [f"pivot{c['i']}"]))
        with db.connect(dbp) as conn:
            res = swarm.deep_investigate(conn, "cx", cost_cap=3.0, budget=99, on_event=lambda l: None)
        _check("backstop stops a cost overrun", res["stop"] == "cost-capped")


def test_loops_until_dry(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        orig = db.connect
        mp.setattr(swarm.db, "connect", lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
        rounds_seen, events = [], []
        mp.setattr(swarm, "plan_investigation", lambda conn, case, limit=12: (["seed1"], {"source": "t"}))
        mp.setattr(swarm, "volley", _fake_volley(rounds_seen))
        n = {"i": 0}
        # round 1 inventory has one untried target; round 2 inventory is empty → dry.
        mp.setattr(swarm, "_uninvestigated_targets",
                   lambda conn, case, seen, limit: (n.__setitem__("i", n["i"] + 1) or (["pivot1"] if n["i"] == 1 else [])))
        with db.connect(dbp) as conn:
            res = swarm.deep_investigate(conn, "cx", on_event=events.append)
        _check("ran exactly 2 rounds", res["round_count"] == 2)
        _check("chased the untried inventory target in round 2", rounds_seen == [["seed1"], ["pivot1"]])
        _check("stopped because the inventory went dry", res["stop"] == "exhausted")
        _check("emitted a round event", any(e.startswith("round 1:") for e in events))
        # No "stuck / stalled / trail exhausted" chatter — recovery is silent.
        _check("no 'got stuck' narration to the user",
               not any("exhausted" in e or "stalled" in e or "stuck" in e for e in events))
        _check("aggregated findings across rounds", res["findings"] == 2)


def test_budget_cap_stops_and_is_flagged(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        orig = db.connect
        mp.setattr(swarm.db, "connect", lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
        rounds_seen = []
        mp.setattr(swarm, "plan_investigation", lambda conn, case, limit=12: (["seed1"], {"source": "t"}))
        mp.setattr(swarm, "volley", _fake_volley(rounds_seen))
        c = {"i": 1}
        # inventory always has a brand-new target → would run forever; budget must stop it.
        mp.setattr(swarm, "_uninvestigated_targets",
                   lambda conn, case, seen, limit: (c.__setitem__("i", c["i"] + 1) or [f"pivot{c['i']}"]))
        with db.connect(dbp) as conn:
            res = swarm.deep_investigate(conn, "cx", budget=3, rounds=10, on_event=lambda l: None)
        _check("stopped at the budget ceiling (not forever)", res["targets"] <= 3)
        _check("finished its planned scope (stop=budget, not a mid-run death)",
               res["stop"] == "budget")


def test_uninvestigated_inventory_includes_wallets():
    # The real helper (not mocked): the next-round pool is the case's pivotable
    # INVENTORY across every asset type — so wallets get chased, and already-seen
    # targets are excluded. This is the fix for "stops after the fan out" + "assets
    # are more than domains".
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            d = db.upsert_entity(conn, "evil.com", "domain", r); db.add_mention(conn, d, r, "evil.com", "c")
            w = db.upsert_entity(conn, "0xWALLET", "crypto_wallet", r); db.add_mention(conn, w, r, "0xWALLET", "c")
            conn.commit()
            out = swarm._uninvestigated_targets(conn, "cx", {"evil.com"}, 50)
            _check("excludes the already-seen domain", "evil.com" not in out)
            _check("includes the untried wallet (assets beyond domains)", "0xWALLET" in out)


def test_web_swarm_default_is_analyst_driven(mp):
    # Founder decision 2026-06-05 (revises 2026-06-03; replay D4): both modes use ONE
    # agent (no fan-out). The DEFAULT is investigate_case_agentic(max_passes=1) — one
    # bounded pass; deep=True re-seeds multi-pass. The old per-entity volley→crew
    # fan-out is no longer the default.
    from investigations.agent import investigator
    called = {"agentic": 0, "deep_loop": 0, "passes": []}
    def _agentic(conn, case, on_event=None, max_passes=1, **k):
        called["agentic"] += 1; called["passes"].append(max_passes); return {"ok": True}
    mp.setattr(investigator, "investigate_case_agentic", _agentic)
    mp.setattr(swarm, "deep_investigate",
               lambda *a, **k: called.__setitem__("deep_loop", called["deep_loop"] + 1) or {"ok": True})
    import contextlib
    @contextlib.contextmanager
    def _noconn(*a, **k):
        yield None
    mp.setattr(app_module.db, "connect", _noconn)
    app_module._investigate_swarm("cx", shallow=False)   # the default
    _check("default → ONE bounded agent (no fan-out)",
           called["agentic"] == 1)
    _check("default loops to completeness (CASE_MAX_PASSES backstop, not a single hop)",
           called["passes"] == [investigator.CASE_MAX_PASSES])
    app_module._investigate_swarm("cx", shallow=False, deep=True)   # opt-in: deep multi-pass
    _check("deep=True → multi-pass agentic (CASE_MAX_PASSES)",
           called["agentic"] == 2 and called["passes"][-1] == investigator.CASE_MAX_PASSES)
    _check("the old Python deep_investigate loop is NOT used", called["deep_loop"] == 0)


def test_pre_run_estimate_math_and_equality(mp):
    """prd: pre-run-cost-estimate. estimate_run is the SINGLE source of truth — its point
    estimate is exactly the number deep_investigate announces up front (no before/after
    drift). Cold-start falls back to EST_COST_PER_TARGET; once there's prior agent spend it
    uses the historical avg. One-hop is a fixed tiny estimate."""
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            # Cold start: no agent runs yet → fallback per-target, basis cold-start.
            est = swarm.estimate_run(conn, "cx", deep=True, cost_cap=2.7, budget=99)
            _check("cold-start basis when no agent history", est["basis"] == "cold-start")
            # cap 2.7 / per-target 0.9 = 3 targets (the SAME math deep_investigate uses).
            _check("est_targets = cap / per-target", est["est_targets"] == 3)
            _check("cold-start typical = targets * fallback per-target",
                   abs(est["est_typical_usd"] - 3 * swarm.EST_COST_PER_TARGET) < 1e-6)
            _check("cap ceiling is carried for the worst case", est["cost_cap_usd"] == 2.7)

            # One-hop expand: fixed tiny point estimate, no cap.
            oh = swarm.estimate_run(conn, "cx", deep=False)
            _check("one-hop is the fixed tiny estimate",
                   oh["est_targets"] == 1
                   and abs(oh["est_typical_usd"] - round(swarm.EST_COST_PER_ONE_HOP, 4)) < 1e-9)
            _check("one-hop has no cap", oh["cost_cap_usd"] is None)

            # Historical: seed past agent runs with known costs → avg drives the point estimate.
            # (FK enforced: the 'agent' provider must exist before its runs.)
            conn.execute("INSERT INTO osint_providers (slug, display_name) VALUES ('agent', 'Agent')")
            for c in (1.0, 2.0):   # avg 1.5
                conn.execute("INSERT INTO enrichment_runs (provider_slug, query, status, cost_usd) "
                             "VALUES ('agent', 'x', 'done', ?)", (c,))
            conn.commit()
            est2 = swarm.estimate_run(conn, "cx", deep=True, cost_cap=2.7, budget=99)
            _check("basis flips to historical once agent runs exist", est2["basis"] == "historical")
            _check("typical = historical avg (1.5) * targets (3) = 4.5",
                   abs(est2["est_typical_usd"] - 4.5) < 1e-6)

        # Equality: the dollar figure deep_investigate announces UP FRONT == estimate_run's.
        orig = db.connect
        mp.setattr(swarm.db, "connect", lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
        mp.setattr(swarm, "plan_investigation", lambda conn, case, limit=12: (["seed1"], {"source": "t"}))
        mp.setattr(swarm, "volley", _cost_volley(0.1))
        mp.setattr(swarm, "_uninvestigated_targets", lambda conn, case, seen, limit: [])
        events = []
        with db.connect(dbp) as conn:
            ref = swarm.estimate_run(conn, "cx", deep=True, cost_cap=2.7, budget=99)
            swarm.deep_investigate(conn, "cx", cost_cap=2.7, budget=99, rounds=1, on_event=events.append)
        plan_line = next((e for e in events if "est ~$" in e), "")
        _check("deep_investigate announces estimate_run's exact number (no drift)",
               f"${ref['est_typical_usd']:.2f}" in plan_line)


def main():
    test_bounded_depth_defaults()
    test_uninvestigated_inventory_includes_wallets()
    for fn in (test_loops_until_dry, test_budget_cap_stops_and_is_flagged,
               test_cost_cap_bounds_scope_and_finishes, test_runaway_backstop,
               test_pre_run_estimate_math_and_equality,
               test_web_swarm_default_is_analyst_driven):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_depth_engine")


if __name__ == "__main__":
    main()
