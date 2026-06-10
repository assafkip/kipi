"""Investigator agent: findings parse + gated landing + swarm target picking.

Run: .venv/bin/python -m investigations.tests.test_investigator

The claude agent subprocess is stubbed so the test is deterministic + offline.
"""
import tempfile
from pathlib import Path

import pytest

from investigations.storage import db
from investigations.agent import investigator, swarm


@pytest.fixture(autouse=True)
def _force_cold_path(monkeypatch):
    """These tests mock the cold _run_agent; warm is default-on, so without pinning it
    off investigate_entity would call _run_agent_warm — boot a real warm agent (hangs on
    MCP startup) and bypass the mock. Warm-path behavior is covered in test_warm_*.py."""
    monkeypatch.setattr(investigator, "warm_run_available", lambda: False)


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


AGENT_JSON = (
    '{"findings":['
    '{"entity":"sub.evil.com","entity_type":"subdomain","claim":"cert-transparency subdomain",'
    '"confidence":"high","provenance":"crtsh: evil.com","unvalidated":false},'
    '{"entity":"9.9.9.9","entity_type":"ip","claim":"resolves here","confidence":"medium",'
    '"provenance":"infra: dns evil.com","unvalidated":true}],'
    '"summary":"two pivots found"}'
)


def test_parse_findings_from_messy_text():
    text = "prose prose\nblah\n" + AGENT_JSON + "\n"
    p = investigator._parse_findings(text)
    _check("parsed 2 findings", len(p["findings"]), 2)
    _check("summary parsed", p["summary"], "two pivots found")


# A real run's tool trail: crt.sh corroborates the subdomain -> grade A -> promotes.
# The unvalidated IP has no corroboration -> stays gated (correct).
_GRAPH_STEPS = [
    {"n": 1, "type": "tool", "tool": "crtsh_subdomains", "input": "evil.com",
     "result": "sub.evil.com observed in CT logs"},
]


def test_investigate_entity_builds_graph(mp):
    mp.setattr(investigator, "_run_agent",
               lambda task, **k: {"ok": True, "result_text": AGENT_JSON, "steps": _GRAPH_STEPS})
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-a','case-a')")
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", "evil.com noted")
            e = db.upsert_entity(conn, "evil.com", "domain", r)
            db.add_mention(conn, e, r, "evil.com", "c")
            conn.commit()
            out = investigator.investigate_entity(conn, "evil.com", case="case-a")
            _check("ok", out["ok"], True)
            _check("2 findings landed", out["findings"], 2)
            # Both findings stored as enrichment_results under one 'agent' run.
            runs = conn.execute("SELECT COUNT(*) FROM enrichment_runs WHERE provider_slug='agent'").fetchone()[0]
            _check("one agent run recorded", runs, 1)
            res = conn.execute("SELECT COUNT(*) FROM enrichment_results er JOIN enrichment_runs r ON r.id=er.run_id WHERE r.provider_slug='agent'").fetchone()[0]
            _check("2 finding results stored", res, 2)
            # Agent builds the graph: the VALIDATED subdomain is auto-added as a node.
            built = conn.execute("SELECT COUNT(*) FROM entities WHERE canonical_name='sub.evil.com'").fetchone()[0]
            _check("validated finding auto-added to the graph", built, 1)
            # The UNVALIDATED pivot (9.9.9.9) stays gated — not written to the graph as fact.
            gated = conn.execute("SELECT COUNT(*) FROM entities WHERE canonical_name='9.9.9.9'").fetchone()[0]
            _check("unvalidated finding NOT auto-added", gated, 0)
            # Unvalidated marker preserved on the gated result.
            unval = conn.execute("SELECT COUNT(*) FROM enrichment_results WHERE summary LIKE '%UNVALIDATED%'").fetchone()[0]
            _check("unvalidated finding flagged", unval, 1)


def test_swarm_targets_picks_pivotable(mp):
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-a','case-a')")
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", "x")
            for name, typ in [("evil.com", "domain"), ("8.8.8.8", "ip"),
                              ("@actor", "handle"), ("just a sentence", "person_candidate")]:
                eid = db.upsert_entity(conn, name, typ, r)
                db.add_mention(conn, eid, r, name, "c")
            conn.commit()
            targets = swarm._targets(conn, "case-a", limit=10)
            assert "evil.com" in targets and "8.8.8.8" in targets and "@actor" in targets, targets
            _check("noise/person_candidate excluded from targets",
                   "just a sentence" in targets, False)


def _belt_type(et):
    return [s for s, _ in investigator._infra_belt_for_type(et)]


def test_infra_belt_by_type():
    _check("domain belt", _belt_type("domain"), ["crtsh", "infra", "infra"])
    _check("ip belt", _belt_type("ip"), ["infra", "ipgeo"])
    _check("email belt", _belt_type("email"), ["whoisxml"])
    _check("handle has no infra belt", _belt_type("handle"), [])


def test_quick_investigate_is_one_hop(mp):
    """The trimmed 'Investigate this node': deterministic infra belt (code) + ONE short read.
    The 28-turn agent must NOT run; infra results land as nodes; a read is stored."""
    from investigations.enrich import registry
    from investigations.enrich.base import EnrichmentResult

    def _crtsh_run(q, mode=None, timeout=90):
        return [EnrichmentResult("subdomain", "sub.evil.com", "CT-log subdomain of evil.com")]

    def _infra_run(q, mode=None, timeout=90):
        if mode == "dns":
            return [EnrichmentResult("dns", "A 9.9.9.9", "evil.com resolves to 9.9.9.9")]
        return [EnrichmentResult("whois", "registrant bad@evil.com", "registrant email bad@evil.com")]

    # The deep agent must never fire on a quick node investigation.
    def _no_agent(*a, **k):
        raise AssertionError("deep 28-turn agent ran on a quick one-hop node investigation")

    mp.setattr(registry.get_adapter("crtsh"), "run", _crtsh_run)
    mp.setattr(registry.get_adapter("infra"), "run", _infra_run)
    mp.setattr(investigator, "_run_agent", _no_agent)
    mp.setattr(investigator, "ask",
               lambda *a, **k: "evil.com is a scam domain. Pivot: reverse-whois on bad@evil.com.")

    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-a','case-a')")
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", "evil.com noted")
            eid = db.upsert_entity(conn, "evil.com", "domain", r)
            db.add_mention(conn, eid, r, "evil.com", "c")
            conn.commit()

            out = investigator.investigate_entity_quick(conn, "evil.com", case="case-a")
            _check("ok", out["ok"], True)
            _check("flagged as a quick one-hop", out["quick"], True)
            _check("ran the keyless infra belt", out["providers_run"], ["crtsh", "infra", "infra"])
            # No 'agent' run was recorded — this hop is deterministic, not the 28-turn agent.
            agent_runs = conn.execute(
                "SELECT COUNT(*) FROM enrichment_runs WHERE provider_slug='agent'").fetchone()[0]
            _check("no deep-agent run recorded", agent_runs, 0)
            # The CT subdomain promoted into a real graph node + edge.
            built = conn.execute(
                "SELECT COUNT(*) FROM entities WHERE canonical_name='sub.evil.com'").fetchone()[0]
            _check("infra result landed as a node", built, 1)
            # The short read was stored on the node's dossier.
            from investigations import annotations as annotations_mod
            ann = annotations_mod.get(conn, eid) or {}
            _check("quick read stored on the node", "Quick read:" in (ann.get("dossier_override") or ""), True)


def test_quick_investigate_stops_on_cancel(mp):
    """Stop must actually stop a one-hop run: a set cancel Event halts the belt before any
    provider runs and skips the read. (Regression: the quick path ignored Stop.)"""
    import threading
    from investigations.enrich import registry
    from investigations.enrich.base import EnrichmentResult

    def _should_not_run(q, mode=None, timeout=90):
        raise AssertionError("belt ran a provider after Stop was pressed")

    mp.setattr(registry.get_adapter("crtsh"), "run", _should_not_run)
    mp.setattr(registry.get_adapter("infra"), "run", _should_not_run)
    mp.setattr(investigator, "ask",
               lambda *a, **k: (_ for _ in ()).throw(AssertionError("read ran after Stop")))

    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-a','case-a')")
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", "evil.com noted")
            db.upsert_entity(conn, "evil.com", "domain", r)
            conn.commit()
            cancel = threading.Event(); cancel.set()  # Stop already pressed
            out = investigator.investigate_entity_quick(conn, "evil.com", case="case-a", cancel=cancel)
            _check("ok", out["ok"], True)
            _check("reported stopped", out.get("stopped"), True)
            _check("no providers ran after Stop", out["providers_run"], [])


def main():
    test_parse_findings_from_messy_text()
    test_infra_belt_by_type()
    mp = _MP()
    try:
        test_investigate_entity_builds_graph(mp)
    finally:
        mp.undo()
    mp = _MP()
    try:
        test_swarm_targets_picks_pivotable(mp)
    finally:
        mp.undo()
    mp = _MP()
    try:
        test_quick_investigate_is_one_hop(mp)
    finally:
        mp.undo()
    mp = _MP()
    try:
        test_quick_investigate_stops_on_cancel(mp)
    finally:
        mp.undo()
    print("\nPASS: test_investigator")


if __name__ == "__main__":
    main()
