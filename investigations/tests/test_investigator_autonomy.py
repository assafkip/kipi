"""The investigator runs like a senior investigator: it (1) PLANS its own targets
instead of a SQL score-sort, and (2) builds the GRAPH itself — but only from findings
it can back up. A finding that ≥2 tools corroborated (or high-confidence with a real
backing tool result) auto-promotes to a node; an unbacked / single-source / unvalidated
finding LANDS but stays gated for the analyst. The agent no longer writes unproven
claims into the graph as fact.

Run: .venv/bin/python -m investigations.tests.test_investigator_autonomy
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.agent import investigator, swarm


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


def _seed(p):
    db.init_db(p)
    with db.connect(p) as conn:
        rep = db.insert_report(conn, "r.md", "h", "markdown", "T", "cat", "x")
        src = db.upsert_entity(conn, "haiyiplants.com", "domain", rep)
        db.add_mention(conn, src, rep, "haiyiplants.com", "ctx")
        for nm in ("a.com", "b.com", "c.com"):
            e = db.upsert_entity(conn, nm, "domain", rep)
            db.add_mention(conn, e, rep, nm, "ctx")
        conn.commit()
    return src


def test_agent_builds_graph():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "t.db"
        src = _seed(p)
        # A BACKED finding (≥2 tools surfaced it, high confidence, real step) — the
        # values _attribute_findings would set in the real flow. 4_points A-F model: a
        # DOMAIN promotes only when INFRA-confirmed; this was surfaced by whois (infra),
        # so infra_source_count>=1 → grade A → promotes.
        parsed = {"summary": "s", "findings": [
            {"entity": "evil-sister.com", "entity_type": "domain",
             "claim": "shares GA tag with the hub", "provenance": "whois: evil-sister.com",
             "confidence": "high", "step_ref": 1, "source_count": 2, "infra_source_count": 2}]}
        with db.connect(p) as conn:
            res = investigator.land_findings(conn, "cat", "haiyiplants.com", "task",
                                             parsed, entity_id=src, auto_promote=True)
            _check("finding stored", res["results"] == 1)
            _check("backed finding auto-promotes to the graph", res["promoted"] == 1)
            _check("backed finding is not gated", res["gated"] == 0)
        with db.connect(p) as conn:
            node = conn.execute(
                "SELECT id FROM entities WHERE canonical_name = 'evil-sister.com'").fetchone()
            _check("graph node exists", node is not None)
            rel = conn.execute(
                "SELECT 1 FROM relationships WHERE src_entity_id = ? AND dst_entity_id = ?",
                (src, node["id"])).fetchone()
            _check("node is linked to the source actor", rel is not None)

        # An UNBACKED finding (no tool result contains it → source_count 0) must NOT
        # auto-promote — it lands gated for the analyst. This is the "stop trusting
        # itself" rule: unprovable claims never enter the graph as fact.
        unbacked = {"summary": "s", "findings": [
            {"entity": "gated-only.com", "entity_type": "domain", "claim": "c",
             "provenance": "p", "confidence": "high", "step_ref": None, "source_count": 0}]}
        with db.connect(p) as conn:
            res = investigator.land_findings(conn, "cat", "haiyiplants.com", "task",
                                             unbacked, entity_id=src, auto_promote=True)
            _check("unbacked finding still lands", res["results"] == 1)
            _check("unbacked finding is gated, not promoted", res["promoted"] == 0)
            _check("gate counted it", res["gated"] == 1)
            node = conn.execute(
                "SELECT id FROM entities WHERE canonical_name = 'gated-only.com'").fetchone()
            _check("unbacked finding makes no graph node", node is None)

        # 4_points reproducibility rule: a domain seen ONLY in web recall (2 web sources,
        # 0 infra) is grade B but NOT a cluster node — it lands as a LEAD. This is the fix
        # for "perplexity-recalled domains reshuffle the graph every run".
        web_only = {"summary": "s", "findings": [
            {"entity": "web-only-lead.com", "entity_type": "domain", "claim": "named in an article",
             "provenance": "web_search", "confidence": "high",
             "step_ref": 2, "source_count": 2, "infra_source_count": 0}]}
        with db.connect(p) as conn:
            res = investigator.land_findings(conn, "cat", "haiyiplants.com", "task",
                                             web_only, entity_id=src, auto_promote=True)
            _check("web-only domain lands", res["results"] == 1)
            _check("web-only domain is gated, not promoted", res["promoted"] == 0 and res["gated"] == 1)
            node = conn.execute(
                "SELECT id FROM entities WHERE canonical_name = 'web-only-lead.com'").fetchone()
            _check("web-only domain makes no graph node", node is None)

        # The hard off switch still works (auto_promote=False keeps everything off-graph).
        off = {"summary": "s", "findings": [
            {"entity": "off-switch.com", "entity_type": "domain", "claim": "c",
             "provenance": "dns: off-switch.com", "confidence": "high", "source_count": 2}]}
        with db.connect(p) as conn:
            res = investigator.land_findings(conn, "cat", "haiyiplants.com", "task",
                                             off, entity_id=src, auto_promote=False)
            _check("auto_promote=False promotes nothing", res["promoted"] == 0)


def test_planner_decides_targets(mp):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "t.db"
        _seed(p)
        # Stub the planner LLM: it picks b.com then a.com, plus a hallucinated ghost.
        mp.setattr(swarm.llm, "ask_json", lambda *a, **k: {
            "plan": [{"entity": "b.com", "why": "hub"},
                     {"entity": "a.com", "why": "operator persona"},
                     {"entity": "ghost.com", "why": "not in roster"}],
            "skip_rationale": "platform noise", "stop_when": "dry"})
        with db.connect(p) as conn:
            targets, meta = swarm.plan_investigation(conn, "cat", limit=12)
        _check("targets come from the agent plan", meta["source"] == "agent-plan")
        _check("agent's priority order is preserved", targets == ["b.com", "a.com"])
        _check("hallucinated target filtered to the roster", "ghost.com" not in targets)

        # LLM down → deterministic fallback so the swarm still runs.
        def boom(*a, **k):
            raise RuntimeError("llm unavailable")
        mp.setattr(swarm.llm, "ask_json", boom)
        with db.connect(p) as conn:
            targets, meta = swarm.plan_investigation(conn, "cat", limit=12)
        _check("falls back to the SQL seed when planning is unavailable",
               meta["source"] == "fallback-sql")
        _check("fallback still returns targets", len(targets) >= 1)


def test_tool_status_preflight():
    # Pre-run readiness so a no-key run isn't a silent surprise.
    s = swarm.tool_status()
    _check("live + missing are lists", isinstance(s["live"], list) and isinstance(s["missing"], list))
    _check("counts match the lists",
           s["live_count"] == len(s["live"]) and s["missing_count"] == len(s["missing"]))
    _check("every missing tool names the env var to set",
           all(m.get("env_var") for m in s["missing"]))
    # Preflight must report on every adapter in the registry (no silent gaps). Tied to
    # the registry size so adding/removing an adapter never drifts this check.
    from investigations.enrich.registry import all_adapters
    _check("covers the full adapter registry",
           s["live_count"] + s["missing_count"] == len(all_adapters()))


def main():
    test_agent_builds_graph()
    test_tool_status_preflight()
    mp = _MP()
    try:
        test_planner_decides_targets(mp)
    finally:
        mp.undo()
    print("\nPASS: test_investigator_autonomy")


if __name__ == "__main__":
    main()
