"""k4p-02 reproducer: the whole-case run concludes on COMPLETENESS (coverage), not a
fixed hop count and not a budget cut (founder: "no budget hop"). 4_points Phase 5.

Pins:
  1. `_coverage_met` — covered when the network is found + attributed + linked.
  2. `_in_scope` — the relevance boundary that replaces the roster cage: in-case OR
     attributive-linked = in-scope; a bare web-co-mention is NOT (it's a lead).
  3. The loop stops with stop_reason='covered' once coverage is met, and 'dry' when a
     pass adds nothing — and records pass-count + stop-reason.

Run: .venv/bin/python -m investigations.tests.test_completeness_stop
"""
from pathlib import Path
import json
import tempfile

from investigations.storage import db
from investigations.agent import investigator


def _ok(label, cond):
    assert cond, f"{label}: FAILED"
    print(f"  ok  {label}")


def test_coverage_met():
    covered = {"coverage_check": {"has_findings": True, "has_assessment": True,
                                  "has_relationships": True}}
    partial = {"coverage_check": {"has_findings": True, "has_assessment": False,
                                  "has_relationships": True}}
    _ok("found + attributed + linked => covered", investigator._coverage_met(covered))
    _ok("missing assessment => NOT covered", not investigator._coverage_met(partial))
    _ok("empty => NOT covered", not investigator._coverage_met({}))


def _link(conn, a, b, rel):
    conn.execute("INSERT OR IGNORE INTO typed_relationships "
                 "(src_entity_id, dst_entity_id, rel_type, confidence, evidence, status) "
                 "VALUES (?, ?, ?, 'high', 'e', 'active')", (a, b, rel))


def test_in_scope_branches():
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('cx','cx')")
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "x")
            a = db.upsert_entity(conn, "seed.com", "domain", r); db.add_mention(conn, a, r, "seed.com", "c")
            # B is NOT mentioned in the case, but is registered_by-linked to in-case A.
            b = db.upsert_entity(conn, "Operator Person", "person", r)
            _link(conn, a, b, "registered_by")
            # C exists globally but no case mention + no attributive link (a web co-mention).
            db.upsert_entity(conn, "coincidental.com", "domain", r)
            # strip C's mention so it's not in-case
            conn.execute("DELETE FROM mentions WHERE entity_id=(SELECT id FROM entities WHERE canonical_name='coincidental.com')")
            conn.commit()
            _ok("a seed/in-case entity is in-scope", investigator._in_scope(conn, "seed.com", "cx"))
            _ok("an attributive-linked entity is in-scope", investigator._in_scope(conn, "Operator Person", "cx"))
            _ok("a bare web-co-mention is NOT in-scope (lead)", not investigator._in_scope(conn, "coincidental.com", "cx"))
            _ok("a non-existent name is NOT in-scope", not investigator._in_scope(conn, "nope.com", "cx"))


def _seed_case(conn):
    conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('casino','casino')")
    r = db.insert_report(conn, "s.md", "h", "markdown", "S", "casino", "trumpfundus.com")
    db.add_mention(conn, db.upsert_entity(conn, "trumpfundus.com", "domain", r), r, "trumpfundus.com", "c")
    conn.commit()


_COVERED = json.dumps({
    "findings": [{"entity": "trumpfundus.com", "entity_type": "domain", "claim": "drainer",
                  "confidence": "high", "provenance": "virustotal"}],
    "relationships": [{"src": "trumpfundus.com", "dst": "Markk Bennett", "rel_type": "registered_by",
                       "direction": "src_to_dst", "confidence": "high", "provenance": "whois",
                       "corroborated": True}],
    "assessment": {"attributed_actor": "Markk Bennett", "best_judgment": "trump scam operator"},
    "summary": "covered",
})


def test_run_stops_on_covered():
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            _seed_case(conn)
            steps = [{"n": 1, "type": "tool", "tool": "infra",
                      "input": {"query": "trumpfundus.com"},
                      "result": "whois trumpfundus.com — Markk Bennett registrant"}]
            orig = investigator._run_agent
            investigator._run_agent = lambda task, **k: {"ok": True, "result_text": _COVERED,
                                                         "steps": steps, "raw": [], "capped": False}
            try:
                out = investigator.investigate_case_agentic(conn, "casino", use_mcp=False,
                                                            max_passes=5)
                _ok("stops on completeness, not the pass cap", out.get("stop_reason") == "covered")
                _ok("did NOT burn all 5 passes (stopped early when covered)", out.get("passes", 99) < 5)
            finally:
                investigator._run_agent = orig


def test_run_stops_dry_on_empty_pass():
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            _seed_case(conn)
            orig = investigator._run_agent
            investigator._run_agent = lambda task, **k: {"ok": True,
                                                         "result_text": '{"findings":[],"summary":""}',
                                                         "steps": [], "raw": [], "capped": False}
            try:
                out = investigator.investigate_case_agentic(conn, "casino", use_mcp=False,
                                                            max_passes=5)
                _ok("an empty pass stops the run as dry (no budget/hop needed)",
                    out.get("stop_reason") == "dry")
                _ok("stop-reason + pass-count are recorded",
                    "stop_reason" in out and "passes" in out)
            finally:
                investigator._run_agent = orig


def test_covered_requires_every_seed_worked():
    """Codex k4p-02 regression: 'covered' must be CUMULATIVE — pass 0 covering ONE seed
    (finding+assessment+rel) must NOT conclude the case while a second seed is unworked."""
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('casino','casino')")
            r = db.insert_report(conn, "s.md", "h", "markdown", "S", "casino", "x")
            db.add_mention(conn, db.upsert_entity(conn, "trumpfundus.com", "domain", r), r, "trumpfundus.com", "c")
            db.add_mention(conn, db.upsert_entity(conn, "trumpstake.us", "domain", r), r, "trumpstake.us", "c")
            conn.commit()
            # The agent only ever covers seed #1; seed #2 stays unworked every pass.
            steps = [{"n": 1, "type": "tool", "tool": "infra", "input": {"query": "trumpfundus.com"},
                      "result": "whois trumpfundus.com — Markk Bennett"}]
            orig = investigator._run_agent
            investigator._run_agent = lambda task, **k: {"ok": True, "result_text": _COVERED,
                                                         "steps": steps, "raw": [], "capped": False}
            try:
                out = investigator.investigate_case_agentic(conn, "casino", use_mcp=False,
                                                            max_passes=3)
                _ok("does NOT conclude 'covered' while a seed is unworked",
                    out.get("stop_reason") != "covered")
            finally:
                investigator._run_agent = orig


if __name__ == "__main__":
    test_coverage_met()
    test_covered_requires_every_seed_worked()
    test_in_scope_branches()
    test_run_stops_on_covered()
    test_run_stops_dry_on_empty_pass()
    print("\nall green")
