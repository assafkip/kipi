"""k4p-01 reproducer: the default whole-case run must be UN-CAGED and must work
EVERY user seed.

Parity bug (case-031 diff): kipi's default run was caged (RULE-112 leads-first +
one-hop) AND the second seed (trumpstake.us, stored as a `url` entity) was dropped
from the roster because `url` is not a TARGET_TYPE. So the agent was both forbidden
from pivoting AND unaware of the second seed — it never ran WHOIS on trumpstake.us,
the exact move that recovered the operator (Markk Bennett) in 4_points.

This test pins the fix:
  1. `_case_roster` host-normalizes a url-typed seed into a domain target, so every
     user seed reaches the roster the agent is handed.
  2. The default run is UN-CAGED: `investigate_case_agentic` builds NO scope cage and
     uses the unbounded persona by default; the opt-in `caged=True` (shallow) re-bounds.
  3. An un-caged run that finds the operator + a cross-seed link actually lands them.

Run: .venv/bin/python -m investigations.tests.test_uncaged_pivots_all_seeds
"""
from pathlib import Path
import json
import tempfile

from investigations.storage import db
from investigations.agent import swarm, investigator


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def _ok(label, cond):
    assert cond, f"{label}: FAILED"
    print(f"  ok  {label}")


def _seed_case(conn):
    """A case the analyst gave TWO seed domains — one of which intake stored as a
    bare `url` (the trumpstake.us drop), plus a report so it's in scope."""
    conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('casino','casino')")
    r = db.insert_report(conn, "seed.md", "h", "markdown", "Seed", "casino",
                         "trumpfundus.com and https://trumpstake.us/")
    d = db.upsert_entity(conn, "trumpfundus.com", "domain", r)
    db.add_mention(conn, d, r, "trumpfundus.com", "c")
    # The second seed, stored as a URL entity (the real-world drop).
    u = db.upsert_entity(conn, "https://trumpstake.us/", "url", r)
    db.add_mention(conn, u, r, "https://trumpstake.us/", "c")
    conn.commit()
    return r


def test_all_seeds_reach_the_roster():
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            _seed_case(conn)
            names = {e["name"] for e in swarm._case_roster(conn, "casino")}
            _ok("first seed (domain) in roster", "trumpfundus.com" in names)
            _ok("second seed (url) host-normalized into roster",
                "trumpstake.us" in names)


def test_default_run_is_uncaged_and_shallow_re_cages():
    """The un-cage seam: capture how _run_agent is invoked. Default => no scope cage,
    unbounded persona. caged=True => scope roster + bounded persona."""
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            _seed_case(conn)
            captured = {}

            def fake_run_agent(task, **kw):
                captured["scope_roster"] = kw.get("scope_roster")
                captured["persona"] = kw.get("persona")
                return {"ok": True, "result_text": "{\"findings\":[],\"summary\":\"\"}",
                        "steps": [], "raw": [], "capped": False}

            orig = investigator._run_agent
            investigator._run_agent = fake_run_agent
            try:
                # Default: un-caged.
                investigator.investigate_case_agentic(conn, "casino", use_mcp=False,
                                                      max_passes=1)
                _ok("default: no scope cage", captured["scope_roster"] is None)
                _ok("default: unbounded persona (not the leads-first BOUNDED one)",
                    captured["persona"] == investigator.CASE_PERSONA)
                # Opt-in shallow cage.
                investigator.investigate_case_agentic(conn, "casino", use_mcp=False,
                                                      max_passes=1, caged=True)
                _ok("caged=True: scope roster present", bool(captured["scope_roster"]))
                _ok("caged=True: bounded (leads-first) persona",
                    captured["persona"] == investigator.CASE_PERSONA_BOUNDED)
            finally:
                investigator._run_agent = orig


_AGENT_JSON = json.dumps({
    "findings": [
        {"entity": "trumpfundus.com", "entity_type": "domain", "claim": "malicious drainer",
         "confidence": "high", "provenance": "virustotal: 3/91 malicious"},
        {"entity": "trumpstake.us", "entity_type": "domain", "claim": "registrant recovered",
         "confidence": "high", "provenance": "whois: trumpstake.us"},
        {"entity": "Markk Bennett", "entity_type": "person", "claim": "registrant of trumpstake.us",
         "confidence": "high", "provenance": "whois: trumpstake.us registrant"},
    ],
    "relationships": [
        {"src": "trumpstake.us", "dst": "Markk Bennett", "rel_type": "registered_by",
         "direction": "src_to_dst", "confidence": "high", "provenance": "whois"},
        {"src": "trumpfundus.com", "dst": "trumpstake.us", "rel_type": "same_campaign",
         "direction": "src_to_dst", "confidence": "medium", "provenance": "same scam kit"},
    ],
    "summary": "two-domain Trump scam; operator Markk Bennett recovered from the .us WHOIS",
})


def test_uncaged_run_lands_operator_and_links_both_seeds():
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            _seed_case(conn)

            # Realistic step trail: the agent ran WHOIS on BOTH seeds — both hosts appear
            # in tool RESULTS, which is what corroborates the cross-seed edge for landing.
            steps = [
                {"n": 1, "type": "tool", "tool": "infra",
                 "input": {"query": "trumpfundus.com"},
                 "result": "whois trumpfundus.com — Cloudflare, registrant privacy"},
                {"n": 2, "type": "tool", "tool": "infra",
                 "input": {"query": "trumpstake.us"},
                 "result": "whois trumpstake.us — registrant Markk Bennett "
                           "markk.bennett.2025@gmail.com +1.807.525.8080"},
            ]

            def fake_run_agent(task, **kw):
                return {"ok": True, "result_text": _AGENT_JSON, "steps": steps,
                        "raw": [], "capped": False}

            orig = investigator._run_agent
            investigator._run_agent = fake_run_agent
            try:
                out = investigator.investigate_case_agentic(conn, "casino", use_mcp=False,
                                                            max_passes=1)
                _ok("run ok", out.get("ok"))
                # The operator was recorded as a finding (gated or promoted, but present).
                op = conn.execute(
                    "SELECT COUNT(*) FROM enrichment_results WHERE title LIKE '%Markk Bennett%' "
                    "OR summary LIKE '%Markk Bennett%'").fetchone()[0]
                _ok("operator (Markk Bennett) landed as a finding", op >= 1)
                # The two seeds are linked (same_campaign edge between them).
                link = conn.execute(
                    "SELECT COUNT(*) FROM typed_relationships tr "
                    "JOIN entities a ON a.id = tr.src_entity_id "
                    "JOIN entities b ON b.id = tr.dst_entity_id "
                    "WHERE (a.canonical_name='trumpfundus.com' AND b.canonical_name='trumpstake.us') "
                    "   OR (a.canonical_name='trumpstake.us' AND b.canonical_name='trumpfundus.com')"
                ).fetchone()[0]
                _ok("the two seeds are linked in the graph", link >= 1)
            finally:
                investigator._run_agent = orig


def test_seed_host_scoped_to_this_case_even_if_entity_exists_globally():
    """Codex k4p-01 regression: a url seed whose host already exists as an entity in
    ANOTHER case must still get a mention IN THIS case, and the materialized mention
    must use a report belonging to THIS case (never another case's report)."""
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            # Case OTHER already has trumpstake.us as a domain entity (global pool).
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('other','other')")
            ro = db.insert_report(conn, "o.md", "ho", "markdown", "O", "other", "x")
            db.add_mention(conn, db.upsert_entity(conn, "trumpstake.us", "domain", ro), ro,
                           "trumpstake.us", "c")
            # Case CASINO has it only as a url seed.
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('casino','casino')")
            rc = db.insert_report(conn, "c.md", "hc", "markdown", "C", "casino", "x")
            db.add_mention(conn, db.upsert_entity(conn, "https://trumpstake.us/", "url", rc), rc,
                           "https://trumpstake.us/", "c")
            conn.commit()

            swarm.ensure_seed_domains(conn, "casino")

            # The host now has a mention in CASINO (not only OTHER).
            in_casino = conn.execute(
                "SELECT COUNT(*) FROM mentions m JOIN reports r ON r.id = m.report_id "
                "JOIN entities e ON e.id = m.entity_id "
                "WHERE e.canonical_name='trumpstake.us' AND r.investigation='casino'").fetchone()[0]
            _ok("pre-existing host entity scoped into THIS case", in_casino >= 1)
            # And it reaches the casino roster.
            names = {e["name"] for e in swarm._case_roster(conn, "casino")}
            _ok("host in this case's roster", "trumpstake.us" in names)


if __name__ == "__main__":
    test_all_seeds_reach_the_roster()
    test_seed_host_scoped_to_this_case_even_if_entity_exists_globally()
    test_default_run_is_uncaged_and_shallow_re_cages()
    test_uncaged_run_lands_operator_and_links_both_seeds()
    print("\nall green")
