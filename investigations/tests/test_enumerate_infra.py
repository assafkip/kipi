"""Stage 1 acceptance (speed-cost-staged-rollout plan): enumerate_infra lands BOTH
seeds + their infra edges with ZERO LLM calls, belts the tier-2 infra it surfaced
(new IP / registrant email) exactly once, and re-running lands no duplicates.

Run: .venv/bin/python -m pytest investigations/tests/test_enumerate_infra.py -q
"""
import tempfile
from pathlib import Path

import pytest

from investigations.agent import investigator
from investigations.enrich import enumerate as enum_mod
from investigations.enrich import registry
from investigations.enrich.base import EnrichmentResult
from investigations.storage import db


# Mocks mirror the REAL adapter shapes: crt.sh promotes per-subdomain results
# (title = the subdomain); infra whois/dns are 'document' results whose raw_json
# lands typed properties (a_record / registrant) on the source node via run_and_persist.
def _crtsh_run(q, mode=None, timeout=90):
    return [EnrichmentResult("subdomain", f"sub.{q}", f"CT-log subdomain of {q}")]


def _infra_run(q, mode=None, timeout=90):
    if mode == "dns":
        return [EnrichmentResult("document", f"DNS: {q}", f"[A]\n{q} A 9.9.9.9",
                                 raw_json={"a": "9.9.9.9"})]
    if mode == "reverse":
        return [EnrichmentResult("document", f"Reverse DNS: {q}", "host.example.")]
    return [EnrichmentResult("document", f"WHOIS/RDAP: {q}",
                             "registrant email bad@evil.com",
                             raw_json={"registrant": "bad@evil.com"})]


def _ipgeo_run(q, mode=None, timeout=90):
    return [EnrichmentResult("document", f"GeoIP: {q}", "AS1 Example",
                             raw_json={"asn": "AS1"})]


def _whoisxml_run(q, mode=None, timeout=90):
    return [EnrichmentResult("domain", "sibling.org", f"{q} also registered sibling.org")]


def _no_llm(*a, **k):
    raise AssertionError("LLM was called during deterministic enumeration")


@pytest.fixture
def case_db(mp):
    mp.setattr(registry.get_adapter("crtsh"), "run", _crtsh_run)
    mp.setattr(registry.get_adapter("infra"), "run", _infra_run)
    for slug, fn in (("ipgeo", _ipgeo_run), ("whoisxml", _whoisxml_run)):
        adapter = registry.get_adapter(slug)
        mp.setattr(adapter, "run", fn)
        mp.setattr(adapter, "is_configured", lambda: True)
    mp.setattr(investigator, "_run_agent", _no_llm)
    mp.setattr(investigator, "ask", _no_llm)

    d = tempfile.mkdtemp()
    p = Path(d) / "t.db"
    db.init_db(p)
    orig = db.connect
    mp.setattr(db, "connect", lambda migrate=True, db_path=p: orig(db_path=db_path, migrate=migrate))
    with db.connect() as conn:
        conn.execute("INSERT INTO investigations (slug, case_name) VALUES ('case-e', 'case-e')")
        rep = db.insert_report(conn, "seeds.txt", "h1", "markdown", "seeds", "case-e",
                               "evil.com scam.net noted")
        for name in ("evil.com", "scam.net"):
            eid = db.upsert_entity(conn, name, "domain", rep)
            db.add_mention(conn, eid, rep, name, "seed")
        conn.commit()
    return p


def _typed_edges(conn):
    return conn.execute("SELECT COUNT(*) c FROM typed_relationships").fetchone()["c"]


def test_enumerates_both_seeds_zero_llm(case_db):
    with db.connect() as conn:
        out = enum_mod.enumerate_infra(conn, "case-e")
        assert set(out["seeds"]) == {"evil.com", "scam.net"}
        assert out["results"] > 0
        names = {r["canonical_name"] for r in conn.execute("SELECT canonical_name FROM entities")}
        # crt.sh subdomains + the A-record landed as real nodes for both seeds
        assert {"sub.evil.com", "sub.scam.net", "9.9.9.9"} <= names
        assert _typed_edges(conn) > 0
        assert out["digest"]   # the compact judgment input exists


def test_tier2_belts_surfaced_ip_and_email(case_db):
    with db.connect() as conn:
        out = enum_mod.enumerate_infra(conn, "case-e")
        # the IP from DNS and the registrant email got their own (single) belt pass
        assert "9.9.9.9" in out["tier2"]
        assert "bad@evil.com" in out["tier2"]
        ipgeo_runs = conn.execute(
            "SELECT COUNT(*) c FROM enrichment_runs WHERE provider_slug = 'ipgeo'").fetchone()["c"]
        assert ipgeo_runs == 1


def test_rerun_is_idempotent(case_db):
    """Same seed set twice → no duplicate nodes or edges. (A default re-run on a GROWN
    roster legitimately enumerates the new entities — that's one-hop coverage, not a dup.)"""
    seeds = ["evil.com", "scam.net"]
    with db.connect() as conn:
        enum_mod.enumerate_infra(conn, "case-e", seeds=seeds)
        edges_first = _typed_edges(conn)
        entities_first = conn.execute("SELECT COUNT(*) c FROM entities").fetchone()["c"]
        enum_mod.enumerate_infra(conn, "case-e", seeds=seeds)
        assert _typed_edges(conn) == edges_first
        assert conn.execute("SELECT COUNT(*) c FROM entities").fetchone()["c"] == entities_first


def test_explicit_seeds_override_roster(case_db):
    with db.connect() as conn:
        out = enum_mod.enumerate_infra(conn, "case-e", seeds=["evil.com"])
        assert out["seeds"] == ["evil.com"]
        names = {r["canonical_name"] for r in conn.execute("SELECT canonical_name FROM entities")}
        assert "sub.scam.net" not in names


def test_unknown_seed_is_classified_and_belted(case_db):
    """Gate-run regression: the agent hands enumerate_infra domains it just SURFACED
    (no entity row yet). They must be classified + created + belted, not 'no recipe'."""
    with db.connect() as conn:
        out = enum_mod.enumerate_infra(conn, "case-e", seeds=["fresh-casino.vip"])
        assert out["skipped_no_recipe"] == []
        assert out["results"] > 0
        row = conn.execute("SELECT entity_type, provenance FROM entities "
                           "WHERE canonical_name = 'fresh-casino.vip'").fetchone()
        assert row and row["entity_type"] == "domain"
        names = {r["canonical_name"] for r in conn.execute("SELECT canonical_name FROM entities")}
        assert "sub.fresh-casino.vip" in names   # its crt.sh result landed too


def test_agent_wiring_complete(case_db):
    """The MCP tool stays registered + allowed (the agent may choose it); the prompt
    steering is OFF by default after the 2026-06-09 A/B (wired runs shrank the graph)."""
    tool = "mcp__kipi-osint__enumerate_infra"
    assert tool in investigator.ALLOWED_TOOLS
    assert tool in investigator._infra_first_allowlist(list(investigator.ALLOWED_TOOLS))
    from investigations.agent import osint_mcp
    assert callable(getattr(osint_mcp, "enumerate_infra", None))
    with db.connect() as conn:
        task = investigator._build_case_task(conn, "case-e")
    assert "enumerate_infra" not in task          # default = control agent
    assert "enumerate_infra" not in investigator._continuation_task("case-e", 3, ["x.com"])


def test_enum_prompt_flag_opt_in(case_db, mp):
    """KIPI_ENUM_PROMPT=1 re-enables the steering for future A/Bs."""
    mp_env = __import__("os").environ
    old = mp_env.get("KIPI_ENUM_PROMPT")
    mp_env["KIPI_ENUM_PROMPT"] = "1"
    try:
        with db.connect() as conn:
            task = investigator._build_case_task(conn, "case-e")
        assert "enumerate_infra" in task and "Do NOT run whois_lookup" in task
    finally:
        if old is None:
            mp_env.pop("KIPI_ENUM_PROMPT", None)
        else:
            mp_env["KIPI_ENUM_PROMPT"] = old


def test_preseed_lands_before_agent_boots(case_db, mp):
    """Stage-2: when the whole-case run starts, the deterministic sweep has ALREADY
    landed nodes by the time _run_agent is first invoked (instant canvas)."""
    seen_at_agent_start = {}

    def fake_run_agent(task, **kw):
        with db.connect() as conn:
            seen_at_agent_start["n"] = conn.execute(
                "SELECT COUNT(*) c FROM entities").fetchone()["c"]
        return {"ok": True, "result_text": "{}", "steps": [], "raw": {}}

    mp.setattr(investigator, "_run_agent", fake_run_agent)
    mp.setattr(investigator, "ask", lambda *a, **k: "")
    with db.connect() as conn:
        baseline_n = conn.execute("SELECT COUNT(*) c FROM entities").fetchone()["c"]
        investigator.investigate_case_agentic(conn, "case-e", max_passes=1)
    assert seen_at_agent_start["n"] > baseline_n, "pre-seed landed nothing before the agent"


def test_preseed_flag_off_is_control(case_db, mp):
    mp_env = __import__("os").environ
    old = mp_env.get("KIPI_PRESEED")
    mp_env["KIPI_PRESEED"] = "0"
    enum_calls = []
    mp.setattr(enum_mod, "enumerate_infra",
               lambda *a, **k: enum_calls.append(1) or {"results": 0, "seeds": [], "tier2": [], "skipped_no_recipe": [], "digest": ""})
    mp.setattr(investigator, "_run_agent",
               lambda task, **kw: {"ok": True, "result_text": "{}", "steps": [], "raw": {}})
    mp.setattr(investigator, "ask", lambda *a, **k: "")
    try:
        with db.connect() as conn:
            investigator.investigate_case_agentic(conn, "case-e", max_passes=1)
        assert enum_calls == []
    finally:
        if old is None:
            mp_env.pop("KIPI_PRESEED", None)
        else:
            mp_env["KIPI_PRESEED"] = old


def test_preseed_failure_never_blocks_the_run(case_db, mp):
    def boom(*a, **k):
        raise RuntimeError("belt exploded")
    mp.setattr(enum_mod, "enumerate_infra", boom)
    mp.setattr(investigator, "_run_agent",
               lambda task, **kw: {"ok": True, "result_text": "{}", "steps": [], "raw": {}})
    mp.setattr(investigator, "ask", lambda *a, **k: "")
    with db.connect() as conn:
        out = investigator.investigate_case_agentic(conn, "case-e", max_passes=1)
    assert out["ok"]


def test_cancel_stops_between_belts(case_db):
    class Cancel:
        def __init__(self): self.calls = 0
        def is_set(self):
            self.calls += 1
            return self.calls > 1   # allow the first seed, stop before the second
    with db.connect() as conn:
        out = enum_mod.enumerate_infra(conn, "case-e", cancel=Cancel())
        names = {r["canonical_name"] for r in conn.execute("SELECT canonical_name FROM entities")}
        assert not ({"sub.evil.com", "sub.scam.net"} <= names)   # at most one seed belted
