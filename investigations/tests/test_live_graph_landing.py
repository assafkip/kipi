"""Live graph build: _persist_step_discovery writes a tool step's discovery
(anchor -> found) into the case graph as REAL entities + a typed edge as the dig runs,
so the analyst watches the real graph build (no provisional preview, no end swap).

Run: .venv/bin/python3 -m pytest investigations/tests/test_live_graph_landing.py -q

Uses a per-test temp DB (db.connect is patched to it via the `mp` fixture) — never the
real database.
"""
import tempfile
from pathlib import Path

import pytest

from investigations.storage import db
from investigations.webapp import app as app_module

_WALLET = "0x" + "a" * 40


@pytest.fixture
def case_db(mp):
    """Fresh temp DB with a 't-case' investigation; app_module.db.connect → this DB.
    Patching db.connect (not DB_PATH) is required because connect()'s default db_path
    arg binds DB_PATH at definition time, so reassigning DB_PATH wouldn't take."""
    d = tempfile.mkdtemp()
    p = Path(d) / "t.db"
    db.init_db(p)                       # base schema (connect()'s _migrate only ALTERs)
    orig = db.connect
    mp.setattr(db, "connect", lambda migrate=True, db_path=p: orig(db_path=db_path, migrate=migrate))
    with db.connect() as conn:
        conn.execute("INSERT INTO investigations (slug) VALUES ('t-case')")
    return p


def _names(conn):
    return {r["canonical_name"] for r in conn.execute("SELECT canonical_name FROM entities")}


def _rels(conn):
    return conn.execute(
        "SELECT e1.canonical_name src, e2.canonical_name dst, r.rel_type "
        "FROM relationships r JOIN entities e1 ON e1.id=r.src_entity_id "
        "JOIN entities e2 ON e2.id=r.dst_entity_id").fetchall()


def _typed_rels(conn):
    return conn.execute(
        "SELECT e1.canonical_name src, e2.canonical_name dst, r.rel_type, r.status, "
        "r.provenance "
        "FROM typed_relationships r JOIN entities e1 ON e1.id=r.src_entity_id "
        "JOIN entities e2 ON e2.id=r.dst_entity_id").fetchall()


def test_crtsh_step_writes_anchor_found_and_typed_edge(case_db):
    step = {"type": "tool", "tool": "Bash", "raw_tool": "crtsh",
            "input": "./invctl osint-tool crtsh trumpfundus.com",
            "result": "hostnames: trumpfundus.com promo.net giveaway.org"}
    wrote = app_module._persist_step_discovery("t-case", step)
    assert wrote == 2, wrote
    with db.connect() as conn:
        assert {"trumpfundus.com", "promo.net", "giveaway.org"} <= _names(conn)
        pairs = {(r["src"], r["dst"]) for r in _rels(conn)}
        assert ("trumpfundus.com", "promo.net") in pairs
        assert ("trumpfundus.com", "giveaway.org") in pairs
        # crtsh → a meaningful typed edge (from the command in the input), not 'linked_to'
        assert all(r["rel_type"] == "tls_cert" for r in _rels(conn))
        # The graph (/api/graph) draws edges and judges "meaningful" nodes ONLY from
        # typed_relationships — the edge MUST land there too (status='active'), or the
        # live dig leaves the canvas empty.
        typed = _typed_rels(conn)
        assert {(r["src"], r["dst"]) for r in typed} == {
            ("trumpfundus.com", "promo.net"), ("trumpfundus.com", "giveaway.org")}
        assert all(r["rel_type"] == "tls_cert" for r in typed)
        assert all(r["status"] == "active" for r in typed)
        assert all(r["provenance"] == "osint" for r in typed)


def test_rel_type_reflects_the_tool(case_db):
    step = {"type": "tool", "tool": "Bash", "raw_tool": "whois",
            "input": "whois promo.net", "result": "registrant also owns giveaway.org"}
    app_module._persist_step_discovery("t-case", step)
    with db.connect() as conn:
        rels = _rels(conn)
        assert rels and all(r["rel_type"] == "registered_via" for r in rels)


def test_idempotent_redundant_sweep_no_duplicate_edges(case_db):
    step = {"type": "tool", "tool": "Bash", "raw_tool": "dns",
            "input": "dns promo.net", "result": "promo.net A 1.2.3.4"}
    app_module._persist_step_discovery("t-case", step)
    app_module._persist_step_discovery("t-case", step)   # same step again
    with db.connect() as conn:
        assert len(_rels(conn)) == 1, [dict(r) for r in _rels(conn)]
        assert len(_typed_rels(conn)) == 1, [dict(r) for r in _typed_rels(conn)]


def test_no_anchor_or_no_found_writes_nothing(case_db):
    assert app_module._persist_step_discovery(
        "t-case", {"type": "reasoning", "text": "looking at promo.net"}) == 0
    assert app_module._persist_step_discovery(
        "t-case", {"type": "tool", "raw_tool": "x", "input": "list", "result": "found evil.xyz"}) == 0
    with db.connect() as conn:
        assert _names(conn) == set()


def test_deleted_case_writes_nothing(case_db):
    step = {"type": "tool", "raw_tool": "crtsh", "input": "crtsh a.com", "result": "a.com b.com"}
    assert app_module._persist_step_discovery("gone-case", step) == 0
