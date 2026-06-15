"""Edge semantic fixes (issue gtl-5-edge-semantic-fixes, PRD graph-trust-layer).

Asserts: an INVERTED has_subdomain edge (src is the subdomain of dst) is flipped
to parent->child; a bare blockchain-name node (Ethereum) with no role is removed
and its targets edge rewritten to a targets_chain node property; a correctly
directed has_subdomain edge is left alone; analyst-touched rows survive;
idempotent; wired into retro_clean.run.
"""
import tempfile
from pathlib import Path

from investigations.maintenance import retro_clean
from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "edgefix.db"
    db.init_db(path)
    return path


def _mk_case(conn, slug="ef-case"):
    conn.execute("INSERT INTO investigations (slug, case_name) VALUES (?, ?)", (slug, slug))
    return db.insert_report(conn, source_path="<t>", source_hash=f"h-{slug}",
                            source_type="text", title="t", investigation=slug, raw_text="")


def _edge(conn, s, d, rel, provenance="agent"):
    db.upsert_typed_relationship(conn, s, d, rel, confidence="high", evidence="t",
                                 provenance=provenance)


def _edge_dir(conn, rel):
    r = conn.execute(
        "SELECT src_entity_id, dst_entity_id FROM typed_relationships WHERE rel_type = ? "
        "AND COALESCE(status,'active')='active'", (rel,)).fetchone()
    return (r["src_entity_id"], r["dst_entity_id"]) if r else None


def test_inverted_has_subdomain_is_flipped():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn)
        parent = db.upsert_entity(conn, "zubdev.xyz", "domain", rep)
        child = db.upsert_entity(conn, "expertinvault.com.zubdev.xyz", "domain", rep)
        for eid in (parent, child):
            db.add_mention(conn, eid, rep, "x", "ctx")
        # Inverted: child -[has_subdomain]-> parent (wrong; vocab is parent->child).
        _edge(conn, child, parent, "has_subdomain")
        conn.commit()
        out = retro_clean.fix_edge_semantics(conn, "ef-case")
        assert len(out["flipped"]) == 1
        assert _edge_dir(conn, "has_subdomain") == (parent, child), "must point parent->child"


def test_correct_has_subdomain_untouched():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="ef-ok")
        parent = db.upsert_entity(conn, "example.com", "domain", rep)
        child = db.upsert_entity(conn, "a.example.com", "domain", rep)
        for eid in (parent, child):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, parent, child, "has_subdomain")   # correct direction
        conn.commit()
        out = retro_clean.fix_edge_semantics(conn, "ef-ok")
        assert out["flipped"] == []
        assert _edge_dir(conn, "has_subdomain") == (parent, child)


def test_blockchain_node_removed_and_targets_demoted():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="ef-chain")
        dom = db.upsert_entity(conn, "drainer.example.com", "domain", rep)
        eth = db.upsert_entity(conn, "Ethereum", "indicator", rep)
        for eid in (dom, eth):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, dom, eth, "targets")
        conn.commit()
        out = retro_clean.fix_edge_semantics(conn, "ef-chain")
        assert "Ethereum" in out["deleted_blockchain_nodes"]
        # Ethereum node gone.
        assert not conn.execute(
            "SELECT 1 FROM entities WHERE canonical_name = 'Ethereum'").fetchone()
        # targets edge gone, rewritten to a property on the source.
        assert _edge_dir(conn, "targets") is None
        prop = conn.execute(
            "SELECT value FROM node_properties WHERE entity_id = ? AND key = 'targets_chain'",
            (dom,)).fetchone()
        assert prop and "Ethereum" in prop["value"]


def test_analyst_flagged_blockchain_node_survives():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="ef-analyst")
        dom = db.upsert_entity(conn, "d2.example.com", "domain", rep)
        eth = db.upsert_entity(conn, "Bitcoin", "indicator", rep)
        for eid in (dom, eth):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, dom, eth, "targets")
        conn.execute("UPDATE entities SET flagged = 1 WHERE id = ?", (eth,))
        conn.commit()
        out = retro_clean.fix_edge_semantics(conn, "ef-analyst")
        assert "Bitcoin" not in out["deleted_blockchain_nodes"]
        assert conn.execute(
            "SELECT 1 FROM entities WHERE canonical_name = 'Bitcoin'").fetchone()


def test_analyst_has_subdomain_edge_not_flipped():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="ef-an-edge")
        parent = db.upsert_entity(conn, "p.example.com", "domain", rep)
        child = db.upsert_entity(conn, "c.p.example.com", "domain", rep)
        for eid in (parent, child):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, child, parent, "has_subdomain", provenance="analyst")
        conn.commit()
        out = retro_clean.fix_edge_semantics(conn, "ef-an-edge")
        assert out["flipped"] == [], "analyst edge is top authority"
        assert _edge_dir(conn, "has_subdomain") == (child, parent), "left as-is"


def test_blockchain_node_shared_across_cases_not_destroyed():
    """Codex gtl-5 finding-1: a case-scoped run must not delete another case's
    targets edge or the shared blockchain node it still references."""
    path = _db_path()
    with db.connect(path) as conn:
        rep_a = _mk_case(conn, slug="ef-a")
        rep_b = _mk_case(conn, slug="ef-b")
        eth = db.upsert_entity(conn, "Ethereum", "indicator", rep_a)
        dom_a = db.upsert_entity(conn, "a.example.com", "domain", rep_a)
        dom_b = db.upsert_entity(conn, "b.example.com", "domain", rep_b)
        # Ethereum mentioned in case A; case B has the targets edge.
        db.add_mention(conn, eth, rep_a, "x", "ctx")
        db.add_mention(conn, dom_a, rep_a, "x", "ctx")
        db.add_mention(conn, dom_b, rep_b, "x", "ctx")
        _edge(conn, dom_b, eth, "targets")   # belongs to case B
        conn.commit()
        retro_clean.fix_edge_semantics(conn, "ef-a")
        # Case A's run must NOT touch case B's edge or delete the shared node.
        assert conn.execute(
            "SELECT 1 FROM entities WHERE canonical_name = 'Ethereum'").fetchone(), \
            "shared blockchain node must survive a foreign case's cleanup"
        assert _edge_dir(conn, "targets") == (dom_b, eth), "case B's edge intact"


def test_analyst_targets_edge_not_rewritten():
    """Codex gtl-5 finding-2: an analyst-authored targets edge to a blockchain is
    top authority — not rewritten, and the node it holds open is not deleted."""
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="ef-an-tgt")
        dom = db.upsert_entity(conn, "d3.example.com", "domain", rep)
        sol = db.upsert_entity(conn, "Solana", "indicator", rep)
        for eid in (dom, sol):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, dom, sol, "targets", provenance="analyst")
        conn.commit()
        out = retro_clean.fix_edge_semantics(conn, "ef-an-tgt")
        assert out["demoted_chains"] == [], "analyst targets edge must not be rewritten"
        assert _edge_dir(conn, "targets") == (dom, sol), "analyst edge intact"
        assert conn.execute(
            "SELECT 1 FROM entities WHERE canonical_name = 'Solana'").fetchone(), \
            "node held open by an analyst edge must survive"
        assert not conn.execute(
            "SELECT 1 FROM node_properties WHERE entity_id = ? AND key='targets_chain'",
            (dom,)).fetchone()


def test_has_subdomain_scoped_by_source_not_destination():
    """Codex gtl-5 adversarial: a case that only mentions the parent (dst) must not
    flip another case's inverted has_subdomain edge."""
    path = _db_path()
    with db.connect(path) as conn:
        rep_a = _mk_case(conn, slug="ef-hs-a")
        rep_b = _mk_case(conn, slug="ef-hs-b")
        parent = db.upsert_entity(conn, "shared.org", "domain", rep_a)
        child = db.upsert_entity(conn, "sub.shared.org", "domain", rep_b)
        db.add_mention(conn, parent, rep_a, "x", "ctx")   # parent in case A
        db.add_mention(conn, child, rep_b, "x", "ctx")    # child (src) only in case B
        _edge(conn, child, parent, "has_subdomain")        # inverted, owned by case B
        conn.commit()
        out = retro_clean.fix_edge_semantics(conn, "ef-hs-a")
        assert out["flipped"] == [], "case A must not flip case B's edge"
        assert _edge_dir(conn, "has_subdomain") == (child, parent), "B's edge untouched"


def test_superseded_targets_edge_not_revived():
    """Codex gtl-5 adversarial: a superseded targets edge must not be rewritten into
    an active targets_chain property nor have its audit row destroyed."""
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="ef-sup")
        dom = db.upsert_entity(conn, "d4.example.com", "domain", rep)
        eth = db.upsert_entity(conn, "Ethereum", "indicator", rep)
        for eid in (dom, eth):
            db.add_mention(conn, eid, rep, "x", "ctx")
        conn.execute(
            "INSERT INTO typed_relationships (src_entity_id, dst_entity_id, rel_type, "
            "confidence, evidence, status) VALUES (?, ?, 'targets', 'high', 't', 'superseded')",
            (dom, eth))
        conn.commit()
        out = retro_clean.fix_edge_semantics(conn, "ef-sup")
        assert out["demoted_chains"] == [], "superseded edge must not be rewritten"
        assert not conn.execute(
            "SELECT 1 FROM node_properties WHERE entity_id = ? AND key='targets_chain'",
            (dom,)).fetchone(), "no property written from a retired edge"
        # The superseded row is preserved (audit trail intact); node had no ACTIVE
        # edges so it is removed — but the historical row remains attached to it...
        # actually _delete_entity would cascade it; guard: node kept since a row exists.
        assert conn.execute(
            "SELECT 1 FROM typed_relationships WHERE src_entity_id = ? AND status='superseded'",
            (dom,)).fetchone(), "superseded audit row preserved"


def test_idempotent_and_wired_into_run():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="ef-idem")
        parent = db.upsert_entity(conn, "site.org", "domain", rep)
        child = db.upsert_entity(conn, "sub.site.org", "domain", rep)
        for eid in (parent, child):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, child, parent, "has_subdomain")
        conn.commit()
        out1 = retro_clean.run(conn, "ef-idem")
        assert "edge_semantics" in out1, "must be wired into retro_clean.run"
        assert len(out1["edge_semantics"]["flipped"]) == 1
        assert _edge_dir(conn, "has_subdomain") == (parent, child)
        out2 = retro_clean.fix_edge_semantics(conn, "ef-idem")
        assert out2["flipped"] == [], "already-correct edge not re-flipped"
