"""Path confidence (issue gtl-1-path-confidence, PRD graph-trust-layer).

Asserts the widest-bottleneck propagation: a node's path_confidence is the
strength of its WEAKEST edge back to the nearest case seed, so a strong
sub-chain hanging off one weak bridge is scored at the bridge's strength;
seeds anchor at 1.0; nodes unreachable from any seed are left UNSCORED (no
row, not 0-faked); the score lands in node_properties and is idempotent.
"""
import tempfile
from pathlib import Path

from investigations import graph_metrics
from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "pathconf.db"
    db.init_db(path)
    return path


def _mk_case(conn, slug="pc-case"):
    conn.execute("INSERT INTO investigations (slug, case_name) VALUES (?, ?)", (slug, slug))
    return db.insert_report(conn, source_path="<t>", source_hash=f"h-{slug}",
                            source_type="text", title="t", investigation=slug, raw_text="")


def _edge(conn, s, d, conf):
    db.upsert_typed_relationship(conn, s, d, "linked_to", confidence=conf,
                                 evidence="t", provenance="t")


def _pc(conn, eid):
    row = conn.execute(
        "SELECT value FROM node_properties WHERE entity_id = ? AND key = 'path_confidence'",
        (eid,)).fetchone()
    return float(row["value"]) if row else None


def test_weak_bridge_caps_the_branch():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn)
        seed = db.upsert_entity(conn, "seed.example.com", "domain", rep)
        bridge = db.upsert_entity(conn, "bridge@example.com", "email", rep)
        deep1 = db.upsert_entity(conn, "deep1.example.com", "domain", rep)
        deep2 = db.upsert_entity(conn, "deep2.example.com", "domain", rep)
        for eid in (seed, bridge, deep1, deep2):
            db.add_mention(conn, eid, rep, "x", "ctx")
        # seed --HIGH-- bridge is reached via a 0.6 (medium) bridge; beyond it the
        # edges are 0.85 (high). The deep nodes must still be capped at 0.6.
        _edge(conn, seed, bridge, "medium")   # the weak bridge (0.6)
        _edge(conn, bridge, deep1, "high")    # 0.85 internal
        _edge(conn, deep1, deep2, "high")     # 0.85 internal
        conn.execute("INSERT INTO seeds (entity_id, label) VALUES (?, 'seed')", (seed,))
        conn.commit()

        out = graph_metrics.compute_path_confidence(conn, "pc-case")
        assert out["scored"] == 4
        assert _pc(conn, seed) == 1.0, "seed anchors at 1.0"
        assert _pc(conn, bridge) == 0.6, "bridge reached by the 0.6 edge"
        assert _pc(conn, deep1) == 0.6, "strong internal edge cannot exceed the weak bridge"
        assert _pc(conn, deep2) == 0.6, "whole branch capped at the weakest link"


def test_strong_path_wins_over_weak_path():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="pc-two")
        seed = db.upsert_entity(conn, "s.example.com", "domain", rep)
        mid = db.upsert_entity(conn, "m.example.com", "domain", rep)
        target = db.upsert_entity(conn, "t.example.com", "domain", rep)
        for eid in (seed, mid, target):
            db.add_mention(conn, eid, rep, "x", "ctx")
        # Two routes to target: direct weak (0.35) vs through mid all-high (min 0.85).
        _edge(conn, seed, target, "low")     # 0.35 direct
        _edge(conn, seed, mid, "high")       # 0.85
        _edge(conn, mid, target, "high")     # 0.85
        conn.execute("INSERT INTO seeds (entity_id, label) VALUES (?, 'seed')", (seed,))
        conn.commit()
        graph_metrics.compute_path_confidence(conn, "pc-two")
        assert _pc(conn, target) == 0.85, "the stronger bottleneck path wins"


def test_unreachable_nodes_left_unscored():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="pc-iso")
        seed = db.upsert_entity(conn, "s2.example.com", "domain", rep)
        island = db.upsert_entity(conn, "island.example.com", "domain", rep)
        other = db.upsert_entity(conn, "other.example.com", "domain", rep)
        for eid in (seed, island, other):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, island, other, "high")  # connected to each other, NOT to seed
        conn.execute("INSERT INTO seeds (entity_id, label) VALUES (?, 'seed')", (seed,))
        conn.commit()
        graph_metrics.compute_path_confidence(conn, "pc-iso")
        assert _pc(conn, seed) == 1.0
        assert _pc(conn, island) is None, "unreachable node must be unscored, not 0"
        assert _pc(conn, other) is None


def test_no_seeds_clears_and_skips():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="pc-noseed")
        a = db.upsert_entity(conn, "a.example.com", "domain", rep)
        b = db.upsert_entity(conn, "b.example.com", "domain", rep)
        for eid in (a, b):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, a, b, "high")
        conn.commit()
        out = graph_metrics.compute_path_confidence(conn, "pc-noseed")
        assert out.get("skipped") == "no case seeds"
        assert _pc(conn, a) is None


def test_idempotent():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="pc-idem")
        seed = db.upsert_entity(conn, "s3.example.com", "domain", rep)
        n = db.upsert_entity(conn, "n3.example.com", "domain", rep)
        for eid in (seed, n):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, seed, n, "medium")
        conn.execute("INSERT INTO seeds (entity_id, label) VALUES (?, 'seed')", (seed,))
        conn.commit()
        graph_metrics.compute_path_confidence(conn, "pc-idem")
        first = _pc(conn, n)
        graph_metrics.compute_path_confidence(conn, "pc-idem")
        rows = conn.execute(
            "SELECT COUNT(*) AS c FROM node_properties WHERE entity_id = ? "
            "AND key = 'path_confidence'", (n,)).fetchone()["c"]
        assert rows == 1, "re-run must not duplicate the property"
        assert _pc(conn, n) == first


def test_degenerate_graph_still_clears_stale_path_confidence():
    """Codex gtl-1 finding: run()'s <2-node/0-edge early return must not skip
    path_confidence clearing — a shrunk case keeps stale rows otherwise."""
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="pc-degen")
        seed = db.upsert_entity(conn, "sd.example.com", "domain", rep)
        n = db.upsert_entity(conn, "nd.example.com", "domain", rep)
        for eid in (seed, n):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, seed, n, "medium")
        conn.execute("INSERT INTO seeds (entity_id, label) VALUES (?, 'seed')", (seed,))
        conn.commit()
        graph_metrics.compute_path_confidence(conn, "pc-degen")
        assert _pc(conn, n) == 0.6
        # Now strip the edge so the graph is degenerate (0 edges) and run() full.
        conn.execute("UPDATE typed_relationships SET status = 'retired'")
        conn.commit()
        out = graph_metrics.run(conn, "pc-degen")
        assert "skipped" in out
        # n is no longer reachable from the seed -> its stale 0.6 must be cleared.
        assert _pc(conn, n) is None, "degenerate run must clear stale path_confidence"


def test_payload_includes_path_confidence():
    """The /api/graph node builder pulls path_confidence into _METRIC_KEYS."""
    src = (Path(__file__).resolve().parents[1] / "webapp" / "app.py").read_text()
    assert '"path_confidence")' in src or "'path_confidence')" in src, \
        "path_confidence must be in the graph payload _METRIC_KEYS"
