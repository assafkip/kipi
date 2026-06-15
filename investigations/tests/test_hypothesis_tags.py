"""Hypothesis-stance tags on edges (issue ea-2-hypothesis-tagging, PRD
evidence-artifacts).

Asserts: the hypothesis_tags table is created by db._migrate; set_tag enforces the
stance set and is idempotent on (edge_id, hypothesis, author); clear_tag removes
one; tags_for_edge(s) read them; setting a tag never mutates the edge; a dropped
edge cascades its tags; the graph payload exposes edge_id + hypotheses.
"""
import tempfile
from pathlib import Path

import pytest

from investigations import hypotheses
from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "hyp.db"
    db.init_db(path)
    return path


def _mk_edge(conn):
    rep = db.insert_report(conn, source_path="<t>", source_hash="h-hyp",
                           source_type="text", title="t", investigation="hyp-case",
                           raw_text="")
    a = db.upsert_entity(conn, "a.example.com", "domain", rep)
    b = db.upsert_entity(conn, "b.example.com", "domain", rep)
    db.upsert_typed_relationship(conn, a, b, "shared_infra", confidence="high",
                                 evidence="same template", provenance="agent")
    return conn.execute(
        "SELECT id FROM typed_relationships WHERE src_entity_id = ? AND dst_entity_id = ?",
        (a, b)).fetchone()["id"]


def test_table_created_by_migrate():
    path = _db_path()
    with db.connect(path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(hypothesis_tags)")}
        assert {"edge_id", "hypothesis", "stance", "author"} <= cols


def test_set_tag_and_read():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_edge(conn)
        out = hypotheses.set_tag(conn, eid, "single affiliate", "supports", author="alice")
        assert out["ok"]
        tags = hypotheses.tags_for_edge(conn, eid)
        assert len(tags) == 1
        assert tags[0]["stance"] == "supports"
        assert tags[0]["hypothesis"] == "single affiliate"
        assert tags[0]["author"] == "alice"


def test_bad_stance_rejected():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_edge(conn)
        with pytest.raises(hypotheses.BadStance):
            hypotheses.set_tag(conn, eid, "h", "maybe-ish")


def test_idempotent_updates_stance_in_place():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_edge(conn)
        hypotheses.set_tag(conn, eid, "copycat", "consistent_with", author="bob")
        hypotheses.set_tag(conn, eid, "copycat", "contradicts", author="bob")
        tags = hypotheses.tags_for_edge(conn, eid)
        assert len(tags) == 1, "same (edge,hypothesis,author) must not duplicate"
        assert tags[0]["stance"] == "contradicts", "stance updates in place"


def test_multiple_hypotheses_on_one_edge():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_edge(conn)
        hypotheses.set_tag(conn, eid, "single affiliate", "supports")
        hypotheses.set_tag(conn, eid, "copycat", "consistent_with")
        assert len(hypotheses.tags_for_edge(conn, eid)) == 2, \
            "an edge can bear on multiple competing hypotheses"


def test_clear_tag():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_edge(conn)
        hypotheses.set_tag(conn, eid, "h1", "supports")
        out = hypotheses.clear_tag(conn, eid, "h1")
        assert out["removed"] == 1
        assert hypotheses.tags_for_edge(conn, eid) == []


def test_set_tag_on_missing_edge_errors():
    path = _db_path()
    with db.connect(path) as conn:
        out = hypotheses.set_tag(conn, 99999, "h", "supports")
        assert out.get("error")


def test_tagging_never_mutates_the_edge():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_edge(conn)
        before = conn.execute(
            "SELECT rel_type, confidence, evidence FROM typed_relationships WHERE id = ?",
            (eid,)).fetchone()
        hypotheses.set_tag(conn, eid, "h", "supports")
        after = conn.execute(
            "SELECT rel_type, confidence, evidence FROM typed_relationships WHERE id = ?",
            (eid,)).fetchone()
        assert tuple(before) == tuple(after), "the edge itself must be untouched"


def test_dropping_edge_cascades_tags():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_edge(conn)
        hypotheses.set_tag(conn, eid, "h", "supports")
        conn.execute("DELETE FROM typed_relationships WHERE id = ?", (eid,))
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM hypothesis_tags").fetchone()[0] == 0


def test_tags_for_edges_bulk():
    path = _db_path()
    with db.connect(path) as conn:
        e1 = _mk_edge(conn)
        hypotheses.set_tag(conn, e1, "h", "supports")
        out = hypotheses.tags_for_edges(conn, [e1, 99999])
        assert e1 in out and len(out[e1]) == 1
        assert hypotheses.tags_for_edges(conn, []) == {}


def test_concurrent_same_key_writes_stay_idempotent():
    """Codex ea-2 adversarial: two same-key writes (simulating a double-submit) must
    both succeed and leave exactly one row, via the atomic upsert."""
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_edge(conn)
    # Two separate connections write the same (edge, hypothesis, author).
    with db.connect(path) as c1, db.connect(path) as c2:
        out1 = hypotheses.set_tag(c1, eid, "single affiliate", "supports", author="alice")
        out2 = hypotheses.set_tag(c2, eid, "single affiliate", "contradicts", author="alice")
        assert out1["ok"] and out2["ok"], "both same-key writes must succeed"
    with db.connect(path) as conn:
        tags = hypotheses.tags_for_edge(conn, eid)
        assert len(tags) == 1, "exactly one row for the same key"


def test_graph_payload_exposes_edge_id_and_hypotheses():
    src = (Path(__file__).resolve().parents[1] / "webapp" / "app.py").read_text()
    assert '"edge_id": r["id"]' in src, "edge payload must expose the integer PK"
    assert '"hypotheses": edge_hyp.get(' in src, "edge payload must fold in tags"
    assert "/api/edge/{edge_id}/hypothesis" in src, "the set/clear route must exist"
