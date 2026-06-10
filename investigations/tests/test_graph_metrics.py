"""Graph metrics: centrality + Louvain over the CASE subgraph into node_properties.

Issues graph-metrics / graph-subgraph-scope / graph-metrics-degenerate
(PRD graph-analyst-craft). Offline + deterministic (seeded sampling/partition).

Run: .venv/bin/python3 -m pytest investigations/tests/test_graph_metrics.py -q
"""
import tempfile
from pathlib import Path

from investigations import graph_metrics
from investigations.storage import db


def _db():
    p = Path(tempfile.mkdtemp()) / "gm.db"
    db.init_db(p)
    return p


def _mk_case(conn, case: str):
    conn.execute("INSERT INTO investigations (slug, status) VALUES (?, 'active')", (case,))
    return db.insert_report(conn, source_path=f"<{case}>", source_hash=f"h-{case}",
                            source_type="report", title=case, investigation=case,
                            raw_text="")


def _node(conn, rep, name):
    eid = db.upsert_entity(conn, name, "domain", rep)
    db.add_mention(conn, eid, rep, name, "test")
    return eid


def _edge(conn, a, b):
    db.upsert_typed_relationship(conn, a, b, "linked_to")


def _props(conn, eid):
    return {r["key"]: (r["value"], r["provenance"]) for r in conn.execute(
        "SELECT key, value, provenance FROM node_properties WHERE entity_id = ?", (eid,))}


def test_metrics_land_in_node_properties_with_case_provenance():
    with db.connect(_db()) as conn:
        rep = _mk_case(conn, "case-a")
        # A path a-b-c-d: b and c are the brokers.
        a, b, c, d = (_node(conn, rep, f"{n}.example.com") for n in "abcd")
        _edge(conn, a, b); _edge(conn, b, c); _edge(conn, c, d)
        out = graph_metrics.run(conn, "case-a")
        assert out["nodes"] == 4 and out["edges"] == 3
        props = _props(conn, b)
        assert set(props) >= {"degree_centrality", "betweenness", "community"}
        assert all(prov == "graph:metrics:case-a" for _, prov in props.values())
        # The middle nodes out-rank the endpoints on betweenness.
        assert float(props["betweenness"][0]) > float(_props(conn, a)["betweenness"][0])


def test_rerun_is_idempotent_no_duplicate_rows():
    with db.connect(_db()) as conn:
        rep = _mk_case(conn, "case-a")
        a, b = _node(conn, rep, "a.example.com"), _node(conn, rep, "b.example.com")
        _edge(conn, a, b)
        graph_metrics.run(conn, "case-a")
        n1 = conn.execute("SELECT COUNT(*) FROM node_properties").fetchone()[0]
        graph_metrics.run(conn, "case-a")
        n2 = conn.execute("SELECT COUNT(*) FROM node_properties").fetchone()[0]
        assert n1 == n2


# ---------- subgraph scoping (issue graph-subgraph-scope, finding-3) ----------

def test_cross_case_edges_never_leak_into_subgraph_metrics():
    with db.connect(_db()) as conn:
        rep_a = _mk_case(conn, "case-a")
        rep_b = _mk_case(conn, "case-b")
        # case-a: shared - x - y (a path; shared is an endpoint, betweenness 0).
        shared = _node(conn, rep_a, "shared.example.com")
        x, y = _node(conn, rep_a, "x.example.com"), _node(conn, rep_a, "y.example.com")
        _edge(conn, shared, x); _edge(conn, x, y)
        # case-b: a hub around the SAME shared entity (high degree there).
        # BOTH directions, so losing EITHER endpoint predicate in _case_subgraph
        # (src-in-case or dst-in-case) changes case-a's edge count/degree.
        db.add_mention(conn, shared, rep_b, "shared.example.com", "test")
        for n in ("p", "q"):
            other = _node(conn, rep_b, f"{n}.example.com")
            _edge(conn, shared, other)        # outside as dst
        for n in ("r", "s"):
            other = _node(conn, rep_b, f"{n}.example.com")
            _edge(conn, other, shared)        # outside as src
        out_a = graph_metrics.run(conn, "case-a")
        assert out_a["nodes"] == 3 and out_a["edges"] == 2, out_a
        # shared's degree in case-a's subgraph is 1 of 2 possible (0.5),
        # NOT inflated by its 4 case-b edges.
        deg = float(_props(conn, shared)["degree_centrality"][0])
        assert abs(deg - 0.5) < 1e-6, deg
        assert _props(conn, shared)["degree_centrality"][1] == "graph:metrics:case-a"


def test_cross_case_shared_entity_provenance_stamps_the_writing_case():
    with db.connect(_db()) as conn:
        rep_a = _mk_case(conn, "case-a")
        rep_b = _mk_case(conn, "case-b")
        shared = _node(conn, rep_a, "shared.example.com")
        a2 = _node(conn, rep_a, "a2.example.com")
        _edge(conn, shared, a2)
        db.add_mention(conn, shared, rep_b, "shared.example.com", "test")
        b2 = _node(conn, rep_b, "b2.example.com")
        _edge(conn, shared, b2)
        graph_metrics.run(conn, "case-a")
        assert _props(conn, shared)["degree_centrality"][1] == "graph:metrics:case-a"
        graph_metrics.run(conn, "case-b")   # last-write-wins, but auditable
        assert _props(conn, shared)["degree_centrality"][1] == "graph:metrics:case-b"


# ---------- degenerate shapes (issue graph-metrics-degenerate, finding-8) ----------

def test_empty_case_skips_cleanly():
    with db.connect(_db()) as conn:
        _mk_case(conn, "case-empty")
        out = graph_metrics.run(conn, "case-empty")
        assert "skipped" in out
        assert conn.execute("SELECT COUNT(*) FROM node_properties").fetchone()[0] == 0


def test_single_node_case_skips_and_clears_stale_metrics():
    with db.connect(_db()) as conn:
        rep = _mk_case(conn, "case-one")
        lone = _node(conn, rep, "lone.example.com")
        # Stale metric from a previous (larger) state of the case.
        conn.execute(
            "INSERT INTO node_properties (entity_id, key, value, value_type, provenance) "
            "VALUES (?, 'betweenness', '0.9', 'number', 'graph:metrics:case-one')", (lone,))
        out = graph_metrics.run(conn, "case-one")
        assert "skipped" in out and out["cleared"] == 1
        assert _props(conn, lone) == {}


def test_eigenvector_nonconvergence_omits_key_run_succeeds(mp):
    import networkx as nx

    def _no_converge(g, max_iter=500):
        raise nx.PowerIterationFailedConvergence(max_iter)

    mp.setattr(nx, "eigenvector_centrality", _no_converge)
    with db.connect(_db()) as conn:
        rep = _mk_case(conn, "case-nc")
        a, b = _node(conn, rep, "a.example.com"), _node(conn, rep, "b.example.com")
        _edge(conn, a, b)
        out = graph_metrics.run(conn, "case-nc")
        assert out.get("eigenvector") is False        # omitted, not fatal
        props = _props(conn, a)
        assert "eigenvector" not in props
        assert "betweenness" in props                  # the other three landed


def test_disconnected_components_compute():
    with db.connect(_db()) as conn:
        rep = _mk_case(conn, "case-disc")
        a, b = _node(conn, rep, "a.example.com"), _node(conn, rep, "b.example.com")
        c, d = _node(conn, rep, "c.example.com"), _node(conn, rep, "d.example.com")
        _edge(conn, a, b); _edge(conn, c, d)   # two islands
        out = graph_metrics.run(conn, "case-disc")
        assert out["nodes"] == 4 and out["communities"] >= 2
        assert "betweenness" in _props(conn, a)


def test_failed_run_leaves_previous_set_and_other_cases_intact(mp):
    import pytest as _pytest
    with db.connect(_db()) as conn:
        rep_a = _mk_case(conn, "case-a")
        rep_b = _mk_case(conn, "case-b")
        shared = _node(conn, rep_a, "shared.example.com")
        a2 = _node(conn, rep_a, "a2.example.com")
        _edge(conn, shared, a2)
        db.add_mention(conn, shared, rep_b, "shared.example.com", "test")
        b2 = _node(conn, rep_b, "b2.example.com")
        _edge(conn, shared, b2)
        # case-b ran last: shared's rows are stamped graph:metrics:case-b.
        graph_metrics.run(conn, "case-a")
        graph_metrics.run(conn, "case-b")
        before = _props(conn, shared)
        assert before["degree_centrality"][1] == "graph:metrics:case-b"

        # Force a WRITE failure MID-transaction: real upserts land first, then
        # boom — exercising the 'never a half-written mix' rollback, not just
        # the trivial fail-before-first-write path.
        real_upsert = graph_metrics._upsert_metric
        calls = {"n": 0}

        def _boom_after_two(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] > 2:
                raise RuntimeError("disk full")
            return real_upsert(*args, **kwargs)
        mp.setattr(graph_metrics, "_upsert_metric", _boom_after_two)
        with _pytest.raises(RuntimeError):
            graph_metrics.run(conn, "case-a")
        assert calls["n"] > 2   # real writes happened before the failure
        # Rollback restored the FULL pre-run set: case-b's rows survive
        # untouched (the old delete-on-failure bug) and none of case-a's
        # partial fresh writes remain.
        assert _props(conn, shared) == before


def test_unknown_case_is_a_named_error():
    with db.connect(_db()) as conn:
        out = graph_metrics.run(conn, "nope")
        assert "error" in out


def test_process_steps_include_graph_metrics():
    from investigations.webapp.app import PROCESS_STEPS
    names = [k for k, _ in PROCESS_STEPS]
    assert "graph_metrics" in names
    assert names.index("graph_metrics") > names.index("analyze")
