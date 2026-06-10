"""Graph metrics — centrality + Louvain communities over the CASE subgraph.

Deterministic, no LLM (issues graph-metrics / graph-metrics-degenerate /
graph-subgraph-scope, PRD graph-analyst-craft). Why: betweenness finds the
broker between two cells; Louvain splits a sockpuppet net into operating
cells — capabilities no commercial OSINT vendor confirmed shipping.

Scope: nodes are the case's entities (mentions → reports.investigation);
edges are ACTIVE typed_relationships where BOTH endpoints are case nodes —
cross-case edges are excluded (typed_relationships is global with no
investigation column; endpoint-scoping is the honest available cut).

Scores land in node_properties (UNIQUE(entity_id,key) — upsert-in-place, so
re-runs are idempotent) under keys degree_centrality / betweenness /
eigenvector / community, provenance `graph:metrics:<case>` so the writing
case of a shared entity's score stays auditable. Known limit: shared
entities are last-Process-wins across cases.

Degenerate shapes: <2 nodes or 0 edges → clean skip (writes nothing);
eigenvector non-convergence → that key is omitted; any failure deletes the
case's stale graph:metrics properties so the UI never styles from values a
newer graph contradicts.
"""
from __future__ import annotations

from investigations.storage import db

METRIC_KEYS = ("degree_centrality", "betweenness", "eigenvector", "community")
_BETWEENNESS_SAMPLE_CAP = 500   # k-sampling above this many nodes bounds cost


def _case_subgraph(conn, case: str) -> tuple[set[int], list[tuple[int, int]]]:
    """The case's node ids + active typed edges with BOTH endpoints in the case.
    Membership filtering happens in SQL (indexed mentions join), not a Python
    scan of the global edge list — one small case must not pay O(all_edges)."""
    node_ids = {r["entity_id"] for r in conn.execute(
        "SELECT DISTINCT m.entity_id FROM mentions m "
        "JOIN reports r ON r.id = m.report_id WHERE r.investigation = ?", (case,))}
    if not node_ids:
        return set(), []
    edges = [(r["src_entity_id"], r["dst_entity_id"]) for r in conn.execute(
        "WITH case_nodes AS (SELECT DISTINCT m.entity_id FROM mentions m "
        "  JOIN reports r ON r.id = m.report_id WHERE r.investigation = ?) "
        "SELECT t.src_entity_id, t.dst_entity_id FROM typed_relationships t "
        "WHERE t.status = 'active' AND t.src_entity_id != t.dst_entity_id "
        "  AND t.src_entity_id IN (SELECT entity_id FROM case_nodes) "
        "  AND t.dst_entity_id IN (SELECT entity_id FROM case_nodes)", (case,))]
    return node_ids, edges


def clear_metrics(conn, case: str) -> int:
    """Delete this case's graph:metrics properties (the stale-value guard)."""
    cur = conn.execute(
        "DELETE FROM node_properties WHERE provenance = ? AND key IN "
        "(?, ?, ?, ?)", (f"graph:metrics:{case}", *METRIC_KEYS))
    return cur.rowcount


def _upsert_metric(conn, entity_id: int, key: str, value, case: str) -> None:
    conn.execute(
        "INSERT INTO node_properties (entity_id, key, value, value_type, provenance, confidence) "
        "VALUES (?, ?, ?, ?, ?, 'high') "
        "ON CONFLICT(entity_id, key) DO UPDATE SET "
        "value=excluded.value, value_type=excluded.value_type, "
        "provenance=excluded.provenance, confidence=excluded.confidence",
        (entity_id, key, str(value), "number" if key != "community" else "string",
         f"graph:metrics:{case}"))


def run(conn, case: str) -> dict:
    """Compute + land the four metrics for `case`. Returns a summary dict."""
    import networkx as nx

    case = (case or "").strip()
    if not case:
        return {"error": "case is required"}
    if not conn.execute("SELECT 1 FROM investigations WHERE slug = ?", (case,)).fetchone():
        return {"error": f"unknown case: {case}"}

    node_ids, edges = _case_subgraph(conn, case)
    if len(node_ids) < 2 or not edges:
        # Degenerate: nothing meaningful to rank. Clear leftovers, write nothing.
        cleared = clear_metrics(conn, case)
        conn.commit()
        return {"skipped": "graph too small (<2 nodes or 0 edges)",
                "nodes": len(node_ids), "edges": len(edges), "cleared": cleared}

    g = nx.Graph()
    g.add_nodes_from(node_ids)
    g.add_edges_from(edges)

    # COMPUTE FIRST, pure — no DB writes until every metric exists. A compute
    # failure leaves the previous consistent metric set untouched (and never
    # touches another case's rows; rollback covers a mid-write failure).
    degree = nx.degree_centrality(g)
    k = min(g.number_of_nodes(), _BETWEENNESS_SAMPLE_CAP)
    # seed pins the k-sample so re-runs are reproducible, not just idempotent
    betweenness = nx.betweenness_centrality(g, k=k, seed=42)
    try:
        eigenvector = nx.eigenvector_centrality(g, max_iter=500)
    except nx.PowerIterationFailedConvergence:
        eigenvector = None   # omit the key; the other three still land
    import community as community_louvain
    partition = community_louvain.best_partition(g, random_state=42)

    # REPLACE atomically: clear this case's old keys (covers nodes that left the
    # case), write the fresh set, one transaction. On any write error, roll back
    # so a shared entity's row re-stamped by another case is never deleted.
    try:
        clear_metrics(conn, case)
        for nid in g.nodes:
            _upsert_metric(conn, nid, "degree_centrality", round(degree.get(nid, 0.0), 6), case)
            _upsert_metric(conn, nid, "betweenness", round(betweenness.get(nid, 0.0), 6), case)
            if eigenvector is not None:
                _upsert_metric(conn, nid, "eigenvector", round(eigenvector.get(nid, 0.0), 6), case)
            _upsert_metric(conn, nid, "community", f"c{partition.get(nid, 0)}", case)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    communities = len(set(partition.values()))
    top = sorted(betweenness, key=betweenness.get, reverse=True)[:3]
    top_names = [r["canonical_name"] for r in conn.execute(
        f"SELECT canonical_name FROM entities WHERE id IN ({','.join('?' * len(top))})",
        top)] if top else []
    return {"case": case, "nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
            "communities": communities,
            "eigenvector": eigenvector is not None,
            "top_brokers": top_names}
