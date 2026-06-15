"""Hypothesis-stance tags on typed edges (PRD evidence-artifacts, issue ea-2).

Every typed edge asserts one story. But identical casino branding is equally
consistent with an unrelated copycat who bought the same kit — the edge supports
H1 ("single affiliate") AND is consistent with H2 ("copycat"). This module lets an
analyst annotate which competing hypothesis an edge bears on, without touching the
edge's own rel_type/confidence: the edge stands on its evidence; the stance is a
separate, reversible opinion layer (graph-side ACH).
"""
from __future__ import annotations

# The stance an edge takes toward a hypothesis. Closed set — a typo must not create
# a meaningless stance.
STANCES = ("supports", "contradicts", "consistent_with")


class BadStance(ValueError):
    """Raised when a stance is not one of STANCES."""


def set_tag(conn, edge_id: int, hypothesis: str, stance: str,
            *, author: str = "analyst") -> dict:
    """Tag a typed edge with a hypothesis stance. Idempotent on
    (edge_id, hypothesis, author) — re-tagging updates the stance in place.
    Raises BadStance on an unknown stance; errors if the edge does not exist."""
    stance = (stance or "").strip().lower()
    if stance not in STANCES:
        raise BadStance(f"stance must be one of {STANCES}, got {stance!r}")
    hyp = (hypothesis or "").strip()
    if not hyp:
        raise ValueError("hypothesis label is required")
    # Normalize author to a non-null value so the UNIQUE(edge_id, hypothesis, author)
    # conflict target always matches (NULLs are distinct in SQLite UNIQUE).
    author = (author or "analyst").strip() or "analyst"
    if not conn.execute("SELECT 1 FROM typed_relationships WHERE id = ?",
                        (edge_id,)).fetchone():
        return {"error": f"no typed edge with id {edge_id}"}
    # Atomic upsert (Codex ea-2 adversarial): SELECT-then-INSERT raced two concurrent
    # same-key writes into a UNIQUE-constraint 500. ON CONFLICT DO UPDATE makes the
    # idempotency contract hold under concurrency — both writers succeed, one row.
    conn.execute(
        "INSERT INTO hypothesis_tags (edge_id, hypothesis, stance, author) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT(edge_id, hypothesis, author) DO UPDATE SET stance = excluded.stance",
        (edge_id, hyp, stance, author))
    row = conn.execute(
        "SELECT id FROM hypothesis_tags WHERE edge_id = ? AND hypothesis = ? AND author = ?",
        (edge_id, hyp, author)).fetchone()
    conn.commit()
    return {"ok": True, "tag_id": row["id"], "edge_id": edge_id,
            "hypothesis": hyp, "stance": stance}


def clear_tag(conn, edge_id: int, hypothesis: str, *, author: str = "analyst") -> dict:
    """Remove one hypothesis tag from an edge. Author normalized to match set_tag."""
    author = (author or "analyst").strip() or "analyst"
    cur = conn.execute(
        "DELETE FROM hypothesis_tags WHERE edge_id = ? AND hypothesis = ? AND author = ?",
        (edge_id, (hypothesis or "").strip(), author))
    conn.commit()
    return {"ok": True, "removed": cur.rowcount}


def tags_for_edge(conn, edge_id: int) -> list[dict]:
    """Every hypothesis stance recorded on an edge."""
    rows = conn.execute(
        "SELECT id, edge_id, hypothesis, stance, author, created_at "
        "FROM hypothesis_tags WHERE edge_id = ? ORDER BY id", (edge_id,)).fetchall()
    return [dict(r) for r in rows]


def tags_for_edges(conn, edge_ids: list[int]) -> dict[int, list[dict]]:
    """Bulk: edge_id -> its tags, for folding into the graph payload without an
    N+1 query per edge."""
    if not edge_ids:
        return {}
    ph = ",".join("?" * len(edge_ids))
    out: dict[int, list[dict]] = {}
    for r in conn.execute(
        f"SELECT id, edge_id, hypothesis, stance, author FROM hypothesis_tags "
        f"WHERE edge_id IN ({ph}) ORDER BY id", edge_ids):
        out.setdefault(r["edge_id"], []).append(dict(r))
    return out
