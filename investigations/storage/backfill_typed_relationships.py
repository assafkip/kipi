"""One-time, idempotent backfill: promote legacy typed `relationships` rows into
`typed_relationships`.

Why this exists: the live-graph landing path (`_persist_step_discovery` in
`webapp/app.py`) used to write a tool-step discovery edge ONLY into the legacy
`relationships` table. The graph draws edges — and judges which nodes are
"meaningful" — exclusively from `typed_relationships`. So digs that landed before
the producer fix have real typed edges (tls_cert / resolves_to / …) sitting in a
table the graph never reads, and their case canvas renders empty.

This promotes every typed `relationships` row (rel_type != 'co_mentioned' — the
co-occurrence edges are handled separately by the graph) into `typed_relationships`.
`INSERT OR IGNORE` + UNIQUE(src,dst,rel_type) makes it safe to re-run: already-landed
edges are skipped, nothing is duplicated.

Run:  ./invctl  is not wired to this; run directly with the project venv:
    .venv/bin/python -m investigations.storage.backfill_typed_relationships
"""
from __future__ import annotations

from investigations.storage import db


def backfill(conn) -> int:
    """Promote legacy typed relationships into typed_relationships. Returns the number
    of NEW rows inserted (idempotent: a second run inserts 0)."""
    created = 0
    rows = conn.execute(
        "SELECT src_entity_id, dst_entity_id, rel_type, evidence FROM relationships "
        "WHERE rel_type IS NOT NULL AND rel_type != 'co_mentioned'"
    ).fetchall()
    for r in rows:
        # A backfill rerun is NOT a re-observation — skip rows that already exist so
        # the documented idempotency holds (rerun inserts 0 AND mutates nothing;
        # bumping last_seen with the rerun time would fake an observation).
        exists = conn.execute(
            "SELECT 1 FROM typed_relationships "
            "WHERE src_entity_id=? AND dst_entity_id=? AND rel_type=?",
            (r["src_entity_id"], r["dst_entity_id"], r["rel_type"])).fetchone()
        if exists:
            continue
        from investigations import store
        landed = store.apply_mutation(conn, store.edge_upserted(
            None, r["src_entity_id"], r["dst_entity_id"], r["rel_type"],
            actor="pipeline:backfill", evidence=r["evidence"],
            provenance="osint"))
        if landed.get("created"):
            created += 1
    conn.commit()
    return created


def main() -> None:
    with db.connect() as conn:
        inserted = backfill(conn)
        total = conn.execute("SELECT COUNT(*) AS n FROM typed_relationships").fetchone()["n"]
    print(f"backfill: inserted {inserted} new typed_relationships row(s); total now {total}")


if __name__ == "__main__":
    main()
