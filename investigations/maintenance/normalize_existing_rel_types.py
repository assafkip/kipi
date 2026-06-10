"""One-time, idempotent sweep that brings EXISTING typed_relationships rows in line
with the controlled vocabulary (issue unify-rel-vocab-gate fixed new writes; this
cleans rows written before the gate existed).

For every row: run its rel_type through normalize_rel (strict — allow_novel=False, since
these predate the per-case-novel path and the observed stragglers are all synonyms or
co-occurrence flags). Then:
  - None            -> DELETE (a co-occurrence flag like flagged_malicious_alongside is a
                       node property, not an edge — it should never have been a line).
  - same label      -> leave it (already canonical).
  - different label -> UPDATE to the vocab term; if (src,dst,new) already exists, DELETE
                       this row instead (merge the duplicate, respect UNIQUE(src,dst,rel)).

Idempotent: a second run is a no-op (every row already maps to itself). Re-runnable.

Run: .venv/bin/python -m investigations.maintenance.normalize_existing_rel_types [db_path]
"""
from __future__ import annotations

import sys
from pathlib import Path

from investigations.storage import db
from investigations.enrich.rel_vocab import normalize_rel

DEFAULT_DB = Path("investigations/data/investigations.db")


def normalize_existing(conn) -> dict:
    rows = conn.execute(
        "SELECT id, src_entity_id, dst_entity_id, rel_type, "
        "COALESCE(evidence,'') AS evidence FROM typed_relationships"
    ).fetchall()
    relabeled = dropped = merged = unchanged = 0
    for r in rows:
        new = normalize_rel(r["rel_type"], r["evidence"])
        if new is None:
            conn.execute("DELETE FROM typed_relationships WHERE id=?", (r["id"],))
            dropped += 1
            continue
        if new == r["rel_type"]:
            unchanged += 1
            continue
        dup = conn.execute(
            "SELECT id FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=? "
            "AND rel_type=? AND id!=?",
            (r["src_entity_id"], r["dst_entity_id"], new, r["id"]),
        ).fetchone()
        if dup:
            conn.execute("DELETE FROM typed_relationships WHERE id=?", (r["id"],))
            merged += 1
        else:
            conn.execute("UPDATE typed_relationships SET rel_type=? WHERE id=?", (new, r["id"]))
            relabeled += 1
    conn.commit()
    return {"relabeled": relabeled, "dropped": dropped, "merged": merged,
            "unchanged": unchanged, "total_seen": len(rows)}


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    dbp = Path(argv[0]) if argv else DEFAULT_DB
    with db.connect(dbp) as conn:
        before = {row["rel_type"]: row["n"] for row in conn.execute(
            "SELECT rel_type, COUNT(*) n FROM typed_relationships GROUP BY rel_type").fetchall()}
        result = normalize_existing(conn)
        after = {row["rel_type"]: row["n"] for row in conn.execute(
            "SELECT rel_type, COUNT(*) n FROM typed_relationships GROUP BY rel_type").fetchall()}
    print("before:", dict(sorted(before.items(), key=lambda x: -x[1])))
    print("after :", dict(sorted(after.items(), key=lambda x: -x[1])))
    print("result:", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
