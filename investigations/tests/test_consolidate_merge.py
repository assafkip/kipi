"""Merge safety: consolidating a duplicate must preserve analyst annotations
and not hit a FK constraint (the regen-safe promise across entity merges).

Run: .venv/bin/python -m investigations.tests.test_consolidate_merge
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import annotations
from investigations import consolidate


def main():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)

        # Case A: canonical has no annotation, duplicate does -> survivor inherits it.
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "a.md", "h", "markdown", "R", "c", "x")
            C = db.upsert_entity(conn, "@canon", "handle", r)
            D = db.upsert_entity(conn, "@dupe", "handle", r)
            annotations.set_notes(conn, D, "I knew this guy from a 2023 case")
            # FK-referencing derived rows on the dupe (would block the entity DELETE).
            conn.execute("INSERT INTO entity_scores VALUES (?, 10, 0, 1)", (D,))
            conn.execute(
                "INSERT INTO claims (entity_id, report_id, claim_type, predicate, value, "
                "status, source) VALUES (?, ?, 'role', 'role', 'operator', 'active', 'backfill')",
                (D, r))
            conn.commit()

            consolidate._merge_entity_refs(conn, D, C)
            conn.execute("DELETE FROM entities WHERE id = ?", (D,))  # must NOT raise FK error
            conn.commit()

            assert annotations.get(conn, C)["notes"] == "I knew this guy from a 2023 case", \
                "duplicate's note did not survive onto the canonical entity"
            assert not conn.execute("SELECT 1 FROM entity_scores WHERE entity_id=?", (D,)).fetchone()
            assert not conn.execute("SELECT 1 FROM claims WHERE entity_id=?", (D,)).fetchone()
            assert not conn.execute("SELECT 1 FROM entities WHERE id=?", (D,)).fetchone()

        # Case B: both have notes -> canonical keeps its own + the dupe's appended.
        with db.connect(dbp) as conn:
            C2 = db.upsert_entity(conn, "@c2", "handle", r)
            D2 = db.upsert_entity(conn, "@d2", "handle", r)
            annotations.set_notes(conn, C2, "canonical note")
            annotations.set_notes(conn, D2, "duplicate note")
            conn.commit()
            consolidate._merge_entity_refs(conn, D2, C2)
            conn.execute("DELETE FROM entities WHERE id = ?", (D2,))
            conn.commit()
            merged_notes = annotations.get(conn, C2)["notes"]
            assert "canonical note" in merged_notes and "duplicate note" in merged_notes, \
                f"notes not merged: {merged_notes!r}"

    print("PASS test_consolidate_merge: merging a duplicate preserves analyst notes "
          "(inherit or append), clears derived rows, and the entity DELETE doesn't hit FK")


if __name__ == "__main__":
    main()
