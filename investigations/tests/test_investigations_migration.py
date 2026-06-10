"""Migration test: reports.investigation tags -> investigations table.

Run: .venv/bin/python -m investigations.tests.test_investigations_migration

Verifies the 1a backbone migration (global pool, case-scoped views):
- A pre-migration DB (no investigations table) backfills cleanly on connect.
- Every distinct tag becomes one case row.
- Untagged reports get filed under 'unfiled'.
- Global entity rows are never rewritten (count preserved).
- The backfill is idempotent across repeated connects.
"""
import tempfile
from pathlib import Path

from investigations.storage import db


def _seed_pre_migration_db(db_path: Path) -> int:
    """Create a DB with data but NO investigations table (simulates old DB)."""
    db.init_db(db_path)
    with db.connect(db_path) as conn:
        # Simulate the pre-migration state: drop the case table the migration adds.
        conn.execute("DROP TABLE IF EXISTS investigations")
        reports = [
            ("a.pdf", "h1", "pdf", "A", "case-a"),
            ("b.pdf", "h2", "pdf", "B", "case-a"),
            ("c.pdf", "h3", "pdf", "C", "case-b"),
            ("d.pdf", "h4", "pdf", "D", None),      # untagged -> unfiled
            ("e.pdf", "h5", "pdf", "E", "   "),     # blank -> unfiled
        ]
        for path, h, typ, title, inv in reports:
            db.insert_report(conn, path, h, typ, title, inv, raw_text="x")
        for i in range(10):
            db.upsert_entity(conn, f"entity-{i}", "person", report_id=1)
        conn.commit()
    return 10


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        entity_count = _seed_pre_migration_db(db_path)

        # First connect triggers _migrate -> _backfill_investigations.
        with db.connect(db_path) as conn:
            cases = {
                r["slug"]: r["case_name"]
                for r in conn.execute("SELECT slug, case_name FROM investigations")
            }
            assert set(cases) == {"case-a", "case-b", "unfiled"}, cases
            assert cases["case-a"] == "case-a", cases

            null_left = conn.execute(
                "SELECT COUNT(*) FROM reports "
                "WHERE investigation IS NULL OR TRIM(investigation) = ''"
            ).fetchone()[0]
            assert null_left == 0, f"{null_left} reports still untagged"

            unfiled = conn.execute(
                "SELECT COUNT(*) FROM reports WHERE investigation = 'unfiled'"
            ).fetchone()[0]
            assert unfiled == 2, f"expected 2 unfiled, got {unfiled}"

            now_entities = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
            assert now_entities == entity_count, "entity rows changed during migration"

        # Idempotency: a second connect must not create duplicate cases.
        with db.connect(db_path) as conn:
            n = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
            assert n == 3, f"backfill not idempotent, got {n} cases"

    print("PASS test_investigations_migration: 5 reports -> 3 cases, "
          "2 unfiled, entities preserved, idempotent")


if __name__ == "__main__":
    main()
