"""Cross-case detection test: shared actors surface, infra noise is excluded.

Run: .venv/bin/python -m investigations.tests.test_cross_case

Seeds a temp DB with one real actor mentioned in two cases plus a generic
infra domain (t.me) in two cases, then exercises the exact SQL the
/cross-case panel and the entity 'also appears in' badge use.
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.webapp.app import GENERIC_INFRA


def _seed(conn):
    # Two cases, each with one report.
    r1 = db.insert_report(conn, "a.md", "h1", "markdown", "A", "case-alpha", "x")
    r2 = db.insert_report(conn, "b.md", "h2", "markdown", "B", "case-beta", "x")
    # A real shared actor in BOTH cases.
    shared = db.upsert_entity(conn, "@sharedactor", "person", r1)
    db.add_mention(conn, shared, r1, "@sharedactor", "ctx")
    db.add_mention(conn, shared, r2, "@sharedactor", "ctx")
    # An actor only in case-alpha.
    solo = db.upsert_entity(conn, "@soloactor", "person", r1)
    db.add_mention(conn, solo, r1, "@soloactor", "ctx")
    # Generic infra in BOTH cases — must NOT count as a shared actor.
    infra = db.upsert_entity(conn, "t.me", "domain", r1)
    db.add_mention(conn, infra, r1, "t.me", "ctx")
    db.add_mention(conn, infra, r2, "t.me", "ctx")
    conn.commit()
    return shared, solo, infra


def _cross_case_rows(conn):
    placeholders = ",".join("?" for _ in GENERIC_INFRA)
    return conn.execute(
        "SELECT e.canonical_name, COUNT(DISTINCT r.investigation) AS case_count "
        "FROM entities e JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation IS NOT NULL "
        "AND (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
        "AND e.entity_type != 'person_candidate' "
        f"AND e.canonical_name NOT IN ({placeholders}) "
        "GROUP BY e.id HAVING case_count >= 2",
        tuple(GENERIC_INFRA),
    ).fetchall()


def _also_in_cases(conn, entity_id):
    return [r["investigation"] for r in conn.execute(
        "SELECT r.investigation, COUNT(*) AS n FROM mentions m "
        "JOIN reports r ON r.id = m.report_id "
        "WHERE m.entity_id = ? AND r.investigation IS NOT NULL "
        "GROUP BY r.investigation ORDER BY n DESC", (entity_id,)).fetchall()]


def main():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        db.init_db(db_path)
        with db.connect(db_path) as conn:
            shared, solo, infra = _seed(conn)

            rows = {r["canonical_name"]: r["case_count"] for r in _cross_case_rows(conn)}
            assert "@sharedactor" in rows, f"shared actor not detected: {rows}"
            assert rows["@sharedactor"] == 2, rows
            assert "@soloactor" not in rows, "single-case actor wrongly flagged cross-case"
            assert "t.me" not in rows, "generic infra (t.me) wrongly flagged as shared actor"

            assert set(_also_in_cases(conn, shared)) == {"case-alpha", "case-beta"}
            assert _also_in_cases(conn, solo) == ["case-alpha"]

    print("PASS test_cross_case: shared actor surfaces across 2 cases, "
          "solo actor excluded, t.me infra filtered, also-in-cases correct")


if __name__ == "__main__":
    main()
