"""Focus gap-analysis tests: short, named, accurate gaps against top actors.

Run: .venv/bin/python -m investigations.tests.test_focus_gaps
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import focus

SCORES_DDL = ("CREATE TABLE IF NOT EXISTS entity_scores ("
              "entity_id INTEGER PRIMARY KEY, threat_score REAL, degree INTEGER, "
              "report_count INTEGER)")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        db.init_db(db_path)
        with db.connect(db_path) as conn:
            conn.execute(SCORES_DDL)
            r1 = db.insert_report(conn, "a.md", "h1", "markdown", "R1", "case-x", "x")

            def actor(name, score, degree, rc, role="operator", enriched=False):
                eid = db.upsert_entity(conn, name, "handle", r1)
                conn.execute("UPDATE entities SET notes = ? WHERE id = ?",
                             (f"role:{role} — x", eid))
                db.add_mention(conn, eid, r1, name, "ctx")
                conn.execute("INSERT INTO entity_scores VALUES (?,?,?,?)",
                             (eid, score, degree, rc))
                if enriched:
                    conn.execute(
                        "INSERT INTO enrichment_runs (entity_id, provider_slug, query, status) "
                        "VALUES (?, 'perplexity', 'q', 'success')", (eid,))
                return eid

            # 8 uninvestigated top actors (deg==0, unenriched) > the 6 display cap, to
            # test true counting. compute_gaps MERGES "isolated" (no edges) + "unenriched"
            # into ONE "uninvestigated" gap (same next action: investigate).
            for i in range(8):
                actor(f"@iso{i}", 70 - i, 0, 2)
            actor("@solo", 50, 3, 1, enriched=True)  # uncorroborated only (1 report, enriched)
            actor("@connected", 40, 5, 3, enriched=True)  # healthy + enriched
            pc = db.upsert_entity(conn, "maybe someone", "person_candidate", r1)
            db.add_mention(conn, pc, r1, "maybe someone", "ctx")
            conn.commit()

            gaps = focus.compute_gaps(conn, "case-x")
            kinds = {g["kind"] for g in gaps}
            assert "uninvestigated" in kinds, f"missing uninvestigated: {kinds}"
            assert "uncorroborated" in kinds, f"missing uncorroborated: {kinds}"
            assert "unconsolidated" in kinds, f"missing unconsolidated: {kinds}"

            # True count is reported even though the named list is capped at 6.
            iso = next(g for g in gaps if g["kind"] == "uninvestigated")
            assert iso["count"] == 8, f"uninvestigated count should be true (8), got {iso['count']}"
            assert len(iso["entities"]) == 6, f"named list should cap at 6, got {len(iso['entities'])}"
            # Healthy enriched actor must NOT show in any actor-level gap.
            for k in ("uninvestigated", "uncorroborated"):
                g = next((x for x in gaps if x["kind"] == k), None)
                if g:
                    assert all(e["name"] != "@connected" for e in g["entities"]), \
                        f"@connected wrongly in {k}"

    # Fresh-DB auto-recalibration: scorer + Focus must work BEFORE analyze ever
    # runs (entity_scores/typed_relationships now created by migrate).
    from investigations import analyze as analyze_mod
    with tempfile.TemporaryDirectory() as tmp2:
        dbp = Path(tmp2) / "fresh.db"
        vault = Path(tmp2) / "vault"
        db.init_db(dbp)
        with db.connect(dbp) as conn:  # connect() runs _migrate
            rid = db.insert_report(conn, "r.md", "hh", "markdown", "R", "c", "x")
            eid = db.upsert_entity(conn, "@op", "handle", rid)
            conn.execute("UPDATE entities SET notes='role:operator — x' WHERE id=?", (eid,))
            db.add_mention(conn, eid, rid, "@op", "ctx")
            conn.commit()
            # These would have raised 'no such table' before the migrate fix.
            scored = analyze_mod.compute_threat_scores(conn)
            focus.run(conn, vault, llm_summary=False)
            assert scored >= 1, "scorer did not score the roled actor on a fresh DB"
            assert conn.execute(
                "SELECT 1 FROM entity_scores WHERE entity_id=?", (eid,)).fetchone(), \
                "roled actor not in entity_scores after recalibration"

    print("PASS test_focus_gaps: gaps detected with TRUE counts (capped display), healthy "
          "actor excluded; fresh-DB auto-recalibration works before analyze")


if __name__ == "__main__":
    main()
