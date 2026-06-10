"""Correction / supersession tests — the Handala 'report 2 fixes report 1' case.

Run: .venv/bin/python -m investigations.tests.test_corrections
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import claims


def main():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:  # migrate creates claims + typed_relationships.status
            r1 = db.insert_report(conn, "h1.md", "h1", "markdown", "Handala 1", "case-b", "x")
            r2 = db.insert_report(conn, "h2.md", "h2", "markdown", "Handala 2", "case-b", "x")
            x = db.upsert_entity(conn, "@x", "handle", r1)
            y = db.upsert_entity(conn, "crewY", "telegram_channel", r1)
            for e in (x, y):
                db.add_mention(conn, e, r1, "s", "c")
                db.add_mention(conn, e, r2, "s", "c")
            # Report 1: X leads Y. Report 2 corrects: X is just a member.
            db.add_relationship(conn, x, y, "leader_of", r1, "report1 says leader", 0.6)
            db.add_relationship(conn, x, y, "member_of", r2, "report2 corrects: member", 0.8)
            # Derived graph (as analyze would have built) holds BOTH edges.
            for rt in ("leader_of", "member_of"):
                conn.execute(
                    "INSERT INTO typed_relationships (src_entity_id, dst_entity_id, rel_type, "
                    "confidence, evidence, status) VALUES (?, ?, ?, 'medium', 'e', 'active')",
                    (x, y, rt))
            conn.commit()

            # --- relationship correction ---
            claims.backfill(conn)
            # Idempotency: re-running backfill on unchanged data adds nothing.
            n1 = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
            claims.backfill(conn); claims.backfill(conn)
            assert conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == n1, \
                "backfill not idempotent on unchanged data"
            cons = claims.detect_contradictions(conn)
            relc = [c for c in cons if c["predicate"].startswith("rel:") and c["entity_id"] == x]
            assert relc, f"no relationship contradiction detected: {cons}"
            vals = {cl["value"] for cl in relc[0]["claims"]}
            assert vals == {"leader_of", "member_of"}, vals

            winner = next(cl for cl in relc[0]["claims"] if cl["value"] == "member_of")
            claims.resolve(conn, winner["id"])

            # Contradiction resolved.
            assert not [c for c in claims.detect_contradictions(conn)
                        if c["predicate"].startswith("rel:") and c["entity_id"] == x], \
                "relationship contradiction still open after resolve"
            # Graph reprojected: member_of active, leader_of superseded (kept, not deleted).
            active = {r["rel_type"] for r in conn.execute(
                "SELECT rel_type FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=? "
                "AND status='active'", (x, y))}
            superseded = {r["rel_type"] for r in conn.execute(
                "SELECT rel_type FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=? "
                "AND status='superseded'", (x, y))}
            assert active == {"member_of"}, f"active edges wrong: {active}"
            assert "leader_of" in superseded, f"old edge not superseded/kept: {superseded}"
            # Audit: the losing claim is kept, marked superseded, pointing at the winner.
            loser = conn.execute(
                "SELECT status, superseded_by FROM claims WHERE entity_id=? AND value='leader_of'",
                (x,)).fetchone()
            assert loser["status"] == "superseded" and loser["superseded_by"] == winner["id"], \
                f"audit trail broken: {dict(loser)}"

            # --- role correction (simulating per-report claims from the extractor) ---
            z = db.upsert_entity(conn, "@z", "handle", r1)
            db.add_mention(conn, z, r1, "s", "c")
            for rep, role in ((r1, "channel"), (r2, "operator")):  # canonical roles
                conn.execute(
                    "INSERT INTO claims (entity_id, report_id, claim_type, predicate, value, "
                    "status, source) VALUES (?, ?, 'role', 'role', ?, 'active', 'extract')",
                    (z, rep, role))
            conn.commit()
            rolec = [c for c in claims.detect_contradictions(conn)
                     if c["entity_id"] == z and c["predicate"] == "role"]
            assert rolec, "role contradiction not detected"
            win_role = next(cl for cl in rolec[0]["claims"] if cl["value"] == "operator")
            claims.resolve(conn, win_role["id"])
            notes = conn.execute("SELECT notes FROM entities WHERE id=?", (z,)).fetchone()["notes"]
            assert notes.startswith("role:operator"), f"role not reprojected to entity: {notes!r}"

            # A 'role' claim whose value is really a sub-role must NOT overwrite the
            # canonical role (that would zero the score) — it routes to sub_role.
            q = db.upsert_entity(conn, "@q", "handle", r1)
            conn.execute("UPDATE entities SET notes='role:operator — orig' WHERE id=?", (q,))
            db.add_mention(conn, q, r1, "s", "c")
            claims.backfill(conn)  # -> role:operator claim
            conn.execute(
                "INSERT INTO claims (entity_id, report_id, claim_type, predicate, value, "
                "status, source) VALUES (?, ?, 'role', 'role', 'leadership', 'active', 'extract')",
                (q, r2))
            rc = [c for c in claims.detect_contradictions(conn)
                  if c["entity_id"] == q and c["predicate"] == "role"]
            assert rc, "operator-vs-leadership role contradiction not detected"
            wl = next(cl for cl in rc[0]["claims"] if cl["value"] == "leadership")
            claims.resolve(conn, wl["id"])
            row = conn.execute("SELECT notes, sub_role FROM entities WHERE id=?", (q,)).fetchone()
            assert row["notes"].startswith("role:operator"), \
                f"canonical role wrongly overwritten by a sub-role value: {row['notes']!r}"
            assert row["sub_role"] == "leadership", f"sub-role not applied: {row['sub_role']!r}"

    print("PASS test_corrections: report-2 supersedes report-1 (relationship + role); "
          "graph reprojects; loser kept + audited; contradiction clears")


if __name__ == "__main__":
    main()
