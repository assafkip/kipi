"""Manual node tests: analyst-created node with type + thumbnail, scoped + linked.

Run: .venv/bin/python -m investigations.tests.test_manual_node
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.enrich import promote


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def main():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            # A node can't be scoped into a case with no investigations row
            # (CaseDeletedError guard) — register the case as production would.
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-a','case-a')")
            ra = db.insert_report(conn, "a.md", "ha", "markdown", "Report A", "case-a", "x")
            actor = db.upsert_entity(conn, "@actor", "username", ra)
            db.add_mention(conn, actor, ra, "@actor", "ctx")
            conn.commit()

            out = promote.add_manual_node(
                conn, "burner@proton.me", "email", analyst="ally",
                thumbnail="https://example.com/avatar.png", link_to=actor, case="case-a")
            assert out.get("ok"), out
            eid = out["entity_id"]
            _check("type honored", out["type"], "email")

            row = conn.execute("SELECT entity_type, thumbnail FROM entities WHERE id=?", (eid,)).fetchone()
            _check("entity type persisted", row["entity_type"], "email")
            _check("thumbnail persisted", row["thumbnail"], "https://example.com/avatar.png")

            # Scoped into case-a via a 'manual' synthetic report.
            st = conn.execute(
                "SELECT DISTINCT r.source_type, r.investigation FROM mentions m "
                "JOIN reports r ON r.id=m.report_id WHERE m.entity_id=?", (eid,)).fetchone()
            _check("scoped via manual report", (st["source_type"], st["investigation"]), ("manual", "case-a"))

            # Linked to the source actor.
            edge = conn.execute(
                "SELECT rel_type, status FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=?",
                (actor, eid)).fetchone()
            _check("linked edge", (edge["rel_type"], edge["status"]), ("linked", "active"))

            # Dedup: re-adding the same name reuses the entity (and can set a thumbnail).
            out2 = promote.add_manual_node(conn, "burner@proton.me", "email", analyst="ally")
            _check("dedup by name", out2["entity_id"], eid)

            # Cross-case: same name already exists -> bridge surfaces.
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-b','case-b')")
            rb = db.insert_report(conn, "b.md", "hb", "markdown", "Report B", "case-b", "x")
            shared = db.upsert_entity(conn, "shared.example", "domain", rb)
            db.add_mention(conn, shared, rb, "shared.example", "ctx")
            conn.commit()
            out3 = promote.add_manual_node(conn, "shared.example", "domain", analyst="ally", case="case-a")
            _check("manual node bridges into existing case", out3["entity_id"], shared)
            _check("cross-case detected", out3["cross_case"], ["case-b"])

    print("\nPASS: test_manual_node")


if __name__ == "__main__":
    main()
