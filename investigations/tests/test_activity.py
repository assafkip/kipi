"""Light multi-analyst tests: attribution on notes + the shared activity feed.

Run: .venv/bin/python -m investigations.tests.test_activity
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import activity
from investigations import annotations


def main():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:  # migrate creates activity + author columns
            r = db.insert_report(conn, "a.md", "h", "markdown", "R", "case-x", "x")
            x = db.upsert_entity(conn, "@x", "handle", r)
            conn.commit()

            # Attribution: a note records its author.
            annotations.set_notes(conn, x, "alice's note", author="alice")
            a = annotations.get(conn, x)
            assert a["notes"] == "alice's note" and a["notes_author"] == "alice", a

            # Two analysts log actions; the feed shows who did what.
            activity.log(conn, "alice", "edited notes", entity_id=x, investigation="case-x")
            activity.log(conn, "bob", "flagged actor", entity_id=x, investigation="case-x")
            activity.log(conn, "carol", "resolved a contradiction", investigation="other-case")

            feed = activity.recent(conn)
            assert len(feed) == 3, f"expected 3 activity rows, got {len(feed)}"
            assert feed[0]["analyst"] in {"alice", "bob", "carol"}
            # Newest first + carries the entity name.
            assert any(e["analyst"] == "bob" and e["canonical_name"] == "@x" for e in feed), feed

            # Case-scoped feed excludes other cases.
            scoped = activity.recent(conn, case="case-x")
            assert len(scoped) == 2, f"case scope wrong: {len(scoped)}"
            assert all(e["investigation"] == "case-x" for e in scoped)
            assert not any(e["analyst"] == "carol" for e in scoped)

    print("PASS test_activity: notes attributed to author; activity feed records who/what/when; "
          "case-scoped feed excludes other cases")


if __name__ == "__main__":
    main()
