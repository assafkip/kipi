"""Tests for .docx ingestion + complete report deletion.

Run: .venv/bin/python -m investigations.tests.test_delete_and_docx
"""
import io
import tempfile
import zipfile
from pathlib import Path

from investigations.storage import db
from investigations.ingest import docx_ingest

_DOC = ('<?xml version="1.0"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>@actor1 runs evil-doc.com from 8.8.8.8.</w:t></w:r></w:p>'
        '<w:p><w:r><w:t>Second paragraph.</w:t></w:r></w:p></w:body></w:document>')


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def test_docx():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "memo.docx"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("word/document.xml", _DOC)
        text = docx_ingest.extract_text(p)
        assert "@actor1 runs evil-doc.com" in text, text
        assert "Second paragraph." in text, text
        print("  ok  .docx text extracted (2 paragraphs)")


def test_delete():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            r1 = db.insert_report(conn, "r1.md", "h1", "markdown", "R1", "case-a", "x")
            r2 = db.insert_report(conn, "r2.md", "h2", "markdown", "R2", "case-a", "x")
            shared = db.upsert_entity(conn, "@shared", "username", r1)   # first-seen r1, in both
            db.add_mention(conn, shared, r1, "@shared", "c")
            db.add_mention(conn, shared, r2, "@shared", "c")
            solo = db.upsert_entity(conn, "@solo", "username", r1)        # only in r1
            db.add_mention(conn, solo, r1, "@solo", "c")
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-a','case-a')")
            conn.commit()

            out = db.delete_report(conn, r1)
            assert out.get("ok"), out
            _check("exclusive entity removed count", out["entities_removed"], 1)
            _check("solo entity gone", conn.execute("SELECT COUNT(*) FROM entities WHERE id=?", (solo,)).fetchone()[0], 0)
            _check("shared entity kept", conn.execute("SELECT COUNT(*) FROM entities WHERE id=?", (shared,)).fetchone()[0], 1)
            _check("shared first-seen reassigned to r2",
                   conn.execute("SELECT first_seen_report_id FROM entities WHERE id=?", (shared,)).fetchone()[0], r2)
            _check("r1 mentions gone", conn.execute("SELECT COUNT(*) FROM mentions WHERE report_id=?", (r1,)).fetchone()[0], 0)
            _check("r2 mention of shared kept", conn.execute("SELECT COUNT(*) FROM mentions WHERE report_id=? AND entity_id=?", (r2, shared)).fetchone()[0], 1)
            _check("r1 report gone", conn.execute("SELECT COUNT(*) FROM reports WHERE id=?", (r1,)).fetchone()[0], 0)
            _check("case kept (r2 remains)", out["case_removed"], False)

            out2 = db.delete_report(conn, r2)
            _check("case removed when last report deleted", out2["case_removed"], True)
            _check("case gone", conn.execute("SELECT COUNT(*) FROM investigations WHERE slug='case-a'").fetchone()[0], 0)


def main():
    test_docx()
    test_delete()
    print("\nPASS: test_delete_and_docx")


if __name__ == "__main__":
    main()
