"""Any-input intake: unmapped extensions fall back to a text read; binary skips.

Run: .venv/bin/python -m investigations.tests.test_intake_fallback
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.cli import invctl


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def test_unknown_ext_text_fallback():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        note = Path(d) / "source-call.weirdext"
        note.write_text("Met @sourceguy who runs evil-domain.com. Notes from 5/29.", encoding="utf-8")
        with db.connect(dbp) as conn:
            rid = invctl._ingest_one(conn, note, "case-notes")
            assert rid, "unmapped-extension text file should ingest, not skip"
            row = conn.execute("SELECT source_type, investigation FROM reports WHERE id=?", (rid,)).fetchone()
            _check("ingested as text", row["source_type"], "text")
            _check("filed under case", row["investigation"], "case-notes")
            ents = conn.execute(
                "SELECT COUNT(*) FROM mentions WHERE report_id=?", (rid,)).fetchone()[0]
            assert ents > 0, "entities should be extracted from the note text"
            print(f"  ok  extracted {ents} mention(s) from pasted-style notes")


def test_binary_skips():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        # PNG header + noise → mostly non-text, should NOT ingest as garbage.
        blob = Path(d) / "image.weirdbin"
        blob.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8)
        with db.connect(dbp) as conn:
            rid = invctl._ingest_one(conn, blob, "case-notes")
            _check("binary file skipped", rid, None)


def main():
    test_unknown_ext_text_fallback()
    test_binary_skips()
    print("\nPASS: test_intake_fallback")


if __name__ == "__main__":
    main()
