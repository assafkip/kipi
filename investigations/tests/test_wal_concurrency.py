"""A long-running writer must NOT block readers — that freeze is what made the UI
hang ("tabs don't move") and Process "look stopped" during consolidate.

Without WAL, the writer holds an EXCLUSIVE lock and a concurrent reader blocks until
busy_timeout (60s) then raises 'database is locked'. With WAL, the reader sees the
last committed snapshot and returns immediately.

Run: .venv/bin/python -m investigations.tests.test_wal_concurrency
"""
import tempfile
from pathlib import Path

from investigations.storage import db


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_reader_not_blocked_by_open_writer():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        db.init_db(db_path)
        with db.connect(db_path) as seed:
            seed.execute("INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?,?)",
                         ("c", "C"))
            seed.commit()

        # 1) WAL is actually on.
        with db.connect(db_path) as probe:
            mode = probe.execute("PRAGMA journal_mode").fetchone()[0]
        _check("journal_mode is WAL", str(mode).lower() == "wal")

        # 2) Hold a write transaction OPEN, then read on a second connection.
        #    The reader uses a short busy_timeout so a non-WAL regression fails fast
        #    (locked error in ~2s) instead of hanging the suite for 60s.
        with db.connect(db_path) as writer:
            writer.execute("INSERT INTO investigations (slug, case_name) VALUES (?,?)",
                           ("c2", "C2"))  # opens + holds the write lock (uncommitted)
            # migrate=False: a read-only probe must not try to write (a second
            # writer would deadlock against the held lock, which is not what we test).
            with db.connect(db_path, migrate=False) as reader:
                reader.execute("PRAGMA busy_timeout = 2000")
                rows = reader.execute("SELECT COUNT(*) FROM investigations").fetchall()
                _check("reader returns while writer holds an open transaction",
                       rows[0][0] >= 1)
                _check("reader sees the committed snapshot (uncommitted write not visible)",
                       rows[0][0] == 1)
            writer.commit()

        # 3) After commit, the new row is visible.
        with db.connect(db_path) as after:
            n = after.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        _check("committed write is visible afterward", n == 2)


def main():
    test_reader_not_blocked_by_open_writer()
    print("\nPASS: test_wal_concurrency")


if __name__ == "__main__":
    main()
