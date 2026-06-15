"""Bench isolation (issue gtl-6-bench-isolation, PRD graph-trust-layer).

Asserts the consolidate bench never writes to the production DB: its resolved DB
path is not db.DB_PATH, KIPI_BENCH_DB redirects it, and running generate() leaves
zero consolidate-bench / kambala rows in the production DB.
"""
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from investigations.storage import db
from investigations.tests import bench_consolidate as bench


def test_bench_db_path_is_not_production():
    # Default (no env): a temp path, never the real DB.
    os.environ.pop("KIPI_BENCH_DB", None)
    p = bench._bench_db_path()
    assert p != db.DB_PATH
    assert "investigations.db" != p.name or p.parent != db.DB_PATH.parent
    assert p.resolve() != db.DB_PATH.resolve()


def test_kipi_bench_db_env_redirects():
    target = Path(tempfile.mkdtemp()) / "redirected-bench.db"
    os.environ["KIPI_BENCH_DB"] = str(target)
    try:
        assert bench._bench_db_path() == target
    finally:
        os.environ.pop("KIPI_BENCH_DB", None)


def test_kipi_bench_db_pointing_at_production_is_rejected():
    """Codex gtl-6 adversarial: an override that resolves to the production DB must
    raise, not open it — the isolation contract cannot be defeated by env."""
    os.environ["KIPI_BENCH_DB"] = str(db.DB_PATH)
    try:
        with pytest.raises(ValueError, match="production DB"):
            bench._bench_db_path()
    finally:
        os.environ.pop("KIPI_BENCH_DB", None)


def test_kipi_bench_db_relative_to_production_is_rejected():
    """A relative path that resolves to the production DB is equally rejected."""
    rel = os.path.relpath(db.DB_PATH, Path.cwd())
    os.environ["KIPI_BENCH_DB"] = rel
    try:
        with pytest.raises(ValueError, match="production DB"):
            bench._bench_db_path()
    finally:
        os.environ.pop("KIPI_BENCH_DB", None)


def test_bench_conn_inits_empty_redirected_file():
    """Codex gtl-6: KIPI_BENCH_DB pointing at a pre-created empty file must still get
    a schema — db.connect's migrations assume base tables exist."""
    fd, name = tempfile.mkstemp(suffix=".db")
    os.close(fd)   # leaves a 0-byte file, like NamedTemporaryFile
    os.environ["KIPI_BENCH_DB"] = name
    try:
        with bench._bench_conn() as conn:
            # The schema must be present — this query errors if init was skipped.
            conn.execute("SELECT COUNT(*) FROM entities").fetchone()
    finally:
        os.environ.pop("KIPI_BENCH_DB", None)
        Path(name).unlink(missing_ok=True)


def test_generate_leaves_production_db_clean():
    """The strongest guard: run the real generate() against an isolated DB and prove
    the production DB gains no consolidate-bench / kambala rows."""
    # Point the bench at a throwaway DB so generate() does real ingest work there.
    target = Path(tempfile.mkdtemp()) / "iso-bench.db"
    os.environ["KIPI_BENCH_DB"] = str(target)
    bench.REPORTS = 2   # keep it fast; we only need to prove isolation
    try:
        # Snapshot production-DB counts before — READ-ONLY (Codex gtl-6): db.connect()
        # would set WAL + run migrations, i.e. the guard test would itself mutate the
        # production DB and mask a real leak. A mode=ro URI connection cannot write.
        def _counts():
            if not db.DB_PATH.exists():
                return (0, 0)
            con = sqlite3.connect(f"file:{db.DB_PATH}?mode=ro", uri=True)
            try:
                cases = con.execute(
                    "SELECT COUNT(*) FROM investigations WHERE slug = ?",
                    (bench.CASE,)).fetchone()[0]
                kambala = con.execute(
                    "SELECT COUNT(*) FROM entities WHERE canonical_name LIKE 'kambala%'"
                ).fetchone()[0]
                return (cases, kambala)
            finally:
                con.close()

        before = _counts()
        bench.generate()
        after = _counts()
        assert after == before, (
            f"production DB changed: bench leaked rows (before={before}, after={after})")
        # And the isolated DB DID get the data.
        with db.connect(target) as conn:
            kambala = conn.execute(
                "SELECT COUNT(*) FROM entities WHERE canonical_name LIKE 'kambala%'"
            ).fetchone()[0]
        assert kambala > 0, "bench data must land in the isolated DB"
    finally:
        os.environ.pop("KIPI_BENCH_DB", None)
        bench.REPORTS = 10
