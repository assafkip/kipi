"""Live-dig nodes are visible to case-scoped views (issue live-dig-mentions, PRD
graph-data-model-hardening).

_persist_step_discovery used to land entities WITHOUT mentions rows; case scoping
joins mentions → reports.investigation (promote._primary_case), so live-dig nodes
vanished from every case-scoped surface. Asserts: anchor + found each get a mentions
row scoped to the case's enrichment report; the 1.2s re-sweep stays idempotent
(no duplicate mentions); the mentions join resolves the nodes to the case.

Run: .venv/bin/python3 -m pytest investigations/tests/test_live_dig_mentions.py -q
"""
import tempfile
from pathlib import Path

import pytest

from investigations.storage import db
from investigations.webapp import app as app_module


@pytest.fixture
def case_db(mp):
    """Fresh temp DB with a 't-case' investigation; app_module.db.connect → this DB
    (same patching pattern as test_live_graph_landing — connect()'s default arg binds
    DB_PATH at definition time, so patching connect itself is required)."""
    d = tempfile.mkdtemp()
    p = Path(d) / "t.db"
    db.init_db(p)
    orig = db.connect
    mp.setattr(db, "connect", lambda migrate=True, db_path=p: orig(db_path=db_path, migrate=migrate))
    with db.connect() as conn:
        conn.execute("INSERT INTO investigations (slug) VALUES ('t-case')")
    return p


_STEP = {"type": "tool", "tool": "Bash", "raw_tool": "crtsh",
         "input": "./invctl osint-tool crtsh trumpfundus.com",
         "result": "hostnames: trumpfundus.com promo.net giveaway.org"}


def _case_scoped_names(conn, case):
    return {r["canonical_name"] for r in conn.execute(
        "SELECT DISTINCT e.canonical_name FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation = ?", (case,))}


def test_anchor_and_found_get_case_scoped_mentions(case_db):
    wrote = app_module._persist_step_discovery("t-case", dict(_STEP))
    assert wrote == 2
    with db.connect() as conn:
        names = _case_scoped_names(conn, "t-case")
        assert "trumpfundus.com" in names      # the anchor
        assert "promo.net" in names            # found
        assert "giveaway.org" in names         # found
        # Every landed entity has exactly one mention on the enrichment report.
        rows = conn.execute(
            "SELECT e.canonical_name, COUNT(m.id) n FROM entities e "
            "JOIN mentions m ON m.entity_id = e.id GROUP BY e.id").fetchall()
        assert all(r["n"] == 1 for r in rows), [(r["canonical_name"], r["n"]) for r in rows]


def test_resweep_does_not_duplicate_mentions(case_db):
    app_module._persist_step_discovery("t-case", dict(_STEP))
    # The watcher sweeps every 1.2s and retries steps on transient lock — the same
    # step landing twice must not double the mentions.
    app_module._persist_step_discovery("t-case", dict(_STEP))
    with db.connect() as conn:
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM mentions m JOIN reports r ON r.id = m.report_id "
            "WHERE r.investigation = 't-case'").fetchone()["n"]
        assert n == 3, n   # anchor + 2 found, once each


def test_mention_context_names_the_tool(case_db):
    app_module._persist_step_discovery("t-case", dict(_STEP))
    with db.connect() as conn:
        ctx = conn.execute("SELECT context FROM mentions LIMIT 1").fetchone()["context"]
        assert "crtsh" in ctx and "live dig" in ctx
