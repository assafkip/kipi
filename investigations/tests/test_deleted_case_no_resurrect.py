"""Reproducer + guard for the deleted-case resurrection bug.

Bug (2026-06-08): an investigate run scoped to a case that the analyst deleted
mid-run wrote its findings back anyway. The orphan report it left behind carried
the deleted case's slug, and the next `_backfill_investigations` pass promoted
that slug back into the investigations table — the deleted case rose from the
dead with its own graph. Two cases, two graphs, where there should be one.

The fix is two guards:
  1. `land_findings` (agent write-back) bails before writing ANY row when its
     case no longer exists — results are dropped silently (founder decision).
  2. `_synthetic_report` (the universal promote choke point) raises
     CaseDeletedError rather than scoping a node into a non-existent case.

Run: .venv/bin/python -m investigations.tests.test_deleted_case_no_resurrect
"""
from pathlib import Path
import tempfile

from investigations.storage import db
from investigations.agent import investigator
from investigations.enrich import promote as promote_mod


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def _case_in_investigations(conn, slug) -> bool:
    return conn.execute(
        "SELECT 1 FROM investigations WHERE slug = ?", (slug,)).fetchone() is not None


def test_deleted_case_not_resurrected_by_run_writeback():
    """A run that finishes after its case is deleted must not resurrect it."""
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            # A real case with one report.
            db.insert_report(conn, "seed.md", "h-seed", "markdown", "Seed",
                             "ghost-case", "trumpfundus.com is bad")
            conn.execute(
                "INSERT OR IGNORE INTO investigations (slug,case_name) VALUES (?,?)",
                ("ghost-case", "ghost-case"))
            conn.commit()
            _check("case exists before delete",
                   _case_in_investigations(conn, "ghost-case"), True)

            # Analyst deletes the case.
            out = db.delete_investigation(conn, "ghost-case")
            assert out.get("ok"), out
            _check("case gone after delete",
                   _case_in_investigations(conn, "ghost-case"), False)

            # The orphaned run finishes and tries to write its findings back to the
            # now-deleted case.
            parsed = {
                "findings": [{"entity": "elonstake.com", "entity_type": "domain",
                              "claim": "drainer", "provenance": "tool: dns",
                              "confidence": "high"}],
                "summary": "orphan run output",
            }
            res = investigator.land_findings(
                conn, "ghost-case", "elonstake.com", "investigate elonstake.com",
                parsed, entity_id=None, auto_promote=True)
            conn.commit()

            # Guard 1: nothing was written for the deleted case.
            _check("run write-back discarded", res.get("discarded"), "case_deleted")
            _check("no enrichment_runs for deleted case",
                   conn.execute("SELECT COUNT(*) FROM enrichment_runs WHERE investigation=?",
                                ("ghost-case",)).fetchone()[0], 0)
            _check("no reports for deleted case",
                   conn.execute("SELECT COUNT(*) FROM reports WHERE investigation=?",
                                ("ghost-case",)).fetchone()[0], 0)

            # Guard against the resurrection vector: the backfill must not re-create it.
            db._backfill_investigations(conn)
            conn.commit()
            _check("case STILL gone after backfill (not resurrected)",
                   _case_in_investigations(conn, "ghost-case"), False)


def test_synthetic_report_refuses_deleted_case():
    """The universal promote choke point raises on a non-existent case."""
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            raised = False
            try:
                promote_mod._synthetic_report(conn, "never-existed", kind="enrichment")
            except promote_mod.CaseDeletedError:
                raised = True
            _check("_synthetic_report raised CaseDeletedError", raised, True)

            # A live case still works (guard only fires on absent cases).
            conn.execute(
                "INSERT OR IGNORE INTO investigations (slug,case_name) VALUES (?,?)",
                ("live-case", "live-case"))
            conn.commit()
            rep_id = promote_mod._synthetic_report(conn, "live-case", kind="enrichment")
            _check("live case still gets a synthetic report", rep_id > 0, True)


if __name__ == "__main__":
    test_deleted_case_not_resurrected_by_run_writeback()
    test_synthetic_report_refuses_deleted_case()
    print("\nall green")
