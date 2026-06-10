"""Auto-corrections-on-ingest tests (founder choice A).

Two parts, both deterministic (the LLM extract call is stubbed):
  1. _ingest_one returns the new report_id (and None on a duplicate) — so
     cmd_ingest can collect the ids it just ingested and extract claims from them.
  2. The extract→detect chain: a NEW report's prose role claim, once extracted,
     surfaces as a contradiction against the earlier report (the Handala 1→2 case).

Run: .venv/bin/python -m investigations.tests.test_ingest_corrections
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.cli import invctl
from investigations import claims


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def part1_ingest_returns_id():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        dbp = root / "t.db"
        db.init_db(dbp)
        # Redirect the archive/asset dirs so ingest doesn't touch the real repo.
        invctl.REPORTS_DIR = root / "reports"
        invctl.ASSETS_DIR = root / "assets"
        invctl.REPORTS_DIR.mkdir(); invctl.ASSETS_DIR.mkdir()
        md = root / "alpha.md"
        md.write_text("@actor_x runs the @channel_y telegram channel.", encoding="utf-8")
        with db.connect(dbp) as conn:
            rid = invctl._ingest_one(conn, md, "case-x")
            assert isinstance(rid, int) and rid > 0, f"expected report id, got {rid!r}"
            print(f"  ok  _ingest_one returned report_id={rid}")
            dup = invctl._ingest_one(conn, md, "case-x")
            _check("duplicate ingest returns None", dup, None)


def part2_extract_creates_contradiction():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            r1 = db.insert_report(conn, "r1.md", "h1", "markdown", "Report 1", "case-x", "actor x is a source")
            r2 = db.insert_report(conn, "r2.md", "h2", "markdown", "Report 2", "case-x",
                                  "Correction: actor x actually operates the network.")
            x = db.upsert_entity(conn, "@actor_x", "username", r1)
            db.add_mention(conn, x, r1, "@actor_x", "ctx1")
            db.add_mention(conn, x, r2, "@actor_x", "ctx2")
            # Report 1's derived role: source. backfill turns it into a claim.
            conn.execute("UPDATE entities SET notes='role:source — per report 1', "
                         "first_seen_report_id=? WHERE id=?", (r1, x))
            conn.commit()
            claims.backfill(conn)
            _check("no contradiction before report 2 is extracted",
                   len(claims.detect_contradictions(conn)), 0)

            # Stub the LLM: report 2 asserts a CONTRADICTING role (operator).
            orig = claims.llm.ask_json
            claims.llm.ask_json = lambda *a, **k: {"claims": [
                {"name": "@actor_x", "claim_type": "role", "predicate": "role",
                 "value": "operator", "evidence": "report 2 says operates the network"}]}
            try:
                n = claims.extract_claims_for_report(conn, r2)
            finally:
                claims.llm.ask_json = orig
            assert n >= 1, f"expected >=1 extracted claim, got {n}"
            print(f"  ok  extract_claims_for_report inserted {n} prose claim(s)")

            cons = claims.detect_contradictions(conn)
            _check("report 2 now contradicts report 1", len(cons), 1)
            values = {c["value"] for c in cons[0]["claims"]}
            assert {"source", "operator"} <= values, values
            _check("contradiction is on the role predicate", cons[0]["predicate"], "role")


def main():
    part1_ingest_returns_id()
    part2_extract_creates_contradiction()
    print("\nPASS: test_ingest_corrections")


if __name__ == "__main__":
    main()
