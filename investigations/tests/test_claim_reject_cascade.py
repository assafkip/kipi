"""PRD-05: the analyst can correct the agent without restarting the case. The claims
spine already supports this; these tests GUARD the two load-bearing behaviors:
  1. Rejecting a claim cascades — its derived graph edge is retired (reprojected).
  2. The analyst is top authority — an analyst claim supersedes the report/AI claim and
     reprojects the derived role.

Run: .venv/bin/python -m investigations.tests.test_claim_reject_cascade
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import claims


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_reject_relationship_cascades_to_graph():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h1", "markdown", "R", "cx", "body")
            e1 = db.upsert_entity(conn, "trump-2026.io", "domain", rid)
            e2 = db.upsert_entity(conn, "0xWALLET", "crypto_wallet", rid)
            conn.commit()
            res = claims.assert_claim(conn, e1, claim_type="rel", predicate=f"rel:{e2}",
                                      value="collects_via", analyst="tester", object_entity_id=e2)
            cid = res["claim_id"]
            active = conn.execute(
                "SELECT status FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=? "
                "AND rel_type='collects_via'", (e1, e2)).fetchone()
            _check("asserted relationship is active on the graph",
                   active and active["status"] == "active")

            claims.reject(conn, cid)
            after = conn.execute(
                "SELECT status FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=? "
                "AND rel_type='collects_via'", (e1, e2)).fetchone()
            _check("rejecting the claim retires the graph edge (cascade)",
                   after and after["status"] == "superseded")


def test_analyst_override_supersedes_report_claim():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h1", "markdown", "R", "cx", "body")
            e = db.upsert_entity(conn, "@suspect", "handle", rid)
            # A report-derived role claim, projected to the entity's derived role.
            conn.execute(
                "INSERT INTO claims (entity_id, report_id, claim_type, predicate, value, "
                "confidence, evidence, status, source) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (e, rid, "role", "role", "operator", "med", "from report", "active", "report"))
            conn.commit()
            claims._project_active(conn, e, "role")
            notes0 = conn.execute("SELECT notes FROM entities WHERE id=?", (e,)).fetchone()["notes"]
            _check("report claim projected role:operator", (notes0 or "").startswith("role:operator"))

            res = claims.assert_claim(conn, e, claim_type="role", predicate="role",
                                      value="channel", analyst="tester", rationale="analyst says so")
            notes1 = conn.execute("SELECT notes FROM entities WHERE id=?", (e,)).fetchone()["notes"]
            report_claim = conn.execute(
                "SELECT status FROM claims WHERE entity_id=? AND source='report' AND predicate='role'",
                (e,)).fetchone()
            _check("analyst override reprojects role:channel", (notes1 or "").startswith("role:channel"))
            _check("the report claim is superseded (kept for audit, not deleted)",
                   report_claim and report_claim["status"] == "superseded")


def main():
    test_reject_relationship_cascades_to_graph()
    test_analyst_override_supersedes_report_claim()
    print("\nPASS: test_claim_reject_cascade")


if __name__ == "__main__":
    main()
