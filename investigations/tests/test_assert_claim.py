"""Analyst-authority tests: an analyst assertion overrides the report/AI claim
and propagates into the derived role the rest of the app reads.

Run: .venv/bin/python -m investigations.tests.test_assert_claim
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import claims


def _role(conn, eid):
    notes = conn.execute("SELECT notes FROM entities WHERE id=?", (eid,)).fetchone()["notes"]
    return (notes or "").split(" — ")[0].replace("role:", "").strip()


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def main():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            r = db.insert_report(conn, "r.md", "hr", "markdown", "Report A", "case-x", "x")
            e = db.upsert_entity(conn, "@actor", "person", r)
            db.add_mention(conn, e, r, "@actor", "ctx")
            # Report-derived role: the report says this actor is a 'source'.
            conn.execute("UPDATE entities SET notes='role:source — per report A', "
                         "first_seen_report_id=? WHERE id=?", (r, e))
            conn.commit()
            claims.backfill(conn)  # turns the derived role into a provenanced claim

            _check("starting role (from report)", _role(conn, e), "source")

            # 1) Analyst contradicts the report: this actor is an operator.
            res = claims.assert_claim(conn, e, claim_type="role", predicate="role",
                                      value="operator", analyst="ally",
                                      rationale="confirmed via direct collection")
            assert res.get("ok"), res
            _check("role after analyst override", _role(conn, e), "operator")

            # 2) The override is attributed + active; the report claim is superseded
            #    (kept for audit, not deleted).
            rows = {(c["value"], c["status"], c["source"], c["author"])
                    for c in claims.entity_claims(conn, e) if c["predicate"] == "role"}
            assert ("operator", "active", "manual", "ally") in rows, rows
            assert ("source", "superseded", "backfill", None) in rows, rows
            print("  ok  analyst claim active+attributed; report claim superseded (audit kept)")

            # 3) Idempotent: re-asserting the same fact doesn't duplicate.
            claims.assert_claim(conn, e, claim_type="role", predicate="role",
                                value="operator", analyst="ally")
            active_ops = [c for c in claims.entity_claims(conn, e)
                          if c["predicate"] == "role" and c["status"] == "active"]
            _check("one active role claim after re-assert", len(active_ops), 1)

            # 4) Free attribute assertion shows up attributed in the entity's claims.
            claims.assert_claim(conn, e, claim_type="attribute", predicate="location",
                                value="Tehran", analyst="ally", rationale="analyst assessment")
            loc = [c for c in claims.entity_claims(conn, e) if c["predicate"] == "location"]
            assert loc and loc[0]["value"] == "Tehran" and loc[0]["author"] == "ally", loc
            print("  ok  attribute assertion stored + attributed")

    print("\nPASS: test_assert_claim")


if __name__ == "__main__":
    main()
