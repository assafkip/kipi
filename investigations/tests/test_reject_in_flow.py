"""PRD-05 (in-flow reject): the graph node panel exposes each connection's backing
claim so the analyst can drop a wrong edge in place. Tests the full loop via the API:
detail carries claim_id → POST reject → the edge is gone.

Run: .venv/bin/python -m investigations.tests.test_reject_in_flow
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations import claims
from investigations.webapp import app as app_module


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def test_reject_connection_in_flow(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            e1 = db.upsert_entity(conn, "trump-2026.io", "domain", rid)
            e2 = db.upsert_entity(conn, "0xWALLET", "crypto_wallet", rid)
            res = claims.assert_claim(conn, e1, claim_type="rel", predicate=f"rel:{e2}",
                                      value="collects_via", analyst="tester", object_entity_id=e2)
            conn.commit()
            cid = res["claim_id"]

        orig = db.connect
        mp.setattr(app_module.db, "connect",
                   lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
        client = TestClient(app_module.app)
        client.cookies.set("case", "__all__")   # unscoped → connection shows regardless of mentions

        d = client.get(f"/api/entity/{e1}/detail").json()
        conn_to_e2 = [c for c in d.get("connections", []) if c["other_id"] == e2]
        _check("connection to the wallet is shown", len(conn_to_e2) == 1)
        _check("connection carries its backing claim_id", conn_to_e2[0]["claim_id"] == cid)

        r = client.post(f"/api/claims/{cid}/reject")
        _check("reject endpoint ok", r.status_code == 200 and r.json().get("ok"))

        d2 = client.get(f"/api/entity/{e1}/detail").json()
        still = [c for c in d2.get("connections", []) if c["other_id"] == e2]
        _check("the edge is gone from the panel after reject", len(still) == 0)


def main():
    mp = _MP()
    try:
        test_reject_connection_in_flow(mp)
    finally:
        mp.undo()
    print("\nPASS: test_reject_in_flow")


if __name__ == "__main__":
    main()
