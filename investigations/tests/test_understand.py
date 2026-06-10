"""Per-case Understand schema: discovery, approval gate, adaptive classify.

Run: .venv/bin/python -m investigations.tests.test_understand

LLM calls are stubbed so the test is deterministic (no `claude` CLI needed).
"""
import json
import re
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import understand, consolidate


CRYPTO_SCHEMA = {
    "domain": "crypto rug-pull network",
    "summary": "Token fraud: promoters shill, devs drain wallets.",
    "entity_types": [{"name": "wallet", "description": "crypto address"},
                     {"name": "token", "description": "the coin"}],
    "roles": [
        {"name": "promoter", "description": "shills the token", "actor": True},
        {"name": "developer", "description": "writes the contract", "actor": True},
        {"name": "wallet", "description": "crypto wallet address", "actor": False},
        {"name": "noise", "description": "junk", "actor": False},
    ],
    "sub_roles": [{"name": "shiller", "description": "pumps on social"},
                  {"name": "drainer", "description": "moves the funds out"}],
    "noise_notes": "Broken URLs and ticker fragments are noise.",
}


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def test_validate_guarantees():
    # A schema with no noise role and nothing marked actor must be repaired.
    raw = {"domain": "x", "roles": [{"name": "Promoter"}, {"name": "Wallet"}]}
    v = understand._validate(raw)
    names = [r["name"] for r in v["roles"]]
    assert "noise" in names, names
    assert any(r["actor"] for r in v["roles"]), v["roles"]
    assert v["sub_roles"], "sub_roles defaulted"
    print("  ok  _validate adds noise role + promotes an actor + defaults sub_roles")


def test_store_and_gate():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            understand.save_schema(conn, "case-x", CRYPTO_SCHEMA, status="proposed")
            row = understand.get_schema(conn, "case-x")
            _check("stored status proposed", row["status"], "proposed")
            _check("not approved → consolidate gets None",
                   understand.approved_schema(conn, "case-x"), None)
            understand.save_schema(conn, "case-x", CRYPTO_SCHEMA, status="approved", analyst="ally")
            row2 = understand.get_schema(conn, "case-x")
            _check("status approved", row2["status"], "approved")
            _check("approver recorded", row2["approved_by"], "ally")
            assert understand.approved_schema(conn, "case-x") is not None
            print("  ok  approved schema now visible to consolidate")


def test_discover_schema_stubbed(monkeypatch):
    monkeypatch.setattr(understand.llm, "ask_json",
                        lambda *a, **k: json.loads(json.dumps(CRYPTO_SCHEMA)))
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-x", "promoters shill MOONCOIN")
            e = db.upsert_entity(conn, "@shiller", "username", rid)
            db.add_mention(conn, e, rid, "@shiller", "ctx")
            conn.commit()
            schema = understand.discover_schema(conn, "case-x")
            _check("discovered domain", schema["domain"], "crypto rug-pull network")
            _check("stored as proposed", understand.get_schema(conn, "case-x")["status"], "proposed")
            _check("not auto-approved", understand.approved_schema(conn, "case-x"), None)


def _fake_consolidate_response(prompt, **kw):
    """Classify each entity in the batch by NAME: '@' handle → promoter (actor),
    anything else → wallet (non-actor). Order-independent."""
    items = re.findall(r'"id":\s*(\d+),\s*"name":\s*"([^"]*)"', prompt)
    clusters = []
    for eid, name in items:
        eid = int(eid)
        if name.startswith("@"):
            clusters.append({"canonical_id": eid, "canonical_name": name,
                             "role": "promoter", "sub_role": "shiller",
                             "sub_role_reason": "pumps", "merge_ids": [], "reason": "x"})
        else:
            clusters.append({"canonical_id": eid, "canonical_name": name,
                             "role": "wallet", "sub_role": "", "merge_ids": [], "reason": "x"})
    return {"clusters": clusters}


def test_adaptive_classify_and_scope(monkeypatch):
    monkeypatch.setattr(consolidate.llm, "ask_json", _fake_consolidate_response)
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            ra = db.insert_report(conn, "a.md", "ha", "markdown", "A", "case-a", "x")
            rb = db.insert_report(conn, "b.md", "hb", "markdown", "B", "case-b", "y")
            a1 = db.upsert_entity(conn, "@promoterguy", "username", ra)
            a2 = db.upsert_entity(conn, "0xdeadbeef", "crypto_wallet", ra)
            b1 = db.upsert_entity(conn, "@othercase", "username", rb)
            for eid, rid in [(a1, ra), (a2, ra), (b1, rb)]:
                db.add_mention(conn, eid, rid, "s", "c")
            conn.commit()

            consolidate.run(conn, schema=CRYPTO_SCHEMA, case="case-a")

            a1_row = conn.execute("SELECT notes, sub_role FROM entities WHERE id=?", (a1,)).fetchone()
            a2_row = conn.execute("SELECT notes, sub_role FROM entities WHERE id=?", (a2,)).fetchone()
            b1_row = conn.execute("SELECT notes, sub_role FROM entities WHERE id=?", (b1,)).fetchone()

            assert a1_row["notes"].startswith("role:promoter"), a1_row["notes"]
            _check("actor role got a sub_role", a1_row["sub_role"], "shiller")
            assert a2_row["notes"].startswith("role:wallet"), a2_row["notes"]
            _check("non-actor role has empty sub_role", a2_row["sub_role"], None)
            _check("other case UNTOUCHED (case-scoped classify)", b1_row["notes"], None)


def test_build_system_uses_schema_roles():
    sys_default = consolidate._build_system(None)
    assert "operator" in sys_default
    sys_crypto = consolidate._build_system(CRYPTO_SCHEMA)
    assert "promoter" in sys_crypto and "developer" in sys_crypto, sys_crypto[:400]
    assert "crypto rug-pull network" in sys_crypto
    print("  ok  _build_system swaps in the case's roles + domain")


# Minimal monkeypatch shim so the file runs without pytest installed.
class _MP:
    def __init__(self): self._undo = []
    def setattr(self, obj, name, val):
        self._undo.append((obj, name, getattr(obj, name)))
        setattr(obj, name, val)
    def undo(self):
        for obj, name, val in reversed(self._undo):
            setattr(obj, name, val)
        self._undo = []


def main():
    test_validate_guarantees()
    test_store_and_gate()
    mp = _MP()
    try:
        test_discover_schema_stubbed(mp)
    finally:
        mp.undo()
    mp = _MP()
    try:
        test_adaptive_classify_and_scope(mp)
    finally:
        mp.undo()
    test_build_system_uses_schema_roles()
    print("\nPASS: test_understand")


if __name__ == "__main__":
    main()
