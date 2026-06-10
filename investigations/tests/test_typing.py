"""Typing pass (re-bucket + gap extraction) + schema-driven analyze scoring.

Run: .venv/bin/python -m investigations.tests.test_typing

LLM calls are stubbed so the test is deterministic.
"""
import json
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import typing, analyze, understand


SCHEMA = {
    "domain": "crypto rug-pull network",
    "summary": "token fraud",
    "entity_types": [{"name": "wallet_address", "description": "addr"},
                     {"name": "scam_domain", "description": "site"},
                     {"name": "person", "description": "human"}],
    "roles": [
        {"name": "promoter", "description": "shills", "actor": True, "weight": 5},
        {"name": "wallet", "description": "wallet", "actor": False, "weight": 4},
        {"name": "noise", "description": "junk", "actor": False, "weight": 0},
    ],
    "sub_roles": [{"name": "shiller", "description": "x"}],
    "noise_notes": "junk",
}


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def test_retype(mp):
    mp.setattr(typing.llm, "ask_json", lambda prompt, **k: {"types": [
        {"id": i, "case_type": "wallet_address" if "0x" in prompt[prompt.find(f'"id": {i}'):][:80] else "person"}
        for i in _ids_in(prompt)]})
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "a.md", "h", "markdown", "A", "case-a", "x")
            e1 = db.upsert_entity(conn, "0xdeadbeef", "crypto_wallet", r)
            e2 = db.upsert_entity(conn, "@promoterguy", "username", r)
            for e in (e1, e2):
                db.add_mention(conn, e, r, "s", "c")
                conn.execute("UPDATE entities SET notes='role:promoter' WHERE id=?", (e,))
            conn.commit()
            out = typing.retype_entities(conn, "case-a", SCHEMA)
            _check("typed both", out["typed"], 2)
            ct1 = conn.execute("SELECT case_type FROM entities WHERE id=?", (e1,)).fetchone()[0]
            assert ct1 in ("wallet_address", "person"), ct1
            print(f"  ok  case_type assigned ({ct1})")


def _ids_in(prompt):
    import re
    return [int(x) for x in re.findall(r'"id":\s*(\d+)', prompt)]


def test_extract_missing(mp):
    mp.setattr(typing.llm, "ask_json", lambda prompt, **k: {"entities": [
        {"name": "0xNEWWALLET", "surface_type": "crypto_wallet",
         "case_type": "wallet_address", "role": "wallet", "sub_role": "",
         "context": "funds moved to 0xNEWWALLET"},
        {"name": "@promoterguy", "surface_type": "handle", "case_type": "person",
         "role": "promoter", "sub_role": "shiller", "context": "already here"},
    ]})
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "a.md", "h", "markdown", "A", "case-a",
                                 "promoterguy moved funds to 0xNEWWALLET")
            existing = db.upsert_entity(conn, "@promoterguy", "username", r)
            db.add_mention(conn, existing, r, "@promoterguy", "c")
            conn.commit()
            out = typing.extract_missing(conn, "case-a", SCHEMA)
            _check("added the missed wallet only (existing skipped)", out["added"], 1)
            w = conn.execute("SELECT entity_type, case_type, notes FROM entities WHERE canonical_name=?",
                             ("0xNEWWALLET",)).fetchone()
            assert w is not None, "wallet not added"
            _check("recovered wallet surface type", w["entity_type"], "crypto_wallet")
            _check("recovered wallet case_type", w["case_type"], "wallet_address")
            assert w["notes"].startswith("role:wallet"), w["notes"]
            men = conn.execute("SELECT COUNT(*) FROM mentions WHERE entity_id="
                               "(SELECT id FROM entities WHERE canonical_name='0xNEWWALLET')").fetchone()[0]
            _check("recovered wallet has a mention", men, 1)


def test_merged_weights_and_scoring():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            understand.save_schema(conn, "case-a", SCHEMA, status="approved", analyst="ally")
            w = analyze._merged_role_weights(conn)
            _check("custom actor role weighted from schema", w["promoter"], 5)
            _check("generic role still present", w["operator"], 5)
            # An entity with the custom 'promoter' role must SCORE (the bug was 0).
            r = db.insert_report(conn, "a.md", "h", "markdown", "A", "case-a", "x")
            e = db.upsert_entity(conn, "@p", "username", r)
            db.add_mention(conn, e, r, "@p", "c")
            conn.execute("UPDATE entities SET notes='role:promoter' WHERE id=?", (e,))
            conn.commit()
            analyze.compute_threat_scores(conn)
            score = conn.execute("SELECT threat_score FROM entity_scores WHERE entity_id=?",
                                 (e,)).fetchone()
            assert score and score[0] > 0, "promoter entity scored 0 — weight fix failed"
            print(f"  ok  custom-role entity scored {score[0]} (was 0 before the fix)")


def test_analyze_prompt_generalizes():
    sys_default = analyze._build_system(None)
    assert "crew" in sys_default.lower() or "OSINT" in sys_default
    sys_crypto = analyze._build_system(SCHEMA)
    assert "crypto rug-pull network" in sys_crypto, sys_crypto[:200]
    # rel_type cleaning now lives in the single binding gate (normalize_rel), not a
    # local analyze helper. A schema-driven (allow_novel) run cleans a messy domain
    # label and rejects empty input — same contract, one validator.
    from investigations.enrich.rel_vocab import normalize_rel
    _check("free rel_type cleaned", normalize_rel("Drains To!", allow_novel=True), "drains_to")
    _check("junk rel_type rejected", normalize_rel("   ", allow_novel=True), None)
    print("  ok  analyze prompt + rel_type handling generalize to the schema")


def main():
    mp = _MP()
    try: test_retype(mp)
    finally: mp.undo()
    mp = _MP()
    try: test_extract_missing(mp)
    finally: mp.undo()
    test_merged_weights_and_scoring()
    test_analyze_prompt_generalizes()
    print("\nPASS: test_typing")


if __name__ == "__main__":
    main()
