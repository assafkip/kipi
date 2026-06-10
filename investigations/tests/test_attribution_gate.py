"""Strong-attribution edges can't outrun their evidence (analyst-integrity gate).

`same_operator` (and kin) assert common control — a definitive claim. The
analyze LLM overclaims them on weak signal. gate_attribution keys on the
model's OWN confidence: low → dropped, medium → demoted to co_listed, high →
kept. Non-attribution rel_types pass through untouched.

Run: .venv/bin/python3 -m pytest investigations/tests/test_attribution_gate.py -q
"""
import tempfile
from pathlib import Path

from investigations import analyze
from investigations.storage import db


def test_gate_drops_low_demotes_medium_keeps_high():
    g = analyze.gate_attribution
    assert g("same_operator", "low") is None            # evidence-free → dropped
    assert g("same_operator", "medium") == "co_listed"  # co-listing → demoted
    assert g("same_operator", "high") == "same_operator" # multi-signal → kept
    # confidence defaults to medium when missing → demote (don't overclaim)
    assert g("same_operator", None) == "co_listed"
    # other strong-attribution synonyms are gated too
    assert g("same_actor", "low") is None
    assert g("common_operator", "medium") == "co_listed"
    # ordinary rel_types are never touched, at any confidence
    assert g("drains_to", "low") == "drains_to"
    assert g("resolves_to", "high") == "resolves_to"
    assert g("registered_via", "medium") == "registered_via"


def _db():
    p = Path(tempfile.mkdtemp()) / "attr.db"
    db.init_db(p)
    return p


def test_apply_to_db_enforces_the_gate_end_to_end():
    with db.connect(_db()) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h", source_type="report",
                               title="t", investigation=None, raw_text="")
        ids = {}
        for name in ("wA", "wB", "wC", "dom1", "dom2"):
            ids[name] = db.upsert_entity(conn, name, "crypto_wallet" if name.startswith("w") else "domain", rep)
        out = {"clusters": [], "typed_relationships": [
            # high → kept as same_operator (the defensible multi-signal case)
            {"src_id": ids["dom1"], "dst_id": ids["dom2"], "rel_type": "same_operator",
             "confidence": "high", "evidence": "shared registrar + infra + persona"},
            # medium co-listing → demoted to co_listed
            {"src_id": ids["wA"], "dst_id": ids["wB"], "rel_type": "same_operator",
             "confidence": "medium", "evidence": "co-listed deposit wallets in the same lure"},
            # low "same cohort" → dropped entirely
            {"src_id": ids["wC"], "dst_id": ids["wB"], "rel_type": "same_operator",
             "confidence": "low", "evidence": "same investigation cohort"},
            # a real money edge is untouched
            {"src_id": ids["wA"], "dst_id": ids["wC"], "rel_type": "drains_to",
             "confidence": "low", "evidence": "on-chain counterparty"},
        ]}
        analyze.apply_to_db(conn, out, allow_free_rel_types=True)
        edges = {(r["rel_type"], r["confidence"]) for r in
                 conn.execute("SELECT rel_type, confidence FROM typed_relationships")}
        rel_types = {r for r, _ in edges}
        assert "same_operator" in rel_types                 # the high domain edge survives
        assert "co_listed" in rel_types                     # the medium wallet edge demoted
        assert "drains_to" in rel_types                     # money edge untouched
        # exactly one same_operator (the high one), no low-confidence attribution edge
        n_same_op = sum(1 for r, _ in edges if r == "same_operator")
        assert n_same_op == 1, edges
        # the low same_operator was dropped, not written under any label between wC,wB
        wc_wb = conn.execute(
            "SELECT rel_type FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=?",
            (ids["wC"], ids["wB"])).fetchall()
        assert wc_wb == [], wc_wb
