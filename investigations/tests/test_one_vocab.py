"""Reproducer + guard for issue unify-rel-vocab-gate.

The gap: analyze.py and fingerprints.py wrote rel_type straight into the rendered
typed_relationships table with their OWN vocabularies, bypassing normalize_rel. This
asserts the unified invariant — every edge-write path goes through normalize_rel, the
known code-defined labels are first-class vocab members, and allow_novel keeps per-case
domain freedom WITHOUT letting junk through.

Run: .venv/bin/python -m pytest investigations/tests/test_one_vocab.py -q
"""
import tempfile
from pathlib import Path

from investigations.enrich import rel_vocab as rv
from investigations.storage import db
from investigations import reextract, fingerprints, analyze, claims


# Labels the system's own deterministic code / default prompt produces. Each MUST be a
# first-class vocab member after this change (NOT generalized to linked_to).
FINGERPRINT_LABELS = [
    "shares_tracking_tag", "shares_walletconnect", "shares_service_account",
    "shares_registrant", "shares_nameserver", "shares_registrar",
]
HACKTIVIST_LABELS = ["posts_in", "ally_with", "predecessor_of", "defaced", "co_admin"]


def test_known_code_labels_are_vocab_members():
    """Fingerprint + hacktivist labels land as themselves, not the linked_to catch-all."""
    for label in FINGERPRINT_LABELS + HACKTIVIST_LABELS:
        out = rv.normalize_rel(label)
        assert out == label, f"{label!r} -> {out!r}, expected first-class vocab member"
    # hosted_by is a known no-schema label that maps onto the existing hosted_on member.
    assert rv.normalize_rel("hosted_by") == "hosted_on"


def test_allow_novel_passes_clean_token_but_still_filters_junk():
    """allow_novel=True keeps a genuine domain-fit token, but synonyms + drop-flags
    still fire — junk cannot ride in on the open path."""
    assert rv.normalize_rel("funded_by", allow_novel=True) == "funded_by"
    assert rv.normalize_rel("deployed", allow_novel=True) == "deployed"
    # synonym still collapses
    assert rv.normalize_rel("enriched", allow_novel=True) == "linked_to"
    # co-occurrence flag still dropped
    assert rv.normalize_rel("flagged_malicious_alongside", allow_novel=True) is None
    assert rv.normalize_rel("x_alongside", allow_novel=True) is None


def test_overlong_novel_label_generalizes_not_truncated():
    """An over-length novel token must NOT be silently truncated-and-accepted (which would
    collapse distinct labels). It generalizes to linked_to. (codex-review finding)"""
    long_label = "a_very_long_domain_specific_relationship_label_that_exceeds_forty_chars"
    assert len(long_label) > 40
    assert rv.normalize_rel(long_label, allow_novel=True) == "linked_to"


def test_non_string_rel_type_is_skipped_not_crash():
    """A malformed non-string rel_type returns None (row skipped), never raising —
    so one bad row can't crash the whole analyze apply pass. (codex-review finding)"""
    for bad in (None, 123, {"x": 1}, ["a"]):
        assert rv.normalize_rel(bad) is None
        assert rv.normalize_rel(bad, allow_novel=True) is None


def test_closed_path_default_unchanged():
    """Default (allow_novel=False) still generalizes an unknown token to linked_to —
    a novel domain label only survives on the allow_novel path, never the closed one."""
    assert rv.normalize_rel("totally_made_up_edge") == "linked_to"
    assert rv.normalize_rel("funded_by") == "linked_to"  # novel token NOT a vocab member


def test_fingerprints_correlate_writes_vocab_labels_and_keeps_hubs():
    """The correlate write path goes through normalize_rel; every landed label is a
    vocab member and the cross-domain hubs are unchanged."""
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            txt = ("alpha-shop.com analytics tag G-HUB12345 confirmed. "
                   "beta-shop.com also carries analytics tag G-HUB12345.")
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", txt)
            reextract.reextract_report(conn, rid, txt)
            res = fingerprints.correlate(conn, "case-a")
            assert res["edges_created"] >= 2, res
            labels = {r["rel_type"] for r in conn.execute(
                "SELECT DISTINCT rel_type FROM typed_relationships").fetchall()}
            assert labels, "no edges written"
            for lab in labels:
                assert rv.normalize_rel(lab) == lab, f"{lab!r} is not a vocab member"
            sh = fingerprints.shared(conn, "case-a")
            hub = next((s for s in sh if s["fingerprint"] == "g-hub12345"), None)
            assert hub, f"cross-report tag hub missing: {sh}"
            names = {p["name"] for p in hub["partners"]}
            assert {"alpha-shop.com", "beta-shop.com"} <= names, names


def test_analyze_apply_routes_through_gate():
    """apply_to_db sends every rel_type through normalize_rel: junk synonym generalizes,
    co-occurrence flag drops, clean novel token survives only when allow_free_rel_types."""
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", "x")
            a = db.upsert_entity(conn, "alpha.com", "domain", rid)
            b = db.upsert_entity(conn, "beta.com", "domain", rid)
            llm_output = {"typed_relationships": [
                {"src_id": a, "dst_id": b, "rel_type": "enriched", "evidence": "x"},
                {"src_id": a, "dst_id": b, "rel_type": "x_alongside", "evidence": "x"},
                {"src_id": a, "dst_id": b, "rel_type": "funded_by", "evidence": "x"},
            ], "clusters": []}
            analyze.apply_to_db(conn, llm_output, allow_free_rel_types=True)
            landed = {r["rel_type"] for r in conn.execute(
                "SELECT rel_type FROM typed_relationships "
                "WHERE src_entity_id=? AND dst_entity_id=?", (a, b)).fetchall()}
            assert "funded_by" in landed, f"clean novel token lost: {landed}"
            assert "linked_to" in landed, f"junk synonym should generalize: {landed}"
            assert "enriched" not in landed and "x_alongside" not in landed, landed


def test_claims_spine_rel_projects_through_gate():
    """The analyst-authored claims spine routes its edge through normalize_rel too: a
    synonym label the analyst types projects as the canonical vocab term (no back door)."""
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", "x")
            src = db.upsert_entity(conn, "alpha.com", "domain", rid)
            dst = db.upsert_entity(conn, "ns.example", "nameserver", rid)
            # analyst asserts the edge with a SYNONYM label -> must project as the vocab term
            claims.assert_claim(conn, src, claim_type="relationship",
                                predicate=f"rel:{dst}", value="registered_same_day",
                                analyst="ally", rationale="co-registration",
                                object_entity_id=dst)
            labels = {r["rel_type"] for r in conn.execute(
                "SELECT rel_type FROM typed_relationships WHERE src_entity_id=? "
                "AND dst_entity_id=? AND status='active'", (src, dst)).fetchall()}
            assert labels == {"same_registrant"}, f"claims spine bypassed the gate: {labels}"


def main():
    test_known_code_labels_are_vocab_members()
    test_allow_novel_passes_clean_token_but_still_filters_junk()
    test_closed_path_default_unchanged()
    test_fingerprints_correlate_writes_vocab_labels_and_keeps_hubs()
    test_analyze_apply_routes_through_gate()
    test_claims_spine_rel_projects_through_gate()
    print("\nPASS: test_one_vocab")


if __name__ == "__main__":
    main()
