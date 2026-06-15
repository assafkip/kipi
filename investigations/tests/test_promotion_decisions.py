"""Promotion decisions (issue gtl-2-promotion-decisions, PRD graph-trust-layer).

Asserts: promoting a finding records decision='accepted' + a manual claim
(author=analyst) on the promoted node; reject_result records decision='rejected'
+ a rejection claim on the source actor; both idempotent; a decision-write
failure never unwinds the promotion; the reject route is registered.
"""
import json
import tempfile
from pathlib import Path
from unittest import mock

from investigations.enrich import promote as promote_mod
from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "promdec.db"
    db.init_db(path)
    return path


def _mk_finding(conn, slug="pd-case", title="evil.example.com", url="http://evil.example.com"):
    conn.execute("INSERT INTO investigations (slug, case_name) VALUES (?, ?)", (slug, slug))
    rep = db.insert_report(conn, source_path="<t>", source_hash=f"h-{slug}",
                           source_type="enrichment", title="t", investigation=slug, raw_text="")
    actor = db.upsert_entity(conn, "actor.example.com", "domain", rep)
    db.add_mention(conn, actor, rep, "actor.example.com", "ctx")
    run = conn.execute(
        "INSERT INTO enrichment_runs (entity_id, provider_slug, query, mode, status, investigation) "
        "VALUES (?, 'infra', 'q', 'auto', 'success', ?)", (actor, slug)).lastrowid
    res = conn.execute(
        "INSERT INTO enrichment_results (run_id, result_type, title, summary, url, confidence) "
        "VALUES (?, 'url', ?, 'a finding', ?, 'high')", (run, title, url)).lastrowid
    conn.commit()
    return actor, res


def _decision(conn, result_id):
    return conn.execute("SELECT decision FROM enrichment_results WHERE id = ?",
                        (result_id,)).fetchone()["decision"]


def _decision_claims(conn, entity_id, value):
    return conn.execute(
        "SELECT COUNT(*) AS c FROM claims WHERE entity_id = ? AND predicate = "
        "'promotion_decision' AND value = ? AND source = 'manual'",
        (entity_id, value)).fetchone()["c"]


def test_promote_records_accept_decision_and_claim():
    path = _db_path()
    with db.connect(path) as conn:
        actor, res = _mk_finding(conn)
        out = promote_mod.promote_result(conn, res, analyst="alice")
        assert out.get("ok"), out
        eid = out["entity_id"]
        assert _decision(conn, res) == "accepted"
        assert _decision_claims(conn, eid, "accepted") == 1
        # The claim is attributed to the analyst.
        author = conn.execute(
            "SELECT author FROM claims WHERE entity_id = ? AND predicate = 'promotion_decision'",
            (eid,)).fetchone()["author"]
        assert author == "alice"


def test_reject_records_decision_and_claim_on_source():
    path = _db_path()
    with db.connect(path) as conn:
        actor, res = _mk_finding(conn, slug="pd-rej")
        out = promote_mod.reject_result(conn, res, analyst="bob", reason="false positive")
        assert out.get("rejected")
        assert _decision(conn, res) == "rejected"
        assert _decision_claims(conn, actor, "rejected") == 1
        # No node was built for the rejected finding.
        assert not conn.execute(
            "SELECT 1 FROM entities WHERE canonical_name = 'evil.example.com'").fetchone()


def test_reject_is_idempotent():
    path = _db_path()
    with db.connect(path) as conn:
        actor, res = _mk_finding(conn, slug="pd-idem")
        promote_mod.reject_result(conn, res, analyst="bob")
        out2 = promote_mod.reject_result(conn, res, analyst="bob")
        assert out2.get("already") == "rejected"
        assert _decision_claims(conn, actor, "rejected") == 1, "no duplicate claim"


def test_decision_write_failure_never_unwinds_promotion():
    path = _db_path()
    with db.connect(path) as conn:
        actor, res = _mk_finding(conn, slug="pd-fail")
        # Make the decision-claim write raise; the promotion itself must still stand.
        with mock.patch.object(promote_mod, "_record_decision_claim",
                               side_effect=RuntimeError("boom")):
            out = promote_mod.promote_result(conn, res, analyst="alice")
        assert out.get("ok"), "promotion must succeed despite a decision-write failure"
        assert conn.execute(
            "SELECT 1 FROM entities WHERE canonical_name = 'evil.example.com'").fetchone(), \
            "the promoted node must persist"


def test_accept_decision_claim_idempotent_on_double_promote():
    """Codex gtl-2 finding: NULL report_id/object make the UNIQUE constraint never
    fire, so check-then-insert must guard against duplicate accept claims."""
    path = _db_path()
    with db.connect(path) as conn:
        actor, res = _mk_finding(conn, slug="pd-dbl")
        out1 = promote_mod.promote_result(conn, res, analyst="alice")
        eid = out1["entity_id"]
        promote_mod.promote_result(conn, res, analyst="alice")
        assert _decision_claims(conn, eid, "accepted") == 1, "double promote must not duplicate the claim"


def test_cannot_reject_already_promoted():
    """Codex gtl-2 finding: rejecting a promoted finding would orphan the graph node
    behind a 'rejected' audit state."""
    path = _db_path()
    with db.connect(path) as conn:
        actor, res = _mk_finding(conn, slug="pd-prom-rej")
        promote_mod.promote_result(conn, res, analyst="alice")
        out = promote_mod.reject_result(conn, res, analyst="bob")
        assert out.get("error"), "must refuse to reject an already-promoted finding"
        assert _decision(conn, res) == "accepted", "decision must stay accepted"


def test_cannot_promote_already_rejected():
    """Codex gtl-2 adversarial: reject-then-promote must not resurrect the finding
    into the graph or flip its decision back to accepted."""
    path = _db_path()
    with db.connect(path) as conn:
        actor, res = _mk_finding(conn, slug="pd-rej-prom")
        promote_mod.reject_result(conn, res, analyst="bob")
        out = promote_mod.promote_result(conn, res, analyst="alice")
        assert out.get("error"), "must refuse to promote a rejected finding"
        assert _decision(conn, res) == "rejected", "decision must stay rejected"
        assert conn.execute(
            "SELECT extracted_entity_id FROM enrichment_results WHERE id = ?",
            (res,)).fetchone()["extracted_entity_id"] is None, "no node may be built"
        assert not conn.execute(
            "SELECT 1 FROM entities WHERE canonical_name = 'evil.example.com'").fetchone()


def test_reject_route_registered():
    src = (Path(__file__).resolve().parents[1] / "webapp" / "app.py").read_text()
    assert '/api/enrich/result/{result_id}/reject' in src
    assert "promote_mod.reject_result" in src


# --- tradecraft-floors PART B: person/handle identity floor in _promotion_gate -----------

def test_person_without_crosslink_is_gated_as_lead():
    """A person attributed with NO non-fakeable crosslink (infra_source_count<1 — name /
    photo / web only) must NOT auto-promote: it caps at grade C and stays a lead. This
    enforces the photo/name-only attribution prohibition in the agent's own gate.
    RED before the floor: source_count 2 → grade B → promoted True."""
    from investigations.agent import investigator as inv
    f = {"entity": "John Q Doe", "entity_type": "person", "confidence": "medium",
         "source_count": 2, "infra_source_count": 0}
    may, reason = inv._promotion_gate(f)
    assert may is False, f"a name-only person must be gated, not promoted: {(may, reason)}"
    assert "crosslink" in reason.lower(), f"reason must cite the missing crosslink: {reason!r}"
    assert f["grade"] == "C", f"a name-only person must cap at grade C, got {f.get('grade')!r}"


def test_handle_without_crosslink_is_gated():
    """Same floor covers handles/usernames (the most common name-only attribution)."""
    from investigations.agent import investigator as inv
    f = {"entity": "@scam_promoter", "entity_type": "handle", "confidence": "high",
         "source_count": 3, "infra_source_count": 0}
    may, reason = inv._promotion_gate(f)
    assert may is False and "crosslink" in reason.lower(), (may, reason)


def test_person_with_infra_crosslink_promotes():
    """Bounded to the no-crosslink case: a person WITH a non-fakeable crosslink
    (infra_source_count>=1) is not blocked by this floor."""
    from investigations.agent import investigator as inv
    f = {"entity": "Jane Q Smith", "entity_type": "person", "confidence": "high",
         "source_count": 2, "infra_source_count": 1}
    may, reason = inv._promotion_gate(f)
    assert may is True, f"a person with an infra crosslink must promote: {(may, reason)}"


def test_bare_number_phone_is_gated_as_noise():
    """Graph-noise gate: the agent types affiliate/URL/tracking IDs (164736471) as phone.
    A bare digit run with no + and no separators isn't a phone, so it's kept off the graph
    (lands as a lead). A real + phone still promotes."""
    from investigations.agent import investigator as inv
    junk = {"entity": "164736471", "entity_type": "phone", "confidence": "high",
            "source_count": 2, "infra_source_count": 2}
    may, reason = inv._promotion_gate(junk)
    assert may is False and "phone" in reason.lower(), (may, reason)
    real = {"entity": "+14805058800", "entity_type": "phone", "confidence": "high",
            "source_count": 2, "infra_source_count": 2}
    assert inv._promotion_gate(real)[0] is True, "a real + phone must still promote"


def test_registry_and_reference_domains_gated_as_noise():
    """Graph-noise gate: registry/WHOIS boilerplate (iana.org, whois.verisign-grs.com) and
    threat-reporting outlets (krebsonsecurity.com) are not the target's infra — kept off the
    graph even at grade A. A real target domain with an infra confirmation still promotes."""
    from investigations.agent import investigator as inv
    for v in ("iana.org", "whois.verisign-grs.com", "krebsonsecurity.com/2025/06/scam"):
        f = {"entity": v, "entity_type": "domain", "confidence": "high",
             "source_count": 2, "infra_source_count": 2}
        may, reason = inv._promotion_gate(f)
        assert may is False and ("boilerplate" in reason.lower() or "reporting" in reason.lower()), \
            f"{v} should be gated as noise: {(may, reason)}"
    real = {"entity": "trumpfundus.com", "entity_type": "domain", "confidence": "high",
            "source_count": 2, "infra_source_count": 2}
    assert inv._promotion_gate(real)[0] is True, "a real target domain must still promote"


def test_infra_entity_unaffected_by_person_floor():
    """The person floor must not perturb infra-entity behavior: a domain with an infra
    confirmation still promotes; a web-only domain is gated by the EXISTING infra rule
    (its reason cites infra, not the person crosslink)."""
    from investigations.agent import investigator as inv
    assert inv._promotion_gate(
        {"entity": "evil-target.com", "entity_type": "domain", "confidence": "high",
         "source_count": 2, "infra_source_count": 2})[0] is True
    may, reason = inv._promotion_gate(
        {"entity": "web-only-target.com", "entity_type": "domain", "confidence": "high",
         "source_count": 2, "infra_source_count": 0})
    assert may is False and "infra" in reason.lower(), (may, reason)
