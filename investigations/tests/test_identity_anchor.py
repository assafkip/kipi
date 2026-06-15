"""Ambient identity anchor (PRD prd-identity-anchor-2026-06-13).

build_reference derives the case's CONFIRMED-actor identity (analyst-authored OR flagged
person/handle/username entities + aliases + both-endpoints-case-scoped emails) and is the
no-op empty Reference until an actor is confirmed. classify annotates a match; reference_prompt
grounds the agent. The promotion gate gains a match annotation that NEVER changes the
promote/deny decision and scrubs any agent-forged annotation.

Run: .venv/bin/python3 -m pytest investigations/tests/test_identity_anchor.py -q
"""
import tempfile
from pathlib import Path

from investigations import identity_anchor
from investigations.agent import investigator
from investigations.storage import db


def _conn():
    p = Path(tempfile.mkdtemp()) / "ia.db"
    db.init_db(p)
    return db.connect(p)


def _report(conn, case="case-a", n=[0]):
    n[0] += 1
    return db.insert_report(conn, source_path=f"<t{n[0]}>", source_hash=f"h{n[0]}",
                            source_type="report", title=f"t{n[0]}",
                            investigation=case, raw_text="x")


def _entity(conn, name, etype, rep, *, provenance=None, flagged=False):
    eid = db.upsert_entity(conn, name, etype, rep, provenance=provenance)
    db.add_mention(conn, eid, rep, name, "ctx")
    if flagged:
        conn.execute("UPDATE entities SET flagged = 1 WHERE id = ?", (eid,))
    return eid


def _edge(conn, src_id, dst_id, rel="uses_email"):
    conn.execute("INSERT INTO typed_relationships (src_entity_id, dst_entity_id, rel_type) "
                 "VALUES (?, ?, ?)", (src_id, dst_id, rel))


# --- build_reference -------------------------------------------------------

def test_build_reference_picks_up_confirmed_actors_aliases_emails():
    with _conn() as conn:
        rep = _report(conn, "case-a")
        # confirmed: analyst-authored handle + flagged person
        h = _entity(conn, "@Alice", "handle", rep, provenance="analyst")
        p = _entity(conn, "Alice Cooper", "person", rep, flagged=True)
        db.add_alias(conn, h, "@alice_alt")
        db.add_alias(conn, p, "A. Cooper")
        # an email crosslinked to the confirmed person, case-scoped
        em = _entity(conn, "alice@proton.me", "email", rep)
        _edge(conn, p, em)
        # NOT confirmed: an agent-discovered handle in the same case
        _entity(conn, "@bob", "handle", rep, provenance="agent")
        conn.commit()

        ref = identity_anchor.build_reference(conn, "case-a")
        assert not ref.is_empty
        assert "alice" in ref.handles                 # canonical_name, @-stripped + lowered
        assert "alice_alt" in ref.handles             # alias bucketed to handles
        assert "alice cooper" in ref.names
        assert "a. cooper" in ref.names               # alias bucketed to names
        assert "alice@proton.me" in ref.emails
        assert "bob" not in ref.handles               # unconfirmed (provenance=agent) excluded


def test_build_reference_empty_when_no_confirmed_actor():
    with _conn() as conn:
        rep = _report(conn, "case-a")
        _entity(conn, "@bob", "handle", rep, provenance="agent")   # not analyst, not flagged
        _entity(conn, "evil.com", "domain", rep, provenance="analyst")  # confirmed but infra
        conn.commit()
        ref = identity_anchor.build_reference(conn, "case-a")
        assert ref.is_empty
        assert identity_anchor.reference_prompt(ref) == ""


def test_build_reference_is_case_scoped():
    with _conn() as conn:
        rep_a = _report(conn, "case-a")
        rep_b = _report(conn, "case-b")
        _entity(conn, "@alice", "handle", rep_a, provenance="analyst")
        _entity(conn, "@carol", "handle", rep_b, provenance="analyst")
        conn.commit()
        ref = identity_anchor.build_reference(conn, "case-a")
        assert "alice" in ref.handles
        assert "carol" not in ref.handles            # other case excluded by the join


def test_cross_case_linked_email_does_not_leak():
    with _conn() as conn:
        rep_a = _report(conn, "case-a")
        rep_b = _report(conn, "case-b")
        subj = _entity(conn, "@alice", "handle", rep_a, provenance="analyst")
        # email linked to the subject by an edge, but mentioned ONLY in case-b
        em = _entity(conn, "leak@evil.com", "email", rep_b)
        _edge(conn, subj, em)
        conn.commit()
        ref = identity_anchor.build_reference(conn, "case-a")
        assert "leak@evil.com" not in ref.emails     # email node not case-a-scoped


def test_build_reference_no_throw_when_typed_relationships_missing():
    with _conn() as conn:
        rep = _report(conn, "case-a")
        _entity(conn, "@alice", "handle", rep, provenance="analyst")
        conn.execute("DROP TABLE typed_relationships")
        conn.commit()
        ref = identity_anchor.build_reference(conn, "case-a")   # must not raise
        assert "alice" in ref.handles
        assert ref.emails == frozenset()


def test_falsy_case_is_empty():
    with _conn() as conn:
        assert identity_anchor.build_reference(conn, None).is_empty
        assert identity_anchor.build_reference(conn, "").is_empty


# --- classify --------------------------------------------------------------

def _ref():
    return identity_anchor.Reference(
        handles=frozenset({"alice"}), names=frozenset({"alice cooper"}),
        emails=frozenset({"alice@proton.me"}))


def test_classify_match_on_handle_name_email():
    ref = _ref()
    assert identity_anchor.classify(ref, "handle", "@Alice") == "match"
    assert identity_anchor.classify(ref, "username", "alice") == "match"
    assert identity_anchor.classify(ref, "person", "Alice Cooper") == "match"
    assert identity_anchor.classify(ref, "email", "ALICE@proton.me") == "match"


def test_classify_unknown_paths():
    ref = _ref()
    assert identity_anchor.classify(ref, "handle", "@bob") == "unknown"
    assert identity_anchor.classify(ref, "domain", "alice") == "unknown"   # non-person type
    assert identity_anchor.classify(ref, "handle", "") == "unknown"
    empty = identity_anchor.Reference(frozenset(), frozenset(), frozenset())
    assert identity_anchor.classify(empty, "handle", "@alice") == "unknown"
    assert identity_anchor.classify(None, "handle", "@alice") == "unknown"


# --- reference_prompt ------------------------------------------------------

def test_reference_prompt_names_actors_and_is_bounded():
    ref = _ref()
    block = identity_anchor.reference_prompt(ref)
    assert "@alice" in block
    assert "alice cooper" in block
    assert "alice@proton.me" in block
    assert "CONFIRMED ACTORS" in block


def test_reference_prompt_caps_each_list():
    big = identity_anchor.Reference(
        handles=frozenset({f"h{i:03d}" for i in range(50)}),
        names=frozenset(), emails=frozenset())
    block = identity_anchor.reference_prompt(big)
    # only the first _PROMPT_CAP sorted handles appear
    assert "@h000" in block
    assert "@h019" in block
    assert "@h020" not in block


# --- _promotion_gate integration ------------------------------------------

def _finding(entity, etype="handle"):
    return {"entity": entity, "entity_type": etype, "claim": "c",
            "confidence": "medium", "provenance": "tool: x"}


def test_gate_annotates_match_without_changing_decision():
    ref = _ref()
    base = _finding("@alice")
    # decision WITHOUT a reference
    d_noref = investigator._promotion_gate(dict(base))
    # decision WITH a reference (annotation added)
    f = dict(base)
    d_ref = investigator._promotion_gate(f, ref)
    assert d_ref == d_noref                          # promote/deny decision unchanged
    assert f.get("identity_anchor") == "match"       # but the match is annotated


def test_gate_scrubs_forged_annotation_no_match():
    ref = _ref()
    f = _finding("@bob")
    f["identity_anchor"] = "match"                   # agent-forged
    investigator._promotion_gate(f, ref)
    assert "identity_anchor" not in f                # scrubbed (no real match)


def test_gate_scrubs_forged_annotation_even_without_reference():
    f = _finding("@alice")
    f["identity_anchor"] = "match"                   # forged, legacy no-reference path
    investigator._promotion_gate(f)
    assert "identity_anchor" not in f


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} passed")
    sys.exit(0)
