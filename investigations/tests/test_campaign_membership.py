"""Campaign membership (issue gtl-4-campaign-membership, PRD graph-trust-layer).

Asserts: a domain whose finding text EXPLICITLY asserts membership and names a
case campaign-org entity gets a member_of edge to that org; a domain with no
marker gets no edge; a marker but no named org gets no edge; the edge is medium
confidence; idempotent; wired into cleanup().
"""
import tempfile
from pathlib import Path

from investigations import graph_cleanup
from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "campaign.db"
    db.init_db(path)
    return path


def _mk_case(conn, slug="cm-case"):
    conn.execute("INSERT INTO investigations (slug, case_name) VALUES (?, ?)", (slug, slug))
    return db.insert_report(conn, source_path="<t>", source_hash=f"h-{slug}",
                            source_type="text", title="t", investigation=slug, raw_text="")


def _finding(conn, entity_id, summary, run_inv):
    run = conn.execute(
        "INSERT INTO enrichment_runs (entity_id, provider_slug, query, mode, status, investigation) "
        "VALUES (NULL, 'exa', 'q', 'auto', 'success', ?)", (run_inv,)).lastrowid
    conn.execute(
        "INSERT INTO enrichment_results (run_id, result_type, title, summary, confidence, "
        "extracted_entity_id) VALUES (?, 'finding', 't', ?, 'high', ?)",
        (run, summary, entity_id))


def _member_edge(conn, src, dst):
    return conn.execute(
        "SELECT confidence FROM typed_relationships WHERE src_entity_id = ? "
        "AND dst_entity_id = ? AND rel_type = 'member_of'", (src, dst)).fetchone()


def test_writes_member_of_when_marker_and_org_named():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn)
        dom = db.upsert_entity(conn, "trumpcasino.us", "domain", rep)
        org = db.upsert_entity(conn, "Gambler Panel", "indicator", rep)
        for eid in (dom, org):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _finding(conn, dom, "Earliest confirmed member of the Gambler Panel network.", "cm-case")
        conn.commit()
        out = graph_cleanup.link_campaign_members(conn, "cm-case")
        assert out["member_edges"] == 1
        edge = _member_edge(conn, dom, org)
        assert edge is not None, "confirmed member must gain a member_of edge"
        assert edge["confidence"] == "medium"


def test_no_marker_no_edge():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cm-nomark")
        dom = db.upsert_entity(conn, "neutral.example.com", "domain", rep)
        org = db.upsert_entity(conn, "Gambler Panel", "indicator", rep)
        for eid in (dom, org):
            db.add_mention(conn, eid, rep, "x", "ctx")
        # Names the org but asserts NO membership relation.
        _finding(conn, dom, "Resolves to the same IP as Gambler Panel infrastructure.", "cm-nomark")
        conn.commit()
        out = graph_cleanup.link_campaign_members(conn, "cm-nomark")
        assert out["member_edges"] == 0, "a passing mention must not fabricate membership"
        assert _member_edge(conn, dom, org) is None


def test_marker_but_no_named_org_no_edge():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cm-noorg")
        dom = db.upsert_entity(conn, "lonely.example.com", "domain", rep)
        org = db.upsert_entity(conn, "Gambler Panel", "indicator", rep)
        for eid in (dom, org):
            db.add_mention(conn, eid, rep, "x", "ctx")
        # Membership marker but does NOT name a known campaign org.
        _finding(conn, dom, "Confirmed member of some unnamed ring.", "cm-noorg")
        conn.commit()
        out = graph_cleanup.link_campaign_members(conn, "cm-noorg")
        assert out["member_edges"] == 0


def test_no_org_entity_in_case():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cm-empty")
        dom = db.upsert_entity(conn, "x.example.com", "domain", rep)
        db.add_mention(conn, dom, rep, "x", "ctx")
        _finding(conn, dom, "Member of the Gambler Panel network.", "cm-empty")
        conn.commit()
        out = graph_cleanup.link_campaign_members(conn, "cm-empty")
        assert out["member_edges"] == 0
        assert "no campaign-org" in out.get("note", "")


def test_idempotent():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cm-idem")
        dom = db.upsert_entity(conn, "trumpbet.cc", "domain", rep)
        org = db.upsert_entity(conn, "Gambler Panel", "indicator", rep)
        for eid in (dom, org):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _finding(conn, dom, "Part of the Gambler Panel operation.", "cm-idem")
        conn.commit()
        graph_cleanup.link_campaign_members(conn, "cm-idem")
        graph_cleanup.link_campaign_members(conn, "cm-idem")
        n = conn.execute(
            "SELECT COUNT(*) AS c FROM typed_relationships WHERE src_entity_id = ? "
            "AND dst_entity_id = ? AND rel_type = 'member_of'", (dom, org)).fetchone()["c"]
        assert n == 1, "re-run must not duplicate the member_of edge"


def test_marker_and_org_must_be_in_same_finding():
    """Codex gtl-4 finding-2: a marker in one finding + org name in ANOTHER must NOT
    stitch into a member_of edge."""
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cm-split")
        dom = db.upsert_entity(conn, "split.example.com", "domain", rep)
        org = db.upsert_entity(conn, "Gambler Panel", "indicator", rep)
        for eid in (dom, org):
            db.add_mention(conn, eid, rep, "x", "ctx")
        # Finding A: marker, no org name. Finding B: org name, no marker.
        _finding(conn, dom, "Confirmed member of an unnamed ring.", "cm-split")
        _finding(conn, dom, "Shares IP with Gambler Panel infrastructure.", "cm-split")
        conn.commit()
        out = graph_cleanup.link_campaign_members(conn, "cm-split")
        assert out["member_edges"] == 0, "marker + org from different findings must not link"


def test_cross_case_evidence_does_not_leak():
    """Codex gtl-4 finding-1: a sibling case's finding on the same global entity must
    not satisfy the marker for THIS case."""
    path = _db_path()
    with db.connect(path) as conn:
        rep_other = _mk_case(conn, slug="cm-other")
        rep_this = _mk_case(conn, slug="cm-this")
        dom = db.upsert_entity(conn, "shared.example.com", "domain", rep_other)
        org = db.upsert_entity(conn, "Gambler Panel", "indicator", rep_this)
        # Domain mentioned in BOTH cases; org only in THIS case.
        db.add_mention(conn, dom, rep_other, "x", "ctx")
        db.add_mention(conn, dom, rep_this, "x", "ctx")
        db.add_mention(conn, org, rep_this, "x", "ctx")
        # The membership finding belongs to the OTHER case.
        _finding(conn, dom, "Confirmed member of the Gambler Panel network.", "cm-other")
        conn.commit()
        out = graph_cleanup.link_campaign_members(conn, "cm-this")
        assert out["member_edges"] == 0, "another case's finding must not drive THIS case's edge"


def test_global_entity_notes_do_not_satisfy_membership():
    """Codex gtl-4 adversarial: a shared domain's GLOBAL notes carrying marker+org
    must NOT create a member_of edge in a case that has no membership finding."""
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cm-notes")
        dom = db.upsert_entity(conn, "noteleak.example.com", "domain", rep)
        org = db.upsert_entity(conn, "Gambler Panel", "indicator", rep)
        for eid in (dom, org):
            db.add_mention(conn, eid, rep, "x", "ctx")
        # Global notes (written in some other context) carry the marker + org name,
        # but THIS case has no enrichment finding asserting membership.
        conn.execute("UPDATE entities SET notes = ? WHERE id = ?",
                     ("Confirmed member of the Gambler Panel network.", dom))
        conn.commit()
        out = graph_cleanup.link_campaign_members(conn, "cm-notes")
        assert out["member_edges"] == 0, "global notes must not be membership evidence"
        assert _member_edge(conn, dom, org) is None


def test_wired_into_cleanup():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cm-wire")
        dom = db.upsert_entity(conn, "trumproll.com", "domain", rep)
        org = db.upsert_entity(conn, "Gambler Panel", "indicator", rep)
        for eid in (dom, org):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _finding(conn, dom, "Confirmed member of the Gambler Panel network.", "cm-wire")
        conn.commit()
        out = graph_cleanup.cleanup(conn, "cm-wire")
        assert out.get("member_edges") == 1, "link_campaign_members must run in cleanup()"
