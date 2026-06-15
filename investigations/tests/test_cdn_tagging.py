"""CDN tagging + de-gating (issue gtl-3-cdn-tagging, PRD graph-trust-layer).

Asserts: is_cdn_ip classifies Cloudflare anycast (104.21.*/172.67.*) as CDN and a
dedicated server (38.46.220.132) as not-CDN; the retro-clean pass tags CDN IP
entities infra_class='cdn'; it DROPS a same_operator/shared_infra edge between two
domains whose only shared infra node is a CDN IP; it KEEPS such an edge when the
shared node is a dedicated server; analyst-provenance edges survive; idempotent.
"""
import tempfile
from pathlib import Path

from investigations import cdn_ranges
from investigations.maintenance import retro_clean
from investigations.storage import db


def test_is_cdn_ip_classification():
    assert cdn_ranges.is_cdn_ip("104.21.42.70")
    assert cdn_ranges.is_cdn_ip("172.67.197.209")
    assert cdn_ranges.is_cdn_ip("104.21.68.184")
    assert cdn_ranges.cdn_label("104.21.42.70") == "cloudflare"
    # Dedicated panel server — must NOT be CDN.
    assert not cdn_ranges.is_cdn_ip("38.46.220.132")
    assert not cdn_ranges.is_cdn_ip("46.4.10.22")        # Hetzner dedicated
    assert not cdn_ranges.is_cdn_ip("not-an-ip")
    assert not cdn_ranges.is_cdn_ip("")


def _db_path():
    path = Path(tempfile.mkdtemp()) / "cdn.db"
    db.init_db(path)
    return path


def _mk_case(conn, slug="cdn-case"):
    conn.execute("INSERT INTO investigations (slug, case_name) VALUES (?, ?)", (slug, slug))
    return db.insert_report(conn, source_path="<t>", source_hash=f"h-{slug}",
                            source_type="text", title="t", investigation=slug, raw_text="")


def _edge(conn, s, d, rel, conf="high", provenance="agent"):
    db.upsert_typed_relationship(conn, s, d, rel, confidence=conf, evidence="t",
                                 provenance=provenance)


def _infra_class(conn, eid):
    row = conn.execute("SELECT value FROM node_properties WHERE entity_id = ? "
                       "AND key = 'infra_class'", (eid,)).fetchone()
    return row["value"] if row else None


def _edge_exists(conn, s, d, rel):
    return conn.execute(
        "SELECT 1 FROM typed_relationships WHERE src_entity_id = ? AND dst_entity_id = ? "
        "AND rel_type = ? AND COALESCE(status,'active')='active'", (s, d, rel)).fetchone() is not None


def test_tags_cdn_ips_and_drops_cdn_only_edge():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn)
        a = db.upsert_entity(conn, "trumpfundus.com", "domain", rep)
        b = db.upsert_entity(conn, "trumpstake.us", "domain", rep)
        cdn = db.upsert_entity(conn, "104.21.42.70", "ip", rep)
        for eid in (a, b, cdn):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, a, cdn, "resolves_to")
        _edge(conn, b, cdn, "resolves_to")
        _edge(conn, a, b, "same_operator")   # rests ONLY on the shared CDN IP
        conn.commit()

        out = retro_clean.tag_and_degate_cdn(conn, "cdn-case")
        assert "104.21.42.70" in out["tagged"]
        assert _infra_class(conn, cdn) == "cdn"
        assert len(out["dropped"]) == 1
        assert not _edge_exists(conn, a, b, "same_operator"), "CDN-only edge must be dropped"
        # resolves_to edges (correct) are untouched.
        assert _edge_exists(conn, a, cdn, "resolves_to")


def test_keeps_edge_backed_by_dedicated_server():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cdn-ded")
        a = db.upsert_entity(conn, "mammothprotocol.fun", "domain", rep)
        b = db.upsert_entity(conn, "gambler-panel.com", "domain", rep)
        ded = db.upsert_entity(conn, "38.46.220.132", "ip", rep)
        for eid in (a, b, ded):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, a, ded, "resolves_to")
        _edge(conn, b, ded, "resolves_to")
        _edge(conn, a, b, "same_operator")   # rests on a DEDICATED server
        conn.commit()
        out = retro_clean.tag_and_degate_cdn(conn, "cdn-ded")
        assert out["dropped"] == []
        assert _edge_exists(conn, a, b, "same_operator"), "dedicated-server edge must survive"
        assert _infra_class(conn, ded) is None, "dedicated IP not tagged cdn"


def test_mixed_infra_keeps_edge():
    """If two domains share BOTH a CDN IP and a dedicated server, the edge stands —
    the dedicated server is real co-hosting evidence."""
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cdn-mix")
        a = db.upsert_entity(conn, "x.example.com", "domain", rep)
        b = db.upsert_entity(conn, "y.example.com", "domain", rep)
        cdn = db.upsert_entity(conn, "172.67.197.209", "ip", rep)
        ded = db.upsert_entity(conn, "38.46.220.132", "ip", rep)
        for eid in (a, b, cdn, ded):
            db.add_mention(conn, eid, rep, "x", "ctx")
        for d in (a, b):
            _edge(conn, d, cdn, "resolves_to")
            _edge(conn, d, ded, "resolves_to")
        _edge(conn, a, b, "shared_infra")
        conn.commit()
        retro_clean.tag_and_degate_cdn(conn, "cdn-mix")
        assert _edge_exists(conn, a, b, "shared_infra"), "mixed infra keeps the edge"


def test_analyst_edge_never_dropped():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cdn-analyst")
        a = db.upsert_entity(conn, "p.example.com", "domain", rep)
        b = db.upsert_entity(conn, "q.example.com", "domain", rep)
        cdn = db.upsert_entity(conn, "104.21.68.184", "ip", rep)
        for eid in (a, b, cdn):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, a, cdn, "resolves_to")
        _edge(conn, b, cdn, "resolves_to")
        _edge(conn, a, b, "same_operator", provenance="analyst")
        conn.commit()
        retro_clean.tag_and_degate_cdn(conn, "cdn-analyst")
        assert _edge_exists(conn, a, b, "same_operator"), "analyst edge is top authority"


def test_case_scoped_run_spares_other_cases():
    """Codex gtl-3 finding: a case-scoped retro-clean must not drop another case's
    CDN-only edge."""
    path = _db_path()
    with db.connect(path) as conn:
        rep_in = _mk_case(conn, slug="case-in")
        rep_out = _mk_case(conn, slug="case-out")
        # in-case CDN-only same_operator edge
        ai = db.upsert_entity(conn, "in-a.example.com", "domain", rep_in)
        bi = db.upsert_entity(conn, "in-b.example.com", "domain", rep_in)
        cdn1 = db.upsert_entity(conn, "104.21.42.70", "ip", rep_in)
        for eid in (ai, bi, cdn1):
            db.add_mention(conn, eid, rep_in, "x", "ctx")
        _edge(conn, ai, cdn1, "resolves_to"); _edge(conn, bi, cdn1, "resolves_to")
        _edge(conn, ai, bi, "same_operator")
        # out-of-case CDN-only same_operator edge
        ao = db.upsert_entity(conn, "out-a.example.com", "domain", rep_out)
        bo = db.upsert_entity(conn, "out-b.example.com", "domain", rep_out)
        cdn2 = db.upsert_entity(conn, "172.67.197.209", "ip", rep_out)
        for eid in (ao, bo, cdn2):
            db.add_mention(conn, eid, rep_out, "x", "ctx")
        _edge(conn, ao, cdn2, "resolves_to"); _edge(conn, bo, cdn2, "resolves_to")
        _edge(conn, ao, bo, "same_operator")
        conn.commit()

        retro_clean.tag_and_degate_cdn(conn, "case-in")
        assert not _edge_exists(conn, ai, bi, "same_operator"), "in-case edge dropped"
        assert _edge_exists(conn, ao, bo, "same_operator"), "OTHER case's edge must survive"


def test_run_drops_cdn_edge_before_attribution_demotes_it():
    """Codex gtl-3 adversarial: a medium-confidence CDN-only same_operator edge must
    be DROPPED by the CDN pass, not demoted to co_listed by the attribution gate
    that runs in the same chain. So run() must order CDN before attribution."""
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cdn-order")
        a = db.upsert_entity(conn, "o1.example.com", "domain", rep)
        b = db.upsert_entity(conn, "o2.example.com", "domain", rep)
        cdn = db.upsert_entity(conn, "104.21.42.70", "ip", rep)
        for eid in (a, b, cdn):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, a, cdn, "resolves_to"); _edge(conn, b, cdn, "resolves_to")
        # MEDIUM confidence: the attribution gate would demote this to co_listed.
        _edge(conn, a, b, "same_operator", conf="medium")
        conn.commit()
        retro_clean.run(conn, "cdn-order")
        # The edge must be GONE, not lingering as co_listed.
        assert not _edge_exists(conn, a, b, "same_operator")
        assert not _edge_exists(conn, a, b, "co_listed"), \
            "CDN-only edge must be dropped, never demoted to co_listed"


def test_idempotent_and_wired_into_run():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="cdn-idem")
        a = db.upsert_entity(conn, "u.example.com", "domain", rep)
        b = db.upsert_entity(conn, "v.example.com", "domain", rep)
        cdn = db.upsert_entity(conn, "104.21.42.70", "ip", rep)
        for eid in (a, b, cdn):
            db.add_mention(conn, eid, rep, "x", "ctx")
        _edge(conn, a, cdn, "resolves_to")
        _edge(conn, b, cdn, "resolves_to")
        _edge(conn, a, b, "same_operator")
        conn.commit()
        out1 = retro_clean.run(conn, "cdn-idem")
        assert "cdn" in out1, "cdn pass must be wired into retro_clean.run"
        assert len(out1["cdn"]["dropped"]) == 1
        out2 = retro_clean.tag_and_degate_cdn(conn, "cdn-idem")
        assert out2["dropped"] == [], "second run drops nothing (idempotent)"
        assert "104.21.42.70" in out2["tagged"], "tagging stays idempotent-stable"
