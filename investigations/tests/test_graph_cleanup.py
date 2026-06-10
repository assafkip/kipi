"""Graph cleanup: bridge same-campaign clusters + declutter prose nodes.

Run: .venv/bin/python -m investigations.tests.test_graph_cleanup
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import graph_cleanup
from investigations.agent import investigator


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _ent(conn, name, etype, rid):
    e = db.upsert_entity(conn, name, etype, rid)
    db.add_mention(conn, e, rid, name, "c")
    return e


def _edge(conn, s, d, rel):
    conn.execute("INSERT OR IGNORE INTO typed_relationships "
                 "(src_entity_id, dst_entity_id, rel_type, confidence, evidence, status) "
                 "VALUES (?, ?, ?, 'medium', 'x', 'active')", (s, d, rel))


def test_normalize_bridges_clusters():
    with tempfile.TemporaryDirectory() as dtmp:
        dbp = Path(dtmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            # Two infra tiers (no shared infra), each hung off its OWN differently-worded
            # campaign label — the exact shape that left the graph in two islands.
            d1 = _ent(conn, "trump-2026.io", "domain", rid)        # PDR tier
            d2 = _ent(conn, "gettrump.co", "domain", rid)          # Contabo tier
            cA = _ent(conn, "trump-impersonation crypto-doubling campaign", "other", rid)
            cB = _ent(conn, "Trump Musk crypto-doubler cluster", "other", rid)
            _edge(conn, d1, cA, "matches_pattern")
            _edge(conn, d2, cB, "operates")
            conn.commit()

            res = graph_cleanup.normalize_campaigns(conn, "cx")
            _check("merged the duplicate campaign nodes", res["merged"] >= 1)
            _check("reported a bridged group", res["bridged_groups"] >= 1)

            # Both tiers now point at ONE campaign node → clusters bridged.
            camp = set()
            for d in (d1, d2):
                for r in conn.execute("SELECT dst_entity_id FROM typed_relationships WHERE src_entity_id=?", (d,)):
                    camp.add(r["dst_entity_id"])
            _check("both tiers now bridge to ONE shared campaign node", len(camp) == 1)
            _check("real indicators (domains) were never merged",
                   conn.execute("SELECT COUNT(*) FROM entities WHERE canonical_name IN "
                                "('trump-2026.io','gettrump.co')").fetchone()[0] == 2)


def test_does_not_merge_distinct_campaigns():
    # Two campaigns that DON'T share >=2 distinctive tokens must stay separate.
    with tempfile.TemporaryDirectory() as dtmp:
        dbp = Path(dtmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            _ent(conn, "trump giveaway scheme", "other", rid)
            _ent(conn, "biden airdrop operation", "other", rid)
            conn.commit()
            res = graph_cleanup.normalize_campaigns(conn, "cx")
            _check("distinct campaigns not merged", res["merged"] == 0)


def test_prune_content_edges():
    with tempfile.TemporaryDirectory() as dtmp:
        dbp = Path(dtmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            d1 = _ent(conn, "trump-2026.io", "domain", rid)
            prose = _ent(conn, "doubled returns promise", "other", rid)
            org = _ent(conn, "PDR Ltd", "org", rid)
            _edge(conn, d1, prose, "deploys")           # page-content → should prune
            _edge(conn, d1, org, "registered_by")       # real infra → must survive
            conn.commit()
            res = graph_cleanup.prune_content_edges(conn, "cx")
            _check("pruned the deploys->prose edge", res["pruned_edges"] >= 1)
            _check("prose node has no graph edges left",
                   conn.execute("SELECT COUNT(*) FROM typed_relationships WHERE dst_entity_id=?", (prose,)).fetchone()[0] == 0)
            _check("real infra edge (registered_by) survived",
                   conn.execute("SELECT COUNT(*) FROM typed_relationships WHERE dst_entity_id=?", (org,)).fetchone()[0] == 1)


def test_persona_connects_clusters():
    _check("case persona has the same_campaign rule", "same_campaign" in investigator.CASE_PERSONA)
    _check("per-target persona has the same_campaign rule", "same_campaign" in investigator.PERSONA)
    _check("case persona names the JS-style 'do not leave disconnected' intent",
           "disconnected" in investigator.CASE_PERSONA)


def main():
    test_normalize_bridges_clusters()
    test_does_not_merge_distinct_campaigns()
    test_prune_content_edges()
    test_persona_connects_clusters()
    print("\nPASS: test_graph_cleanup")


if __name__ == "__main__":
    main()
