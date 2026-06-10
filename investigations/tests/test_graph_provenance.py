"""Provenance is first-class on every node and edge (issue graph-provenance-fields).

Asserts: the migration adds the columns and is idempotent across two connects; a node
created via the agent path carries provenance='agent'; an enrichment-promoted node +
its edge carry provenance='enrich:<provider>'; an analyst manual node carries 'analyst'.
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.enrich import promote


def _db_path():
    path = Path(tempfile.mkdtemp()) / "prov.db"
    db.init_db(path)
    return path


def test_provenance_columns_exist_and_migration_is_idempotent():
    path = _db_path()
    with db.connect(path) as conn:
        ent_cols = {r[1] for r in conn.execute("PRAGMA table_info(entities)")}
        typed_cols = {r[1] for r in conn.execute("PRAGMA table_info(typed_relationships)")}
        assert "provenance" in ent_cols
        assert "provenance" in typed_cols
    # Second connect on the same file must not error (lazy ALTER guarded by the col check).
    with db.connect(path) as conn2:
        ent_cols2 = {r[1] for r in conn2.execute("PRAGMA table_info(entities)")}
        assert "provenance" in ent_cols2


def test_upsert_entity_stamps_provenance_and_first_stamp_wins():
    with db.connect(_db_path()) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h1",
                               source_type="manual", title="t", investigation=None, raw_text="")
        eid = db.upsert_entity(conn, "agent-node.com", "domain", rep, provenance="agent")
        row = conn.execute("SELECT provenance FROM entities WHERE id=?", (eid,)).fetchone()
        assert row["provenance"] == "agent"
        # Re-upsert with a different provenance must NOT overwrite the original.
        eid2 = db.upsert_entity(conn, "agent-node.com", "domain", rep, provenance="enrich:whois")
        assert eid2 == eid
        row = conn.execute("SELECT provenance FROM entities WHERE id=?", (eid,)).fetchone()
        assert row["provenance"] == "agent"


def test_promoted_node_and_edge_carry_enrich_provenance():
    with db.connect(_db_path()) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h2",
                               source_type="report", title="t", investigation="case-x", raw_text="")
        conn.execute("INSERT INTO investigations (slug, status) VALUES ('case-x','active')")
        actor = db.upsert_entity(conn, "Actor One", "person", rep, provenance="ingest:report")
        run = conn.execute(
            "INSERT INTO enrichment_runs (entity_id, provider_slug, query, status, investigation) "
            "VALUES (?, 'crtsh', 'q', 'success', 'case-x')", (actor,)).lastrowid
        res = conn.execute(
            "INSERT INTO enrichment_results (run_id, result_type, title, summary, url, confidence) "
            "VALUES (?, 'url', 'sub', 'cert', 'https://sub.evil.com', 'medium')", (run,)).lastrowid
        conn.commit()
        out = promote.promote_result(conn, res)
        assert out.get("ok"), out
        node = conn.execute("SELECT provenance FROM entities WHERE id=?",
                            (out["entity_id"],)).fetchone()
        assert node["provenance"] == "enrich:crtsh"
        edge = conn.execute(
            "SELECT provenance FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=?",
            (actor, out["entity_id"])).fetchone()
        assert edge is not None and edge["provenance"] == "enrich:crtsh"


def test_manual_node_and_edge_carry_analyst_provenance():
    with db.connect(_db_path()) as conn:
        conn.execute("INSERT INTO investigations (slug, status) VALUES ('case-y','active')")
        rep = db.insert_report(conn, source_path="<t>", source_hash="h3",
                               source_type="report", title="t", investigation="case-y", raw_text="")
        anchor = db.upsert_entity(conn, "Anchor", "org", rep, provenance="ingest:report")
        conn.commit()
        out = promote.add_manual_node(conn, "manual-node.com", "domain",
                                      link_to=anchor, case="case-y")
        assert out.get("ok"), out
        node = conn.execute("SELECT provenance FROM entities WHERE id=?",
                            (out["entity_id"],)).fetchone()
        assert node["provenance"] == "analyst"
        edge = conn.execute(
            "SELECT provenance FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=?",
            (anchor, out["entity_id"])).fetchone()
        assert edge is not None and edge["provenance"] == "analyst"


def test_manual_node_backfills_provenance_on_existing_null_node():
    """A manual add that targets a pre-existing node with NULL provenance backfills it
    to 'analyst' (Codex review gap on add_manual_node's existing-row branch)."""
    with db.connect(_db_path()) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h4",
                               source_type="report", title="t", investigation=None, raw_text="")
        # A node that entered with no provenance (legacy / pre-migration row).
        conn.execute("INSERT INTO entities (canonical_name, entity_type, first_seen_report_id) "
                     "VALUES ('legacy.com', 'domain', ?)", (rep,))
        conn.commit()
        out = promote.add_manual_node(conn, "legacy.com", "domain")
        assert out.get("ok"), out
        row = conn.execute("SELECT provenance FROM entities WHERE id=?",
                           (out["entity_id"],)).fetchone()
        assert row["provenance"] == "analyst"
