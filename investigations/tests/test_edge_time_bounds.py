"""Edge time bounds + single edge writer (issue edge-time-bounds, PRD
graph-data-model-hardening).

Asserts: the first_seen/last_seen migration is a lazy ALTER and idempotent;
db.upsert_typed_relationship stamps both bounds on create, bumps ONLY last_seen
on re-observation (same src,dst,rel_type = same edge, no duplicate row); existing
confidence/evidence/provenance/status are never downgraded; a legacy NULL-bounds
edge gets first_seen backfilled on its next sighting; and no module outside
storage/db.py writes typed_relationships directly (single-writer guard).
"""
import subprocess
import tempfile
from pathlib import Path

from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "bounds.db"
    db.init_db(path)
    return path


def _mk_entities(conn):
    rep = db.insert_report(conn, source_path="<t>", source_hash="h-bounds",
                           source_type="manual", title="t", investigation=None,
                           raw_text="")
    a = db.upsert_entity(conn, "a.example.com", "domain", rep)
    b = db.upsert_entity(conn, "b.example.com", "domain", rep)
    return a, b


def test_migration_adds_time_bounds_and_is_idempotent():
    path = _db_path()
    with db.connect(path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(typed_relationships)")}
        assert "first_seen" in cols and "last_seen" in cols
    # Second connect re-runs _migrate on the same file — must not error.
    with db.connect(path) as conn2:
        cols2 = {r[1] for r in conn2.execute("PRAGMA table_info(typed_relationships)")}
        assert "first_seen" in cols2 and "last_seen" in cols2


def test_create_stamps_both_bounds_and_reobservation_bumps_last_seen():
    with db.connect(_db_path()) as conn:
        a, b = _mk_entities(conn)
        created = db.upsert_typed_relationship(
            conn, a, b, "resolves_to", evidence="dns A", provenance="osint",
            observed_at="2026-06-01 00:00:00")
        assert created is True
        row = conn.execute("SELECT * FROM typed_relationships").fetchone()
        assert row["first_seen"] == "2026-06-01 00:00:00"
        assert row["last_seen"] == "2026-06-01 00:00:00"

        # Re-observation: same key — updates in place, no second row.
        created2 = db.upsert_typed_relationship(
            conn, a, b, "resolves_to", evidence="dns A again", provenance="agent",
            observed_at="2026-06-09 12:00:00")
        assert created2 is False
        rows = conn.execute("SELECT * FROM typed_relationships").fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row["first_seen"] == "2026-06-01 00:00:00"   # unchanged
        assert row["last_seen"] == "2026-06-09 12:00:00"    # bumped
        # Never downgrade what's already set.
        assert row["evidence"] == "dns A"
        assert row["provenance"] == "osint"


def test_out_of_order_observation_never_inverts_bounds():
    with db.connect(_db_path()) as conn:
        a, b = _mk_entities(conn)
        db.upsert_typed_relationship(conn, a, b, "resolves_to",
                                     observed_at="2026-06-05 00:00:00")
        # A replayed OLDER observation: must widen first_seen, not regress last_seen.
        db.upsert_typed_relationship(conn, a, b, "resolves_to",
                                     observed_at="2026-06-01 00:00:00")
        row = conn.execute("SELECT * FROM typed_relationships").fetchone()
        assert row["first_seen"] == "2026-06-01 00:00:00"
        assert row["last_seen"] == "2026-06-05 00:00:00"
        assert row["first_seen"] <= row["last_seen"]


def test_distinct_rel_type_is_a_distinct_edge():
    with db.connect(_db_path()) as conn:
        a, b = _mk_entities(conn)
        assert db.upsert_typed_relationship(conn, a, b, "resolves_to") is True
        assert db.upsert_typed_relationship(conn, a, b, "registered_by") is True
        n = conn.execute("SELECT COUNT(*) AS n FROM typed_relationships").fetchone()["n"]
        assert n == 2


def test_legacy_null_bounds_edge_backfills_first_seen_on_next_sighting():
    with db.connect(_db_path()) as conn:
        a, b = _mk_entities(conn)
        # Simulate a pre-migration edge: write directly with NULL bounds (test-only;
        # production code must go through the helper — see the single-writer guard).
        conn.execute(
            "INSERT INTO typed_relationships "
            "(src_entity_id, dst_entity_id, rel_type, confidence, status) "
            "VALUES (?, ?, 'shared_infra', 'medium', 'active')", (a, b))
        db.upsert_typed_relationship(conn, a, b, "shared_infra",
                                     observed_at="2026-06-09 09:00:00")
        row = conn.execute("SELECT * FROM typed_relationships").fetchone()
        assert row["first_seen"] == "2026-06-09 09:00:00"   # earliest RECORDED
        assert row["last_seen"] == "2026-06-09 09:00:00"


def test_superseded_edge_stays_superseded_on_reobservation():
    with db.connect(_db_path()) as conn:
        a, b = _mk_entities(conn)
        db.upsert_typed_relationship(conn, a, b, "resolves_to")
        conn.execute("UPDATE typed_relationships SET status='superseded'")
        db.upsert_typed_relationship(conn, a, b, "resolves_to")
        row = conn.execute("SELECT status FROM typed_relationships").fetchone()
        assert row["status"] == "superseded"


def test_default_observed_at_uses_sqlite_native_format():
    with db.connect(_db_path()) as conn:
        a, b = _mk_entities(conn)
        db.upsert_typed_relationship(conn, a, b, "resolves_to")
        row = conn.execute("SELECT first_seen FROM typed_relationships").fetchone()
        # 'YYYY-MM-DD HH:MM:SS' — comparable with CURRENT_TIMESTAMP columns via SQL
        # MIN/MAX (the mixed-format trap from the TTFN metric bug).
        assert len(row["first_seen"]) == 19
        assert row["first_seen"][10] == " " and "T" not in row["first_seen"]


def test_backfill_stamps_bounds_and_rerun_mutates_nothing():
    from investigations.storage.backfill_typed_relationships import backfill
    with db.connect(_db_path()) as conn:
        a, b = _mk_entities(conn)
        rep = conn.execute("SELECT id FROM reports").fetchone()["id"]
        db.add_relationship(conn, a, b, "resolves_to", rep, "legacy edge", 0.5)
        assert backfill(conn) == 1
        row = conn.execute("SELECT * FROM typed_relationships").fetchone()
        assert row["first_seen"] is not None and row["last_seen"] is not None
        stamped = (row["first_seen"], row["last_seen"])
        # Rerun: inserts 0 AND mutates nothing — a backfill rerun is not a
        # re-observation, so last_seen must not move to the rerun time.
        assert backfill(conn) == 0
        row2 = conn.execute("SELECT * FROM typed_relationships").fetchone()
        assert (row2["first_seen"], row2["last_seen"]) == stamped


def test_graph_chat_add_edge_writes_time_bounds():
    from investigations.webapp import graph_chat
    with db.connect(_db_path()) as conn:
        a, b = _mk_entities(conn)
        # case=None: the unscoped pool — _mk_entities' report has investigation=None,
        # and _resolve is case-scoped through mentions when a case is given.
        out = graph_chat.execute(conn, "add_edge",
                                 {"src": "a.example.com", "dst": "b.example.com",
                                  "rel_type": "linked_to"}, None, None)
        assert out.get("deltas", {}).get("add_edges"), out
        row = conn.execute("SELECT * FROM typed_relationships").fetchone()
        assert row["first_seen"] is not None and row["last_seen"] is not None
        assert row["provenance"] == "analyst"


def test_single_writer_no_direct_inserts_outside_db_py():
    root = Path(__file__).resolve().parents[1]
    out = subprocess.run(
        ["grep", "-rln", "INTO typed_relationships", "--include=*.py", str(root)],
        capture_output=True, text=True)
    offenders = [
        line for line in out.stdout.splitlines()
        if "__pycache__" not in line
        and not line.endswith("storage/db.py")
        and f"{root.name}/tests/" not in line.replace(str(root), root.name)
    ]
    assert offenders == [], f"direct typed_relationships writers found: {offenders}"


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print("OK")
