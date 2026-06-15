"""Legacy edge time-bounds backfill (issue gma-2-edge-time-backfill, PRD
graph-machinery-activation).

Asserts: backfill_edge_times stamps NULL/empty-bound legacy edges from
MAX(endpoint entities.first_seen_at) — the earliest moment both endpoints
existed; is idempotent; never overwrites non-empty bounds; preserves a
half-filled bound's existing side; dry mode writes nothing; and the pass is
wired into retro_clean.run (CLI + Process pick it up without further wiring).
"""
import tempfile
from pathlib import Path

from investigations.maintenance import retro_clean
from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "backfill.db"
    db.init_db(path)
    return path


def _mk_case(conn, slug="case-bf"):
    conn.execute("INSERT INTO investigations (slug, case_name) VALUES (?, ?)",
                 (slug, slug))
    rep = db.insert_report(conn, source_path="<t>", source_hash=f"h-{slug}",
                           source_type="text", title="t", investigation=slug,
                           raw_text="")
    return rep


def _legacy_edge(conn, src, dst, rel="resolves_to", first_seen=None, last_seen=None):
    """Insert a typed edge BYPASSING the single writer — simulates pre-bounds rows."""
    conn.execute(
        "INSERT INTO typed_relationships (src_entity_id, dst_entity_id, rel_type, "
        "confidence, evidence, status, first_seen, last_seen) "
        "VALUES (?, ?, ?, 'high', 't', 'active', ?, ?)",
        (src, dst, rel, first_seen, last_seen))
    return conn.execute("SELECT last_insert_rowid() AS i").fetchone()["i"]


def _set_entity_seen(conn, eid, ts):
    conn.execute("UPDATE entities SET first_seen_at = ? WHERE id = ?", (ts, eid))


def test_backfill_stamps_max_of_endpoint_first_seen():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn)
        a = db.upsert_entity(conn, "a.example.com", "domain", rep)
        b = db.upsert_entity(conn, "b.example.com", "domain", rep)
        _set_entity_seen(conn, a, "2026-01-01 00:00:00")
        _set_entity_seen(conn, b, "2026-03-15 12:00:00")
        eid = _legacy_edge(conn, a, b)

        out = retro_clean.backfill_edge_times(conn)
        assert out["stamped"] == 1
        row = conn.execute("SELECT first_seen, last_seen FROM typed_relationships "
                           "WHERE id = ?", (eid,)).fetchone()
        # MAX of the endpoints: the edge can't predate its later endpoint.
        assert row["first_seen"] == "2026-03-15 12:00:00"
        assert row["last_seen"] == "2026-03-15 12:00:00"


def test_backfill_is_idempotent_and_never_overwrites():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="case-bf2")
        a = db.upsert_entity(conn, "c.example.com", "domain", rep)
        b = db.upsert_entity(conn, "d.example.com", "domain", rep)
        _set_entity_seen(conn, a, "2026-02-01 00:00:00")
        _set_entity_seen(conn, b, "2026-02-02 00:00:00")
        legacy = _legacy_edge(conn, a, b)
        # A live-writer edge with real bounds must be untouched.
        live = _legacy_edge(conn, b, a, rel="linked_to",
                            first_seen="2025-12-25 08:00:00",
                            last_seen="2026-04-04 09:00:00")
        # Half-filled: only the empty side gets stamped.
        half = _legacy_edge(conn, a, b, rel="shared_infra",
                            first_seen="2026-01-15 00:00:00", last_seen=None)

        out1 = retro_clean.backfill_edge_times(conn)
        assert out1["stamped"] == 2  # legacy + half; live untouched
        out2 = retro_clean.backfill_edge_times(conn)
        assert out2["stamped"] == 0, "second run must be a no-op"

        rows = {r["id"]: r for r in conn.execute(
            "SELECT id, first_seen, last_seen FROM typed_relationships")}
        assert rows[live]["first_seen"] == "2025-12-25 08:00:00"
        assert rows[live]["last_seen"] == "2026-04-04 09:00:00"
        assert rows[half]["first_seen"] == "2026-01-15 00:00:00", \
            "existing half-bound must survive"
        assert rows[half]["last_seen"] == "2026-02-02 00:00:00"
        assert rows[legacy]["first_seen"] == "2026-02-02 00:00:00"


def test_half_filled_bounds_never_invert_ordering():
    """Codex finding-1: stamping the empty side must clamp against the existing
    side so first_seen <= last_seen always holds."""
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="case-bf-ord")
        a = db.upsert_entity(conn, "o1.example.com", "domain", rep)
        b = db.upsert_entity(conn, "o2.example.com", "domain", rep)
        # Endpoints predate the existing first_seen -> naive stamp would invert.
        _set_entity_seen(conn, a, "2026-06-01 00:00:00")
        _set_entity_seen(conn, b, "2026-06-01 00:00:00")
        inverted = _legacy_edge(conn, a, b, rel="linked_to",
                                first_seen="2026-06-10 00:00:00", last_seen=None)
        # And the mirror: existing last_seen earlier than the stamp.
        mirror = _legacy_edge(conn, b, a, rel="shared_infra",
                              first_seen=None, last_seen="2026-05-01 00:00:00")
        retro_clean.backfill_edge_times(conn)
        rows = {r["id"]: r for r in conn.execute(
            "SELECT id, first_seen, last_seen FROM typed_relationships")}
        for eid in (inverted, mirror):
            fs, ls = rows[eid]["first_seen"], rows[eid]["last_seen"]
            assert fs and ls and fs <= ls, f"ordering inverted: {fs} > {ls}"
        assert rows[inverted]["last_seen"] == "2026-06-10 00:00:00"
        assert rows[mirror]["first_seen"] == "2026-05-01 00:00:00"


def test_dry_mode_reports_but_writes_nothing():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="case-bf3")
        a = db.upsert_entity(conn, "e.example.com", "domain", rep)
        b = db.upsert_entity(conn, "f.example.com", "domain", rep)
        eid = _legacy_edge(conn, a, b)
        out = retro_clean.backfill_edge_times(conn, dry=True)
        assert out["stamped"] == 1
        assert out["edges"][0]["src"] == "e.example.com"
        row = conn.execute("SELECT first_seen FROM typed_relationships WHERE id = ?",
                           (eid,)).fetchone()
        assert not row["first_seen"], "dry mode must not write"


def test_case_scoping_limits_to_case_edges():
    path = _db_path()
    with db.connect(path) as conn:
        rep1 = _mk_case(conn, slug="case-in")
        rep2 = _mk_case(conn, slug="case-out")
        a = db.upsert_entity(conn, "in1.example.com", "domain", rep1)
        b = db.upsert_entity(conn, "in2.example.com", "domain", rep1)
        c = db.upsert_entity(conn, "out1.example.com", "domain", rep2)
        d = db.upsert_entity(conn, "out2.example.com", "domain", rep2)
        for eid, rid in ((a, rep1), (b, rep1), (c, rep2), (d, rep2)):
            db.add_mention(conn, eid, rid, "x", "ctx")
        _legacy_edge(conn, a, b)
        _legacy_edge(conn, c, d)
        out = retro_clean.backfill_edge_times(conn, case="case-in")
        assert out["stamped"] == 1
        assert out["edges"][0]["src"] == "in1.example.com"


def test_wired_into_retro_clean_run():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="case-bf4")
        a = db.upsert_entity(conn, "g.example.com", "domain", rep)
        b = db.upsert_entity(conn, "h.example.com", "domain", rep)
        _legacy_edge(conn, a, b)
        out = retro_clean.run(conn)
        assert "edge_times" in out, "backfill must run as a retro-clean pass"
        assert out["edge_times"]["stamped"] == 1
