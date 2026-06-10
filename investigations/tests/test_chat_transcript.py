"""Chat transcript store: chat_turns table + add/get helpers + delete cleanup.

The durable record behind the chat-led investigator (PRD
prd-chat-transcript-store-2026-06-06, issue-chat-transcript-store).

Run: .venv/bin/python3 -m investigations.tests.test_chat_transcript

Asserts every acceptance criterion:
  - add_chat_turn / get_chat_turns round-trip
  - ordering (id ASC; limit returns most-recent N, still id-ASC)
  - JSON survival (dict/list -> raw JSON string; None -> NULL; default=str on
    nested non-serializable; {_unserializable:true} last-resort marker)
  - case-scoped reads (case A never returns case B)
  - blank/None case raises ValueError
  - created_at is timezone-aware UTC ISO8601
  - delete_investigation removes the case's chat_turns
  - migration is idempotent on an existing DB
"""
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from investigations.storage import db


def _roundtrip_and_ordering(conn):
    t1 = db.add_chat_turn(conn, "case-a", "analyst", "hello")
    t2 = db.add_chat_turn(conn, "case-a", "agent", "world")
    t3 = db.add_chat_turn(conn, "case-a", "analyst", "again")
    assert t1 < t2 < t3, (t1, t2, t3)

    rows = db.get_chat_turns(conn, "case-a")
    assert [r["text"] for r in rows] == ["hello", "world", "again"], rows
    assert [r["role"] for r in rows] == ["analyst", "agent", "analyst"], rows

    # limit returns the most-recent N, STILL oldest-first (id ASC) for render.
    last2 = db.get_chat_turns(conn, "case-a", limit=2)
    assert [r["text"] for r in last2] == ["world", "again"], last2
    print("ok: round-trip + ordering + limit")


def _json_survival(conn):
    deltas = {"add_nodes": [{"data": {"id": "1"}}], "focus_id": "1"}
    steps = [{"n": 1, "type": "tool", "tool": "dns_lookup"}]
    tid = db.add_chat_turn(conn, "case-j", "agent", "did work",
                           deltas=deltas, steps=steps)
    row = next(r for r in db.get_chat_turns(conn, "case-j") if r["id"] == tid)
    # Stored as raw JSON strings; callers parse.
    assert json.loads(row["deltas_json"]) == deltas, row["deltas_json"]
    assert json.loads(row["step_trail_json"]) == steps, row["step_trail_json"]

    # None -> NULL (not the string "null").
    n = db.add_chat_turn(conn, "case-j", "analyst", "plain")
    nrow = next(r for r in db.get_chat_turns(conn, "case-j") if r["id"] == n)
    assert nrow["deltas_json"] is None and nrow["step_trail_json"] is None, nrow

    # Nested non-serializable (a set) degrades via default=str, never raises.
    d = db.add_chat_turn(conn, "case-j", "agent", "weird", deltas={"s": {1, 2}})
    drow = next(r for r in db.get_chat_turns(conn, "case-j") if r["id"] == d)
    parsed = json.loads(drow["deltas_json"])
    assert isinstance(parsed["s"], str), parsed  # set stringified, not dropped

    # Last-resort marker: a circular ref defeats even default=str -> visible marker.
    circ = {}
    circ["self"] = circ
    c = db.add_chat_turn(conn, "case-j", "agent", "circular", deltas=circ)
    crow = next(r for r in db.get_chat_turns(conn, "case-j") if r["id"] == c)
    assert json.loads(crow["deltas_json"]) == {"_unserializable": True}, crow["deltas_json"]

    # __str__ raising a non-TypeError/ValueError must still degrade to the marker
    # (the turn is never dropped). Proves the broad except, not just TypeError.
    class _Hostile:
        def __str__(self):
            raise RuntimeError("nope")
    h = db.add_chat_turn(conn, "case-j", "agent", "hostile", deltas={"x": _Hostile()})
    hrow = next(r for r in db.get_chat_turns(conn, "case-j") if r["id"] == h)
    assert json.loads(hrow["deltas_json"]) == {"_unserializable": True}, hrow["deltas_json"]
    print("ok: JSON survival (dict/list, None, default=str, unserializable marker, hostile __str__)")


def _case_scoping(conn):
    db.add_chat_turn(conn, "case-x", "analyst", "x-only")
    db.add_chat_turn(conn, "case-y", "analyst", "y-only")
    xs = db.get_chat_turns(conn, "case-x")
    ys = db.get_chat_turns(conn, "case-y")
    assert all(r["text"] == "x-only" for r in xs), xs
    assert all(r["text"] == "y-only" for r in ys), ys
    assert "y-only" not in [r["text"] for r in xs], "case A leaked case B's turns"
    print("ok: case-scoped reads")


def _blank_case_rejected(conn):
    for bad in (None, "", "   "):
        try:
            db.add_chat_turn(conn, bad, "analyst", "should fail")
        except ValueError:
            continue
        raise AssertionError(f"blank case {bad!r} did not raise ValueError")
    print("ok: blank/None case raises ValueError")


def _created_at_utc(conn):
    tid = db.add_chat_turn(conn, "case-ts", "system", "stamp")
    row = next(r for r in db.get_chat_turns(conn, "case-ts") if r["id"] == tid)
    parsed = datetime.fromisoformat(row["created_at"])
    assert parsed.tzinfo is not None, "created_at not timezone-aware"
    assert parsed.utcoffset() == timedelta(0), ("not UTC", row["created_at"])
    print("ok: created_at is timezone-aware UTC ISO8601")


def _delete_cleanup(conn):
    rep = db.insert_report(conn, "d.md", "dh", "markdown", "R", "case-del", "x")
    conn.commit()
    db.add_chat_turn(conn, "case-del", "analyst", "doomed")
    db.add_chat_turn(conn, "case-del", "agent", "also doomed")
    assert db.get_chat_turns(conn, "case-del"), "setup failed"
    res = db.delete_investigation(conn, "case-del")
    assert res.get("ok"), res
    assert db.get_chat_turns(conn, "case-del") == [], "transcript orphaned after case delete"
    print("ok: delete_investigation removes the case's chat_turns")


def _migration_idempotent(dbp):
    # connect() runs _migrate each call; a second connect must not error and the
    # table keeps working (CREATE TABLE/INDEX IF NOT EXISTS).
    with db.connect(dbp) as conn2:
        tid = db.add_chat_turn(conn2, "case-mig", "analyst", "after re-migrate")
        assert any(r["id"] == tid for r in db.get_chat_turns(conn2, "case-mig"))
    print("ok: migration idempotent on an existing DB")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            _roundtrip_and_ordering(conn)
            _json_survival(conn)
            _case_scoping(conn)
            _blank_case_rejected(conn)
            _created_at_utc(conn)
            _delete_cleanup(conn)
        _migration_idempotent(dbp)
    print("\nALL PASS: test_chat_transcript")


if __name__ == "__main__":
    main()
