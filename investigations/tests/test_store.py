"""Feature tests for store.apply_mutation — the one write path.

Pins the issue's contract (sp1-store-apply-mutation):
  - one entity_upserted event admits + writes + appends + bumps atomically
  - a rolled-back caller transaction leaves NO row, NO event, NO version bump
  - an inadmissible value writes nothing and returns the gate reason
  - analyst-actor adds bypass value-noise admission (top-authority semantics)
  - gate=False constructor paths skip admission (pre-migration behavior)
  - claim status flips + annotations + hidden flips ride the same choke-point
"""

import pytest

from investigations import store
from investigations.storage import db


CASE = "spinetest"


@pytest.fixture
def conn(tmp_path):
    db_path = tmp_path / "t.db"
    db.init_db(db_path)
    with db.connect(db_path) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?, ?)",
            (CASE, CASE))
        connection.commit()
        yield connection


def _event_rows(conn):
    return conn.execute(
        "SELECT analyst, action, investigation, detail FROM activity "
        "WHERE investigation = ?", (CASE,)).fetchall()


def test_entity_upserted_admits_writes_logs_bumps(conn):
    before = store.case_version(conn, CASE)
    result = store.apply_mutation(conn, store.entity_upserted(
        CASE, "evil-corp.com", "domain", None, actor="agent",
        provenance="agent"))
    assert result["applied"] is True
    assert result["entity_id"] > 0
    row = conn.execute("SELECT canonical_name FROM entities WHERE id = ?",
                       (result["entity_id"],)).fetchone()
    assert row[0] == "evil-corp.com"
    events = _event_rows(conn)
    assert [(e[0], e[1]) for e in events] == [("agent", "entity_upserted")]
    assert store.case_version(conn, CASE) == before + 1
    assert result["version"] == before + 1


def test_rollback_leaves_no_row_no_event_no_bump(conn):
    before = store.case_version(conn, CASE)
    store.apply_mutation(conn, store.entity_upserted(
        CASE, "rollback.example", "domain", None, actor="agent"))
    conn.rollback()
    assert conn.execute(
        "SELECT COUNT(*) FROM entities WHERE canonical_name = ?",
        ("rollback.example",)).fetchone()[0] == 0
    assert _event_rows(conn) == []
    assert store.case_version(conn, CASE) == before


def test_inadmissible_value_writes_nothing(conn):
    # '000000' is an all-same-digit placeholder — a junk class from the
    # admission table (test_admission.py).
    result = store.apply_mutation(conn, store.entity_upserted(
        CASE, "000000", "phone", None, actor="agent"))
    assert result["applied"] is False
    assert result["reason"]
    assert conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0] == 0
    assert _event_rows(conn) == []


def test_analyst_actor_bypasses_value_gate(conn):
    # The same junk value an agent may NOT land is an analyst's call to make
    # (top authority — pre-migration graph_chat add_node semantics).
    result = store.apply_mutation(conn, store.entity_upserted(
        CASE, "000000", "phone", None, actor="analyst:assaf"))
    assert result["applied"] is True


def test_gate_false_path_skips_admission(conn):
    result = store.apply_mutation(conn, store.entity_upserted(
        CASE, "000000", "phone", None, actor="pipeline:ingest", gate=False))
    assert result["applied"] is True


def test_edge_upserted_writes_and_logs(conn):
    a = store.apply_mutation(conn, store.entity_upserted(
        CASE, "a.com", "domain", None, actor="agent"))["entity_id"]
    b = store.apply_mutation(conn, store.entity_upserted(
        CASE, "b.com", "domain", None, actor="agent"))["entity_id"]
    result = store.apply_mutation(conn, store.edge_upserted(
        CASE, a, b, "resolves_to", actor="agent", evidence="dns"))
    assert result["applied"] and result["created"]
    assert conn.execute(
        "SELECT COUNT(*) FROM typed_relationships WHERE src_entity_id = ?",
        (a,)).fetchone()[0] == 1
    actions = [e[1] for e in _event_rows(conn)]
    assert actions.count("edge_upserted") == 1


def test_hidden_flip_and_annotation(conn):
    eid = store.apply_mutation(conn, store.entity_upserted(
        CASE, "c.com", "domain", None, actor="agent"))["entity_id"]
    store.apply_mutation(conn, store.entity_hidden(CASE, eid, actor="analyst:assaf"))
    assert conn.execute("SELECT hidden FROM entities WHERE id = ?",
                        (eid,)).fetchone()[0] == 1
    store.apply_mutation(conn, store.analyst_annotated(
        CASE, eid, {"notes": "role: infra"}, actor="analyst:assaf"))
    assert conn.execute("SELECT notes FROM entities WHERE id = ?",
                        (eid,)).fetchone()[0] == "role: infra"
    with pytest.raises(ValueError):
        store.apply_mutation(conn, store.analyst_annotated(
            CASE, eid, {"canonical_name": "x"}, actor="analyst:assaf"))


def test_claim_resolve_flips_status_and_supersedes(conn):
    eid = store.apply_mutation(conn, store.entity_upserted(
        CASE, "claimed.com", "domain", None, actor="agent"))["entity_id"]
    conn.execute(
        "INSERT INTO claims (entity_id, claim_type, predicate, value, status, source)"
        f" VALUES ({eid}, 'role', 'role', 'operator', 'active', 'extract')")
    winner = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO claims (entity_id, claim_type, predicate, value, status, source)"
        f" VALUES ({eid}, 'role', 'role', 'noise', 'active', 'extract')")
    loser = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    store.apply_mutation(conn, store.claim_resolved(
        CASE, winner, actor="analyst:assaf", superseded_ids=[loser]))
    rows = dict(conn.execute(
        "SELECT id, status FROM claims WHERE id IN (?, ?)", (winner, loser)))
    assert rows[winner] == "active"
    assert rows[loser] == "superseded"


def test_unknown_action_rejected(conn):
    with pytest.raises(ValueError):
        store.apply_mutation(conn, {"case": CASE, "actor": "agent",
                                    "action": "made_up", "payload": {}})


def test_recent_activity_newest_first_capped(conn):
    for i in range(6):
        store.apply_mutation(conn, store.entity_upserted(
            CASE, f"d{i}.com", "domain", None, actor="agent"))
    tail = store.recent_activity(conn, CASE, limit=4)
    assert len(tail) == 4
    assert tail[0]["detail"].find("d5.com") != -1  # newest first


def test_event_only_actions_log_and_bump(conn):
    before = store.case_version(conn, CASE)
    store.apply_mutation(conn, store.brief_generated(
        CASE, actor="analyst:assaf"))
    store.apply_mutation(conn, store.noise_swept(
        CASE, "escape-twins", actor="pipeline:retro_clean",
        counts={"merged": 3}))
    actions = [e[1] for e in _event_rows(conn)]
    assert "brief_generated" in actions and "noise_swept" in actions
    assert store.case_version(conn, CASE) == before + 2


def test_stale_id_writes_nothing_no_event_no_bump(conn):
    # codex finding-2: a no-op write must not fabricate an event or a bump.
    before = store.case_version(conn, CASE)
    for event in (store.entity_hidden(CASE, 99999, actor="analyst:assaf"),
                  store.analyst_annotated(CASE, 99999, {"notes": "x"},
                                          actor="analyst:assaf"),
                  store.claim_rejected(CASE, 99999, actor="analyst:assaf")):
        result = store.apply_mutation(conn, event)
        assert result["applied"] is False
        assert "no " in result["reason"]
    assert _event_rows(conn) == []
    assert store.case_version(conn, CASE) == before


def test_analyst_prefix_is_exact(conn):
    # codex finding-4: 'analyst-bot' is not an analyst; no admission bypass.
    result = store.apply_mutation(conn, store.entity_upserted(
        CASE, "000000", "phone", None, actor="analyst-bot"))
    assert result["applied"] is False


def test_unserializable_payload_rolls_back_the_write(conn):
    # Adversarial finding: an event-append failure AFTER the handler write
    # must roll the write back inside the savepoint — a caller catching the
    # exception and committing cannot commit an un-logged write.
    eid = store.apply_mutation(conn, store.entity_upserted(
        CASE, "atomic.com", "domain", None, actor="agent"))["entity_id"]
    conn.commit()
    before_version = store.case_version(conn, CASE)
    event = store.analyst_annotated(
        CASE, eid, {"notes": "ok"}, actor="analyst:assaf")
    event["payload"]["bad"] = {1, 2}  # a set: json.dumps raises
    with pytest.raises(TypeError):
        store.apply_mutation(conn, event)
    conn.commit()  # the hostile caller commits anyway
    assert conn.execute("SELECT notes FROM entities WHERE id = ?",
                        (eid,)).fetchone()[0] is None
    assert [e for e in _event_rows(conn) if e[1] == "analyst_annotated"] == []
    assert store.case_version(conn, CASE) == before_version
