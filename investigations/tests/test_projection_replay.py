"""The replay gate (sp3-projection-core): projection is a pure function of
the canonical sources.

  replay     — project() twice with no intervening events -> IDENTICAL
               digests AND no derived-row changes
  sensitivity— an intervening store event -> the digest CHANGES
  genesis    — written once, idempotent, inert
  purity     — projection makes zero LLM calls (runtime guard)
"""
import tempfile
from pathlib import Path

import pytest

from investigations import projection, store
from investigations.storage import db

CASE = "proj-case"


@pytest.fixture
def conn(tmp_path):
    dbp = tmp_path / "t.db"
    db.init_db(dbp)
    with db.connect(dbp) as c:
        c.execute("INSERT OR IGNORE INTO investigations (slug, case_name) "
                  "VALUES (?, ?)", (CASE, CASE))
        rid = db.insert_report(c, "r.md", "h1", "markdown", "R1", CASE, "body")
        a = store.apply_mutation(c, store.entity_upserted(
            CASE, "evil.com", "domain", rid, actor="agent"))["entity_id"]
        b = store.apply_mutation(c, store.entity_upserted(
            CASE, "9.9.9.9", "ip", rid, actor="agent"))["entity_id"]
        db.add_mention(c, a, rid, "evil.com", "ctx")
        db.add_mention(c, b, rid, "9.9.9.9", "ctx")
        store.apply_mutation(c, store.edge_upserted(
            CASE, a, b, "resolves_to", actor="agent", evidence="dns"))
        c.execute(
            "INSERT INTO claims (entity_id, report_id, claim_type, predicate, "
            "value, status, source) VALUES (?, ?, 'role', 'role', 'operator', "
            "'active', 'extract')", (a, rid))
        c.commit()
        yield c, a, b


def test_replay_is_idempotent(conn):
    c, a, b = conn
    d1 = projection.project(c, CASE)
    rows1 = c.execute("SELECT COUNT(*) FROM activity").fetchone()[0]
    seen1 = [tuple(r) for r in c.execute(
        "SELECT id, last_seen FROM typed_relationships ORDER BY id")]
    d2 = projection.project(c, CASE)
    rows2 = c.execute("SELECT COUNT(*) FROM activity").fetchone()[0]
    seen2 = [tuple(r) for r in c.execute(
        "SELECT id, last_seen FROM typed_relationships ORDER BY id")]
    assert d1 == d2, "replay must be idempotent — identical derived state"
    # STATE-idempotent, not just digest-idempotent (codex): a no-drift replay
    # writes nothing — zero new events, zero last_seen churn.
    assert rows2 == rows1, "no-drift replay must not append events"
    assert seen2 == seen1, "no-drift replay must not bump last_seen"


def test_digest_changes_on_new_event(conn):
    c, a, b = conn
    d1 = projection.project(c, CASE)
    store.apply_mutation(c, store.entity_hidden(CASE, b, actor="analyst:assaf"))
    d2 = projection.project(c, CASE)
    assert d1 != d2, "an intervening event must change the digest"


def test_claim_authority_lands_on_graph(conn):
    c, a, b = conn
    projection.project(c, CASE)
    notes = c.execute("SELECT notes FROM entities WHERE id = ?", (a,)).fetchone()[0]
    assert notes and notes.startswith("role:operator")


def test_genesis_written_once(conn):
    c, a, b = conn
    projection.project(c, CASE)
    projection.project(c, CASE)
    n = c.execute(
        "SELECT COUNT(*) FROM activity WHERE investigation = ? AND "
        "detail LIKE '%\"genesis\": true%'", (CASE,)).fetchone()[0]
    assert n == 1


def test_caller_owns_the_transaction(conn):
    """codex: a rollback after project() must erase EVERYTHING it did —
    nothing inside (incl. score recompute) may commit."""
    c, a, b = conn
    base_rows = c.execute("SELECT COUNT(*) FROM activity").fetchone()[0]
    projection.project(c, CASE)
    c.rollback()
    assert c.execute("SELECT COUNT(*) FROM activity").fetchone()[0] == base_rows
    assert c.execute("SELECT COUNT(*) FROM entity_scores").fetchone()[0] == 0


def test_projection_makes_zero_llm_calls(conn, mp):
    from investigations.llm import client as llm_client
    def _no_llm(*a, **k):
        raise AssertionError("projection called the LLM — it must be pure")
    mp.setattr(llm_client, "ask", _no_llm)
    c, a, b = conn
    projection.project(c, CASE)


def test_brief_inputs_schema(conn):
    c, a, b = conn
    projection.project(c, CASE)
    bi = projection.brief_inputs(c, CASE)
    assert set(bi) == {"reports", "entities", "findings", "leads", "agent_costs"}
    assert bi["reports"] == [{"id": 1, "title": "R1"}]
    names = [e["name"] for e in bi["entities"]]
    assert "evil.com" in names and "9.9.9.9" in names
    assert all(set(e) == {"id", "name", "type", "role", "score"}
               for e in bi["entities"])


def test_convergence_has_no_prefix_false_positive(conn):
    # codex adversarial: 'role:infra' authority must REPAIR a drifted
    # 'role:infra_provider' note, not call it converged.
    c, a, b = conn
    c.execute("UPDATE claims SET value='ioc' WHERE predicate='role'")
    c.execute("UPDATE entities SET notes='role:ioc_lookalike — drifted' "
              "WHERE id=?", (a,))
    projection.project(c, CASE)
    notes = c.execute("SELECT notes FROM entities WHERE id=?", (a,)).fetchone()[0]
    assert notes.startswith("role:ioc") and "lookalike" not in notes.split(" — ")[0]


def test_prd05_reject_propagates_everywhere_in_one_step(conn):
    """prd-05 acceptance: plant a bad input, reject it as an event,
    re-project -> gone from the graph AND brief inputs AND scores in ONE
    step (the reject call itself; no manual follow-ups)."""
    from investigations import claims
    c, a, b = conn
    # plant: a bad role claim that projects onto the graph + scores + brief
    c.execute(
        "INSERT INTO claims (entity_id, report_id, claim_type, predicate, "
        "value, status, source) VALUES (?, 1, 'role', 'role', 'operator', "
        "'active', 'extract')", (b,))
    bad = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    projection.project(c, CASE)
    c.commit()
    assert c.execute("SELECT notes FROM entities WHERE id=?",
                     (b,)).fetchone()[0].startswith("role:operator")
    bi_before = projection.brief_inputs(c, CASE)
    role_before = [e for e in bi_before["entities"] if e["id"] == b][0]["role"]
    assert role_before == "operator"
    score_before = c.execute(
        "SELECT threat_score FROM entity_scores WHERE entity_id=?",
        (b,)).fetchone()[0]

    # ONE step: reject (claims.reject projects fully inside)
    out = claims.reject(c, bad)
    assert out.get("ok")

    # gone from the graph...
    notes = c.execute("SELECT notes FROM entities WHERE id=?", (b,)).fetchone()[0]
    assert not (notes or "").startswith("role:operator")
    # ...AND the brief inputs...
    bi_after = projection.brief_inputs(c, CASE)
    role_after = [e for e in bi_after["entities"] if e["id"] == b][0]["role"]
    assert role_after != "operator"
    # ...AND the scores (operator weight gone)
    score_after_row = c.execute(
        "SELECT threat_score FROM entity_scores WHERE entity_id=?",
        (b,)).fetchone()
    score_after = score_after_row[0] if score_after_row else 0
    assert score_after < score_before


def test_projection_failure_rolls_back_the_override(conn, mp):
    """The override commits ONLY after projection returns: a projection
    failure leaves the claim decision uncommitted (no half-propagated state)."""
    from investigations import claims, projection as proj_mod
    c, a, b = conn
    c.execute(
        "INSERT INTO claims (entity_id, report_id, claim_type, predicate, "
        "value, status, source) VALUES (?, 1, 'role', 'role', 'channel', "
        "'active', 'extract')", (b,))
    claim_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    c.commit()
    def _boom(conn_, case_):
        raise RuntimeError("projection died mid-run")
    mp.setattr(proj_mod, "project", _boom)
    import pytest as _pytest
    with _pytest.raises(RuntimeError):
        claims.reject(c, claim_id)
    c.rollback()
    status = c.execute("SELECT status FROM claims WHERE id=?",
                       (claim_id,)).fetchone()[0]
    assert status == "active", "the claim decision must not survive a failed projection"


def test_assert_claim_is_one_transaction(conn, mp):
    """codex batched-review: a projection failure during assert_claim must
    leave NO manual claim behind (the early commit split the override)."""
    from investigations import claims, projection as proj_mod
    c, a, b = conn
    c.commit()
    def _boom(conn_, case_):
        raise RuntimeError("projection died")
    mp.setattr(proj_mod, "project", _boom)
    import pytest as _pytest
    with _pytest.raises(RuntimeError):
        claims.assert_claim(c, a, claim_type="role", predicate="role",
                            value="channel", analyst="tester")
    c.rollback()
    n = c.execute("SELECT COUNT(*) FROM claims WHERE source='manual'").fetchone()[0]
    assert n == 0, "the manual claim must not survive a failed projection"
