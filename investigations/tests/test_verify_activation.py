"""Activation run + verification harness (issue gma-4-activation-script, PRD
graph-machinery-activation).

Hermetic: builds its own fixture DB (no dependence on the analyst's live DB) and
monkeypatches the LLM typing pass so no API key is needed. Asserts the chain runs
in order, the four checks pass on a correctly-activated case, and each check fails
loudly when its target is broken.
"""
import tempfile
from pathlib import Path

from investigations.scripts import verify_activation as va
from investigations.storage import db


def _build_case(path, slug="act-case"):
    db.init_db(path)
    with db.connect(path) as conn:
        conn.execute("INSERT INTO investigations (slug, case_name) VALUES (?, ?)",
                     (slug, slug))
        rep = db.insert_report(conn, source_path="<intake>", source_hash=f"h-{slug}",
                               source_type="text", title="intake", investigation=slug,
                               raw_text="")
        a = db.upsert_entity(conn, "seed.example.com", "domain", rep)
        b = db.upsert_entity(conn, "infra.example.com", "domain", rep)
        ind = db.upsert_entity(conn, "Gambler Panel", "indicator", rep)
        for eid in (a, b, ind):
            db.add_mention(conn, eid, rep, "x", "ctx")
        # A legacy typed edge with no time bounds + an indicator with no case_type.
        conn.execute(
            "INSERT INTO typed_relationships (src_entity_id, dst_entity_id, rel_type, "
            "confidence, evidence, status) VALUES (?, ?, 'resolves_to', 'high', 't', 'active')",
            (a, b))
        conn.execute(
            "INSERT INTO typed_relationships (src_entity_id, dst_entity_id, rel_type, "
            "confidence, evidence, status) VALUES (?, ?, 'operated_by', 'high', 't', 'active')",
            (b, ind))
        # An approved schema so run_chain calls the (patched) typing pass.
        from investigations import understand
        understand.save_schema(conn, slug, {"domain": "test",
                                             "entity_types": [{"name": "org"}],
                                             "roles": []}, status="approved")
        conn.commit()
    return slug


def _patch_typing(monkeypatch):
    """Stub the LLM typing pass: set case_type on every indicator (what the real
    pass does), deterministically, with no API call."""
    def fake_run(conn, case, schema):
        conn.execute(
            "UPDATE entities SET case_type = 'org' "
            "WHERE entity_type = 'indicator' AND (case_type IS NULL OR case_type = '')")
        return {"retype": {"typed": 1, "total": 1}, "extract": {"added": 0}}
    monkeypatch.setattr("investigations.typing.run", fake_run)


def test_chain_runs_and_all_checks_pass(monkeypatch):
    path = Path(tempfile.mkdtemp()) / "act.db"
    slug = _build_case(path)
    _patch_typing(monkeypatch)
    with db.connect(path) as conn:
        result = va.run_chain(conn, slug, on_log=lambda *_: None)
        checks = va.verify(conn, slug, result)
    names = {n for n, _, _ in checks}
    assert names == {"scores", "edge_times", "indicator_typed", "regate_ran"}
    for name, ok, detail in checks:
        assert ok, f"{name} failed: {detail}"


def test_chain_seeds_scores_and_dates_edges(monkeypatch):
    path = Path(tempfile.mkdtemp()) / "act2.db"
    slug = _build_case(path, slug="act-case2")
    _patch_typing(monkeypatch)
    with db.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM entity_scores").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM seeds").fetchone()[0] == 0
        result = va.run_chain(conn, slug, on_log=lambda *_: None)
        assert result["seeded"] >= 2
        assert result["scored"] >= 2
        assert result["cleaned"]["edge_times"]["stamped"] >= 2
        # indicator got typed by the patched pass
        untyped = conn.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_type='indicator' "
            "AND (case_type IS NULL OR case_type='')").fetchone()[0]
        assert untyped == 0


def test_check_edge_times_fails_when_undated():
    path = Path(tempfile.mkdtemp()) / "act3.db"
    slug = _build_case(path, slug="act-case3")
    # No chain run -> edges stay undated -> check must FAIL.
    with db.connect(path) as conn:
        ok, detail = va.check_edge_times(conn, slug)
    assert not ok, f"expected failure on undated edges, got: {detail}"


def test_check_indicator_typed_fails_when_untyped():
    path = Path(tempfile.mkdtemp()) / "act4.db"
    slug = _build_case(path, slug="act-case4")
    with db.connect(path) as conn:
        ok, detail = va.check_indicator_typed(conn, slug)
    assert not ok, f"expected failure on untyped indicator, got: {detail}"


def test_ensure_schema_approves_existing_proposed_wrapper():
    """Codex finding: get_schema returns a {schema,status,...} wrapper; ensure_schema
    must unwrap it before save_schema, or a previously-proposed-but-unapproved case
    skips typing."""
    from investigations import understand
    path = Path(tempfile.mkdtemp()) / "act_sch.db"
    slug = _build_case(path, slug="act-proposed")
    with db.connect(path) as conn:
        # Replace the approved schema with a PROPOSED one (the realistic pre-approve state).
        conn.execute("DELETE FROM case_schemas WHERE case_slug = ?", (slug,))
        understand.save_schema(conn, slug, {"domain": "test",
                                            "entity_types": [{"name": "org"}],
                                            "roles": []}, status="proposed")
        conn.commit()
        assert understand.approved_schema(conn, slug) is None
        schema = va.ensure_schema(conn, slug, on_log=lambda *_: None)
        assert schema is not None, "proposed schema must be unwrapped + approved, not skipped"
        assert understand.approved_schema(conn, slug) is not None


def test_check_regate_ran_detects_missing_pass():
    ok, _ = va.check_regate_ran({"cleaned": {}})
    assert not ok
    ok2, _ = va.check_regate_ran({"cleaned": {"attribution": {"dropped": 0}}})
    assert ok2


def test_backup_is_numbered_and_real():
    path = Path(tempfile.mkdtemp()) / "act5.db"
    _build_case(path, slug="act-case5")
    bak = va.backup_db(path)
    assert bak.exists()
    assert "bak-activation-0" in bak.name
    bak2 = va.backup_db(path)
    assert "bak-activation-1" in bak2.name, "second backup must not clobber the first"


def test_backup_captures_uncheckpointed_wal_data():
    """Codex adversarial finding: the live DB is WAL; a file-copy backup would miss
    committed-but-uncheckpointed rows in the -wal sidecar. backup() must capture them."""
    import sqlite3
    path = Path(tempfile.mkdtemp()) / "act_wal.db"
    slug = _build_case(path, slug="act-wal")
    # Write a row through a WAL connection and COMMIT, but do NOT checkpoint — the
    # row now lives in the -wal sidecar, not the main .db file.
    raw = sqlite3.connect(str(path))
    raw.execute("PRAGMA journal_mode = WAL")
    raw.execute("INSERT INTO entities (canonical_name, entity_type) VALUES "
                "('wal-only.example.com', 'domain')")
    raw.commit()
    raw.close()  # closing may checkpoint; force the hard case below instead

    # Re-open, write another committed row, and hold the connection open so the WAL
    # is not checkpointed when we back up.
    hold = sqlite3.connect(str(path))
    hold.execute("PRAGMA journal_mode = WAL")
    hold.execute("PRAGMA wal_autocheckpoint = 0")
    hold.execute("INSERT INTO entities (canonical_name, entity_type) VALUES "
                 "('wal-held.example.com', 'domain')")
    hold.commit()
    try:
        bak = va.backup_db(path)
        names = {r[0] for r in sqlite3.connect(str(bak)).execute(
            "SELECT canonical_name FROM entities")}
        assert "wal-only.example.com" in names
        assert "wal-held.example.com" in names, \
            "backup must capture committed WAL data not yet checkpointed"
    finally:
        hold.close()
