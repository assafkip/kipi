"""Deterministic safety tests for the parallelized typing pass. The LLM is stubbed
(no API, no tokens); a real temp SQLite DB exercises the concurrency. These prove the
three traps the RCA flagged are closed:
  - DB single-writer: parallel workers never touch the DB, so no lock / no crash.
  - dedup-no-race: two reports proposing the SAME missed entity add it exactly once.
  - fork-bomb + cost guards: every call goes tools=False on CLASSIFY_MODEL (Haiku).
"""
from investigations.storage import db
from investigations import typing


SCHEMA = {
    "domain": "test", "summary": "t",
    "entity_types": [{"name": "handle", "description": "h"}],
    "roles": [{"name": "promoter", "actor": True, "description": "p"},
              {"name": "noise", "description": "n"}],
    "sub_roles": [{"name": "paid_promoter", "description": "x"}],
}


def _seed_db(path):
    db.init_db(path)


def test_extract_missing_dedups_across_parallel_reports(tmp_path, monkeypatch):
    calls = []

    def fake_ask_json(prompt, system=None, timeout=180, tools=True, model=None):
        calls.append({"tools": tools, "model": model})
        # BOTH reports propose the identical missed entity — the race case.
        return {"entities": [{"name": "SharedGuy", "surface_type": "handle",
                              "case_type": "handle", "role": "promoter",
                              "sub_role": "paid_promoter", "context": "ctx"}]}

    monkeypatch.setattr(typing.llm, "ask_json", fake_ask_json)
    p = tmp_path / "t.db"
    _seed_db(p)
    with db.connect(p) as conn:
        for rid in (1, 2):
            conn.execute(
                "INSERT INTO reports (id,title,investigation,source_path,source_hash,"
                "source_type,raw_text) VALUES (?,?,?,?,?,?,?)",
                (rid, f"r{rid}", "c", f"/x{rid}", f"h{rid}", "note", f"text {rid}"))
        conn.commit()
        res = typing.extract_missing(conn, "c", SCHEMA)
        n = conn.execute(
            "SELECT COUNT(*) FROM entities WHERE canonical_name='SharedGuy'"
        ).fetchone()[0]

    assert n == 1, f"dedup race: expected 1 SharedGuy, got {n}"
    assert res["added"] == 1
    assert len(calls) == 2, "one parallel call per report"
    assert all(c["tools"] is False for c in calls), "fork-bomb guard: tools must be False"
    assert all(c["model"] == typing.llm.CLASSIFY_MODEL for c in calls), "must route to Haiku"


def test_retype_parallel_single_writer(tmp_path, monkeypatch):
    calls = []

    def fake_ask_json(prompt, system=None, timeout=180, tools=True, model=None):
        calls.append({"tools": tools, "model": model})
        return {"types": [{"id": i, "case_type": "handle"} for i in (1, 2, 3)]}

    monkeypatch.setattr(typing.llm, "ask_json", fake_ask_json)
    p = tmp_path / "t.db"
    _seed_db(p)
    with db.connect(p) as conn:
        conn.execute(
            "INSERT INTO reports (id,title,investigation,source_path,source_hash,"
            "source_type) VALUES (1,'r','c','/x','h','note')")
        for eid in (1, 2, 3):
            conn.execute(
                "INSERT INTO entities (id,canonical_name,entity_type,notes) "
                "VALUES (?,?,?,?)", (eid, f"e{eid}", "handle", "role:promoter"))
            conn.execute(
                "INSERT INTO mentions (entity_id,report_id,surface_form,context) "
                "VALUES (?,?,?,?)", (eid, 1, "x", "c"))
        conn.commit()
        res = typing.retype_entities(conn, "c", SCHEMA)
        typed = conn.execute(
            "SELECT COUNT(*) FROM entities WHERE case_type='handle'").fetchone()[0]

    assert res["typed"] == 3 and typed == 3, "all entities typed, no lost writes"
    assert all(c["tools"] is False for c in calls)
    assert all(c["model"] == typing.llm.CLASSIFY_MODEL for c in calls)
