"""Deterministic tests for the analyze fix: salvage of truncated/malformed JSON, and
case-scoping of the context (the two root causes of the live `analyze` skip — a 4,031-
entity cross-case prompt whose clustering output overran max_tokens and truncated)."""
from investigations import analyze
from investigations.storage import db


def test_salvage_valid_passthrough():
    s = ('{"typed_relationships":[{"src_id":1,"dst_id":2,"rel_type":"x"}],'
         '"clusters":[{"name":"A","member_ids":[1,2]}]}')
    out = analyze._salvage_json(s)
    assert len(out["typed_relationships"]) == 1
    assert len(out["clusters"]) == 1


def test_salvage_recovers_truncated_array():
    # 2 complete relationships, then a 3rd cut off mid-string (the real failure mode).
    s = ('{"typed_relationships":[{"src_id":1,"dst_id":2,"rel_type":"a"},'
         '{"src_id":3,"dst_id":4,"rel_type":"b"},{"src_id":5,"dst_id":6,"rel_type":"unterm')
    out = analyze._salvage_json(s)
    assert len(out["typed_relationships"]) == 2  # the complete ones survive
    assert out["clusters"] == []                 # array never reached → empty, no crash


def test_salvage_strips_code_fence():
    s = '```json\n{"typed_relationships":[],"clusters":[{"name":"C","member_ids":[1]}]}\n```'
    out = analyze._salvage_json(s)
    assert len(out["clusters"]) == 1


def test_extract_objects_survives_quotes_and_braces_in_strings():
    # Quotes/braces INSIDE string values must not break the brace matcher.
    s = ('"clusters":[{"name":"a \\"q\\" and {brace}","member_ids":[1]},'
         '{"name":"b","member_ids":[2]}]')
    objs = analyze._extract_objects(s, "clusters")
    assert len(objs) == 2
    assert objs[0]["member_ids"] == [1]


def test_gather_context_is_case_scoped(tmp_path):
    p = tmp_path / "t.db"
    db.init_db(p)
    with db.connect(p) as conn:
        for rid, inv in [(1, "c1"), (2, "c2")]:
            conn.execute(
                "INSERT INTO reports (id,title,investigation,source_path,source_hash,"
                "source_type) VALUES (?,?,?,?,?,?)",
                (rid, f"r{rid}", inv, f"/x{rid}", f"h{rid}", "note"))
        eid = 1
        for inv, rid, count in [("c1", 1, 2), ("c2", 2, 3)]:
            for k in range(count):
                conn.execute(
                    "INSERT INTO entities (id,canonical_name,entity_type,notes) "
                    "VALUES (?,?,?,?)", (eid, f"{inv}_e{k}", "handle", "role:promoter"))
                conn.execute(
                    "INSERT INTO mentions (entity_id,report_id,surface_form,context) "
                    "VALUES (?,?,?,?)", (eid, rid, "x", "c"))
                eid += 1
        conn.commit()
        novault = tmp_path / "novault"
        ctx_c1 = analyze._gather_context(conn, novault, case="c1")
        ctx_all = analyze._gather_context(conn, novault, case=None)

    assert "ENTITIES (2):" in ctx_c1     # only c1's two entities
    assert "c2_e0" not in ctx_c1         # no leak from c2
    assert "ENTITIES (5):" in ctx_all    # unscoped still sees all five
