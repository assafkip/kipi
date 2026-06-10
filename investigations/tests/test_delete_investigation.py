"""Delete an entire investigation: cascade + cross-case entity safety.

Run: .venv/bin/python -m investigations.tests.test_delete_investigation

Proves db.delete_investigation removes the case and everything scoped to it
(reports, exclusive entities, schema, agent runs) while entities SHARED with
another case survive and the other case is untouched.
"""
import tempfile
from pathlib import Path

from investigations.storage import db


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _seed(conn):
    # case-a: two reports, an exclusive entity, a shared entity, schema, objective.
    ra1 = db.insert_report(conn, "a1.md", "ha1", "markdown", "A1", "case-a", "alpha")
    ra2 = db.insert_report(conn, "a2.md", "ha2", "markdown", "A2", "case-a", "beta")
    excl = db.upsert_entity(conn, "0xEXCLUSIVE", "crypto_wallet", ra1)   # only in case-a
    shared = db.upsert_entity(conn, "@shared_actor", "username", ra1)    # also in case-b
    db.add_mention(conn, excl, ra1, "0xEXCLUSIVE", "ctx")
    db.add_mention(conn, shared, ra2, "@shared_actor", "ctx")
    db.set_objective(conn, "case-a", "map the crew")
    conn.execute("INSERT OR REPLACE INTO case_schemas (case_slug, schema_json, status) "
                 "VALUES (?, ?, 'approved')", ("case-a", "{}"))
    # An agent enrichment run + result scoped to case-a.
    rid = conn.execute(
        "INSERT INTO enrichment_runs (provider_slug, query, status, investigation) "
        "VALUES ('perplexity', 'q', 'done', 'case-a')").lastrowid
    conn.execute("INSERT INTO enrichment_results (run_id, title) VALUES (?, 'finding')", (rid,))

    # case-b: its own report, mentions the SHARED entity too.
    rb1 = db.insert_report(conn, "b1.md", "hb1", "markdown", "B1", "case-b", "gamma")
    db.add_mention(conn, shared, rb1, "@shared_actor", "ctx")
    conn.commit()
    return {"excl": excl, "shared": shared, "rb1": rb1}


def test_delete_cascade_and_cross_case_safety():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            ids = _seed(conn)

            res = db.delete_investigation(conn, "case-a")
            _check("returns ok", res.get("ok") is True)
            _check("counted 2 reports removed", res["reports_removed"] == 2)
            _check("counted the agent run removed", res["runs_removed"] == 1)

            gone = lambda q, p: conn.execute(q, p).fetchone() is None
            _check("investigations row gone",
                   gone("SELECT 1 FROM investigations WHERE slug='case-a'", ()))
            _check("case-a reports gone",
                   conn.execute("SELECT COUNT(*) FROM reports WHERE investigation='case-a'").fetchone()[0] == 0)
            _check("case_schemas row gone",
                   gone("SELECT 1 FROM case_schemas WHERE case_slug='case-a'", ()))
            _check("agent runs gone",
                   conn.execute("SELECT COUNT(*) FROM enrichment_runs WHERE investigation='case-a'").fetchone()[0] == 0)
            _check("agent results gone (cascaded by run_id)",
                   conn.execute("SELECT COUNT(*) FROM enrichment_results").fetchone()[0] == 0)
            _check("exclusive entity deleted",
                   gone("SELECT 1 FROM entities WHERE id=?", (ids["excl"],)))

            # Cross-case safety: shared entity + case-b survive intact.
            _check("shared entity SURVIVES",
                   conn.execute("SELECT 1 FROM entities WHERE id=?", (ids["shared"],)).fetchone() is not None)
            _check("case-b report intact",
                   conn.execute("SELECT 1 FROM reports WHERE id=?", (ids["rb1"],)).fetchone() is not None)
            _check("shared entity still mentioned in case-b",
                   conn.execute("SELECT COUNT(*) FROM mentions WHERE entity_id=?", (ids["shared"],)).fetchone()[0] >= 1)


def test_delete_with_node_properties_and_entity_runs():
    """Reproducer: an exclusive entity that has node_properties + an entity-scoped
    enrichment run/result (the shape a real dug case has) must delete cleanly. Before the
    fix the entity DELETE hit 'FOREIGN KEY constraint failed' because node_properties and
    enrichment_runs.entity_id / enrichment_results.extracted_entity_id weren't cleared."""
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-x", "x")
            ent = db.upsert_entity(conn, "evil.com", "domain", rid)
            db.add_mention(conn, ent, rid, "evil.com", "ctx")
            # typed properties on the node (graph-model-hardening)
            conn.execute("INSERT INTO node_properties (entity_id, key, value, value_type) "
                         "VALUES (?, 'registrar', 'NameCheap', 'string')", (ent,))
            # an enrichment run keyed to the ENTITY (not just the investigation) + a result
            # whose extracted_entity_id points at it
            run = conn.execute(
                "INSERT INTO enrichment_runs (entity_id, provider_slug, query, status, "
                "investigation) VALUES (?, 'infra', 'q', 'done', 'case-x')", (ent,)).lastrowid
            conn.execute("INSERT INTO enrichment_results (run_id, title, extracted_entity_id) "
                         "VALUES (?, 'r', ?)", (run, ent))
            conn.commit()

            res = db.delete_investigation(conn, "case-x")
            _check("delete succeeds (no FK violation)", res.get("ok") is True)
            _check("entity removed", conn.execute(
                "SELECT 1 FROM entities WHERE id=?", (ent,)).fetchone() is None)
            _check("no orphan node_properties", conn.execute(
                "SELECT COUNT(*) FROM node_properties").fetchone()[0] == 0)
            _check("no orphan enrichment_runs", conn.execute(
                "SELECT COUNT(*) FROM enrichment_runs").fetchone()[0] == 0)
            _check("no orphan enrichment_results", conn.execute(
                "SELECT COUNT(*) FROM enrichment_results").fetchone()[0] == 0)


def test_delete_objective_only_case():
    # A case with an objective but zero reports must still delete cleanly.
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            db.set_objective(conn, "empty-case", "just a goal, no files yet")
            _check("case row exists pre-delete",
                   conn.execute("SELECT 1 FROM investigations WHERE slug='empty-case'").fetchone() is not None)
            res = db.delete_investigation(conn, "empty-case")
            _check("ok with zero reports", res.get("ok") is True and res["reports_removed"] == 0)
            _check("case row gone",
                   conn.execute("SELECT 1 FROM investigations WHERE slug='empty-case'").fetchone() is None)


def test_delete_missing_case():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            res = db.delete_investigation(conn, "nope")
            _check("missing case → error", res.get("error") == "investigation not found")


def main():
    test_delete_cascade_and_cross_case_safety()
    test_delete_with_node_properties_and_entity_runs()
    test_delete_objective_only_case()
    test_delete_missing_case()
    print("\nPASS: test_delete_investigation")


if __name__ == "__main__":
    main()
