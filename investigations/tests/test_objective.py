"""Objective (the case scope anchor): storage + threading through scoping.

Run: .venv/bin/python -m investigations.tests.test_objective

Covers the full chain the analyst's free-text objective flows through:
  db round-trip → Understand schema prompt → investigator thesis → synthesis brief.
No LLM calls — every check is on stored state or built prompt text.
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import understand, synthesize
from investigations.agent import investigator


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_db_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            # No case set yet → empty, never None.
            _check("missing case → ''", db.get_objective(conn, "case-x") == "")
            # Setting registers the case row even before any ingest.
            db.set_objective(conn, "case-x", "  confirm wallet 0xabc drained victims  ")
            _check("stored + trimmed",
                   db.get_objective(conn, "case-x") == "confirm wallet 0xabc drained victims")
            row = conn.execute("SELECT slug FROM investigations WHERE slug='case-x'").fetchone()
            _check("case row auto-registered", row is not None)
            # Blank clears it back to ''.
            db.set_objective(conn, "case-x", "   ")
            _check("blank → ''", db.get_objective(conn, "case-x") == "")
            # None case is safe.
            _check("None case → ''", db.get_objective(conn, None) == "")


def test_understand_prompt_includes_objective():
    base = {"report_count": 1, "report_text": "some text", "entity_types": {}}
    with_obj = dict(base, objective="map the drainer crew behind MOONCOIN")
    p_with = understand._build_prompt(with_obj)
    p_without = understand._build_prompt(dict(base, objective=""))
    _check("objective injected into schema prompt",
           "map the drainer crew behind MOONCOIN" in p_with)
    _check("ANALYST OBJECTIVE header present", "ANALYST OBJECTIVE" in p_with)
    _check("no objective → no header", "ANALYST OBJECTIVE" not in p_without)


def test_case_corpus_reads_objective():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            db.insert_report(conn, "r.md", "h", "markdown", "R", "case-y", "body")
            db.set_objective(conn, "case-y", "who controls the infra")
            conn.commit()
            corpus = understand._case_corpus(conn, "case-y")
            _check("corpus carries the objective",
                   corpus.get("objective") == "who controls the infra")


def test_investigator_thesis_prefers_objective():
    crypto_schema = {"domain": "crypto rug-pull", "summary": "promoters shill, devs drain"}
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            understand.save_schema(conn, "case-z", crypto_schema, status="approved", analyst="ally")
            # Schema present but no objective → thesis falls back to schema.
            thesis_schema = investigator._case_thesis(conn, "case-z")
            _check("falls back to schema domain", "crypto rug-pull" in thesis_schema)
            # Objective set → it wins outright.
            db.set_objective(conn, "case-z", "prove @kingpin runs the whole network")
            thesis_obj = investigator._case_thesis(conn, "case-z")
            _check("objective outranks schema",
                   thesis_obj == "prove @kingpin runs the whole network")


def test_synthesis_prompt_includes_objective():
    base = {"reports": [], "hubs_by_role": {}, "dossiers": {}}
    p_with = synthesize._build_prompt(dict(base, objective="attribute the breach to an actor"))
    p_without = synthesize._build_prompt(dict(base, objective=""))
    _check("objective leads the brief prompt",
           "attribute the breach to an actor" in p_with)
    _check("INVESTIGATION OBJECTIVE header present", "INVESTIGATION OBJECTIVE" in p_with)
    _check("no objective → no header", "INVESTIGATION OBJECTIVE" not in p_without)


def main():
    test_db_roundtrip()
    test_understand_prompt_includes_objective()
    test_case_corpus_reads_objective()
    test_investigator_thesis_prefers_objective()
    test_synthesis_prompt_includes_objective()
    print("\nPASS: test_objective")


if __name__ == "__main__":
    main()
