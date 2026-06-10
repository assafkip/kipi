"""PRD-06 (self-explaining UI): the stages Maya (the junior analyst) explicitly got
stuck on must explain themselves in plain language on the page — no naked jargon.
This guards the explainer copy against regression on the key surfaces.

Run: .venv/bin/python -m investigations.tests.test_stage_explainers
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.webapp import app as app_module


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def _client(dbp, mp):
    db.init_db(dbp)
    with db.connect(dbp) as conn:
        conn.execute("INSERT OR IGNORE INTO investigations(slug,case_name) VALUES('cx','CX')")
        conn.commit()
    orig = db.connect
    mp.setattr(app_module.db, "connect",
               lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
    c = TestClient(app_module.app)
    c.cookies.set("case", "cx")
    return c


def test_schema_page_defines_the_term(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/schema").text
        _check("schema page defines 'a schema is'", "A schema is the list of" in html)
        _check("schema page drops the 'typed + classified' jargon",
               "typed + classified" not in html)


def test_enrich_page_explains_enrichment(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/enrich").text
        _check("enrich page says what enrichment does", "Enrichment runs OSINT tools" in html)
        _check("enrich page drops the 'Configure env vars' jargon",
               "Configure env vars" not in html)


def test_simple_page_explains_itself(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/simple").text
        _check("simple page tells you what to drop in", "Drop one thing" in html)


def test_reports_page_says_what_it_is(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/reports").text
        _check("reports page frames 'your evidence'", "Your evidence" in html)
        _check("reports page says raw is fine", "Raw is fine" in html)


def test_entities_page_defines_entity(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/entities").text
        _check("entities page says what an entity is", "Every person, account" in html)


def test_graph_legend_explains_lines(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/graph").text
        _check("graph legend: dot = entity, line = connection",
               "Each dot is an entity" in html)
        _check("graph legend explains a known link + direction", "a known link" in html)


def main():
    for fn in (test_schema_page_defines_the_term, test_enrich_page_explains_enrichment,
               test_simple_page_explains_itself, test_reports_page_says_what_it_is,
               test_entities_page_defines_entity, test_graph_legend_explains_lines):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_stage_explainers")


if __name__ == "__main__":
    main()
