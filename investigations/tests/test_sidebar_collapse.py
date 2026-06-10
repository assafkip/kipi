"""PRD-06 (reduce complexity): the Investigate stage's 5 links (Graph / Runs / Enrich /
Chat / Entities) collapse to ONE sidebar item by default, and reveal as indented
sub-tabs only when you're in the Investigate section. Cuts the first-timer's sidebar
from a wall of 13 to ~9.

Run: .venv/bin/python -m investigations.tests.test_sidebar_collapse
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


def test_collapsed_off_section(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/cases").text  # not an investigate page
        _check("single 'Investigate' item present", ">Investigate<" in html)
        _check("Runs sub-tab hidden when off-section", "Runs &amp; findings" not in html
               and "Runs & findings" not in html)
        _check("Enrich sub-tab hidden when off-section", ">Enrich<" not in html)


def test_expanded_in_section(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/graph").text  # an investigate page
        _check("Graph sub-tab shown in-section", ">Graph<" in html)
        _check("Enrich sub-tab shown in-section", ">Enrich<" in html)
        # Chat is no longer a sidebar sub-tab — it moved to the always-on bubble.
        _check("Chat is the always-on bubble, not a side link", "Ask the case" in html)


def main():
    for fn in (test_collapsed_off_section, test_expanded_in_section):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_sidebar_collapse")


if __name__ == "__main__":
    main()
