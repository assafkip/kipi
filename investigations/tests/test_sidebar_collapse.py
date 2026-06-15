"""The sidebar is FLAT by design (decision recorded in _layout.html: "Flat nav —
no lifecycle staging/wizard"; the chat+graph home does the investigating and
destinations retire as chat absorbs them). The old PRD-06 section-collapse
design is gone; these tests pin the FLAT contract so neither the collapse
machinery nor a nav wall creeps back.

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


FLAT_NAV = ("Chat + graph", "Reports &amp; intake", "Runs &amp; findings",
            "Enrich", "Entities", "Deliverables", "Inbox",
            "Cross-case", "Cross-domain")


def test_flat_nav_on_every_page(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        for path in ("/cases", "/graph"):
            html = c.get(path).text
            for label in FLAT_NAV:
                # Present from every page (a page body may legitimately reuse
                # a label like 'Enrich', so presence, not an exact count).
                _check(f"{path}: '{label}' present", f">{label}<" in html)
            _check(f"{path}: no section-collapse 'Investigate' parent",
                   ">Investigate<" not in html)


def test_flat_decision_recorded_in_layout(mp):
    layout = (Path(__file__).resolve().parents[1] /
              "webapp" / "templates" / "_layout.html").read_text()
    _check("flat-nav decision comment present", "Flat nav" in layout)


def main():
    for fn in (test_flat_nav_on_every_page, test_flat_decision_recorded_in_layout):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_sidebar_collapse")


if __name__ == "__main__":
    main()
