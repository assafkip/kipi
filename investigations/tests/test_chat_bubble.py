"""The unified investigator chat is an always-available floating component (every
page), not a sidebar link. One chat with everything (grounded Q&A + investigator +
graph control + case creation), backed by /api/chat (prd-unified-chat 2026-06-08).
Guards that the chat is on every page and the old sidebar link is gone.

Run: .venv/bin/python -m investigations.tests.test_chat_bubble
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


def test_bubble_on_every_page(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        for path in ("/cases", "/reports", "/graph", "/entities"):
            html = c.get(path).text
            # signature-agnostic: caseChat gained a `docked` param for the dual
            # corner/docked layout — match the opener, not the empty-paren form.
            _check(f"{path}: unified chat present", "function caseChat(" in html)
            _check(f"{path}: chat wired to /api/chat", "/api/chat" in html)


def test_no_sidebar_chat_link(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/graph").text
        _check("the old sidebar Chat sub-link is gone", "sidelink('/ask'" not in html)


def main():
    for fn in (test_bubble_on_every_page, test_no_sidebar_chat_link):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_chat_bubble")


if __name__ == "__main__":
    main()
