"""PRD-06 (self-explaining UI / first-run): a junior analyst who has never seen a tool
like this ("Maya") must land on a map, not a wall of 13 nav links. The first-run
welcome frames the 5 steps + one place to start, shows once (localStorage), and is
reopenable from "How it works". Guards that it's present + wired on every page (it
lives in the shared layout).

Run: .venv/bin/python -m investigations.tests.test_first_run_welcome
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


# The first-run welcome modal was REMOVED on purpose (founder call: a daily
# tool, not a tour — the modal covered the actual feature; decision recorded
# as a comment in _layout.html). These tests now pin the REMOVAL so the modal
# cannot silently creep back.


def test_welcome_modal_stays_removed(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        for path in ("/cases", "/simple"):
            html = c.get(path).text
            _check(f"{path}: no welcome modal", "New here? Here's how it works." not in html)
            _check(f"{path}: no welcome localStorage flag", "kipi_welcome_seen" not in html)


def test_removal_decision_is_recorded_in_layout(mp):
    layout = (Path(__file__).resolve().parents[1] /
              "webapp" / "templates" / "_layout.html").read_text()
    _check("removal decision comment present",
           "welcome modal removed" in layout)


def main():
    for fn in (test_welcome_modal_stays_removed, test_removal_decision_is_recorded_in_layout):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_first_run_welcome")


if __name__ == "__main__":
    main()
