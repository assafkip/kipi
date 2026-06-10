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


def test_welcome_is_on_every_page(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        for path in ("/cases", "/simple"):
            html = c.get(path).text
            _check(f"{path}: welcome present", "New here? Here's how it works." in html)
            _check(f"{path}: 'How it works' reopener present", "How it works" in html)


def test_welcome_frames_the_four_steps_and_a_start(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(Path(tmp) / "t.db", mp)
        html = c.get("/cases").text
        # Schema/Understand step removed — the tool models the case itself.
        for step in ("Intake", "Investigate", "Deliver", "Portfolio"):
            _check(f"step framed: {step}", step in html)
        _check("no Understand/schema step in the welcome", "Understand" not in html)
        _check("offers the zero-setup start (Quick look)", "Try Quick look" in html)
        _check("offers the case start", "Start with a case" in html)
        _check("shows once via localStorage flag", "kipi_welcome_seen" in html)


def main():
    for fn in (test_welcome_is_on_every_page, test_welcome_frames_the_four_steps_and_a_start):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_first_run_welcome")


if __name__ == "__main__":
    main()
