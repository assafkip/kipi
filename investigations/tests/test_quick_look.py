"""PRD-03 Simple Mode: one seed creates a case behind the scenes and starts the full
investigator on it — no intake, no schema gate. Tests the /api/quick-look endpoint
(the agent thread is mocked so the test doesn't make live calls).

Run: .venv/bin/python -m investigations.tests.test_quick_look
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
    orig = db.connect
    mp.setattr(app_module.db, "connect",
               lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
    # Don't run the real agent in a test — record the dispatch instead.
    calls = []
    mp.setattr(app_module, "_investigate_job",
               lambda *a, **k: calls.append((a, k)))
    return TestClient(app_module.app), calls


def test_quick_look_creates_case_and_starts(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        client, calls = _client(dbp, mp)
        client.cookies.clear()
        r = client.post("/api/quick-look", json={"seed": "trump-2026.io"},
                        follow_redirects=False)
        d = r.json()
        _check("started", r.status_code == 200 and d["status"] == "started")
        _check("seed slugified to a case", d["case"] == "trump-2026-io")
        _check("quick-look case is made active (cookie)",
               r.cookies.get("case") == "trump-2026-io")

        with db.connect(dbp) as conn:
            row = conn.execute("SELECT case_name FROM investigations WHERE slug=?",
                               ("trump-2026-io",)).fetchone()
        _check("case row created", row is not None and "Quick look" in row["case_name"])
        # The investigator was dispatched on the seed (mocked), not the real agent.
        _check("agent dispatched on the seed",
               calls and calls[0][0][0] == "trump-2026.io")


def test_empty_seed_rejected(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        client, _ = _client(dbp, mp)
        client.cookies.clear()
        r = client.post("/api/quick-look", json={"seed": "  "}, follow_redirects=False)
        _check("blank seed → 400", r.status_code == 400 and "error" in r.json())


def test_simple_page_renders(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        client, _ = _client(dbp, mp)
        r = client.get("/simple")
        _check("simple page renders", r.status_code == 200 and "Quick look" in r.text)


def main():
    for fn in (test_quick_look_creates_case_and_starts, test_empty_seed_rejected,
               test_simple_page_renders):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_quick_look")


if __name__ == "__main__":
    main()
