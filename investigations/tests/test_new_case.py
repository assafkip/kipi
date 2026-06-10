"""The web UI must be able to create a case directly (no CLI). POST /api/cases
creates an empty investigation row, makes it the active case (sets the cookie),
and is idempotent on a repeated name.

Run: .venv/bin/python -m investigations.tests.test_new_case
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


def _client(db_path, mp):
    db.init_db(db_path)
    orig_connect = db.connect
    mp.setattr(app_module.db, "connect",
               lambda migrate=True, db_path=db_path: orig_connect(db_path=db_path, migrate=migrate))
    return TestClient(app_module.app)


def test_create_case_from_ui(mp):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        client = _client(db_path, mp)
        client.cookies.clear()

        r = client.post("/api/cases", data={"name": "Case A Hacktivists", "client": "Acme Intel"},
                        follow_redirects=False)
        d = r.json()
        _check("create returns ok + slug", r.status_code == 200 and d["ok"] and d["slug"] == "case-a-hacktivists")
        _check("create did not flag pre-existing", d["existed"] is False)
        _check("active-case cookie set to new slug",
               r.cookies.get("case") == "case-a-hacktivists")

        with db.connect(db_path) as conn:
            row = conn.execute(
                "SELECT slug, case_name, client FROM investigations WHERE slug = ?",
                ("case-a-hacktivists",)).fetchone()
        _check("row persisted with name + client",
               row is not None and row["case_name"] == "Case A Hacktivists" and row["client"] == "Acme Intel")


def test_duplicate_is_idempotent(mp):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        client = _client(db_path, mp)

        client.cookies.clear()
        client.post("/api/cases", data={"name": "Same Case"}, follow_redirects=False)
        client.cookies.clear()
        r2 = client.post("/api/cases", data={"name": "Same Case"}, follow_redirects=False)
        d2 = r2.json()
        _check("second create flags existed", d2["ok"] and d2["existed"] is True)

        with db.connect(db_path) as conn:
            n = conn.execute(
                "SELECT COUNT(*) c FROM investigations WHERE slug = ?", ("same-case",)).fetchone()["c"]
        _check("only one row exists", n == 1)


def test_empty_name_rejected(mp):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        client = _client(db_path, mp)
        client.cookies.clear()
        r = client.post("/api/cases", data={"name": "  !! "}, follow_redirects=False)
        _check("blank/symbol-only name → 400", r.status_code == 400 and "error" in r.json())


def main():
    for fn in (test_create_case_from_ui, test_duplicate_is_idempotent, test_empty_name_rejected):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_new_case")


if __name__ == "__main__":
    main()
