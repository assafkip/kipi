"""A stale `case` cookie (DB reset, deleted/renamed case) must NOT render a ghost
chip in the case selector, and must self-heal.

Reproduces the live bug: after `invctl reset` emptied the DB, the header still
showed `CASES case-a` because `_tpl` rendered the raw cookie without checking the
slug still existed. The fix prunes the selection in `_tpl` to slugs that exist and
rewrites the cookie on drift.

Run: .venv/bin/python -m investigations.tests.test_stale_case_cookie
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


def _seed_one_real_case(db_path: Path):
    db.init_db(db_path)
    with db.connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?, ?)",
            ("real-case", "Real Case"))
        db.insert_report(conn, "r.md", "h1", "markdown", "body", "real-case", "x")
        conn.commit()


def test_stale_cookie_is_pruned_and_healed(mp):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        _seed_one_real_case(db_path)

        # Point every app DB connection at the temp DB (default-arg binding means
        # we must patch the function, not db.DB_PATH).
        orig_connect = db.connect
        mp.setattr(app_module.db, "connect",
                   lambda migrate=True, db_path=db_path: orig_connect(db_path=db_path, migrate=migrate))

        client = TestClient(app_module.app)

        def _get(cookie_value):
            # Drive one request with an exact cookie; read the server's Set-Cookie
            # off the response (not the jar, which would merge sent + returned).
            client.cookies.clear()
            r = client.get("/alerts", headers={"cookie": f"{app_module.CASE_COOKIE}={cookie_value}"})
            return r, r.headers.get("set-cookie", "")

        # 1) Cookie mixes a real case with a ghost. Ghost is pruned, cookie healed.
        r, sc = _get("real-case,case-a")
        _check("page renders", r.status_code == 200)
        _check("ghost slug not shown in selector", "case-a" not in r.text)
        _check("real case still shown", "real-case" in r.text)
        _check("cookie healed to the real case only", "case=real-case" in sc and "case-a" not in sc)

        # 2) Cookie is ONLY a ghost (the exact live bug: empty/wrong selection).
        r, sc = _get("case-a")
        _check("page renders with all-ghost cookie", r.status_code == 200)
        _check("ghost-only slug not shown", "case-a" not in r.text)
        _check("cookie cleared when nothing real remains (Max-Age=0)",
               "case=" in sc and ('Max-Age=0' in sc or 'expires=' in sc.lower()))

        # 3) A clean cookie (real case) is left untouched — no needless rewrite.
        r, sc = _get("real-case")
        _check("real-only cookie preserved (no Set-Cookie rewrite)", "case=" not in sc)


def test_unprocessed_home_routes_by_stage(mp):
    # An ingested-but-unprocessed case has no scored focus, so the Focus page is a
    # dead end. Home routes forward to /reports (where Process runs). Schema is
    # auto-modeled inside Process now — there's no /schema step to route to
    # (founder decision 2026-06-10).
    from investigations import understand as understand_mod
    from investigations.tests.test_understand import CRYPTO_SCHEMA
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        _seed_one_real_case(db_path)  # report present, no schema → unprocessed
        orig_connect = db.connect
        mp.setattr(app_module.db, "connect",
                   lambda migrate=True, db_path=db_path: orig_connect(db_path=db_path, migrate=migrate))

        client = TestClient(app_module.app)
        hdr = {"cookie": f"{app_module.CASE_COOKIE}=real-case"}

        r = client.get("/", headers=hdr, follow_redirects=False)
        _check("unprocessed case → home routes to /reports (no schema step)",
               r.status_code == 302 and r.headers.get("location") == "/reports")


def main():
    # Fresh patch stack per test so each one's db.connect override resolves to its
    # own temp DB (stacked patches would cross paths between the two).
    for fn in (test_stale_cookie_is_pruned_and_healed, test_unprocessed_home_routes_by_stage):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_stale_case_cookie")


if __name__ == "__main__":
    main()
