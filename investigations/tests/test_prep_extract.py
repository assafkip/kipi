"""The 'brush' before a whole-case investigator pass: _prep_extract must re-extract
report TEXT into entities so a re-run can investigate artifacts the prior run left as
prose (not just the auto-promoted findings). Tested deterministically via the no-schema
path (re-extract runs; typing is gated on an approved schema, so no LLM call here).

Run: .venv/bin/python -m investigations.tests.test_prep_extract
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.webapp import app as app_module


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_prep_extracts_text_artifacts_no_schema():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)
        # A report whose TEXT mentions a wallet + domain that aren't entities yet —
        # exactly the "stuck in the fur" case: surfaced by OSINT, never extracted.
        body = ("OSINT note: scam infra at evil-doubler.io collects to "
                "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh — also seen on payout-now.io")
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations(slug,case_name) VALUES('cx','CX')")
            db.insert_report(conn, "osint.md", "h1", "enrichment", "OSINT", "cx", body)
            conn.commit()
            before = conn.execute("SELECT COUNT(*) c FROM entities").fetchone()["c"]

        # Point the helper's db at the temp DB, capture the event stream.
        orig = db.connect
        app_module.db.connect = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
        events = []
        try:
            app_module._prep_extract("cx", on_event=events.append)
        finally:
            app_module.db.connect = orig

        with db.connect(dbp) as conn:
            after = conn.execute("SELECT COUNT(*) c FROM entities").fetchone()["c"]
            names = [r["canonical_name"] for r in conn.execute("SELECT canonical_name FROM entities")]

        _check("re-extract created entities from report text", after > before)
        _check("the wallet became an entity",
               any("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" in n for n in names))
        _check("a domain became an entity", any("evil-doubler.io" in n for n in names))
        _check("emitted a re-extract event", any("re-extracting" in e for e in events))
        _check("typing skipped without an approved schema",
               any("skipped typing" in e for e in events))


def main():
    test_prep_extracts_text_artifacts_no_schema()
    print("\nPASS: test_prep_extract")


if __name__ == "__main__":
    main()
