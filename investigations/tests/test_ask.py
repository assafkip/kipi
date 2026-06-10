"""Ask retrieval tests: ranking, scoping, full-vs-partial coverage, refusal.

The LLM synthesis step is not unit-tested (it shells out to the claude CLI);
these cover the deterministic parts — passage selection, coverage reporting,
the whole-report chunking, and the partial-mode refusal that keeps the
assistant from guessing when a case is too big to fit and nothing matched.

Run: .venv/bin/python -m investigations.tests.test_ask
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import ask


def _seed(conn):
    # A report whose raw_text has a marker PAST the old 9k head-slice cap, to
    # prove the whole report is now chunked (not just the first 6 chunks).
    raw = ("alpha " * 2000) + "ZEBRAMARKER deep infrastructure note"  # marker ~char 12000
    r = db.insert_report(conn, "r.pdf", "hr", "pdf", "NVE Report", "case-x", raw)
    db.add_asset(conn, r, "p1.png", "pdf_page", page_number=1, image_index=0,
                 ocr_text="Unydigma operates the channel and recruits new members daily")
    db.add_asset(conn, r, "p2.png", "pdf_page", page_number=2, image_index=0,
                 ocr_text="The hosting infrastructure resolves to 1.2.3.4 and a mirror")
    r2 = db.insert_report(conn, "o.pdf", "ho", "pdf", "Other", "case-y", "unrelated")
    db.add_asset(conn, r2, "o1.png", "pdf_page", page_number=1, image_index=0,
                 ocr_text="Different operation entirely with its own operators")
    conn.commit()
    return r, r2


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def main():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            r, r2 = _seed(conn)

            # 1) Small case fits the budget -> FULL coverage, every passage fed.
            hits, cov = ask.select(conn, "case-x", "who operates the channel")
            _check("coverage mode", cov["mode"], "full")
            _check("pct full", cov["pct"], 100)
            _check("used == total", cov["passages_used"], cov["passages_total"])
            assert hits, "expected passages"
            _check("top hit is the operator page", hits[0]["page_number"], 1)

            # 2) Whole report is chunked — a marker past the old 9k cap is reachable.
            zebra = ask.retrieve(conn, "case-x", "zebramarker")
            assert any("ZEBRAMARKER" in h["text"] for h in zebra), \
                "marker past the old head-slice cap was not retrieved"
            print("  ok  deep marker (past old 9k cap) is now retrievable")

            # 3) Case scoping: case-x selection never returns case-y pages.
            rids = {h["report_id"] for h in ask.retrieve(conn, "case-x", "operators operation")}
            _check("case-x excludes case-y report", r2 in rids, False)

            # 4) Oversized case (tiny budget forces partial): a match -> partial coverage.
            part, cov_p = ask.select(conn, "case-x", "infrastructure", char_budget=50)
            _check("partial mode", cov_p["mode"], "partial")
            assert part, "partial mode should still return the top passage(s)"
            assert cov_p["pct"] < 100, cov_p

            # 5) Oversized case + nothing matched -> refuse, do NOT feed a random slice.
            none_hits, cov_n = ask.select(conn, "case-x", "qwertzxcv nonsense", char_budget=50)
            _check("no-match refusal passages", none_hits, [])
            _check("no-match coverage mode", cov_n["mode"], "none")

            # 6) Source-link naming convention is stable.
            _check("vault image naming", ask._vault_image(7, "foo/bar.png"), "r0007_bar.png")

    print("\nPASS: test_ask")


if __name__ == "__main__":
    main()
