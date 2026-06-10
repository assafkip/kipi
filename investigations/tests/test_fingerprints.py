"""Cross-domain correlation by shared fingerprint + re-extraction backfill.

Run: .venv/bin/python -m investigations.tests.test_fingerprints
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import reextract, fingerprints


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def _ingest(conn, report_id_seed, text, case):
    """Minimal ingest: a report + re-extract into it."""
    rid = db.insert_report(conn, f"r{report_id_seed}.md", f"h{report_id_seed}",
                           "markdown", f"R{report_id_seed}", case, text)
    reextract.reextract_report(conn, rid, text)
    return rid


def test_reextract_finds_fingerprints():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            txt = "Site uses Google Analytics G-ABCD1234XY and a JivoSite account ID Y0q86ZSjlX."
            rid = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", txt)
            out = reextract.reextract_report(conn, rid, txt)
            assert out["by_type"].get("tracking_tag", 0) >= 1, out["by_type"]
            t = conn.execute("SELECT COUNT(*) FROM entities WHERE entity_type='tracking_tag'").fetchone()[0]
            _check("tracking_tag now exists after re-extract", t, 1)


def test_within_report_proximity_link():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            # a.com + b.com share GA tag (near it); c.com is far away on a different ns.
            txt = ("Domain a-site.com uses Google Analytics G-SHARED1234. "
                   "Domain b-site.com also uses G-SHARED1234 on the same page. "
                   + ("filler. " * 80) +
                   "Separately, c-site.com runs on nameserver Name Server: evil.ns.example.")
            _ingest(conn, 1, txt, "case-a")
            res = fingerprints.correlate(conn, "case-a")
            assert res["edges_created"] >= 2, res
            sh = fingerprints.shared(conn, "case-a")
            tags = [s for s in sh if s["type"] == "tracking_tag"]
            assert tags, f"expected a shared tracking_tag hub, got {sh}"
            partners = {p["name"] for p in tags[0]["partners"]}
            _check("GA tag links both sharing domains",
                   {"a-site.com", "b-site.com"} <= partners, True)
            assert "c-site.com" not in partners, "far domain should NOT be linked to the tag"
            print("  ok  proximity kept the unrelated far domain out of the tag hub")


def test_cross_report_link():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            # Same GA tag in TWO separate reports, each about a different domain.
            _ingest(conn, 1, "alpha-shop.com analytics tag G-CROSS9999 confirmed.", "case-a")
            _ingest(conn, 2, "beta-shop.com also carries analytics tag G-CROSS9999.", "case-a")
            res = fingerprints.correlate(conn, "case-a")
            sh = fingerprints.shared(conn, "case-a")
            hub = next((s for s in sh if s["fingerprint"] == "g-cross9999"), None)
            assert hub, f"cross-report tag hub missing: {sh}"
            names = {p["name"] for p in hub["partners"]}
            _check("cross-report GA tag links domains from both reports",
                   {"alpha-shop.com", "beta-shop.com"} <= names, True)


def main():
    test_reextract_finds_fingerprints()
    test_within_report_proximity_link()
    test_cross_report_link()
    print("\nPASS: test_fingerprints")


if __name__ == "__main__":
    main()
