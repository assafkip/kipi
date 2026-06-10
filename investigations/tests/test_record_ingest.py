"""Structured CSV ingest: columns become TYPED entities, one dataset report.

Run: .venv/bin/python -m investigations.tests.test_record_ingest
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.ingest import record_ingest
from investigations.cli import invctl

CSV = """name,wallet,email,domain,note
Alice Smith,0x1111111111111111111111111111111111111111,alice@evil.com,evil-shop.com,promoter
Bob Jones,0x2222222222222222222222222222222222222222,bob@evil.com,evil-shop.com,dev
"""


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def test_csv_columns_typed():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        csv = Path(d) / "actors.csv"
        csv.write_text(CSV, encoding="utf-8")
        with db.connect(dbp) as conn:
            out = record_ingest.ingest(conn, csv, "hash1", "case-data")
            assert out, "csv should ingest"
            _check("typed 4 columns (name/wallet/email/domain)", out["typed_columns"], 4)

            # The dataset report.
            ek = conn.execute("SELECT evidence_kind, source_type FROM reports WHERE id=?",
                              (out["report_id"],)).fetchone()
            _check("report tagged dataset", ek["evidence_kind"], "dataset")

            # Typed entities exist with the right surface type + case_type.
            w = conn.execute("SELECT entity_type, case_type FROM entities WHERE canonical_name=?",
                             ("0x1111111111111111111111111111111111111111",)).fetchone()
            assert w, "wallet entity not created"
            _check("wallet typed as crypto_wallet", w["entity_type"], "crypto_wallet")
            _check("wallet case_type set", w["case_type"], "crypto_wallet")

            em = conn.execute("SELECT entity_type FROM entities WHERE canonical_name=?",
                              ("alice@evil.com",)).fetchone()
            _check("email typed", em["entity_type"], "email")

            dom = conn.execute("SELECT COUNT(*) FROM entities WHERE canonical_name=? AND entity_type='domain'",
                               ("evil-shop.com",)).fetchone()[0]
            _check("shared domain deduped to one entity", dom, 1)

            person = conn.execute("SELECT COUNT(*) FROM entities WHERE entity_type='person'").fetchone()[0]
            assert person >= 2, f"name column should yield person entities, got {person}"

            # The 'note' column (promoter/dev) is NOT a typed entity column.
            note_ent = conn.execute("SELECT COUNT(*) FROM entities WHERE canonical_name='promoter'").fetchone()[0]
            _check("untyped column not turned into entities", note_ent, 0)
            print(f"  ok  {out['entities']} typed entities from {out['rows']} rows")


def test_dispatch_routes_csv():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        csv = Path(d) / "x.csv"
        csv.write_text(CSV, encoding="utf-8")
        with db.connect(dbp) as conn:
            rid = invctl._ingest_one(conn, csv, "case-data")
            assert rid, "_ingest_one should route .csv through record_ingest"
            ek = conn.execute("SELECT evidence_kind FROM reports WHERE id=?", (rid,)).fetchone()[0]
            _check("dispatch produced a dataset report", ek, "dataset")


def main():
    test_csv_columns_typed()
    test_dispatch_routes_csv()
    print("\nPASS: test_record_ingest")


if __name__ == "__main__":
    main()
