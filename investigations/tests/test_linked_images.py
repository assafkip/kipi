"""Deterministic tests for the gated linked-image capture. No real network: discover is
pure text, and scan_one's fetch is stubbed. Locks in the gate — discover NEVER fetches,
and an image only lands as an asset when scan_one is called for that specific id."""
from investigations.storage import db
from investigations.ingest import linked_images as li

# a valid 1x1 PNG so PIL's Image.open succeeds in scan_one's OCR step
PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c6360000002000154a24f680000000049454e44ae426082")


def _report(conn, rid, case, text):
    conn.execute(
        "INSERT INTO reports (id,title,investigation,source_path,source_hash,"
        "source_type,raw_text) VALUES (?,?,?,?,?,?,?)",
        (rid, f"r{rid}", case, f"/x{rid}", f"h{rid}", "markdown", text))


def test_discover_finds_urls_and_never_fetches(tmp_path, monkeypatch):
    monkeypatch.setattr(li, "_download",
                        lambda url: (_ for _ in ()).throw(AssertionError("discover must NOT fetch")))
    p = tmp_path / "t.db"
    db.init_db(p)
    with db.connect(p) as conn:
        _report(conn, 1, "c",
                "img http://haiyiplants.com/cdn/shop/files/a.png and https://x.com/b.jpg "
                "and a dup http://haiyiplants.com/cdn/shop/files/a.png plus non-image https://x.com/page")
        conn.commit()
        n = li.discover(conn, "c")
        cands = li.candidates(conn, "c")
    assert n == 2  # two unique image URLs; dup collapsed, non-image ignored
    assert all(c["status"] == "pending" for c in cands)
    assert {c["url"] for c in cands} == {
        "http://haiyiplants.com/cdn/shop/files/a.png", "https://x.com/b.jpg"}


def test_discover_is_idempotent(tmp_path):
    p = tmp_path / "t.db"
    db.init_db(p)
    with db.connect(p) as conn:
        _report(conn, 1, "c", "http://a.com/x.png")
        conn.commit()
        assert li.discover(conn, "c") == 1
        assert li.discover(conn, "c") == 0  # no duplicate candidates on a re-scan


def test_scan_one_fetches_ocrs_and_stores_asset(tmp_path, monkeypatch):
    monkeypatch.setattr(li, "ocr_image_object", lambda img, *a, **k: "OCRTEXT")
    p = tmp_path / "t.db"
    db.init_db(p)
    with db.connect(p) as conn:
        _report(conn, 1, "c", "http://a.com/x.png")
        conn.commit()
        li.discover(conn, "c")
        cid = li.candidates(conn, "c")[0]["id"]
        res = li.scan_one(conn, cid, fetcher=lambda url: (PNG_1x1, "image/png"))
        assert res["status"] == "fetched" and res["asset_id"]
        a = conn.execute("SELECT source_kind, ocr_text FROM assets WHERE id=?",
                         (res["asset_id"],)).fetchone()
        assert a["source_kind"] == "linked_image"
        assert a["ocr_text"] == "OCRTEXT"
        assert len(li.candidates(conn, "c", status="fetched")) == 1


def test_scan_one_non_image_errors_no_asset(tmp_path):
    p = tmp_path / "t.db"
    db.init_db(p)
    with db.connect(p) as conn:
        _report(conn, 1, "c", "http://a.com/x.png")
        conn.commit()
        li.discover(conn, "c")
        cid = li.candidates(conn, "c")[0]["id"]
        res = li.scan_one(conn, cid,
                          fetcher=lambda url: (_ for _ in ()).throw(ValueError("not an image")))
        assert res["status"] == "error"
        assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0


def test_skip_one_marks_rejected(tmp_path):
    p = tmp_path / "t.db"
    db.init_db(p)
    with db.connect(p) as conn:
        _report(conn, 1, "c", "http://a.com/x.png")
        conn.commit()
        li.discover(conn, "c")
        cid = li.candidates(conn, "c")[0]["id"]
        assert li.skip_one(conn, cid)["status"] == "skipped"
        assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0
