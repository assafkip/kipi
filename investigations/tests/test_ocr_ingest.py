"""XLSX structural ingest + PDF full-page OCR + DOCX image OCR.

Run: .venv/bin/python -m investigations.tests.test_ocr_ingest

OCR itself is stubbed (deterministic); a separate real-OCR smoke proves Tesseract.
The structured-XLSX path is exercised for real (no OCR needed).
"""
import io
import tempfile
import zipfile
from pathlib import Path

from investigations.storage import db
from investigations.ingest import record_ingest, pdf_assets, docx_ingest
from investigations.ingest import screenshot


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def test_xlsx_structural():
    from openpyxl import Workbook
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        xlsx = Path(d) / "actors.xlsx"
        wb = Workbook(); ws = wb.active
        ws.append(["name", "wallet", "email"])
        ws.append(["Alice Smith", "0x1111111111111111111111111111111111111111", "a@evil.com"])
        ws.append(["Bob Jones", "0x2222222222222222222222222222222222222222", "b@evil.com"])
        wb.save(xlsx)
        with db.connect(dbp) as conn:
            out = record_ingest.ingest(conn, xlsx, "h1", "case-x")
            assert out, "xlsx should ingest structurally"
            _check("typed 3 columns", out["typed_columns"], 3)
            st = conn.execute("SELECT source_type, evidence_kind FROM reports WHERE id=?",
                              (out["report_id"],)).fetchone()
            _check("source_type xlsx", st["source_type"], "xlsx")
            _check("dataset kind", st["evidence_kind"], "dataset")
            w = conn.execute("SELECT entity_type FROM entities WHERE canonical_name=?",
                             ("0x1111111111111111111111111111111111111111",)).fetchone()
            _check("wallet column typed", w["entity_type"], "crypto_wallet")


def test_pdf_fullpage_ocr(mp):
    from PIL import Image
    mp.setattr(pdf_assets, "ocr_image_object",
               lambda img, **k: "Scanned page: @scanguy ran scan-domain.com")
    with tempfile.TemporaryDirectory() as d:
        # Build a 1-page image-only PDF (no text layer): PIL saving an image
        # as PDF produces exactly a "scanned" page. No fitz/PyMuPDF — the
        # AGPL dep was swapped for pdfium (license decision 2026-06-10).
        pdf = Path(d) / "scanned.pdf"
        Image.new("RGB", (300, 200), "white").save(pdf, format="PDF")

        result = pdf_assets.extract(pdf, Path(d) / "assets")
        assert "scan-domain.com" in result.text, result.text[:200]
        assert any(a.image_index == 0 and "fullpage" in a.saved_path.name for a in result.assets), \
            "a rendered full-page asset should be recorded"
        print("  ok  scanned/image-only PDF page rendered + OCR'd into text")


def test_docx_image_ocr(mp):
    from PIL import Image
    mp.setattr(screenshot, "ocr_image_object",
               lambda img, **k: "Embedded shot: wallet 0xfeed")
    with tempfile.TemporaryDirectory() as d:
        img_bytes = io.BytesIO(); Image.new("RGB", (60, 30), "white").save(img_bytes, "PNG")
        docx = Path(d) / "memo.docx"
        doc_xml = ('<?xml version="1.0"?>'
                   '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                   '<w:body><w:p><w:r><w:t>Typed paragraph here.</w:t></w:r></w:p></w:body></w:document>')
        with zipfile.ZipFile(docx, "w") as z:
            z.writestr("word/document.xml", doc_xml)
            z.writestr("word/media/image1.png", img_bytes.getvalue())
        text = docx_ingest.extract_text(docx)
        assert "Typed paragraph here." in text, text
        assert "Embedded shot: wallet 0xfeed" in text, "embedded image OCR not appended"
        print("  ok  .docx body text + embedded-image OCR both extracted")


def main():
    test_xlsx_structural()
    mp = _MP()
    try:
        test_pdf_fullpage_ocr(mp)
    finally:
        mp.undo()
    mp = _MP()
    try:
        test_docx_image_ocr(mp)
    finally:
        mp.undo()
    print("\nPASS: test_ocr_ingest")


if __name__ == "__main__":
    main()


def test_pdf_repeated_image_dedupes():
    # The same image drawn N times on a page must extract ONCE (content-hash
    # dedup in _page_images — the old xref-keyed extractor never double-saved
    # reused XObjects). Drives _page_images directly with a fake page whose
    # object walk yields the same bitmap three times + one distinct image.
    from PIL import Image
    import pypdfium2 as pdfium
    from investigations.ingest import pdf_assets as pa

    class _FakeBitmap:
        def __init__(self, pil): self._pil = pil
        def to_pil(self): return self._pil

    class _FakeImgObj:
        type = pdfium.raw.FPDF_PAGEOBJ_IMAGE
        def __init__(self, pil): self._pil = pil
        def get_bitmap(self, render=False): return _FakeBitmap(self._pil)

    class _FakePage:
        def get_objects(self, filter=None, **kw):
            blue = Image.new("RGB", (120, 120), "blue")
            red = Image.new("RGB", (120, 120), "red")
            return [_FakeImgObj(blue), _FakeImgObj(blue.copy()),
                    _FakeImgObj(blue.copy()), _FakeImgObj(red)]

    out = pa._page_images(_FakePage())
    assert len(out) == 2, f"expected dedup to 2 distinct images, got {len(out)}"
