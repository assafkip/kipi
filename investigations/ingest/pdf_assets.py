"""PDF image extraction + OCR. Uses pypdfium2 (BSD-licensed pdfium — Chrome's
PDF engine) to pull page text, render scanned pages, and decode embedded image
objects. Replaced PyMuPDF 2026-06-10: it is AGPL and was the one
license-constraining dependency (see q-system/output/oss-license-decision.md);
pdfium covers the same surface with no outbound-license strings."""
import io
import re
from dataclasses import dataclass, field
from pathlib import Path

from investigations.ingest.screenshot import ocr_image_object

# A page whose text layer yields fewer than this many chars is treated as
# scanned/image-only → rendered to an image and OCR'd in full.
MIN_PAGE_TEXT_CHARS = 25
OCR_DPI = 200

HEADER_PATTERNS = [
    re.compile(r"^\s*International Online Crime Coordination Center.*$", re.MULTILINE),
    re.compile(r"^\s*Intelligence\s*$", re.MULTILINE),
    re.compile(r"^\s*(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\w*,?\s+\d{1,2}\w*\s+of\s+\w+\s+\d{4}\s*$",
               re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Page\s+\d+\s+of\s+\d+\s*$", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*\d{1,4}\s*$", re.MULTILINE),
]


@dataclass
class ExtractedAsset:
    page_number: int
    image_index: int
    saved_path: Path
    ocr_text: str = ""


@dataclass
class ExtractedPDF:
    text: str
    assets: list[ExtractedAsset] = field(default_factory=list)


def strip_headers(text: str) -> str:
    for pat in HEADER_PATTERNS:
        text = pat.sub("", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _page_images(page):
    """Decoded embedded image objects on a page as PIL images. Uses pdfium's
    own decoder (get_bitmap) so filtered encodings (CCITT, JBIG2, JPX) come
    out as plain bitmaps instead of undecodable raw streams. Default recursion
    depth (15) so images nested in Form XObjects aren't silently missed; the
    same image drawn multiple times on a page is deduped by content hash (the
    old xref-keyed path never double-extracted reused XObjects)."""
    import hashlib

    import pypdfium2 as pdfium

    out, seen = [], set()
    for obj in page.get_objects(filter=(pdfium.raw.FPDF_PAGEOBJ_IMAGE,)):
        try:
            pil = obj.get_bitmap(render=False).to_pil()
        except Exception:
            continue
        digest = hashlib.md5(pil.tobytes()).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        out.append(pil)
    return out


def extract(pdf_path: Path, assets_dir: Path, min_size: int = 80) -> ExtractedPDF:
    """Extract text + embedded images. OCRs each image. Saves images to assets_dir.

    min_size: skip tiny images (logos, decorations) below this pixel dimension."""
    import pypdfium2 as pdfium

    assets_dir.mkdir(parents=True, exist_ok=True)
    text_parts: list[str] = []
    extracted_assets: list[ExtractedAsset] = []

    doc = pdfium.PdfDocument(str(pdf_path))
    try:
        for page_index in range(len(doc)):
            page = doc[page_index]
            page_num = page_index + 1
            try:
                textpage = page.get_textpage()
                try:
                    page_text = textpage.get_text_range() or ""
                finally:
                    textpage.close()
                page_text = strip_headers(page_text)

                # Full-page OCR for scanned / image-only pages (no usable text layer).
                if len(page_text.strip()) < MIN_PAGE_TEXT_CHARS:
                    try:
                        pil = page.render(scale=OCR_DPI / 72).to_pil()
                        page_img = assets_dir / f"page_{page_num:03d}_fullpage.png"
                        pil.save(page_img, format="PNG")
                        ocr = ocr_image_object(pil)
                        if ocr:
                            page_text = ocr
                            extracted_assets.append(ExtractedAsset(
                                page_number=page_num, image_index=0,
                                saved_path=page_img, ocr_text=ocr))
                    except Exception:
                        pass

                if page_text:
                    text_parts.append(f"\n\n--- PAGE {page_num} ---\n{page_text}")

                for img_idx, pil in enumerate(_page_images(page)):
                    if pil.width < min_size or pil.height < min_size:
                        continue
                    filename = f"page_{page_num:03d}_img_{img_idx:02d}.png"
                    saved = assets_dir / filename
                    try:
                        pil.save(saved, format="PNG")
                    except Exception:
                        continue
                    try:
                        ocr_text = ocr_image_object(pil).strip()
                    except Exception:
                        ocr_text = ""
                    extracted_assets.append(ExtractedAsset(
                        page_number=page_num,
                        image_index=img_idx,
                        saved_path=saved,
                        ocr_text=ocr_text,
                    ))
                    if ocr_text:
                        text_parts.append(
                            f"\n[IMAGE p{page_num} #{img_idx} → {filename}]\n{ocr_text}"
                        )
            finally:
                page.close()
    finally:
        doc.close()

    return ExtractedPDF(text="".join(text_parts).strip(), assets=extracted_assets)
