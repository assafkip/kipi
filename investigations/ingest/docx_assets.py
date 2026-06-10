"""DOCX image extraction + OCR. A .docx is a zip: word/document.xml holds the
body text; word/media/ holds embedded images. This mirrors pdf_assets: it pulls
the body text AND saves each embedded image as an asset (OCR'd), so a Word report
full of email screenshots ingests with each image viewable in Sources — not just
folded into the report's text.
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

from investigations.ingest.screenshot import ocr_image_object

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_IMG_EXTS = (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif", ".webp")


@dataclass
class ExtractedAsset:
    page_number: int | None
    image_index: int
    saved_path: Path
    ocr_text: str = ""


@dataclass
class ExtractedDocx:
    text: str
    assets: list[ExtractedAsset] = field(default_factory=list)


def _body_text(z: zipfile.ZipFile) -> str:
    """Paragraph + table text from word/document.xml (no image OCR folded in)."""
    try:
        xml = z.read("word/document.xml")
    except KeyError:
        raise ValueError("not a Word .docx (no word/document.xml)")
    root = ET.fromstring(xml)
    lines: list[str] = []
    body = root.find(f"{_W}body") or root
    for el in body.iter():
        if el.tag == f"{_W}p":
            text = "".join(t.text or "" for t in el.iter(f"{_W}t"))
            if text.strip():
                lines.append(text)
        elif el.tag == f"{_W}tr":
            cells = ["".join(t.text or "" for t in tc.iter(f"{_W}t")).strip()
                     for tc in el.iter(f"{_W}tc")]
            row = "\t".join(c for c in cells if c)
            if row.strip():
                lines.append(row)
    return "\n".join(lines)


def extract(docx_path: Path, assets_dir: Path) -> ExtractedDocx:
    """Body text + every embedded image (saved to assets_dir, each OCR'd).

    Best-effort on images: a missing PIL/tesseract or an unreadable image yields
    no OCR text for that image, never an error.
    """
    assets_dir.mkdir(parents=True, exist_ok=True)
    assets: list[ExtractedAsset] = []
    with zipfile.ZipFile(docx_path) as z:
        text = _body_text(z)
        try:
            from PIL import Image
        except ImportError:
            Image = None
        idx = 0
        for name in z.namelist():
            low = name.lower()
            if not low.startswith("word/media/") or not low.endswith(_IMG_EXTS):
                continue
            idx += 1
            out_path = assets_dir / f"img{idx:03d}_{Path(name).name}"
            data = z.read(name)
            out_path.write_bytes(data)
            ocr_text = ""
            if Image is not None:
                try:
                    ocr_text = ocr_image_object(Image.open(io.BytesIO(data))).strip()
                except Exception:
                    ocr_text = ""
            assets.append(ExtractedAsset(
                page_number=None, image_index=idx, saved_path=out_path, ocr_text=ocr_text))
    return ExtractedDocx(text=text, assets=assets)
