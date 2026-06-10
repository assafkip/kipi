"""Extract text from a .docx (Word) file, with OCR of embedded images.

A .docx is a zip: word/document.xml holds the body text; word/media/ holds
embedded images. We pull every run's text (joined per paragraph) plus tables,
then OCR each embedded image and append it, so a Word report with screenshots
ingests with its image text too.
"""
from __future__ import annotations

import io
import zipfile
from xml.etree import ElementTree as ET

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_IMG_EXTS = (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif", ".webp")


def _ocr_media(z: zipfile.ZipFile) -> list[str]:
    """OCR every image under word/media/. Returns one text block per image that
    yields text. Best-effort: missing PIL/tesseract → no image text, no error."""
    try:
        from PIL import Image
        from investigations.ingest.screenshot import ocr_image_object
    except ImportError:
        return []
    out: list[str] = []
    for name in z.namelist():
        if not name.lower().startswith("word/media/"):
            continue
        if not name.lower().endswith(_IMG_EXTS):
            continue
        try:
            img = Image.open(io.BytesIO(z.read(name)))
            text = ocr_image_object(img)
        except Exception:
            continue
        if text.strip():
            out.append(f"\n[IMAGE {name.split('/')[-1]} (OCR)]\n{text.strip()}")
    return out


def extract_text(path) -> str:
    with zipfile.ZipFile(path) as z:
        try:
            xml = z.read("word/document.xml")
        except KeyError:
            raise ValueError("not a Word .docx (no word/document.xml)")
        root = ET.fromstring(xml)

        lines: list[str] = []
        body = root.find(f"{_W}body") or root
        for el in body.iter():
            if el.tag == f"{_W}p":                       # paragraph
                text = "".join(t.text or "" for t in el.iter(f"{_W}t"))
                if text.strip():
                    lines.append(text)
            elif el.tag == f"{_W}tr":                    # table row -> tab-joined cells
                cells = []
                for tc in el.iter(f"{_W}tc"):
                    cells.append("".join(t.text or "" for t in tc.iter(f"{_W}t")).strip())
                row = "\t".join(c for c in cells if c)
                if row.strip():
                    lines.append(row)

        # OCR embedded images (read inside the open zip).
        lines.extend(_ocr_media(z))
    return "\n".join(lines)
