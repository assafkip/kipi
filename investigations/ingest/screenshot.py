"""Screenshot/image OCR ingestion. Multi-language: English + Arabic + Persian/Farsi
+ Hebrew + Russian + Chinese. Tries all languages by default; falls back to eng.

Drives the `tesseract` binary directly via subprocess + STDIN (not a file path).
Why stdin: leptonica 1.87 built with libcurl mis-handles local file-path args
("failed to open locally with tail …"), and pytesseract's error path crashes on
Python 3.14 when decoding tesseract stderr. Piping image bytes to `tesseract -
stdout` sidesteps both and is deterministic.
"""
import io
import shutil
import subprocess
from pathlib import Path

DEFAULT_LANGS = "eng+ara+fas+heb+rus+chi_sim"
_TESSERACT = shutil.which("tesseract") or "tesseract"
_OCR_TIMEOUT = 120


def _run_tesseract(img_bytes: bytes, langs: str) -> str:
    """OCR raw image bytes via `tesseract - stdout -l <langs>`. '' on any failure."""
    if not img_bytes:
        return ""
    try:
        proc = subprocess.run(
            [_TESSERACT, "-", "stdout", "-l", langs],
            input=img_bytes, capture_output=True, timeout=_OCR_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode("utf-8", errors="replace").strip()


def _to_png_bytes(img) -> bytes:
    """A PIL Image → PNG bytes (tesseract reads PNG reliably from stdin)."""
    try:
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return b""


def ocr_image_object(img, langs: str = DEFAULT_LANGS) -> str:
    """OCR an in-memory PIL Image, returning raw text (no header wrapper). Used by
    the PDF full-page and DOCX-image OCR paths. Multi-language with eng fallback."""
    data = _to_png_bytes(img)
    return _run_tesseract(data, langs) or _run_tesseract(data, "eng")


def extract_text(path: Path, langs: str = DEFAULT_LANGS) -> str:
    """OCR an image FILE (the .png/.jpg ingest path). Wraps the text with a header;
    returns a clearly-marked failure string so callers can detect + skip it."""
    path = Path(path)
    try:
        data = path.read_bytes()
    except Exception as exc:
        return f"[OCR FAILED ({exc})] {path.name}"
    text = _run_tesseract(data, langs) or _run_tesseract(data, "eng")
    if not text:
        return f"[OCR FAILED] {path.name}"
    return f"[OCR from {path.name}]\n{text}"
