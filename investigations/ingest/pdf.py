"""PDF ingestion. Text-only legacy path retained for callers that don't need image assets.
Use pdf_assets.extract() for full extraction (text + images + OCR)."""
from pathlib import Path


def extract_text(path: Path) -> str:
    try:
        import fitz
        text_parts = []
        with fitz.open(path) as doc:
            for i in range(len(doc)):
                t = doc[i].get_text("text") or ""
                if t.strip():
                    text_parts.append(t)
        return "\n\n".join(text_parts)
    except ImportError:
        pass
    try:
        import pdfplumber
        with pdfplumber.open(path) as pdf:
            return "\n\n".join((p.extract_text() or "") for p in pdf.pages)
    except ImportError:
        pass
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        return "\n\n".join((p.extract_text() or "") for p in reader.pages)
    except ImportError:
        pass
    try:
        import subprocess
        result = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    raise RuntimeError(
        f"No PDF extractor available for {path}. "
        "Install: pip install pymupdf  OR  pdfplumber  OR  brew install poppler"
    )
