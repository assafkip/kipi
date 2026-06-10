"""Fetch images that reports only LINK to (not embedded), gated per-link.

Scrape-based cases (markdown / telegram / text) reference image URLs in their text, but
the regular ingesters never download them — so an image-centric case shows zero assets.
This module finds those URLs as *candidates* (pure text, NO network), and downloads +
OCRs them into assets ONLY when the analyst approves each specific link. Nothing here
fetches automatically — `discover()` never touches the network; `scan_one()` is the only
fetch, and it runs one approved candidate at a time.
"""
import re
import urllib.error
import urllib.request
from io import BytesIO
from pathlib import Path

from investigations.storage import db
from investigations.ingest.screenshot import ocr_image_object

LINKED_DIR = Path(__file__).resolve().parents[1] / "assets" / "linked"
FETCH_TIMEOUT = 20
MAX_BYTES = 15 * 1024 * 1024  # 15 MB cap — refuse anything larger

_IMG_URL_RE = re.compile(
    r'https?://[^\s"\'<>)\]}]+\.(?:jpe?g|png|webp|gif|bmp|tiff?)\b', re.I)
_EXT_BY_CTYPE = {
    "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp",
    "image/gif": ".gif", "image/bmp": ".bmp", "image/tiff": ".tiff",
}


def _domain(url: str) -> str:
    m = re.match(r'https?://([^/]+)', url)
    return m.group(1) if m else ""


def discover(conn, case: str) -> int:
    """Scan the case's report text for image URLs; record NEW ones as 'pending'
    candidates. Pure text work — no network. Returns how many new candidates were added."""
    rows = conn.execute(
        "SELECT id, raw_text FROM reports WHERE investigation = ?", (case,)).fetchall()
    added = 0
    for r in rows:
        # dict.fromkeys = dedup per report, preserve order
        for url in dict.fromkeys(_IMG_URL_RE.findall(r["raw_text"] or "")):
            cur = conn.execute(
                "INSERT OR IGNORE INTO linked_image_candidates "
                "(report_id, investigation, url, domain, status) VALUES (?,?,?,?, 'pending')",
                (r["id"], case, url, _domain(url)))
            added += cur.rowcount
    conn.commit()
    return added


def candidates(conn, case: str, status: str | None = None) -> list[dict]:
    q = "SELECT * FROM linked_image_candidates WHERE investigation = ?"
    params = [case]
    if status:
        q += " AND status = ?"
        params.append(status)
    return [dict(r) for r in conn.execute(q + " ORDER BY id", params).fetchall()]


def skip_one(conn, cand_id: int) -> dict:
    """Reject one candidate — it will never be fetched."""
    conn.execute("UPDATE linked_image_candidates SET status='skipped' WHERE id=?", (cand_id,))
    conn.commit()
    return {"id": cand_id, "status": "skipped"}


def _download(url: str) -> tuple[bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations/1.0"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        if "image" not in ctype:
            raise ValueError(f"not an image (content-type: {ctype or 'unknown'})")
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"image exceeds {MAX_BYTES // (1024 * 1024)}MB cap")
    return data, ctype


def scan_one(conn, cand_id: int, fetcher=None) -> dict:
    """GATED: download + OCR + store ONE approved candidate as an asset. The only place
    a network fetch happens, and only for the single id passed in."""
    row = conn.execute(
        "SELECT * FROM linked_image_candidates WHERE id = ?", (cand_id,)).fetchone()
    if not row:
        return {"error": "no such candidate"}
    if row["status"] == "fetched":
        return {"id": cand_id, "status": "fetched", "asset_id": row["asset_id"],
                "note": "already fetched"}

    try:
        data, ctype = (fetcher or _download)(row["url"])
    except Exception as exc:
        conn.execute("UPDATE linked_image_candidates SET status='error', error=? WHERE id=?",
                     (str(exc)[:300], cand_id))
        conn.commit()
        return {"id": cand_id, "status": "error", "error": str(exc)[:300]}

    LINKED_DIR.mkdir(parents=True, exist_ok=True)
    ext = _EXT_BY_CTYPE.get(ctype) or Path(row["url"].split("?")[0]).suffix or ".img"
    path = LINKED_DIR / f"cand_{cand_id}{ext}"
    path.write_bytes(data)

    ocr = ""
    try:
        from PIL import Image
        ocr = ocr_image_object(Image.open(BytesIO(data))).strip()
    except Exception:
        ocr = ""  # OCR is best-effort; the saved image is still a captured asset

    asset_id = db.add_asset(conn, row["report_id"], str(path), "linked_image",
                            page_number=None, image_index=None, ocr_text=ocr)
    conn.execute("UPDATE linked_image_candidates SET status='fetched', asset_id=? WHERE id=?",
                 (asset_id, cand_id))
    conn.commit()
    return {"id": cand_id, "status": "fetched", "asset_id": asset_id, "ocr_len": len(ocr)}
