"""EXIF adapter — GPS + device metadata from images/PDFs (keyless, local).

kipi OCRs dropped images but discarded all metadata. This runs the `exiftool` system
binary (same subprocess pattern as the tesseract OCR), surfacing EXIF GPS coordinates
(a near-T1 geo anchor) and the device make/model/serial (a device fingerprint).

Two entry points:
  - run(path): the analyst/agent transform (MCP `exif_extract`) -> header + GPS/serial nodes.
  - exif_summary_for_ingest(path): the ingest drop-path hook -> a one-line "[EXIF] ..."
    block appended to the report text so GPS/serial are captured + searchable on drop.

Keyless. exiftool is a SYSTEM binary (brew install exiftool / apt install
libimage-exiftool-perl), NOT a pip dep — the adapter self-guards when it is absent
(returns a [needs exiftool] result; the ingest hook no-ops), never crashing a drop.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_SERIAL_KEYS = ("SerialNumber", "InternalSerialNumber", "BodySerialNumber")


def _run_exiftool(path: str, timeout: int = 60) -> dict | None:
    """exiftool -json -n <path> -> the first metadata dict. None if exiftool is absent."""
    if shutil.which("exiftool") is None:
        return None
    try:
        proc = subprocess.run(
            ["exiftool", "-json", "-n", path],
            capture_output=True, timeout=timeout)
    except subprocess.SubprocessError as exc:
        raise EnrichmentError(f"exiftool failed: {exc}")
    out = proc.stdout.decode("utf-8", "replace").strip()
    if not out:
        return {}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        raise EnrichmentError("exiftool returned non-JSON")
    return data[0] if isinstance(data, list) and data else {}


def _gps_str(data: dict) -> str:
    """A 'lat,lon' string from EXIF GPS fields (with -n they are numeric). '' if absent."""
    lat = data.get("GPSLatitude")
    lon = data.get("GPSLongitude")
    if lat is not None and lon is not None:
        return f"{lat},{lon}"
    pos = data.get("GPSPosition")
    return str(pos) if pos else ""


def _serial(data: dict) -> str:
    for k in _SERIAL_KEYS:
        if data.get(k):
            return str(data[k])
    return ""


def exif_summary_for_ingest(path: str, timeout: int = 60) -> str:
    """One-line '[EXIF] ...' block for the ingest drop path. '' when exiftool is absent
    or the file carries no useful metadata (so the caller appends nothing)."""
    try:
        data = _run_exiftool(path, timeout)
    except EnrichmentError:
        return ""
    if not data:
        return ""
    parts = []
    gps = _gps_str(data)
    if gps:
        parts.append(f"GPS: {gps}")
    for k in ("Make", "Model", "CreateDate"):
        if data.get(k):
            parts.append(f"{k}: {data[k]}")
    serial = _serial(data)
    if serial:
        parts.append(f"Serial: {serial}")
    return "[EXIF] " + " | ".join(parts) if parts else ""


class ExifAdapter(Adapter):
    slug = "exif"
    # watched_types satisfy the registry recipe-presence contract; EXIF's real invocation
    # paths are the MCP verb + the ingest drop hook, not an entity-type pivot (audit O-4).
    watched_types = ("indicator", "fingerprint")
    display_name = "EXIF (GPS + device serial)"
    env_var = None  # keyless; exiftool is a system binary, self-guarded
    category = "forensics"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        path = (query or "").strip()
        if not path:
            raise EnrichmentError("exif: empty path")
        if shutil.which("exiftool") is None:
            return [EnrichmentResult(
                result_type="document",
                title="EXIF: exiftool not installed",
                summary="[needs exiftool] install it (brew install exiftool / "
                        "apt install libimage-exiftool-perl) and retry.",
                confidence="low")]
        data = _run_exiftool(path, timeout)
        if not data:
            return [EnrichmentResult(
                result_type="document",
                title=f"EXIF: {path} — no metadata",
                summary="exiftool returned no metadata for this file.",
                raw_json={"path": path}, confidence="low")]
        gps = _gps_str(data)
        serial = _serial(data)
        make = data.get("Make", "")
        model = data.get("Model", "")
        # raw_json keys match properties.PROPERTY_MAP so promotion types them onto the node.
        header = EnrichmentResult(
            result_type="document",
            title=f"EXIF: {path} — {make} {model}".strip(),
            summary=(f"make: {make}\nmodel: {model}\n"
                     f"capture date: {data.get('CreateDate', '')}\n"
                     f"GPS: {gps or '(none)'}\nserial: {serial or '(none)'}"),
            raw_json={"path": path, "gps_coords": gps, "Make": make, "Model": model,
                      "SerialNumber": serial, "CreateDate": data.get("CreateDate", ""),
                      "exif": data},
            confidence="medium")
        rows: list[EnrichmentResult] = []
        if gps:
            rows.append(EnrichmentResult(
                result_type="profile", title=gps,
                summary=f"GPS coordinates from EXIF of {path}.",
                raw_json={"gps_coords": gps}, confidence="medium"))
        if serial:
            rows.append(EnrichmentResult(
                result_type="profile", title=serial,
                summary=f"Device serial from EXIF of {path}.",
                confidence="medium"))
        return [header] + rows
