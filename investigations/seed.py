"""Seed ingestion — pull known-bad-actor priors from a markdown case file.

Workflow:
  ./invctl seed path/to/case_file.md [--weight 1.5] [--investigation case-b]

Case file format (any combination works):

    ---
    investigation: case-b
    weight: 2.0
    ---

    # Known bad actors

    - @example_handle — Ring-A leader (prior intel from 2026-Q1)
    - t.me/example_channel — primary channel
    - 192.0.2.1 — known C2
    - some-domain.com

    # Notes

    Free text…

The parser looks for bulleted entries under a "Known bad actors" / "Targets" /
"Seeds" heading. Each entry must contain at least one entity-shaped token
(handle, channel, IP, hash, email, phone, wallet, domain, URL).

Matched entities get a row in `seeds`. Unmatched lines are reported so the
founder can decide (add alias, ingest a source that mentions them, or skip).
"""
import re
from datetime import datetime
from pathlib import Path

from investigations.ingest.extractor import extract_all


SEED_HEADINGS = {"known bad actors", "known actors", "targets", "seeds",
                 "priors", "watchlist", "focus targets"}


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter_dict, body_text)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    fm_block = text[3:end].strip()
    body = text[end + 4:].lstrip("\n")
    fm = {}
    for line in fm_block.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fm[k.strip().lower()] = v.strip()
    return fm, body


def _seed_blocks(body: str) -> list[str]:
    """Return the lines under seed-relevant headings."""
    lines = body.splitlines()
    chunks = []
    capturing = False
    current = []
    for line in lines:
        stripped = line.strip().lower()
        if stripped.startswith("#"):
            head = stripped.lstrip("#").strip()
            if any(h in head for h in SEED_HEADINGS):
                if current:
                    chunks.append("\n".join(current))
                    current = []
                capturing = True
                continue
            else:
                if capturing and current:
                    chunks.append("\n".join(current))
                    current = []
                capturing = False
                continue
        if capturing:
            current.append(line)
    if current:
        chunks.append("\n".join(current))
    return chunks


def _candidate_lines(blocks: list[str]) -> list[tuple[str, str]]:
    """From seed blocks, return (raw_name, note) for each bullet."""
    out = []
    for block in blocks:
        for line in block.splitlines():
            m = re.match(r"^\s*[-*+]\s+(.+)$", line)
            if not m:
                continue
            content = m.group(1).strip()
            # Split on em-dash, en-dash, colon, or " - " to separate name from note
            for sep in [" — ", " – ", " - ", ": "]:
                if sep in content:
                    name, note = content.split(sep, 1)
                    out.append((name.strip(), note.strip()))
                    break
            else:
                out.append((content.strip(), ""))
    return out


def _resolve_entity(conn, raw_name: str) -> int | None:
    """Look up an entity by canonical name or alias. Try extractor for normalization too."""
    # exact match
    row = conn.execute(
        "SELECT id FROM entities WHERE canonical_name = ?", (raw_name,)
    ).fetchone()
    if row:
        return row["id"]
    # alias
    row = conn.execute(
        "SELECT entity_id FROM aliases WHERE alias = ?", (raw_name,)
    ).fetchone()
    if row:
        return row["entity_id"]
    # Try the extractor: parse the raw name as a snippet, take first extracted
    try:
        extracted = extract_all(raw_name)
    except Exception:
        extracted = []
    for e in extracted:
        row = conn.execute(
            "SELECT id FROM entities WHERE canonical_name = ?", (e.canonical,)
        ).fetchone()
        if row:
            return row["id"]
        row = conn.execute(
            "SELECT entity_id FROM aliases WHERE alias = ?", (e.canonical,)
        ).fetchone()
        if row:
            return row["entity_id"]
        # case-insensitive last try
        row = conn.execute(
            "SELECT id FROM entities WHERE canonical_name COLLATE NOCASE = ?",
            (e.canonical,),
        ).fetchone()
        if row:
            return row["id"]
    # case-insensitive fallback on original
    row = conn.execute(
        "SELECT id FROM entities WHERE canonical_name COLLATE NOCASE = ?",
        (raw_name,),
    ).fetchone()
    if row:
        return row["id"]
    return None


def run(conn, case_file: Path, default_weight: float = 1.5) -> dict:
    """Read a case file, register seed priors.
    Returns stats. Does NOT recompute scores — that's `./invctl focus`.
    """
    text = case_file.read_text(encoding="utf-8")
    fm, body = _parse_frontmatter(text)
    weight = float(fm.get("weight", default_weight))
    label_prefix = fm.get("label", case_file.stem)
    investigation = fm.get("investigation")

    blocks = _seed_blocks(body)
    candidates = _candidate_lines(blocks)
    if not candidates:
        # fallback: scan whole body for entity-shaped tokens
        try:
            extracted = extract_all(body)
        except Exception:
            extracted = []
        candidates = [(e.canonical, "") for e in extracted]

    matched = 0
    unmatched = []
    seeds_added = []
    seen_ids = set()
    source_str = str(case_file.resolve())
    for raw_name, note in candidates:
        eid = _resolve_entity(conn, raw_name)
        if eid is None:
            unmatched.append((raw_name, note))
            continue
        if eid in seen_ids:
            continue
        seen_ids.add(eid)
        label = f"{label_prefix}: {raw_name}"[:200]
        conn.execute(
            "INSERT OR REPLACE INTO seeds "
            "(entity_id, label, source_file, weight, raw_name, notes, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (eid, label, source_str, weight, raw_name, note,
             datetime.utcnow().isoformat(timespec="seconds")),
        )
        matched += 1
        seeds_added.append({"entity_id": eid, "raw_name": raw_name,
                            "weight": weight, "note": note})
    conn.commit()
    return {
        "case_file": str(case_file),
        "investigation": investigation,
        "weight": weight,
        "candidates": len(candidates),
        "matched": matched,
        "unmatched": unmatched,
        "seeds_added": seeds_added,
    }


def list_seeds(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT s.entity_id, s.label, s.weight, s.source_file, s.raw_name, s.notes, "
        "s.added_at, e.canonical_name, e.entity_type, e.sub_role "
        "FROM seeds s LEFT JOIN entities e ON e.id = s.entity_id "
        "ORDER BY s.weight DESC, s.added_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def clear_seeds(conn) -> int:
    n = conn.execute("SELECT COUNT(*) FROM seeds").fetchone()[0]
    conn.execute("DELETE FROM seeds")
    conn.commit()
    return n
