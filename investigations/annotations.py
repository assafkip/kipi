"""Analyst annotation layer — notes + dossier override, kept separate from the
AI-generated vault dossier so regeneration never wipes analyst work.
"""
from __future__ import annotations

from investigations.storage import db


def _has(conn) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='entity_annotations'"
    ).fetchone())


_EMPTY = {"notes": "", "dossier_override": None, "notes_updated_at": None,
          "dossier_updated_at": None, "notes_author": None, "dossier_author": None}


def get(conn, entity_id: int) -> dict:
    if not _has(conn):
        return dict(_EMPTY)
    row = conn.execute(
        "SELECT notes, dossier_override, notes_updated_at, dossier_updated_at, "
        "notes_author, dossier_author FROM entity_annotations WHERE entity_id = ?",
        (entity_id,)).fetchone()
    return dict(row) if row else dict(_EMPTY)


def _ensure_row(conn, entity_id: int) -> None:
    conn.execute("INSERT OR IGNORE INTO entity_annotations (entity_id) VALUES (?)", (entity_id,))


def set_notes(conn, entity_id: int, notes: str | None, author: str | None = None) -> None:
    _ensure_row(conn, entity_id)
    conn.execute(
        "UPDATE entity_annotations SET notes = ?, notes_author = ?, "
        "notes_updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?", (notes, author, entity_id))
    conn.commit()


def set_dossier_override(conn, entity_id: int, body: str | None, author: str | None = None) -> None:
    _ensure_row(conn, entity_id)
    conn.execute(
        "UPDATE entity_annotations SET dossier_override = ?, dossier_author = ?, "
        "dossier_updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?", (body, author, entity_id))
    conn.commit()


def clear_dossier_override(conn, entity_id: int) -> None:
    """Revert to the AI dossier (override + its author dropped; notes untouched)."""
    conn.execute(
        "UPDATE entity_annotations SET dossier_override = NULL, dossier_author = NULL, "
        "dossier_updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?", (entity_id,))
    conn.commit()


# ---------- report-level analyst notes (the report workspace) ----------

def _has_report(conn) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_annotations'"
    ).fetchone())


def get_report(conn, report_id: int) -> dict:
    empty = {"notes": "", "notes_author": None, "notes_updated_at": None}
    if not _has_report(conn):
        return dict(empty)
    row = conn.execute(
        "SELECT notes, notes_author, notes_updated_at FROM report_annotations "
        "WHERE report_id = ?", (report_id,)).fetchone()
    return dict(row) if row else dict(empty)


def set_report_notes(conn, report_id: int, notes: str | None, author: str | None = None) -> None:
    conn.execute("INSERT OR IGNORE INTO report_annotations (report_id) VALUES (?)", (report_id,))
    conn.execute(
        "UPDATE report_annotations SET notes = ?, notes_author = ?, "
        "notes_updated_at = CURRENT_TIMESTAMP WHERE report_id = ?", (notes, author, report_id))
    conn.commit()
