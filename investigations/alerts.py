"""Auto-alerts: surface a flagged/known actor without manual spotting.

Two triggers, evaluated per (entity, report):
  - watchlist  — the entity is analyst-flagged OR a known-bad seed (HIGH)
  - cross_case — the entity also appears in a DIFFERENT case (MEDIUM)

Detection is idempotent: alerts has UNIQUE(entity_id, report_id, alert_type),
so re-running never duplicates. Call detect_for_report() after ingest, or
scan_all() to backfill, or detect_for_entity() right after flagging.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Generic platform domains that are not real shared actors. Single source of
# truth — webapp imports this so the cross-case panel and alerts agree.
GENERIC_INFRA = {
    "t.me", "t.co", "twitter.com", "x.com", "telegram.org", "instagram.com",
    "facebook.com", "fb.com", "github.com", "youtube.com", "youtu.be",
    "tiktok.com", "discord.com", "discord.gg", "reddit.com", "google.com",
    "bit.ly", "linktr.ee",
}

# Date-shaped tokens get mis-extracted (a date typed as a phone, etc.) and are
# never a cross-case actor. The phone canonicalizer strips separators, so a
# date like "2026-03-27" is stored as "20260327" — match BOTH the separated
# form and the bare-digit form it canonicalizes to.
_DATE_SEP_RE = re.compile(r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$")
_DATE_YMD_RE = re.compile(r"^(?:19|20)\d{6}$")        # YYYYMMDD
_DATE_DMY_RE = re.compile(r"^\d{6}(?:19|20)\d{2}$")   # DDMMYYYY / MMDDYYYY


def _host_of(name: str) -> str:
    """Bare host of a URL-ish string, lowercased, www. stripped."""
    try:
        netloc = urlparse(name if "://" in name else "//" + name).netloc.lower()
    except Exception:
        return ""
    return netloc[4:] if netloc.startswith("www.") else netloc


def is_pivotable(name: str | None, entity_type: str | None,
                 notes: str | None = None) -> bool:
    """True if this entity is a real actor/indicator worth cross-case attention.

    Excludes generic infrastructure (by name AND by URL host), role:noise,
    low-confidence person_candidates, and date-shaped noise. Shared by alert
    detection and the cross-case panel so they never disagree.
    """
    if not name:
        return False
    if (notes or "").startswith("role:noise"):
        return False
    if name in GENERIC_INFRA:
        return False
    if entity_type == "person_candidate":
        return False
    if _DATE_SEP_RE.match(name) or _DATE_YMD_RE.match(name) or _DATE_DMY_RE.match(name):
        return False
    # Platform URLs (https://t.me/...) are infra noise — judge by host.
    if entity_type == "url" or "://" in name:
        if _host_of(name) in GENERIC_INFRA:
            return False
    return True


def _insert(conn, entity_id, report_id, alert_type, severity, message, case) -> int:
    cur = conn.execute(
        "INSERT OR IGNORE INTO alerts "
        "(entity_id, report_id, alert_type, severity, message, investigation) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (entity_id, report_id, alert_type, severity, message, case),
    )
    return 1 if cur.rowcount else 0


def _check(conn, entity_row, report_row) -> int:
    """Emit any alerts for one entity appearing in one report. Returns # new."""
    eid = entity_row["id"]
    name = entity_row["canonical_name"]
    etype = entity_row["entity_type"]
    notes = entity_row["notes"] if "notes" in entity_row.keys() else None
    rid = report_row["id"]
    case = report_row["investigation"]
    title = report_row["title"] or f"report {rid}"
    new = 0

    # T1 — watchlist: analyst-flagged (explicit intent, un-gated) OR a known-bad
    # seed (gated by pivotability so a seed that matched date/infra noise can't
    # spray high alerts).
    is_seed = conn.execute(
        "SELECT 1 FROM seeds WHERE entity_id = ? LIMIT 1", (eid,)
    ).fetchone() if _has_table(conn, "seeds") else None
    if entity_row["flagged"] or (is_seed and is_pivotable(name, etype, notes)):
        in_case = f" [{case}]" if case else ""
        new += _insert(conn, eid, rid, "watchlist", "high",
                       f"Watchlist actor {name} appeared in “{title}”{in_case}", case)

    # T2 — cross-case: the entity also appears in a different case.
    if case and is_pivotable(name, etype, notes):
        others = sorted({
            r[0] for r in conn.execute(
                "SELECT DISTINCT r.investigation FROM mentions m "
                "JOIN reports r ON r.id = m.report_id "
                "WHERE m.entity_id = ? AND r.investigation IS NOT NULL "
                "AND r.investigation != ?",
                (eid, case),
            ).fetchall() if r[0]
        })
        if others:
            new += _insert(conn, eid, rid, "cross_case", "medium",
                           f"{name} also appears in case(s): {', '.join(others)}", case)
    return new


def _has_table(conn, name) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (name,)
    ).fetchone())


def detect_for_report(conn, report_id: int) -> int:
    """Run both triggers for every entity in a freshly-ingested report."""
    rep = conn.execute(
        "SELECT id, investigation, title FROM reports WHERE id = ?", (report_id,)
    ).fetchone()
    if not rep:
        return 0
    ents = conn.execute(
        "SELECT DISTINCT e.id, e.canonical_name, e.entity_type, e.notes, e.flagged "
        "FROM mentions m JOIN entities e ON e.id = m.entity_id "
        "WHERE m.report_id = ?",
        (report_id,),
    ).fetchall()
    new = sum(_check(conn, e, rep) for e in ents)
    conn.commit()
    return new


def detect_for_entity(conn, entity_id: int) -> int:
    """Run triggers for one entity across every report it appears in.

    Used right after flagging so the analyst immediately sees where a
    newly-flagged actor already is.
    """
    ent = conn.execute(
        "SELECT id, canonical_name, entity_type, notes, flagged FROM entities WHERE id = ?",
        (entity_id,),
    ).fetchone()
    if not ent:
        return 0
    reports = conn.execute(
        "SELECT DISTINCT r.id, r.investigation, r.title FROM mentions m "
        "JOIN reports r ON r.id = m.report_id WHERE m.entity_id = ?",
        (entity_id,),
    ).fetchall()
    new = sum(_check(conn, ent, rep) for rep in reports)
    conn.commit()
    return new


def scan_all(conn) -> int:
    """Backfill alerts across every report (idempotent)."""
    total = 0
    for r in conn.execute("SELECT id FROM reports").fetchall():
        total += detect_for_report(conn, r["id"])
    return total


_UNCHANGED = object()


def set_flag(conn, entity_id: int, flagged: bool, note=_UNCHANGED) -> int:
    """Flag/unflag an entity.

    - Flagging on backfills alerts for it (returns the count).
    - Unflagging retracts its flag-driven watchlist alerts (acknowledges them),
      but keeps any still justified by a known-bad seed.
    - note left as _UNCHANGED preserves the existing note (a bare toggle from the
      UI must not wipe an analyst's note); pass a string to set it.
    """
    if note is _UNCHANGED:
        conn.execute("UPDATE entities SET flagged = ? WHERE id = ?",
                     (1 if flagged else 0, entity_id))
    else:
        conn.execute("UPDATE entities SET flagged = ?, flagged_note = ? WHERE id = ?",
                     (1 if flagged else 0, note, entity_id))
    conn.commit()

    if flagged:
        return detect_for_entity(conn, entity_id)

    # Unflag: retract flag-driven watchlist alerts; keep seed-justified ones.
    seed_guard = ("AND entity_id NOT IN (SELECT entity_id FROM seeds) "
                  if _has_table(conn, "seeds") else "")
    conn.execute(
        "UPDATE alerts SET acknowledged = 1 "
        "WHERE entity_id = ? AND alert_type = 'watchlist' AND acknowledged = 0 "
        f"{seed_guard}",
        (entity_id,),
    )
    conn.commit()
    return 0


def open_count(conn) -> int:
    if not _has_table(conn, "alerts"):
        return 0
    return conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
    ).fetchone()[0]


def list_alerts(conn, include_ack: bool = False, limit: int = 300) -> list[dict]:
    if not _has_table(conn, "alerts"):
        return []
    where = "" if include_ack else "WHERE a.acknowledged = 0 "
    rows = conn.execute(
        "SELECT a.id, a.entity_id, a.report_id, a.alert_type, a.severity, "
        "a.message, a.investigation, a.created_at, a.acknowledged, "
        "e.canonical_name, e.entity_type, r.title AS report_title "
        "FROM alerts a "
        "JOIN entities e ON e.id = a.entity_id "
        "LEFT JOIN reports r ON r.id = a.report_id "
        f"{where}"
        "ORDER BY CASE a.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, "
        "a.created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def acknowledge(conn, alert_id: int) -> None:
    conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
    conn.commit()


def acknowledge_all(conn) -> int:
    cur = conn.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
    conn.commit()
    return cur.rowcount
