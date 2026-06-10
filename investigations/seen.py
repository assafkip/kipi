"""Per-analyst 'since you last looked' tracking for the Signals inbox.

No auth: the analyst name is a per-session cookie (see webapp). We keep one
last-seen timestamp per (analyst, scope), where scope is the active case slug or
'__all__'. Opening the inbox shows what arrived since that timestamp, then stamps
it forward to now.

All timestamps use the SQLite clock (CURRENT_TIMESTAMP / strftime 'now' = UTC,
'YYYY-MM-DD HH:MM:SS') so they string-compare correctly against
alerts.created_at, claims.created_at, and activity.created_at.
"""
from __future__ import annotations

from investigations import claims as claims_mod

ALL_SCOPE = "__all__"


def _scope(case: str | None) -> str:
    return case or ALL_SCOPE


def _has(conn) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='analyst_views'"
    ).fetchone())


def get_last_seen(conn, analyst: str, case: str | None) -> str | None:
    """The analyst's last-seen timestamp for this scope, or None on first visit."""
    if not _has(conn):
        return None
    row = conn.execute(
        "SELECT last_seen_at FROM analyst_views WHERE analyst = ? AND scope = ?",
        (analyst, _scope(case)),
    ).fetchone()
    return row["last_seen_at"] if row else None


def mark_seen(conn, analyst: str, case: str | None) -> str | None:
    """Stamp last-seen forward to the SQLite UTC clock. Returns what was written."""
    if not _has(conn):
        return None
    now = conn.execute("SELECT strftime('%Y-%m-%d %H:%M:%S','now')").fetchone()[0]
    conn.execute(
        "INSERT INTO analyst_views (analyst, scope, last_seen_at) VALUES (?, ?, ?) "
        "ON CONFLICT(analyst, scope) DO UPDATE SET last_seen_at = excluded.last_seen_at",
        (analyst, _scope(case), now),
    )
    conn.commit()
    return now


def compute_delta(conn, analyst: str, case: str | None, since: str | None) -> dict:
    """What arrived since `since`, scoped to the case.

    Three honest streams, each keyed off a real created_at:
      - new open alerts (watchlist / cross-case hits)
      - new corrections (contradiction groups whose newest claim arrived since)
      - new activity by OTHERS (the analyst's own actions aren't news to them)

    since=None (first visit ever) yields an empty delta — we don't replay the
    whole backlog as 'new' to a first-time analyst.
    """
    out = {
        "since": since, "first_visit": since is None,
        "alerts": [], "alert_count": 0,
        "corrections": 0,
        "activity": [], "activity_count": 0,
        "total": 0,
    }
    if not since:
        return out

    # New open alerts, scoped to case, newest first.
    case_sql = "AND a.investigation = ? " if case else ""
    alert_params = [since] + ([case] if case else [])
    out["alerts"] = [dict(r) for r in conn.execute(
        "SELECT a.id, a.alert_type, a.severity, a.message, a.investigation, "
        "a.created_at, a.entity_id, e.canonical_name "
        "FROM alerts a JOIN entities e ON e.id = a.entity_id "
        "WHERE a.acknowledged = 0 AND a.created_at > ? " + case_sql +
        "ORDER BY a.created_at DESC LIMIT 6",
        alert_params,
    ).fetchall()]
    out["alert_count"] = conn.execute(
        "SELECT COUNT(*) FROM alerts a "
        "WHERE a.acknowledged = 0 AND a.created_at > ? " + case_sql,
        alert_params,
    ).fetchone()[0]

    # New corrections: contradiction groups with at least one claim created since
    # `since`. Reuses the same detector the badge + page use, so they agree.
    new_corrections = 0
    for c in claims_mod.detect_contradictions(conn, case):
        if any((cl.get("created_at") or "") > since for cl in c["claims"]):
            new_corrections += 1
    out["corrections"] = new_corrections

    # New activity by others (exclude the current analyst's own actions).
    act_case_sql = "AND a.investigation = ? " if case else ""
    act_params = [since, analyst] + ([case] if case else [])
    out["activity"] = [dict(r) for r in conn.execute(
        "SELECT a.id, a.analyst, a.action, a.detail, a.investigation, a.created_at, "
        "a.entity_id, e.canonical_name "
        "FROM activity a LEFT JOIN entities e ON e.id = a.entity_id "
        "WHERE a.created_at > ? AND a.analyst != ? " + act_case_sql +
        "ORDER BY a.created_at DESC LIMIT 6",
        act_params,
    ).fetchall()]
    out["activity_count"] = conn.execute(
        "SELECT COUNT(*) FROM activity a "
        "WHERE a.created_at > ? AND a.analyst != ? " + act_case_sql,
        act_params,
    ).fetchone()[0]

    out["total"] = out["alert_count"] + out["corrections"] + out["activity_count"]
    return out
