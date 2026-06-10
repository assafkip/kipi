"""Activity log — the shared progress trail for a multi-analyst instance.

No auth: the analyst sets a name per session (a cookie). Every meaningful write
is stamped with that name so co-workers on the same instance can see who did
what, when. This is the 'light' multi-analyst layer (attribution + feed), not a
hosted multi-user system.
"""
from __future__ import annotations


def _has(conn) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='activity'").fetchone())


def log(conn, analyst: str, action: str, *, entity_id=None, report_id=None,
        investigation=None, detail=None) -> None:
    """Record an action. Best-effort: never let logging break the real write."""
    if not _has(conn):
        return
    try:
        conn.execute(
            "INSERT INTO activity (analyst, action, entity_id, report_id, investigation, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (analyst or "anonymous", action, entity_id, report_id, investigation, detail))
        conn.commit()
    except Exception:
        pass


def recent(conn, case: str | None = None, limit: int = 100) -> list[dict]:
    if not _has(conn):
        return []
    cases = [case] if isinstance(case, str) else [c for c in (case or []) if c]
    where, params = "", []
    if cases:
        where = f"WHERE a.investigation IN ({','.join('?' for _ in cases)}) "
        params.extend(cases)
    params.append(limit)
    return [dict(r) for r in conn.execute(
        "SELECT a.id, a.analyst, a.action, a.entity_id, a.report_id, a.investigation, "
        "a.detail, a.created_at, e.canonical_name "
        "FROM activity a LEFT JOIN entities e ON e.id = a.entity_id "
        f"{where}ORDER BY a.created_at DESC, a.id DESC LIMIT ?",
        params).fetchall()]
