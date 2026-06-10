"""'Since you last looked' delta tests: per-analyst tracking + scoped deltas.

Timestamps are inserted explicitly so the since-comparison is deterministic
(no reliance on wall-clock ordering).

Run: .venv/bin/python -m investigations.tests.test_seen
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import seen


def _seed(conn):
    rx = db.insert_report(conn, "x.md", "hx", "markdown", "Case X Report", "case-x", "t")
    actor = db.upsert_entity(conn, "@actor", "person", rx)
    db.add_mention(conn, actor, rx, "@actor", "ctx")
    conn.commit()
    return rx, actor


def _alert(conn, entity_id, report_id, created_at, case="case-x", ack=0,
           alert_type="watchlist"):
    conn.execute(
        "INSERT INTO alerts (entity_id, report_id, alert_type, severity, message, "
        "investigation, created_at, acknowledged) "
        "VALUES (?, ?, ?, 'high', 'Watchlist actor @actor appeared', ?, ?, ?)",
        (entity_id, report_id, alert_type, case, created_at, ack),
    )
    conn.commit()


def _activity(conn, analyst, created_at, case="case-x", action="flagged actor"):
    conn.execute(
        "INSERT INTO activity (analyst, action, investigation, created_at) "
        "VALUES (?, ?, ?, ?)",
        (analyst, action, case, created_at),
    )
    conn.commit()


def _claim(conn, entity_id, report_id, value, created_at):
    conn.execute(
        "INSERT INTO claims (entity_id, report_id, claim_type, predicate, value, "
        "status, source, created_at) VALUES (?, ?, 'role', 'role', ?, 'active', 'test', ?)",
        (entity_id, report_id, value, created_at),
    )
    conn.commit()


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def main():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            rx, actor = _seed(conn)

            # 1) First visit: no row yet.
            _check("first get_last_seen", seen.get_last_seen(conn, "me", "case-x"), None)
            first = seen.compute_delta(conn, "me", "case-x", None)
            _check("first_visit flag", first["first_visit"], True)
            _check("first_visit total", first["total"], 0)

            # 2) mark_seen roundtrip + scope mapping (None -> '__all__').
            ts = seen.mark_seen(conn, "me", "case-x")
            assert isinstance(ts, str) and len(ts) == 19, f"bad timestamp {ts!r}"
            _check("get after mark", seen.get_last_seen(conn, "me", "case-x"), ts)
            seen.mark_seen(conn, "me", None)
            allrow = conn.execute(
                "SELECT 1 FROM analyst_views WHERE analyst='me' AND scope='__all__'"
            ).fetchone()
            _check("None case stored as __all__", bool(allrow), True)

            # 3) Seed events around a fixed `since`.
            since = "2026-01-15 00:00:00"
            _alert(conn, actor, rx, "2026-03-01 00:00:00")          # after  -> counts
            _alert(conn, actor, rx, "2026-01-01 00:00:00",          # before -> no
                   alert_type="cross_case")
            _activity(conn, "ally", "2026-03-02 00:00:00")          # other  -> counts
            _activity(conn, "me",   "2026-03-03 00:00:00")          # self   -> excluded
            # Contradiction: two active role claims, newest after `since`.
            _claim(conn, actor, rx, "operator", "2026-01-10 00:00:00")  # before
            _claim(conn, actor, rx, "source",   "2026-02-01 00:00:00")  # after

            d = seen.compute_delta(conn, "me", "case-x", since)
            _check("new alerts", d["alert_count"], 1)
            _check("alert carries name", d["alerts"][0]["canonical_name"], "@actor")
            _check("activity excludes self", d["activity_count"], 1)
            _check("activity is ally's", d["activity"][0]["analyst"], "ally")
            _check("new corrections", d["corrections"], 1)
            _check("delta total", d["total"], 3)

            # 4) Future `since` -> nothing is new.
            future = seen.compute_delta(conn, "me", "case-x", "2027-01-01 00:00:00")
            _check("future total", future["total"], 0)

            # 5) Wrong case scope -> alert in case-x is invisible to case-y.
            other = seen.compute_delta(conn, "me", "case-y", since)
            _check("other-case alerts", other["alert_count"], 0)

    print("\nPASS: test_seen")


if __name__ == "__main__":
    main()
