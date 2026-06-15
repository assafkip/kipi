"""Auto-alert tests: watchlist + cross-case triggers, idempotency, ack.

Run: .venv/bin/python -m investigations.tests.test_alerts
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import alerts


def _seed_db(conn):
    ra = db.insert_report(conn, "a.md", "ha", "markdown", "Alpha Report", "case-alpha", "x")
    rb = db.insert_report(conn, "b.md", "hb", "markdown", "Beta Report", "case-beta", "x")
    # Shared actor in BOTH cases (cross-case trigger).
    shared = db.upsert_entity(conn, "@sharedactor", "person", ra)
    db.add_mention(conn, shared, ra, "@sharedactor", "ctx")
    db.add_mention(conn, shared, rb, "@sharedactor", "ctx")
    # Solo actor in one case (no triggers unless flagged).
    solo = db.upsert_entity(conn, "@soloactor", "person", ra)
    db.add_mention(conn, solo, ra, "@soloactor", "ctx")
    # Known-bad seed actor (watchlist trigger) in beta.
    bad = db.upsert_entity(conn, "@knownbad", "person", rb)
    db.add_mention(conn, bad, rb, "@knownbad", "ctx")
    conn.execute("INSERT INTO seeds (entity_id, label, weight) VALUES (?, 'known-bad', 2.0)", (bad,))
    # Generic infra in both cases — must NOT cross-case alert.
    infra = db.upsert_entity(conn, "t.me", "domain", ra)
    db.add_mention(conn, infra, ra, "t.me", "ctx")
    db.add_mention(conn, infra, rb, "t.me", "ctx")
    # A date mis-extracted as a phone, stored as bare digits (separators stripped
    # by the phone canonicalizer). In both cases — must NOT cross-case alert.
    datephone = db.upsert_entity(conn, "20260327", "phone", ra)
    db.add_mention(conn, datephone, ra, "20260327", "ctx")
    db.add_mention(conn, datephone, rb, "20260327", "ctx")
    conn.commit()
    return {"ra": ra, "rb": rb, "shared": shared, "solo": solo, "bad": bad,
            "infra": infra, "datephone": datephone}


def _types(conn, entity_id):
    return {r[0] for r in conn.execute(
        "SELECT alert_type FROM alerts WHERE entity_id = ?", (entity_id,))}


def main():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        db.init_db(db_path)
        with db.connect(db_path) as conn:
            ids = _seed_db(conn)

            # Backfill scan.
            n1 = alerts.scan_all(conn)
            assert n1 > 0, "scan produced no alerts"

            # Cross-case: shared actor flagged across cases; infra is NOT.
            assert "cross_case" in _types(conn, ids["shared"]), "shared actor missing cross-case alert"
            assert _types(conn, ids["infra"]) == set(), f"infra wrongly alerted: {_types(conn, ids['infra'])}"
            # Date-as-phone (bare digits) must NOT cross-case alert (the real bug).
            assert _types(conn, ids["datephone"]) == set(), \
                f"date-as-phone wrongly alerted: {_types(conn, ids['datephone'])}"
            # Solo actor: no alerts yet (not flagged, single case).
            assert _types(conn, ids["solo"]) == set(), "solo actor wrongly alerted"
            # Seed actor: watchlist alert.
            assert "watchlist" in _types(conn, ids["bad"]), "known-bad seed missing watchlist alert"

            # Idempotency: re-scan adds nothing.
            n2 = alerts.scan_all(conn)
            assert n2 == 0, f"scan not idempotent, added {n2}"

            # Flagging the solo actor backfills a watchlist alert immediately.
            before = alerts.open_count(conn)
            new = alerts.set_flag(conn, ids["solo"], True)
            assert new >= 1, "flagging did not backfill an alert"
            assert "watchlist" in _types(conn, ids["solo"]), "flagged actor missing watchlist alert"
            assert alerts.open_count(conn) == before + new

            # Unflagging retracts the solo actor's flag-driven watchlist alerts.
            alerts.set_flag(conn, ids["solo"], False)
            open_solo = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE entity_id = ? AND alert_type='watchlist' "
                "AND acknowledged = 0", (ids["solo"],)).fetchone()[0]
            assert open_solo == 0, "unflag did not retract the actor's watchlist alerts"
            # Unflag must NOT clear the seed actor's watchlist (seed-justified).
            alerts.set_flag(conn, ids["bad"], False)
            open_seed = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE entity_id = ? AND alert_type='watchlist' "
                "AND acknowledged = 0", (ids["bad"],)).fetchone()[0]
            assert open_seed >= 1, "unflag wrongly cleared a seed-justified watchlist alert"

            # Note is preserved across a bare toggle.
            alerts.set_flag(conn, ids["solo"], True, note="vip target")
            alerts.set_flag(conn, ids["solo"], False)  # bare toggle, no note
            kept = conn.execute("SELECT flagged_note FROM entities WHERE id=?",
                                (ids["solo"],)).fetchone()[0]
            assert kept == "vip target", f"bare toggle wiped the note: {kept!r}"

            # Acknowledge one → open count drops by one.
            open_now = alerts.open_count(conn)
            one = alerts.list_alerts(conn)[0]
            alerts.acknowledge(conn, one["id"])
            assert alerts.open_count(conn) == open_now - 1, "ack did not decrement open count"

    # Direct is_pivotable checks (the noise rules).
    assert alerts.is_pivotable("20260327", "phone") is False, "bare-digit date slipped through"
    assert alerts.is_pivotable("2026-03-27", "phone") is False, "separated date slipped through"
    assert alerts.is_pivotable("https://t.me/examplegroup", "url") is False, "platform URL slipped through"
    assert alerts.is_pivotable("x", "handle", "role:noise — junk") is False, "role:noise slipped through"
    assert alerts.is_pivotable("@realactor", "handle") is True, "real actor wrongly excluded"

    print("PASS test_alerts: triggers fire; infra/date/solo/role:noise excluded; "
          "idempotent; flag backfills; unflag retracts (keeps seed); note preserved; ack decrements")


if __name__ == "__main__":
    main()
