"""Graph-machinery activation run + verification (PRD graph-machinery-activation,
issue gma-4).

Runs the dormant-machinery chain on a case, in order, then asserts each piece
actually took against the DB:

    backup → write seeds → score → typing pass → retro-clean (+ edge-time backfill)

Acceptance (each a named check; any failure → non-zero exit):
  - entity_scores has rows for the case's CONNECTED entities (the degree-term fix)
  - ≥70% of the case's typed edges carry first_seen (the backfill)
  - 0 entities typed 'indicator' without a schema case_type (the typing pass)
  - the same_operator re-gate ran (retro-clean attribution pass reported)

The DB is copied to investigations.db.bak-<n> before any mutation, because
retro-clean deletes junk + demotes edges (NOT purely additive). Rollback =
restore the backup.

Usage:
    python3 -m investigations.scripts.verify_activation <case-slug> [--db PATH]
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from investigations.storage import db


# --- the activation chain -------------------------------------------------------

def backup_db(db_path: Path) -> Path:
    """Snapshot the DB to a numbered .bak before mutating (retro-clean is
    destructive). Uses sqlite3's native backup() — NOT a file copy: the live DB
    runs in WAL mode, so committed rows can still be in the -wal sidecar. A bare
    copy of the main .db would miss them and the 'rollback' would silently lose
    committed data. backup() produces a checkpoint-consistent snapshot.
    Numbered, not timestamped: Date.now()-free for deterministic test runs."""
    n = 0
    while True:
        dest = db_path.with_name(db_path.name + f".bak-activation-{n}")
        if not dest.exists():
            break
        n += 1
    src = sqlite3.connect(str(db_path))
    try:
        out = sqlite3.connect(str(dest))
        try:
            src.backup(out)
        finally:
            out.close()
    finally:
        src.close()
    return dest


def ensure_schema(conn, case: str, on_log=print):
    """Return the case's approved schema, auto-modeling one if absent (mirrors the
    webapp _schema_gate: propose + auto-approve, no human step). LLM-backed — on a
    keyless run discover_schema raises; we log and return None so typing skips
    honestly rather than the chain dying."""
    from investigations import understand
    schema = understand.approved_schema(conn, case)
    if schema is not None:
        return schema
    try:
        # get_schema returns a {schema, status, ...} WRAPPER; save_schema wants the
        # inner dict. Unwrap an existing proposed schema before re-approving it.
        existing = understand.get_schema(conn, case)
        proposed = existing["schema"] if existing else understand.discover_schema(conn, case)
        understand.save_schema(conn, case, proposed, status="approved")
        on_log("  schema: auto-modeled + approved")
        return proposed
    except Exception as exc:
        on_log(f"  schema: SKIPPED — auto-model failed ({type(exc).__name__})")
        return None


def run_chain(conn, case: str, on_log=print) -> dict:
    """Seed → schema → score → type → retro-clean, in order. Returns each result."""
    from investigations import analyze, typing as typing_mod
    from investigations.agent import investigator
    from investigations.maintenance import retro_clean

    seeded = investigator.write_case_seeds(conn, case)
    on_log(f"  seeds: {seeded} intake entit(y/ies) registered")

    schema = ensure_schema(conn, case, on_log)

    scored = analyze.compute_threat_scores(conn)
    on_log(f"  score: {scored} entit(y/ies) scored")

    typed = None
    if schema:
        typed = typing_mod.run(conn, case, schema)
        on_log(f"  typing: {typed.get('retype', {}).get('typed', 0)} retyped")
    else:
        on_log("  typing: SKIPPED — no schema")

    cleaned = retro_clean.run(conn, case)
    # retro_clean's backfill is case-scoped (both endpoints in-case). A case edge to
    # an agent-discovered out-of-case endpoint is still a real edge on the graph, so
    # date GLOBALLY too — observation time is a property of the edge, not the case.
    # Idempotent: edges already stamped by the case pass are skipped.
    global_bf = retro_clean.backfill_edge_times(conn)
    cleaned["edge_times_global"] = global_bf
    at = cleaned.get("attribution", {})
    total_bf = cleaned.get("edge_times", {}).get("stamped", 0) + global_bf.get("stamped", 0)
    on_log(f"  retro-clean: same_operator re-gate dropped {at.get('dropped', 0)}, "
           f"demoted {at.get('demoted', 0)}; backfilled {total_bf} edge time(s)")
    conn.commit()
    return {"seeded": seeded, "scored": scored, "typed": typed, "cleaned": cleaned}


# --- the verification checks ----------------------------------------------------

def _case_entity_ids(conn, case: str) -> set[int]:
    return {r["id"] for r in conn.execute(
        "SELECT DISTINCT e.id FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id WHERE r.investigation = ?",
        (case,)).fetchall()}


def check_scores(conn, case: str) -> tuple[bool, str]:
    """Connected case entities must have scores (the degree-term fix)."""
    ids = _case_entity_ids(conn, case)
    if not ids:
        return False, "no entities found for case"
    ph = ",".join("?" * len(ids))
    connected = {r["id"] for r in conn.execute(
        f"SELECT DISTINCT e.id FROM entities e "
        f"JOIN typed_relationships t ON (t.src_entity_id = e.id OR t.dst_entity_id = e.id) "
        f"WHERE COALESCE(t.status,'active') = 'active' AND e.id IN ({ph})",
        tuple(ids)).fetchall()}
    if not connected:
        return True, "no connected entities to score (vacuously ok)"
    cph = ",".join("?" * len(connected))
    scored = conn.execute(
        f"SELECT COUNT(*) AS n FROM entity_scores WHERE entity_id IN ({cph})",
        tuple(connected)).fetchone()["n"]
    ok = scored >= len(connected)
    return ok, (f"{scored}/{len(connected)} connected entities scored"
                if ok else f"only {scored}/{len(connected)} connected entities scored")


def check_edge_times(conn, case: str, threshold: float = 0.70) -> tuple[bool, str]:
    """≥threshold of the case's typed edges must carry first_seen (the backfill)."""
    ids = _case_entity_ids(conn, case)
    if not ids:
        return False, "no entities found for case"
    ph = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT first_seen FROM typed_relationships "
        f"WHERE COALESCE(status,'active') = 'active' "
        f"AND (src_entity_id IN ({ph}) OR dst_entity_id IN ({ph}))",
        tuple(ids) + tuple(ids)).fetchall()
    total = len(rows)
    if total == 0:
        return True, "no typed edges to date (vacuously ok)"
    dated = sum(1 for r in rows if (r["first_seen"] or "").strip())
    frac = dated / total
    ok = frac >= threshold
    return ok, f"{dated}/{total} typed edges dated ({frac:.0%}, need {threshold:.0%})"


def check_indicator_typed(conn, case: str) -> tuple[bool, str]:
    """0 entities typed 'indicator' without a schema case_type (the typing pass)."""
    ids = _case_entity_ids(conn, case)
    if not ids:
        return False, "no entities found for case"
    ph = ",".join("?" * len(ids))
    stragglers = [r["canonical_name"] for r in conn.execute(
        f"SELECT canonical_name FROM entities "
        f"WHERE entity_type = 'indicator' AND (case_type IS NULL OR case_type = '') "
        f"AND id IN ({ph})", tuple(ids)).fetchall()]
    ok = not stragglers
    return ok, ("0 untyped indicator entities" if ok
                else f"{len(stragglers)} indicator entities lack case_type: "
                     + ", ".join(stragglers[:5]))


def check_regate_ran(result: dict) -> tuple[bool, str]:
    """The same_operator re-gate (retro-clean attribution pass) must have run."""
    at = (result.get("cleaned") or {}).get("attribution")
    ok = at is not None
    return ok, ("same_operator re-gate ran" if ok
                else "attribution pass did not run")


def verify(conn, case: str, result: dict) -> list[tuple[str, bool, str]]:
    return [
        ("scores", *check_scores(conn, case)),
        ("edge_times", *check_edge_times(conn, case)),
        ("indicator_typed", *check_indicator_typed(conn, case)),
        ("regate_ran", *check_regate_ran(result)),
    ]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Activation run + verification.")
    parser.add_argument("case", help="case slug to activate")
    parser.add_argument("--db", default=None, help="DB path (default: configured)")
    parser.add_argument("--no-backup", action="store_true",
                        help="skip the pre-mutation backup (tests use isolated DBs)")
    args = parser.parse_args(argv)

    db_path = Path(args.db) if args.db else db.DB_PATH
    if not args.no_backup:
        bak = backup_db(db_path)
        print(f"backup: {bak.name}")

    with db.connect(db_path) as conn:
        print(f"activating '{args.case}':")
        result = run_chain(conn, args.case)
        checks = verify(conn, args.case, result)

    print("\nverification:")
    failures = []
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        if not ok:
            failures.append(name)
    if failures:
        print(f"\nACTIVATION INCOMPLETE — failed: {', '.join(failures)}")
        return 1
    print("\nACTIVATION VERIFIED — all checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
