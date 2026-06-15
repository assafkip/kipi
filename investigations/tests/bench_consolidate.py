"""Consolidate benchmark — Stage 3's red/green measurement harness.

Generates a reproducible multi-report corpus (synthetic names, zero overlap with real
cases), ingests it under one bench case, times `consolidate.run` on it, and snapshots
the merge/role decisions so a deterministic-layer change can be diffed old-vs-new.

Usage:
    .venv/bin/python -m investigations.tests.bench_consolidate generate   # build corpus + ingest
    .venv/bin/python -m investigations.tests.bench_consolidate run       # time + snapshot decisions
    .venv/bin/python -m investigations.tests.bench_consolidate cleanup   # delete the bench case

Plan: q-system/output/plans/speed-cost-staged-rollout-2026-06-09.md (Stage 3)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

CASE = "consolidate-bench"
REPORTS = 10
OUT = Path(__file__).parent / "baselines" / "consolidate-bench-decisions.json"


def _bench_db_path() -> Path:
    """The ISOLATED DB the bench writes to — NEVER the production db.DB_PATH
    (issue gtl-6). Synthetic kambala* fixtures used to land in the real
    investigations.db via db.connect() (default) and `invctl ingest` (default),
    mixing test rows into case data. Redirect: KIPI_BENCH_DB if set, else a stable
    temp file. The caller initializes the schema if missing.

    HARD GUARD (Codex gtl-6 adversarial): a KIPI_BENCH_DB that resolves to the
    production DB (absolute, relative, or symlinked) is REJECTED — the whole point
    is that the bench can never touch production, and an override must not defeat it."""
    from investigations.storage import db
    env = os.environ.get("KIPI_BENCH_DB")
    candidate = Path(env) if env else (
        Path(tempfile.gettempdir()) / "kipi-consolidate-bench" / "bench.db")
    try:
        same = candidate.resolve() == db.DB_PATH.resolve()
    except OSError:
        same = False
    if same:
        raise ValueError(
            "KIPI_BENCH_DB must not point at the production DB "
            f"({db.DB_PATH}) — the bench must stay isolated.")
    return candidate


def _bench_conn():
    """Open (and lazily create) the isolated bench DB. Initializes the schema when
    the file is missing OR exists-but-empty (e.g. KIPI_BENCH_DB pointed at an
    mktemp/NamedTemporaryFile 0-byte file) — db.connect runs migrations that assume
    base tables exist, so an empty redirected DB must be init'd first (Codex gtl-6)."""
    from investigations.storage import db
    path = _bench_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_init = not path.exists() or path.stat().st_size == 0
    if not needs_init:
        # A non-empty file that somehow lacks the base schema also needs init.
        import sqlite3
        try:
            con = sqlite3.connect(str(path))
            has = con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='entities'"
            ).fetchone()
            con.close()
            needs_init = has is None
        except sqlite3.DatabaseError:
            needs_init = True
    if needs_init:
        db.init_db(path)
    return db.connect(path)

# Deterministic corpus: per report, a mix of unique entities + alias variants of
# shared ones (scheme/www/case variants, @handle vs t.me, name-vs-email actors) +
# noise strings — the shapes the real telegram/report pipeline produces.
def _report_text(i: int) -> str:
    lines = [f"Bench report {i}: monitoring the kambala panel affiliate ring."]
    for j in range(12):
        lines.append(f"kambala-shop-{i}-{j}.example seen serving the kit.")
    # shared across reports under alias variants → the dedup work
    lines.append(f"Operator handle @kambala_boss{'  ' if i % 2 else ''} coordinates payouts.")
    lines.append(f"See t.me/kambala_boss for the channel.")
    lines.append(f"Panel at {'https://www.' if i % 2 else ''}kambala-panel.example/ rotates.")
    lines.append(f"Contact support@kambala-mail.example for the kit.")
    lines.append(f"Payout wallet 0x{'ab%02d' % i}{'c' * 36} drained twice.")
    lines.append(f"Mirror {'HTTPS://' if i % 3 == 0 else ''}Kambala-Mirror.example holds assets.")
    for j in range(6):
        lines.append(f"Affiliate kambala{i}{j}@mail-{j}.example registered domain "
                     f"aff-{i}-{j}.example via the panel.")
    lines.append("color-blocking: 600px;")          # css noise shape
    lines.append("Creation Date")                    # whois fragment noise shape
    return "\n".join(lines)


def generate() -> None:
    # IN-PROCESS ingest against the ISOLATED bench DB (issue gtl-6) — the old path
    # shelled out to `./invctl ingest`, which has no DB override and so wrote the
    # synthetic corpus into the production investigations.db. Reuse invctl's own
    # _ingest_one (identical extraction logic) but pass it the bench connection.
    from investigations.cli.invctl import _ingest_one
    d = Path(tempfile.gettempdir()) / "consolidate-bench-src"
    d.mkdir(exist_ok=True)
    with _bench_conn() as conn:
        for i in range(REPORTS):
            f = d / f"bench-{i}.txt"
            f.write_text(_report_text(i))
            rid = _ingest_one(conn, f, CASE)
            print(f"  ingested bench-{i}.txt (report_id={rid})" if rid
                  else f"  skipped bench-{i}.txt")
        conn.commit()
    print(f"bench corpus ingested into isolated DB: {_bench_db_path()}")


def _decisions(conn) -> dict:
    """The judgeable output of consolidate for the bench case: role per entity +
    which names were absorbed (alias table) + survivor count."""
    ents = conn.execute(
        "SELECT e.canonical_name, e.entity_type, e.notes, e.hidden FROM entities e "
        "WHERE e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
        "ON r.id = m.report_id WHERE r.investigation = ?) "
        "ORDER BY e.canonical_name", (CASE,)).fetchall()
    aliases = conn.execute(
        "SELECT a.alias, e.canonical_name FROM aliases a JOIN entities e ON e.id = a.entity_id "
        "WHERE e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
        "ON r.id = m.report_id WHERE r.investigation = ?) ORDER BY a.alias", (CASE,)).fetchall()
    return {
        "survivors": len(ents),
        "roles": {r["canonical_name"]: (r["notes"] or "").split("\n")[0] for r in ents},
        "absorbed": {r["alias"]: r["canonical_name"] for r in aliases},
    }


def run_bench() -> None:
    from investigations import consolidate
    with _bench_conn() as conn:
        n = conn.execute(
            "SELECT COUNT(DISTINCT m.entity_id) c FROM mentions m JOIN reports r "
            "ON r.id = m.report_id WHERE r.investigation = ?", (CASE,)).fetchone()["c"]
        print(f"bench case has {n} entities; running consolidate (case-scoped)…")
        t0 = time.monotonic()
        stats = consolidate.run(conn, case=CASE)
        wall = round(time.monotonic() - t0, 1)
        decisions = _decisions(conn)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(
        {"wall_clock_s": wall, "entities_in": n, "stats": {k: v for k, v in stats.items()},
         "decisions": decisions}, indent=2, default=str))
    print(f"wall clock: {wall}s | merged: {stats['merged']} | noise: {stats['noise']} "
          f"| survivors: {decisions['survivors']}")
    print(f"decisions snapshot: {OUT}")


def cleanup() -> None:
    # The bench now lives in its own throwaway DB — deleting that file is the whole
    # cleanup, and it never touched the production DB to begin with.
    path = _bench_db_path()
    if path.exists() and os.environ.get("KIPI_BENCH_DB") is None:
        path.unlink()
        print(f"removed isolated bench DB: {path}")
    else:
        print(f"bench DB is isolated at {path}; remove it manually if you set KIPI_BENCH_DB.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    {"generate": generate, "run": run_bench, "cleanup": cleanup}[cmd]()
