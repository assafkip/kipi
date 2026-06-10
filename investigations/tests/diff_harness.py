"""Differential harness — Stage 0 of the speed/cost staged rollout.

The make-sure machinery: a behavior change to the investigator ships ONLY when a run
on the same case produces a superset-or-equal graph vs a frozen baseline. The graph
half (entities + typed edges) is judged deterministically here; the brief half is
emitted side-by-side for the analyst (judgment can't be regex'd).

Plan: q-system/output/plans/speed-cost-staged-rollout-2026-06-09.md

Usage:
    ./invctl diff-run <case> --save              # run live + freeze as the baseline
    ./invctl diff-run <case>                     # run live + diff vs frozen baseline
    pytest investigations/tests/test_diff_harness.py   # offline self-diff proof
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from investigations.storage import db

BASELINE_DIR = Path(__file__).parent / "baselines"

# Case membership covers BOTH landing shapes: promote/agent paths write a mention;
# the live-dig path (_persist_step_discovery) only stamps first_seen_report_id.
_IN_CASE = (
    "(e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id "
    "  WHERE r.investigation = ?) "
    " OR e.first_seen_report_id IN (SELECT id FROM reports WHERE investigation = ?))"
)

_CASE_ENTITY_SQL = (
    f"SELECT e.canonical_name, e.entity_type FROM entities e "
    f"WHERE e.hidden = 0 AND {_IN_CASE}"
)

_CASE_EDGE_SQL = (
    "SELECT e1.canonical_name src, e2.canonical_name dst, t.rel_type "
    "FROM typed_relationships t "
    "JOIN entities e1 ON e1.id = t.src_entity_id "
    "JOIN entities e2 ON e2.id = t.dst_entity_id "
    "WHERE t.status = 'active' AND e1.hidden = 0 AND e2.hidden = 0 "
    "AND t.src_entity_id IN ("
    f"  SELECT e.id FROM entities e WHERE {_IN_CASE})"
)


def snapshot_case(conn, case: str) -> dict:
    """The case's graph spine: entities + active typed edges, name-normalized."""
    entities = sorted({(r["canonical_name"].strip().lower(), r["entity_type"])
                       for r in conn.execute(_CASE_ENTITY_SQL, (case, case))})
    edges = sorted({(r["src"].strip().lower(), r["dst"].strip().lower(), r["rel_type"])
                    for r in conn.execute(_CASE_EDGE_SQL, (case, case))})
    return {
        "case": case,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entities": [list(e) for e in entities],
        "edges": [list(e) for e in edges],
        "entity_count": len(entities),
        "edge_count": len(edges),
    }


def _first_node_seconds(conn, case: str, started_utc: str) -> float | None:
    """Seconds from run start to the first IN-CASE landed lookup, or None.
    Measured on enrichment_runs (case-scoped, timestamped) — entities.first_seen_at is
    GLOBAL, so on a repeat case every 'discovery' already exists and the entity-based
    metric reads end-of-run (the s2 gate showed 1268s while nodes landed at 5s)."""
    # finished_at formats are MIXED ('2026-06-10T02:53:54Z' from the belt, space-
    # separated from the agent) — a SQL string MIN() picks the wrong row, so
    # normalize + compare in Python.
    started = datetime.fromisoformat(started_utc).replace(tzinfo=timezone.utc)
    times = []
    for r in conn.execute(
            "SELECT finished_at t FROM enrichment_runs "
            "WHERE investigation = ? AND status = 'success' AND finished_at IS NOT NULL",
            (case,)):
        norm = r["t"].replace("T", " ").replace("Z", "").strip()
        ts = datetime.fromisoformat(norm).replace(tzinfo=timezone.utc)
        if ts >= started:
            times.append(ts)
    if not times:
        return None
    return round((min(times) - started).total_seconds(), 1)


def run_and_snapshot(case: str, runner=None) -> dict:
    """Run the whole-case investigator live, then snapshot the graph + run metrics.
    `runner` is injectable for tests; defaults to investigate_case_agentic."""
    if runner is None:
        from investigations.agent import investigator
        runner = investigator.investigate_case_agentic
    started_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    t0 = time.monotonic()
    with db.connect() as conn:
        result = runner(conn, case)
    wall_clock = round(time.monotonic() - t0, 1)
    with db.connect() as conn:
        snap = snapshot_case(conn, case)
        snap["metrics"] = {
            "wall_clock_s": wall_clock,
            "time_to_first_node_s": _first_node_seconds(conn, case, started_utc),
            "cost_usd": result.get("cost_usd"),
            "passes": result.get("passes"),
            "findings": result.get("findings"),
            "stop_reason": result.get("stop_reason"),
        }
        snap["brief"] = result.get("summary") or ""
    return snap


def diff_snapshots(baseline: dict, current: dict) -> dict:
    """Superset-or-equal gate: every baseline entity + edge must exist in current.
    Additions are informational; any missing item fails the verdict."""
    base_entities = {tuple(e) for e in baseline["entities"]}
    cur_entities = {tuple(e) for e in current["entities"]}
    base_edges = {tuple(e) for e in baseline["edges"]}
    cur_edges = {tuple(e) for e in current["edges"]}
    missing_entities = sorted(base_entities - cur_entities)
    missing_edges = sorted(base_edges - cur_edges)
    return {
        "verdict": "pass" if not missing_entities and not missing_edges else "fail",
        "missing_entities": [list(e) for e in missing_entities],
        "missing_edges": [list(e) for e in missing_edges],
        "added_entities": len(cur_entities - base_entities),
        "added_edges": len(cur_edges - base_edges),
        "baseline_counts": {"entities": len(base_entities), "edges": len(base_edges)},
        "current_counts": {"entities": len(cur_entities), "edges": len(cur_edges)},
    }


def baseline_path(case: str) -> Path:
    return BASELINE_DIR / f"{case}.json"


def save_baseline(snapshot: dict) -> Path:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    path = baseline_path(snapshot["case"])
    path.write_text(json.dumps(snapshot, indent=2))
    return path


def load_baseline(case: str) -> dict:
    """One baseline by name, or the INTERSECTION CORE of several (comma-separated).
    Gate v2 (Stage-1 lesson): run-to-run variance between identical agents is large,
    so the required set is what ≥2 unwired runs BOTH found — the reproducible core —
    not one lucky run's full graph."""
    names = [n.strip() for n in case.split(",") if n.strip()]
    if len(names) == 1:
        path = baseline_path(names[0])
        if not path.exists():
            raise FileNotFoundError(
                f"no frozen baseline for '{names[0]}' — run `./invctl diff-run {names[0]} --save` first")
        return json.loads(path.read_text())
    snaps = [load_baseline(n) for n in names]
    entities = set.intersection(*({tuple(e) for e in s["entities"]} for s in snaps))
    edges = set.intersection(*({tuple(e) for e in s["edges"]} for s in snaps))
    return {
        "case": "+".join(names),
        "captured_at": snaps[0]["captured_at"],
        "entities": sorted([list(e) for e in entities]),
        "edges": sorted([list(e) for e in edges]),
        "entity_count": len(entities),
        "edge_count": len(edges),
        "core_of": names,
        "metrics": snaps[0].get("metrics"),
        "brief": snaps[0].get("brief", ""),
    }


def format_report(diff: dict, baseline: dict, current: dict) -> str:
    """Human-readable diff report; briefs side-by-side when both runs carry one."""
    lines = [
        f"verdict: {diff['verdict'].upper()}",
        f"baseline: {diff['baseline_counts']['entities']} entities / "
        f"{diff['baseline_counts']['edges']} edges  →  current: "
        f"{diff['current_counts']['entities']} entities / {diff['current_counts']['edges']} edges",
        f"added: +{diff['added_entities']} entities, +{diff['added_edges']} edges",
    ]
    for label, items in (("MISSING entities", diff["missing_entities"]),
                         ("MISSING edges", diff["missing_edges"])):
        if items:
            lines.append(f"{label} ({len(items)}):")
            lines.extend(f"  - {' '.join(i)}" for i in items)
    if baseline.get("metrics") and current.get("metrics"):
        b, c = baseline["metrics"], current["metrics"]
        lines.append("metrics (baseline → current):")
        for k in ("wall_clock_s", "time_to_first_node_s", "cost_usd", "passes", "findings"):
            lines.append(f"  {k}: {b.get(k)} → {c.get(k)}")
    if baseline.get("brief") and current.get("brief"):
        lines.append("\n--- BRIEF (baseline) ---\n" + baseline["brief"])
        lines.append("\n--- BRIEF (current) ---\n" + current["brief"])
        lines.append("\n^ analyst judges the briefs side-by-side; the verdict above "
                     "covers only the graph spine.")
    return "\n".join(lines)
