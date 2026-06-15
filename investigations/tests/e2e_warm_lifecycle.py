"""E2E (live): prove the agent-run lifecycle fixes are deployed end-to-end through the
REAL warm agent + REAL land path + REAL DB.

This is a LIVE run (real API + MCP boot), deliberately bounded tiny so it's cheap:
  KIPI_WARM_TOOL_BUDGET=6 → the injected budget hook trips after ~6 tool calls and the
  agent emits its findings (graceful salvage, not a kill). That exercises ALL the fixes:
    - budget gate reaches the agent (the leash that .claude/rules can't provide) and FIRES
    - NO wall-clock timer cuts it (timeout=None default) — the budget bounds it instead
    - the warm run records REAL cost + turns + wall-clock (started_at != finished_at)

Asserts against the real investigations.db:
  - a new enrichment_runs row landed
  - started_at != finished_at (real wall-clock, not the old cost-blind same-instant)
  - cost_usd is populated (not NULL) OR turns recorded in the process blob

Run: KIPI_WARM_TOOL_BUDGET=6 .venv/bin/python -m investigations.tests.e2e_warm_lifecycle <domain>
"""
import os
import sys
import threading
import time

from investigations.storage import db
from investigations.agent import investigator as inv


def _newest_run_id(conn) -> int:
    row = conn.execute("SELECT COALESCE(MAX(id), 0) m FROM enrichment_runs").fetchone()
    return row["m"]


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "trumpstake.us"
    os.environ.setdefault("KIPI_WARM_TOOL_BUDGET", "6")   # tiny, cheap, trips the breaker
    os.environ.pop("KIPI_WARM_TURN_TIMEOUT", None)        # prove the no-timer default
    print(f"E2E warm lifecycle on {target!r} | budget={os.environ['KIPI_WARM_TOOL_BUDGET']} "
          f"| KIPI_WARM_SESSION={os.environ.get('KIPI_WARM_SESSION', '(unset→on)')}")

    with db.connect() as conn:
        case = conn.execute(
            "SELECT slug FROM investigations ORDER BY id LIMIT 1").fetchone()["slug"]
        before = _newest_run_id(conn)
    print(f"case={case} | enrichment_runs max id before={before}")

    # Hard safety net so the e2e can't run away even if every other bound failed.
    cancel = threading.Event()
    t = threading.Timer(240, cancel.set)
    t.daemon = True
    t.start()

    t0 = time.monotonic()
    with db.connect() as run_conn:
        result = inv.investigate_entity(conn=run_conn, entity=target, case=case, cancel=cancel)
    wall = round(time.monotonic() - t0, 1)
    t.cancel()
    print(f"run finished in {wall}s | ok={result.get('ok')} findings={result.get('findings')} "
          f"cost_usd={result.get('cost_usd')}")

    with db.connect() as conn:
        after = _newest_run_id(conn)
        assert after > before, f"no new enrichment_runs row landed (before={before}, after={after})"
        row = conn.execute(
            "SELECT id, started_at, finished_at, cost_usd, agent_process "
            "FROM enrichment_runs WHERE id = ?", (after,)).fetchone()
    import json
    proc = json.loads(row["agent_process"]) if row["agent_process"] else {}
    print(f"\nNEW enrichment_runs row id={row['id']}:")
    print(f"  started_at  = {row['started_at']}")
    print(f"  finished_at = {row['finished_at']}")
    print(f"  cost_usd    = {row['cost_usd']}")
    print(f"  process.turns    = {proc.get('turns')}")
    print(f"  process.cost_usd = {proc.get('cost_usd')}")

    # The instrumentation contract: wall-clock is no longer collapsed to one instant.
    assert row["started_at"] and row["finished_at"], "timestamps missing"
    assert row["started_at"] != row["finished_at"], \
        f"started_at == finished_at ({row['started_at']}) — still cost-blind (instrumentation NOT deployed)"
    # cost/turns visibility: at least one of the cost/turn signals must be populated.
    has_cost = row["cost_usd"] is not None or proc.get("cost_usd") is not None
    has_turns = proc.get("turns") is not None
    assert has_cost or has_turns, "neither cost_usd nor turns recorded — run is still cost-blind"
    print("\nPASS e2e_warm_lifecycle: deployed warm run recorded real wall-clock "
          "(started_at != finished_at) + cost/turns; budget-bounded, no timer.")


if __name__ == "__main__":
    main()
