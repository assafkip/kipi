"""Per-target run-progress semantics (run-progress-semantics PRD, issue rps-1).

Guards the per-node state machine the run card renders: queued → running →
done(K)/done(none), assembled by `_update_progress` from the swarm's own UNTAGGED
event lines. The point of the feature is that '0 findings' is never a standing
mid-run result — a running target reads `running`, a zero-result target reads
`done · 0` only once it has actually finished. These tests pin the marker strings
(so a swarm emit-string change trips here) and prove the new '→ start' emit is
additive (identical aggregate counts with and without it).

Also covers the ETA basis: `swarm._historical_seconds_per_target` over an in-memory
copy of the enrichment_runs shape (test isolation — never a live DB), and the pure
`_recompute_eta` arithmetic + cold-start null.

Run: .venv/bin/python -m pytest investigations/tests/test_run_progress_semantics.py -q
"""
import sqlite3

from investigations.webapp import app as app_module
from investigations.agent import swarm


def _state(prog, name):
    for t in prog.get("targets", []):
        if t["name"] == name:
            return t
    return None


def test_picked_seeds_queued_targets():
    prog = app_module._new_progress()
    app_module._update_progress(prog, "picked 3 target(s): a.io, b.io, c.io")
    assert prog["targets_total"] == 3
    assert [t["name"] for t in prog["targets"]] == ["a.io", "b.io", "c.io"]
    assert all(t["state"] == "queued" for t in prog["targets"])


def test_target_transitions_queued_running_done():
    prog = app_module._new_progress()
    app_module._update_progress(prog, "picked 2 target(s): a.io, b.io")
    assert _state(prog, "a.io")["state"] == "queued"

    app_module._update_progress(prog, "→ start a.io")
    assert _state(prog, "a.io")["state"] == "running"
    # b.io must still be queued — starting one target does not move the others.
    assert _state(prog, "b.io")["state"] == "queued"

    app_module._update_progress(prog, "✓ a.io: 5 finding(s)")
    assert _state(prog, "a.io")["state"] == "done"
    assert _state(prog, "a.io")["findings"] == 5


def test_zero_result_target_is_done_none_not_a_mid_run_verdict():
    # The core fix: a finished target with zero findings reads `done · 0` (neutral),
    # and a target that is STILL RUNNING is never shown as `done · 0`.
    prog = app_module._new_progress()
    app_module._update_progress(prog, "picked 2 target(s): empty.io, slow.io")
    app_module._update_progress(prog, "→ start empty.io")
    app_module._update_progress(prog, "→ start slow.io")
    # empty.io finishes with nothing; slow.io never reports back.
    app_module._update_progress(prog, "✓ empty.io: 0 finding(s)")

    empty = _state(prog, "empty.io")
    assert empty["state"] == "done" and empty["findings"] == 0
    # NEGATIVE SELF-TEST: slow.io must stay `running`, NOT be faked to done·0.
    slow = _state(prog, "slow.io")
    assert slow["state"] == "running", "a never-completed target must not read as done·0"


def test_failed_target_is_done_zero():
    prog = app_module._new_progress()
    app_module._update_progress(prog, "picked 1 target(s): bad.io")
    app_module._update_progress(prog, "✗ bad.io: whois timed out")
    rec = _state(prog, "bad.io")
    assert rec["state"] == "done" and rec["findings"] == 0
    assert prog["targets_done"] == 1


def test_expand_path_markers():
    # The one-hop set-expand path (the founder's 0/7 case): picked seed + "expanding X…"
    # running signal + "✓ X: K finding(s)" done. Was previously invisible (no markers).
    prog = app_module._new_progress()
    app_module._update_progress(prog, "picked 2 target(s): x.io, y.io")
    app_module._update_progress(prog, "expanding x.io…")
    assert _state(prog, "x.io")["state"] == "running"
    app_module._update_progress(prog, "✓ x.io: 3 finding(s)")
    assert _state(prog, "x.io")["state"] == "done" and _state(prog, "x.io")["findings"] == 3


def test_lazy_add_for_deep_runs_without_picked_seed():
    # Deep/whole-case runs emit no "picked" line; targets appear as they start/finish.
    prog = app_module._new_progress()
    app_module._update_progress(prog, "→ start z.io")
    assert _state(prog, "z.io")["state"] == "running"
    app_module._update_progress(prog, "✓ z.io: 1 finding(s)")
    assert _state(prog, "z.io")["state"] == "done"


def test_tagged_substeps_do_not_match():
    # Per-target sub-steps are prefixed 'entity · …' and must not touch any state.
    prog = app_module._new_progress()
    app_module._update_progress(prog, "x.io · [16] Bash extract wallets")
    app_module._update_progress(prog, "x.io ·     ↳ found 3 wallets")
    assert prog["targets_done"] == 0 and prog["findings"] == 0
    assert prog.get("targets", []) == []


def test_start_emit_is_aggregate_invariant():
    # EMIT SAFETY (finding-4): adding the new "→ start {ent}" lines must NOT change the
    # aggregate counters (targets_done / findings) — they are additive instrumentation.
    base = ["picked 2 target(s): a.io, b.io",
            "✓ a.io: 5 finding(s)", "✓ b.io: 2 finding(s)"]
    with_starts = ["picked 2 target(s): a.io, b.io",
                   "→ start a.io", "→ start b.io",
                   "✓ a.io: 5 finding(s)", "✓ b.io: 2 finding(s)"]

    p1 = app_module._new_progress()
    for ln in base:
        app_module._update_progress(p1, ln)
    p2 = app_module._new_progress()
    for ln in with_starts:
        app_module._update_progress(p2, ln)

    assert p1["targets_done"] == p2["targets_done"] == 2
    assert p1["findings"] == p2["findings"] == 7


def test_crew_path_counts_each_target_once():
    # finding-1: the crew path emits a TAGGED "{ent} · crew merged: N" inner rollup AND
    # volley emits the UNTAGGED "✓ {ent}: N" completion. Only the untagged ✓ may count —
    # the tagged rollup must fall through inert (no double-count of targets_done/findings).
    prog = app_module._new_progress()
    app_module._update_progress(prog, "picked 1 target(s): a.io")
    app_module._update_progress(prog, "→ start a.io")
    app_module._update_progress(prog, "a.io · crew merged: 5 finding(s), 3 node(s)")
    app_module._update_progress(prog, "✓ a.io: 5 finding(s)")
    assert prog["targets_done"] == 1, "crew rollup + ✓ must not double-count targets_done"
    assert prog["findings"] == 5, "crew rollup + ✓ must not double-count findings"
    assert _state(prog, "a.io")["state"] == "done"
    assert _state(prog, "a.io")["findings"] == 5


def test_whole_case_summary_does_not_fabricate_a_target():
    # finding-2: the whole-case run ends with "✓ case mapped (exhausted): N finding(s)".
    # That is NOT a target — it must not lazy-add a "case mapped (...)" per-target node.
    prog = app_module._new_progress()
    app_module._update_progress(prog, "✓ case mapped (exhausted): 12 finding(s)")
    assert prog.get("targets", []) == [], "summary line must not create a per-target node"


def test_lazy_add_keeps_targets_total_in_sync():
    # finding-4: deep/whole-case runs have no "picked N" seed; lazy-added targets must keep
    # targets_total >= len(targets) so the card never shows an impossible "1/0".
    prog = app_module._new_progress()
    app_module._update_progress(prog, "→ start a.io")
    app_module._update_progress(prog, "→ start b.io")
    assert prog["targets_total"] >= 2
    app_module._update_progress(prog, "✓ a.io: 1 finding(s)")
    assert prog["targets_done"] <= prog["targets_total"], "never targets_done > targets_total"


def test_non_domain_names_match():
    # finding-3: name matching must work for any entity identifier, not just domains
    # (wallets, telegram URLs, @handles). Commas don't occur in these identifier types.
    prog = app_module._new_progress()
    app_module._update_progress(prog, "picked 2 target(s): bc1qzz9, t.me/examplegroup")
    app_module._update_progress(prog, "→ start t.me/examplegroup")
    assert _state(prog, "t.me/examplegroup")["state"] == "running"
    app_module._update_progress(prog, "✓ bc1qzz9: 2 finding(s)")
    assert _state(prog, "bc1qzz9")["state"] == "done"
    assert _state(prog, "bc1qzz9")["findings"] == 2


def test_recompute_eta_arithmetic_and_cold_start():
    prog = app_module._new_progress()
    prog["secs_per_target"] = 30.0
    app_module._update_progress(prog, "picked 2 target(s): a.io, b.io")
    # 2 not-done × 30s = 60s.
    assert prog["eta_s"] == 60
    app_module._update_progress(prog, "✓ a.io: 1 finding(s)")
    # 1 not-done × 30s = 30s.
    assert prog["eta_s"] == 30

    # Cold-start: no secs_per_target → never a fabricated ETA.
    cold = app_module._new_progress()
    cold["secs_per_target"] = None
    app_module._update_progress(cold, "picked 2 target(s): a.io, b.io")
    assert cold["eta_s"] is None


def _seed_runs_db():
    """In-memory copy of the enrichment_runs columns the ETA query reads. Test isolation —
    never the live data path (build-craft)."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE enrichment_runs (id INTEGER PRIMARY KEY, provider_slug TEXT, "
        "started_at TEXT, finished_at TEXT, cost_usd REAL)"
    )
    return conn


def test_historical_seconds_per_target_cold_start():
    conn = _seed_runs_db()
    avg, basis = swarm._historical_seconds_per_target(conn)
    assert avg is None and basis == "cold-start"


def test_historical_seconds_per_target_historical():
    conn = _seed_runs_db()
    # Two agent rows: 20s and 40s elapsed → avg 30s.
    conn.execute("INSERT INTO enrichment_runs (provider_slug, started_at, finished_at) "
                 "VALUES ('agent', '2026-06-15 10:00:00', '2026-06-15 10:00:20')")
    conn.execute("INSERT INTO enrichment_runs (provider_slug, started_at, finished_at) "
                 "VALUES ('agent', '2026-06-15 10:00:00', '2026-06-15 10:00:40')")
    # A legacy zero-elapsed row (started_at==finished_at) must be excluded.
    conn.execute("INSERT INTO enrichment_runs (provider_slug, started_at, finished_at) "
                 "VALUES ('agent', '2026-06-15 10:00:00', '2026-06-15 10:00:00')")
    # A non-agent row must be excluded.
    conn.execute("INSERT INTO enrichment_runs (provider_slug, started_at, finished_at) "
                 "VALUES ('whois', '2026-06-15 10:00:00', '2026-06-15 10:05:00')")
    avg, basis = swarm._historical_seconds_per_target(conn)
    assert basis == "historical"
    assert avg == 30.0


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\nPASS: {len(fns)} tests")
    sys.exit(0)
