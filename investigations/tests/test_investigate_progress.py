"""The investigator progress snapshot is parsed from the swarm's own event lines.
This guards that parse against drift: if swarm.py changes a marker string, this
test fails (the bar would otherwise silently stop counting).

Run: .venv/bin/python -m investigations.tests.test_investigate_progress
"""
from investigations.webapp import app as app_module


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_progress_parse_swarm_flow():
    prog = app_module._new_progress()
    _check("starts at zero", prog == {"phase": "starting", "targets_total": 0,
                                      "targets_done": 0, "findings": 0})

    # Replay the exact lines volley/investigate_selected emit (see swarm.py).
    app_module._update_progress(prog, "planning targets…")
    _check("planning phase", prog["phase"] == "planning")

    app_module._update_progress(prog, "picked 3 target(s): trump-2026.io, bc1qzmtqkk64, trump-2025.io")
    _check("targets_total parsed", prog["targets_total"] == 3)
    _check("phase → investigating", prog["phase"] == "investigating")

    app_module._update_progress(prog, "✓ trump-2026.io: 5 finding(s)")
    app_module._update_progress(prog, "✓ bc1qzmtqkk64: 5 finding(s)")
    _check("two targets done", prog["targets_done"] == 2)
    _check("findings summed", prog["findings"] == 10)

    app_module._update_progress(prog, "✗ trump-2025.io: whois timed out")
    _check("failed target still counts as done", prog["targets_done"] == 3)
    _check("failed target adds no findings", prog["findings"] == 10)


def test_tagged_substeps_do_not_miscount():
    # Per-target sub-steps are prefixed 'entity · …' and must NOT match the markers.
    prog = app_module._new_progress()
    app_module._update_progress(prog, "trump-2026.io · [16] Bash extract wallets")
    app_module._update_progress(prog, "trump-2026.io ·     ↳ found 3 wallets")
    _check("tagged lines don't bump targets_done", prog["targets_done"] == 0)
    _check("tagged lines don't bump findings", prog["findings"] == 0)


def test_no_pivots_marks_done():
    prog = app_module._new_progress()
    app_module._update_progress(prog, "no pivotable entities in scope to investigate")
    _check("no-pivots → done", prog["phase"] == "done")


def main():
    test_progress_parse_swarm_flow()
    test_tagged_substeps_do_not_miscount()
    test_no_pivots_marks_done()
    print("\nPASS: test_investigate_progress")


if __name__ == "__main__":
    main()
