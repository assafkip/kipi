"""Spec-conformance contract tests (gap 1, prd-spine-phase0).

Pins PRD-fixed constants to their spec values so drift fails the build
instead of shipping silently. This is the class fix for the observed
instance: swarm.MAX_ROUNDS shipped as 3 while the PRD-09 depth-engine spec
said 5, and nothing went red.

Each assertion names its authoritative source. Changing a constant here
means changing the spec first; the test then moves WITH the spec, never
ahead of it.

Imports are plain module imports: swarm and warm_session resolve their
config from os.environ defaults at import time with no network or DB side
effects (verified: both import cleanly in the offline suite).
"""

import os
import subprocess
import sys

from investigations.agent import swarm, warm_session

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def test_max_rounds_matches_depth_engine_spec():
    # Source: PRD-09 depth engine (loop-until-dry round cap = 5),
    # reaffirmed by prd-spine-phase0 2026-06-11 (gap 1).
    assert swarm.MAX_ROUNDS == 5


def test_warm_max_turns_default_floor(monkeypatch):
    # Source: prd-spine-architecture 2026-06-11 — the warm turn ceiling's
    # DEFAULT must leave a real deep dig room (a live one runs ~30 turns; the
    # floor is 28). The spec pins the unset default (shipped: 80), not the
    # KIPI_WARM_MAX_TURNS override — that env knob is a deliberate founder
    # control and existing tests pin its pass-through behavior.
    monkeypatch.delenv("KIPI_WARM_MAX_TURNS", raising=False)
    assert warm_session._warm_max_turns() >= 28


def test_deep_cost_cap_default_matches_docs20():
    # Source: docs/20 §4 — the canonical deep-run dollar cap default is 5.
    # KIPI_DEEP_COST_CAP stays a deliberate founder knob; what this pins is
    # the UNSET default. The constant binds at module import, so assert it in
    # a clean interpreter with the knob stripped (a monkeypatch on the
    # already-imported module would pin nothing). Runtime cap BEHAVIOR
    # (target sizing, the 1.5x backstop) is test_depth_engine's contract.
    env = {k: v for k, v in os.environ.items() if k != "KIPI_DEEP_COST_CAP"}
    out = subprocess.run(
        [sys.executable, "-c",
         "from investigations.agent import swarm; print(swarm.DEEP_COST_CAP_USD)"],
        capture_output=True, text=True, env=env, cwd=REPO_ROOT, timeout=30)
    assert out.returncode == 0, out.stderr
    assert float(out.stdout.strip()) == 5.0
