"""4pa-03 — mid-run analyst steering: phase gates over the warm session.

Deterministic + offline: the phase runner is faked, so we verify the state
machine (pause between phases; continue / redirect / stop) without a live run.

Asserts:
  - the run PAUSES after each phase (presents a checkpoint with the proposed next),
  - 'continue' resumes the next phase,
  - 'redirect' steers every remaining phase with the analyst's focus,
  - 'stop' ends the run and no further phase executes,
  - the registry drives a run by case and drops it when finished.

Run: .venv/bin/python -m investigations.tests.test_phase_gates
"""
from investigations.agent import phase_gates
from investigations.agent.phase_gates import (
    PhaseGatedRun, PHASE_PAUSED, PHASE_DONE, PHASE_STOPPED,
)


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _recording_runner(log):
    """Fake phase runner: records (phase, focus) and returns a canned result."""
    def _run(phase, focus, prior):
        log.append((phase, focus))
        return {"phase": phase, "focus": focus, "n_prior": len(prior)}
    return _run


def test_pause_then_continue():
    log = []
    run = PhaseGatedRun("case-x", ["recon", "pivot", "corroborate"], _recording_runner(log))

    status = run.start()
    _check("run pauses after phase 1", status["state"] == PHASE_PAUSED)
    _check("checkpoint names the completed phase", status["checkpoint"]["phase"] == "recon")
    _check("checkpoint proposes the next phase", status["checkpoint"]["proposed_next"] == "pivot")
    _check("only phase 1 ran during the pause", log == [("recon", None)])

    status = run.control("continue")
    _check("continue runs phase 2, still paused", status["state"] == PHASE_PAUSED
           and status["checkpoint"]["phase"] == "pivot")

    status = run.control("continue")
    _check("final phase completes -> done", status["state"] == PHASE_DONE)
    _check("all three phases ran in order",
           [p for p, _ in log] == ["recon", "pivot", "corroborate"])


def test_redirect_steers_remaining_phases():
    log = []
    run = PhaseGatedRun("case-y", ["recon", "pivot"], _recording_runner(log))
    run.start()  # phase 1 ran with no focus
    status = run.control("redirect", redirect="follow the payout wallets")
    _check("redirect ran the next phase with the analyst focus",
           log[-1] == ("pivot", "follow the payout wallets"))
    _check("redirect carried into the run state", status["focus"] == "follow the payout wallets")


def test_stop_ends_run():
    log = []
    run = PhaseGatedRun("case-z", ["recon", "pivot", "corroborate"], _recording_runner(log))
    run.start()
    status = run.control("stop")
    _check("stop ends the run", status["state"] == PHASE_STOPPED)
    _check("no further phase ran after stop", log == [("recon", None)])
    try:
        run.control("continue")
        _check("stopped run rejects further control", False)
    except RuntimeError:
        _check("stopped run rejects further control", True)


def test_registry_drives_by_case():
    log = []
    reg = phase_gates.PhaseGateRegistry()
    status = reg.start("case-reg", ["recon", "pivot"], _recording_runner(log))
    _check("registry start pauses after phase 1", status["state"] == PHASE_PAUSED)
    _check("registry tracks the active run", reg.get("case-reg") is not None)

    status = reg.control("case-reg", "continue")
    _check("registry continue finishes the run", status["state"] == PHASE_DONE)
    _check("finished run is dropped from the registry", reg.get("case-reg") is None)

    try:
        reg.control("case-reg", "continue")
        _check("controlling an unknown run errors", False)
    except KeyError:
        _check("controlling an unknown run errors", True)


def test_endpoints_wire_start_and_control():
    """P1 wiring: /api/run/start is the production start path; /api/run/control
    drives a live run. Gated on KIPI_WARM_SESSION."""
    import os
    from fastapi.testclient import TestClient
    from investigations.webapp import app as app_module

    client = TestClient(app_module.app)

    # Warm is now the DEFAULT (opt-out). The /api/run/start gate fires only when warm is
    # EXPLICITLY disabled — KIPI_WARM_SESSION=0 — not merely unset.
    saved = os.environ.get("KIPI_WARM_SESSION")
    os.environ["KIPI_WARM_SESSION"] = "0"
    try:
        r = client.post("/api/run/start", json={"case": "case-web"})
        _check("start with warm explicitly disabled is rejected (400)", r.status_code == 400)
    finally:
        if saved is not None:
            os.environ["KIPI_WARM_SESSION"] = saved
        else:
            os.environ.pop("KIPI_WARM_SESSION", None)

    # Seed a run via the shared registry singleton the endpoint reads.
    log = []
    phase_gates.registry().start("case-web", ["recon", "pivot"], _recording_runner(log))
    r = client.post("/api/run/control", json={"case": "case-web", "command": "continue"})
    _check("control endpoint 200", r.status_code == 200)
    _check("control endpoint drove the run", r.json().get("state") in (PHASE_PAUSED, PHASE_DONE))

    r = client.post("/api/run/control", json={"case": "no-such-case", "command": "continue"})
    _check("control on unknown run is 400", r.status_code == 400)


def main():
    test_pause_then_continue()
    test_redirect_steers_remaining_phases()
    test_stop_ends_run()
    test_registry_drives_by_case()
    test_endpoints_wire_start_and_control()
    print("PASS test_phase_gates: phased run pauses between phases; continue/redirect/"
          "stop drive it; registry steers by case and cleans up on finish")


if __name__ == "__main__":
    main()
