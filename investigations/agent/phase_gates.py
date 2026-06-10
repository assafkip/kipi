"""Mid-run analyst steering: phase gates over the warm session (4pa-03).

4_points lets the analyst sit in the loop — the run works a phase, presents what
it found, and PAUSES for "do it" / "go this way instead" / "stop". kipi's runs
were fire-and-forget. This adds the same gate: a phased run that pauses between
phases and resumes on an analyst command (continue / redirect / stop), driven
from the chat surface via /api/run/control.

The phase RUNNER is injected — production runs each phase on the warm session
(run_turn_on_warm_loop); the test injects a fake runner so the state machine is
verified deterministically and offline.
"""

PHASE_READY = "ready"
PHASE_PAUSED = "paused"
PHASE_DONE = "done"
PHASE_STOPPED = "stopped"


class PhaseGatedRun:
    """A multi-phase run that pauses for the analyst between phases."""

    def __init__(self, case_slug: str, phases: list, runner) -> None:
        if not phases:
            raise ValueError("a phased run needs at least one phase")
        self.case_slug = case_slug
        self.phases = list(phases)
        self._runner = runner          # callable(phase, focus, prior_results) -> dict
        self.index = 0
        self.state = PHASE_READY
        self.results: list = []
        self.focus: str | None = None  # analyst redirect, applied to remaining phases
        self.checkpoint: dict | None = None  # what the last phase found + what's next

    def start(self) -> dict:
        if self.state != PHASE_READY:
            raise RuntimeError(f"run already started (state={self.state})")
        return self._run_current_phase()

    def control(self, command: str, redirect: str | None = None) -> dict:
        """Analyst steering between phases: continue / redirect / stop."""
        if self.state == PHASE_STOPPED:
            raise RuntimeError("run is already stopped")
        if self.state == PHASE_DONE:
            raise RuntimeError("run is already done")
        cmd = (command or "").strip().lower()
        if cmd == "stop":
            self.state = PHASE_STOPPED
            return self.status()
        if cmd == "redirect":
            self.focus = redirect  # steers every remaining phase
            return self._run_current_phase()
        if cmd == "continue":
            if self.state != PHASE_PAUSED:
                raise RuntimeError(f"nothing to continue (state={self.state})")
            return self._run_current_phase()
        raise ValueError(f"unknown control command: {command!r}")

    def _run_current_phase(self) -> dict:
        if self.index >= len(self.phases):
            self.state, self.checkpoint = PHASE_DONE, None
            return self.status()
        phase = self.phases[self.index]
        result = self._runner(phase, self.focus, list(self.results))
        self.results.append({"phase": phase, "result": result})
        self.index += 1
        proposed_next = self.phases[self.index] if self.index < len(self.phases) else None
        self.state = PHASE_DONE if proposed_next is None else PHASE_PAUSED
        self.checkpoint = {"phase": phase, "found": result, "proposed_next": proposed_next}
        return self.status()

    def status(self) -> dict:
        return {
            "case": self.case_slug,
            "state": self.state,
            "phase_index": self.index,
            "phases_total": len(self.phases),
            "focus": self.focus,
            "checkpoint": self.checkpoint,
        }


class PhaseGateRegistry:
    """Tracks the active phased run per case so the chat surface can steer it."""

    def __init__(self) -> None:
        self._runs: dict[str, PhaseGatedRun] = {}

    def start(self, case_slug: str, phases: list, runner) -> dict:
        run = PhaseGatedRun(case_slug, phases, runner)
        self._runs[case_slug] = run
        return run.start()

    def get(self, case_slug: str) -> PhaseGatedRun | None:
        return self._runs.get(case_slug)

    def control(self, case_slug: str, command: str, redirect: str | None = None) -> dict:
        run = self._runs.get(case_slug)
        if run is None:
            raise KeyError(f"no active phased run for case {case_slug!r}")
        status = run.control(command, redirect)
        if status["state"] in (PHASE_STOPPED, PHASE_DONE):
            self._runs.pop(case_slug, None)  # finished — don't leak
        return status


_REGISTRY = PhaseGateRegistry()


def registry() -> PhaseGateRegistry:
    return _REGISTRY


def _phase_task(phase: str, focus: str | None, prior: list) -> str:
    """Assemble the warm-session task for a phase, carrying the analyst's redirect."""
    steer = f"\n\nANALYST REDIRECT (prioritize): {focus}" if focus else ""
    seen = "; ".join(p["phase"] for p in prior) or "none yet"
    return (f"Investigation phase: {phase}. Phases already done: {seen}.{steer}\n"
            "Work this phase with the OSINT tools, then output the findings JSON.")


def warm_phase_runner(case_slug: str):
    """Default runner: each phase runs as one warm turn on the persistent loop."""
    from investigations.agent.warm_session import run_turn_on_warm_loop

    def _run(phase: str, focus: str | None, prior: list) -> dict:
        task = _phase_task(phase, focus, prior)
        return run_turn_on_warm_loop(case_slug, task, timeout=600)

    return _run


DEFAULT_PHASES = ["recon", "infrastructure pivot", "corroboration", "attribution"]


def start_phased_run(case_slug: str, phases: list | None = None) -> dict:
    """Production start path: register + start a phased warm run for a case and
    return its first checkpoint. Each phase runs as a warm turn; the run pauses
    after each for analyst control via the registry. This is what /api/run/start
    calls so /api/run/control has a live run to drive."""
    return registry().start(
        case_slug, phases or DEFAULT_PHASES, warm_phase_runner(case_slug)
    )
