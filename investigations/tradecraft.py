"""Tradecraft gates for the chat investigator.

The chat is a fast, rule-free agent (warm_session runs setting_sources=[]), so the
analytical discipline that 4_points enforces via the /q-* commands never reached it.
This module makes the tradecraft steps first-class in the chat: a per-case checklist
the analyst drives by pressing buttons, with state that is CODE-ENFORCED (a step is
"done" when its artifact row exists), not a prompt rule the agent can skip.

Founder decisions (2026-06-11):
  - SOFT nudge, never a hard block: the brief surfaces a warning listing unmet gates,
    but you're never stopped (the chat stays fast and frictionless).
  - 3 GATES + 3 HELPERS: Scope / Challenge / Premortem are tracked gates (they show in
    the checklist and drive the brief nudge); Timeline / Target / Reality-check are
    one-click helpers that just steer the investigator.

Scope captures analyst input (the framing). Challenge and Premortem RUN an analysis over
the case's current findings + graph and store the result. Helpers route a templated
request to the chat — no stored artifact, no gate.
"""
from __future__ import annotations

STEPS = [
    {"key": "scope", "label": "Scope", "kind": "gate", "icon": "◎",
     "blurb": "Frame the question, the hypotheses, and what counts as proof."},
    {"key": "challenge", "label": "Challenge", "kind": "gate", "icon": "⚔",
     "blurb": "Pressure-test the findings: name-match traps, circular reasoning, "
              "source independence, confirmation bias."},
    {"key": "premortem", "label": "Premortem", "kind": "gate", "icon": "⚑",
     "blurb": "Assume the brief is wrong six months from now. What made it wrong?"},
    {"key": "timeline", "label": "Timeline", "kind": "helper", "icon": "⏱",
     "blurb": "Build a chronology of the case."},
    {"key": "target", "label": "Target", "kind": "helper", "icon": "◉",
     "blurb": "Profile a specific target in depth."},
    {"key": "reality_check", "label": "Reality check", "kind": "helper", "icon": "⚖",
     "blurb": "Sanity-check the current picture for overreach."},
]
GATE_KEYS = [s["key"] for s in STEPS if s["kind"] == "gate"]
_STEP_KEYS = {s["key"] for s in STEPS}

# Templated chat requests for the helper buttons (steer the investigator, no gate).
HELPER_PROMPTS = {
    "timeline": "Build a chronological timeline of this case from the findings so far.",
    "target": "Profile the highest-value target in this case in depth.",
    "reality_check": "Reality-check the current picture: where am I overreaching, what "
                     "is asserted beyond the evidence, and what's the weakest link?",
}


def state(conn, case: str | None) -> list[dict] | None:
    """Per-case checklist: every step + a done flag + when it last ran. None for no/multi
    case (the checklist is per single case)."""
    if not case:
        return None
    done: dict[str, str] = {}
    try:
        for r in conn.execute(
            "SELECT step, created_at FROM case_tradecraft WHERE investigation = ?", (case,)):
            done[r["step"]] = r["created_at"]
    except Exception:
        pass
    return [{**s, "done": s["key"] in done, "when": done.get(s["key"])} for s in STEPS]


def record(conn, case: str, step: str, content: str, analyst: str | None = None) -> None:
    """Store (or refresh) a step's artifact. Re-running a step overwrites its row."""
    if step not in _STEP_KEYS:
        raise ValueError(f"unknown tradecraft step: {step}")
    conn.execute(
        "INSERT INTO case_tradecraft (investigation, step, content, analyst, created_at) "
        "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(investigation, step) DO UPDATE SET content = excluded.content, "
        "analyst = excluded.analyst, created_at = CURRENT_TIMESTAMP",
        (case, step, content, analyst))
    conn.commit()


def get(conn, case: str, step: str) -> str | None:
    r = conn.execute(
        "SELECT content FROM case_tradecraft WHERE investigation = ? AND step = ?",
        (case, step)).fetchone()
    return r["content"] if r else None


def unmet_gates(conn, case: str | None) -> list[dict]:
    """Gate steps not yet run — drives the soft brief nudge."""
    st = state(conn, case) or []
    return [s for s in st if s["kind"] == "gate" and not s["done"]]


def _case_evidence(conn, case: str | None, cap: int = 9000) -> str:
    """A compact evidence pack (the case's discoveries + graph) for the analytical steps.
    Reuses ask._candidates so it sees agent findings + entities, not just report text."""
    from investigations import ask
    lines: list[str] = []
    try:
        for c in ask._candidates(conn, case):
            if c.get("kind") in ("finding", "entity"):
                t = (c.get("text") or "").strip()
                if t:
                    lines.append(("- " + t)[:400])
    except Exception:
        pass
    body = "\n".join(lines)
    return body[:cap] if body else "(no findings or graph entities yet)"


_CHALLENGE_SYSTEM = (
    "You are a devil's-advocate intelligence analyst. Pressure-test the case below. Be "
    "concrete and specific to THIS evidence, not generic. Cover, with a short heading each: "
    "1) Name-match traps (an entity tied in only by a shared name); 2) Circular reasoning / "
    "single-source loops; 3) Source-independence failures (claims that trace back to one "
    "origin); 4) Confirmation bias (what we assumed and never tested); 5) The single weakest "
    "load-bearing claim. End with 'To resolve:' and 2-4 concrete checks. Keep it tight."
)
_PREMORTEM_SYSTEM = (
    "You are running a PREMORTEM. Assume it is six months from now and the brief on this "
    "case turned out to be WRONG and embarrassing. Working backward, explain what made it "
    "wrong. Be specific to THIS evidence. Give: 1) The 3-5 most likely failure modes "
    "(misattribution, stale infra, CDN-shared false links, an unverified identity, etc.), "
    "each with why it would happen here; 2) Which current finding each would invalidate; "
    "3) 'Before delivery:' a short checklist that would have caught it. Keep it tight."
)


def run_analysis(conn, case: str, step: str, analyst: str | None = None) -> dict:
    """Run Challenge or Premortem over the case's evidence, store the result, return it.
    Deterministic plumbing; the judgment is one bounded LLM call (Sonnet by default)."""
    from investigations.llm import client as llm
    if step not in ("challenge", "premortem"):
        raise ValueError(f"run_analysis is for challenge/premortem, not {step}")
    evidence = _case_evidence(conn, case)
    system = _CHALLENGE_SYSTEM if step == "challenge" else _PREMORTEM_SYSTEM
    prompt = (f"Case: {case}\n\nCurrent findings + graph:\n{evidence}\n\n"
              f"Now produce the {step} analysis.")
    try:
        out = llm.ask(prompt, system=system, tools=False, max_tokens=1200).strip()
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}
    if not out:
        return {"ok": False, "error": "empty analysis"}
    record(conn, case, step, out, analyst=analyst)
    return {"ok": True, "step": step, "content": out}
