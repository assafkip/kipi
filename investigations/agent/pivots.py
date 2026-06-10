"""PRD-04: classify the agent's recommended pivots into 'do it now' vs 'needs
external'. The investigator emits `recommended_pivots` (entity + why). A pivot the
tool can run itself (whois / DNS / cert / search on an entity) should become a
one-click investigation — not a chore handed back to the analyst. Only pivots that
genuinely need something the tool can't get (subpoena, internal/exchange records, a
missing API key) stay as recommendations, each with WHY it's blocked.

Deterministic keyword classifier — no LLM. The agent's `why` text is short and uses
consistent investigative language; this keeps the split cheap and predictable.
"""
from __future__ import annotations

# Signals that a pivot needs something OUTSIDE open-source reach. Maps a matched
# phrase to the plain reason shown to the analyst.
_EXTERNAL = [
    (("subpoena", "court order", "warrant", "legal process", "law enforcement",
      "compel", "preservation request"), "needs legal process"),
    (("internal log", "server log", "access log", "internal record", "first-party",
      "platform data", "backend"), "needs internal/first-party data"),
    (("kyc", "exchange record", "exchange's", "bank record", "financial institution",
      "chain analysis subpoena"), "needs records from a third party"),
    (("contact the", "reach out to", "request from", "ask the registrar",
      "report to", "notify"), "needs an outbound request to a third party"),
]

# A missing-key tool the agent named — actionable, but only once the key is set.
_NEEDS_KEY = ("virustotal", "apify", "perplexity", "shodan", "censys")


def classify_pivot(pivot: dict, configured_tools: set[str] | None = None) -> dict:
    """Return the pivot annotated with {actionable_now, reason}.

    actionable_now=True  -> the tool can investigate this entity right now.
    actionable_now=False -> reason names what's blocking (legal / internal / key)."""
    why = (pivot.get("why") or "").lower()
    entity = (pivot.get("entity") or "").strip()
    text = f"{entity} {why}".lower()

    for phrases, reason in _EXTERNAL:
        if any(p in text for p in phrases):
            return {**pivot, "actionable_now": False, "reason": reason}

    # Names a keyed tool that isn't configured → actionable once the key is added.
    if configured_tools is not None:
        for tool in _NEEDS_KEY:
            if tool in why and tool not in configured_tools:
                return {**pivot, "actionable_now": False,
                        "reason": f"needs an API key for {tool}"}

    # Otherwise the tool can OSINT the named entity now.
    if entity:
        return {**pivot, "actionable_now": True, "reason": ""}
    # No concrete entity to point the agent at.
    return {**pivot, "actionable_now": False, "reason": "no concrete target named"}


def classify_all(pivots: list[dict], configured_tools: set[str] | None = None) -> list[dict]:
    return [classify_pivot(p, configured_tools) for p in (pivots or []) if isinstance(p, dict)]
