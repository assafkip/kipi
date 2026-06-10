"""Deterministic claim-faithfulness primitives (replay D5).

Shared by the investigator (finding / edge corroboration), ask (Q&A citation check), and
consolidate (role-evidence check). Pure regex, no heavy deps, so any pipeline stage can
import it. The principle: a stated HARD fact (date / IP / email / wallet) must appear in the
real source (tool result / passage / mention) — the model's say-so is not a source. Soft /
interpretive claims have no hard token and aren't penalized here (string-match doesn't fit;
that's an NLI job we deliberately don't take on, to keep this an auditable deterministic check).
"""
from __future__ import annotations

import re

_HARD_TOKEN_RES = (
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),                                     # ISO date
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                              # IPv4
    re.compile(r"\b[a-z0-9][a-z0-9._%+-]*@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),  # email
    re.compile(r"\b0x[a-fA-F0-9]{40}\b"),                                    # ETH wallet
)


def hard_tokens(text: str) -> set[str]:
    """High-precision facts asserted in `text` (ISO date / IPv4 / email / ETH wallet),
    lowercased. Empty set = nothing hard to verify (a soft / interpretive claim)."""
    if not text:
        return set()
    out: set[str] = set()
    for rx in _HARD_TOKEN_RES:
        out |= {m.group(0).lower() for m in rx.finditer(text)}
    return out


def unbacked_tokens(claim: str, source_text: str) -> set[str]:
    """Hard tokens asserted in `claim` that do NOT appear in `source_text`. Empty set means
    either the claim is soft (nothing to check) or every asserted fact is grounded."""
    toks = hard_tokens(claim)
    if not toks:
        return set()
    src = (source_text or "").lower()
    return {t for t in toks if t not in src}
