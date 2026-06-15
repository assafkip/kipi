"""The single entity-admission contract (RCA rca-recurring-graph-noise-2026-06-11).

Every path that creates a graph node MUST call `is_admissible(entity_type, value)` before
making it. This is the ONE place "is this a real entity of type X, or noise?" is decided,
so a new junk class is one rule HERE — not a new retro-clean pass, and not a per-path
patch that leaves the other paths open (the recurrence the RCA diagnosed).

It composes the type-specific checks (noise.is_real_phone, noise.is_noise_domain) plus the
universal junk rules (empty, too-short, CSS / mis-parse fragments, all-same-digit, and
date-shaped bare numbers). Callers: extractor.extract_all, investigator._promotion_gate
+ _resolve_entity_id, webapp._persist_step_discovery (live dig), graph_chat.execute
add_node (the agent's graph_add_node tool; the analyst's own add is exempt — top
authority), retro_clean.clean_noise, enrich.properties.extract_and_upsert. Add a new
rule by adding a clause here, with a row in test_admission.py — then every creation
path inherits it.
"""
from __future__ import annotations

import re

from investigations import noise

_CSS_AT_RE = re.compile(
    r"^@(media|import|keyframes|font-face|charset|supports|namespace|page)\b", re.I)
# Mis-parse / boilerplate phrases the extractor itself emits as descriptive labels — these
# are reliable noise (they come from the parser, not the world). Sourced from the long-time
# consolidate._NOISE_PHRASES list, now centralized here.
_MISPARSE_PHRASES = (
    "report date", "registrar privacy", "privacy-proxy", "privacy proxy",
    "whois privacy", "mis-parsed", "misparsed", "parser glitch", "ocr artifact",
)
_DOMAINISH = {"domain", "subdomain", "url"}
# Types whose value is LEGITIMATELY a bare/opaque token, so the numeric-junk rule must not
# fire on them (an affiliate id IS a bare number; a hash IS hex; a wallet IS base58/hex).
_OPAQUE_VALUE_TYPES = {"affiliate_id", "wallet", "crypto_wallet", "hash_sha256", "hash_md5",
                       "asn", "indicator", "fingerprint"}


def _is_universal_junk(value: str) -> bool:
    """Junk regardless of declared type: a CSS fragment, a parser mis-parse label, an
    all-same-digit placeholder (000000000), a date-shaped bare number (20260419), or a
    value carrying (escaped) control characters — regex ran over a JSON-escaped blob and
    matched across the '\\n' ('https://x/path\\nconfidence: high', trump-demo 2026-06-11)."""
    low = value.lower()
    if _CSS_AT_RE.match(value):
        return True
    if any(ch in value for ch in "\n\r\t") or re.search(r"\\[nrt]", value):
        return True
    if any(p in low for p in _MISPARSE_PHRASES):
        return True
    if _is_dotted_quad(value):
        # A syntactically valid IPv4 is structural, never a bare-number
        # placeholder: the dot-stripping below (meant for phone formatting)
        # turned 9.9.9.9 into '9999' and ate real resolver IPs (9.9.9.9,
        # 1.1.1.1) — admission-RCA collateral, fixed 2026-06-11. Type-specific
        # IP noise rules, if ever needed, belong in noise.py.
        return False
    digits = re.sub(r"[\s().+\-]", "", value)
    if digits.isdigit():
        if len(set(digits)) <= 1:            # 000000000 / 111111111 — placeholder
            return True
        if len(digits) == 8:                 # YYYYMMDD date masquerading as a value
            y, mo, d = int(digits[:4]), int(digits[4:6]), int(digits[6:8])
            if 2000 <= y <= 2099 and 1 <= mo <= 12 and 1 <= d <= 31:
                return True
    return False


_DOTTED_QUAD_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_dotted_quad(value: str) -> bool:
    if not _DOTTED_QUAD_RE.match(value):
        return False
    return all(int(octet) <= 255 for octet in value.split("."))


def is_admissible(entity_type: str | None, value: str | None, *,
                  phone_prevalidated: bool = False) -> tuple[bool, str]:
    """(True, "") if this entity may become a graph node; (False, reason) if it's noise,
    a reference, or mistyped junk. THE contract every creation path calls. Conservative:
    it rejects only proven junk classes — a real `+` phone, a real target domain, a
    scammer's social handle all pass.

    `phone_prevalidated=True` is for the regex extractor: its `_looks_like_phone` already
    validated phones WITH extraction context (a 'Phone:' / 'tel:' label vouches for a bare
    number), context this value-only check can't recover. So the extractor skips the phone
    shape rule; the agent (which has no such context) keeps it, catching bare-id 'phones'."""
    et = (entity_type or "").strip().lower()
    v = (value or "").strip()
    if not v:
        return False, "empty value"
    if len(v) <= 2:
        return False, "too short to be a real entity"
    if et not in _OPAQUE_VALUE_TYPES and _is_universal_junk(v):
        return False, "mis-parsed / placeholder / date — not an entity"
    if et == "phone" and noise.is_boilerplate_phone(v):
        return False, "a registry's own whois contact number — boilerplate, not the target"
    if et == "phone" and not phone_prevalidated and not noise.is_real_phone(v):
        return False, "not a phone number — a bare id / tracking number"
    if et in _DOMAINISH and v[-1] in "'\"":
        return False, "trailing quote — a quoted-string fragment, not the entity itself"
    if et in _DOMAINISH and noise.is_noise_domain(v):
        return False, ("registry / WHOIS / reference boilerplate (lookup infrastructure, or "
                       "a source reporting on the case) — not target infrastructure")
    if et == "email" and noise.is_noise_domain(v):
        return False, ("a registry / reference domain's contact address — whois boilerplate, "
                       "not the target's email")
    return True, ""


# --- Text admission (issue text-admission-gate) -----------------------------
# is_admissible above guards graph NODES. This guards model-generated free TEXT
# before it is persisted as a dossier. A tool-less model prompted to
# "investigate" can role-play a fake tool transcript (verified: a quick-read
# stored <tool_call>{"name":"phonebook_lookup"...}</tool_call> on a phone node).
# That shape is NEVER a legitimate dossier from anyone, so it is stripped
# deterministically at the single write choke-point
# (annotations.set_dossier_override) and in retro_clean. Author-INDEPENDENT,
# because the machine note at app.py:5118 is mislabeled "analyst (from finding)"
# — trusting author labels would leak it.

# Paired transcript blocks: <tool_call ...> ... </tool_call> (case-insensitive,
# attribute-tolerant, DOTALL). The body uses a TEMPERED quantifier that cannot
# scan across another tag, so matching is linear — a flood of unclosed
# `<tool_call>` openers can't trigger quadratic backtracking (ReDoS, codex adv).
_TOOL_BLOCK_RE = re.compile(
    r"<(tool_call|tool_response)\b[^>]*>"
    r"(?:(?!</?(?:tool_call|tool_response)\b).)*?</\1\s*>", re.I | re.S)
# An orphaned opening tag (a TRUNCATED transcript, e.g. the cut-off last block):
# strip from the tag to the next blank line, the next tool_ tag, or end-of-text.
# The `\s*(?:\n|\{)` after the tag requires the structural transcript shape (tag
# then a newline or a JSON body), so an inline prose mention of `<tool_call>`
# (an analyst documenting this very bug) is NOT stripped.
_TOOL_ORPHAN_RE = re.compile(
    r"<tool_(?:call|response)\b[^>]*>\s*(?:\n|\{)"
    r".*?(?=\n\s*\n|\n\s*(?:#{1,6}\s|\*\*|[-*>]\s)|<tool_(?:call|response)\b|\Z)",
    re.I | re.S)
# The agentic bluff OPENER that precedes a transcript ("I'll investigate ...
# using available OSINT tools"). ANCHORED to the start of the text (after an
# optional leading dossier label) so it strips ONLY the leading bluff sentence,
# never a legit sentence elsewhere that says "search ... using tools" (codex
# adv). `[^\n.]` bounds it to the sentence (ends at the first period), so a real
# finding on the same line after the bluff survives. Only runs when a transcript
# was also found.
_BLUFF_PREAMBLE_RE = re.compile(
    r"^\s*(?:\*\*(?:Quick read|Investigator note)\b:?\*\*\s*)?"
    r"(?:I['’]ll|I will|I'm going to|I am going to|Let me)\s+"
    r"[^\n.]*?\b(?:tools?|OSINT|look ?up|lookup|search|investigate)\b[^\n.]*\.?",
    re.I)
# Machine-added dossier labels — stripped only to decide "is anything real left?"
_DOSSIER_LABEL_RE = re.compile(r"\*\*(?:Quick read|Investigator note)\b:?\*\*", re.I)
# A dossier label left empty once its transcript body was stripped (followed only
# by whitespace then another label or end-of-text) — drop the orphaned heading.
_EMPTY_LABEL_RE = re.compile(
    r"\*\*(?:Quick read|Investigator note)\b:?\*\*\s*"
    r"(?=\*\*(?:Quick read|Investigator note)\b|\Z)", re.I)


def sanitize_model_text(text: str | None) -> tuple[str, bool]:
    """Strip tool-call / tool-response transcript blocks (paired + orphaned) — and,
    when a transcript was present, the leading bluff preamble — from
    model-generated text before it is persisted. Returns (cleaned, removed);
    `removed` is True iff anything was stripped. THE text companion to
    is_admissible: a transcript shape is never a legitimate dossier, so this runs
    on every set_dossier_override write and in retro_clean."""
    if not text:
        return (text or ""), False
    cleaned, n1 = _TOOL_BLOCK_RE.subn("", text)
    cleaned, n2 = _TOOL_ORPHAN_RE.subn("", cleaned)
    if (n1 + n2) > 0:
        cleaned = _BLUFF_PREAMBLE_RE.sub("", cleaned)
        cleaned = _EMPTY_LABEL_RE.sub("", cleaned)
    removed = cleaned != text
    if removed:
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned, removed


def text_is_effectively_blank(text: str | None) -> bool:
    """True if, after dropping the machine dossier labels, NO alphanumeric content
    remains — i.e. sanitizing left only a vacuous shell (markdown, an em dash,
    bullets, whitespace). Checking for any letter/digit (rather than stripping a
    punctuation allowlist) is robust to unicode punctuation the allowlist would
    miss. Used by the write gate to skip a pure bluff vs store the de-poisoned
    remainder."""
    t = _DOSSIER_LABEL_RE.sub("", text or "")
    # `[^\W_]` = any unicode letter or digit (not underscore). A non-Latin
    # finding (Chinese / Arabic / Farsi — kipi is multilingual) is real content
    # and must NOT be judged blank (codex adversarial: that would drop the write).
    return not re.search(r"[^\W_]", t)
