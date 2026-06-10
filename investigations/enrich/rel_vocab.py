"""Controlled vocabulary for graph edge labels (`rel_type`).

The graph used to accept whatever free-form `rel_type` string the LLM wrote, then
catch the bad ones downstream with a growing pile of synonym maps and skip-lists
(`_REL_SYNONYMS`, `_DROP_RELS`, `_skip_rel`, `_concrete_rel` in investigator.py, plus
a parallel `_enrich_rel_type` in promote.py). Every new render surfaced a label the
patches didn't anticipate. This module ends that: a CLOSED enum (`REL_VOCAB`) plus one
function (`normalize_rel`) that every landing path calls. No free-form label reaches
the DB — `normalize_rel` returns a vocab member, or `None` (skip), nothing else.

The enum was sized against a live-label audit of the working DB (typed_relationships +
relationships) on 2026-06-09 plus every label produced in code, so it covers what
actually occurs. `linked_to` is the catch-all: an unrecognized label is generalized to
it, never dropped silently (except true co-occurrence flags, which aren't edges at all).
"""
from __future__ import annotations

import re

# The closed set. Grouped by category for readability; membership is what matters.
REL_VOCAB: dict[str, str] = {
    # DNS / hosting
    "resolves_to": "resolves to IP",
    "hosted_on": "hosted on",
    "uses_nameserver": "uses nameserver",
    "uses_mailserver": "uses mailserver (MX)",
    "has_subdomain": "has subdomain",
    "reverse_dns": "reverse DNS",
    "prior_resolution": "previously resolved to",
    "routes_through": "routes through (CDN/proxy)",
    # TLS / platform fingerprint
    "shares_certificate": "shares TLS certificate",
    "same_platform": "same backend platform / kit",
    # Registration
    "registered_by": "registered by",
    "same_registrant": "same registrant",
    # Geo / network
    "geolocated_in": "geolocated in",
    "shared_infra": "shared infrastructure",
    # Threat
    "flagged_ioc": "flagged as IOC",
    "exposed_service": "exposed service",
    # Identity
    "same_as": "same entity as",
    "alias_of": "alias of",
    "linked_account": "linked account",
    # Actor / org
    "operated_by": "operated by",
    "operates": "operates",
    "same_operator": "same operator as",
    "member_of": "member of",
    "affiliated_with": "affiliated with",
    # Backend / application
    "uses_backend": "uses backend",
    "api_endpoint": "API endpoint",
    "payment_endpoint": "payment endpoint",
    # Financial
    "transacts_with": "transacts with",
    "drains_to": "drains funds to",
    "uses_affiliate": "uses affiliate program",
    # Behavioral
    "shills": "shills / promotes",
    "targets": "targets",
    "contradicts": "contradicts",
    # Shared-fingerprint correlation (deterministic fingerprints.py — the "same operator"
    # signal: two assets that share one tracking tag / wallet id / registrant / nameserver)
    "shares_tracking_tag": "shares tracking tag (same operator)",
    "shares_walletconnect": "shares WalletConnect id (same kit/operator)",
    "shares_service_account": "shares SaaS service account (same operator)",
    "shares_registrant": "shares registrant (same registrant)",
    "shares_nameserver": "shares nameserver (shared infrastructure)",
    "shares_registrar": "shares registrar (weak)",
    # Hacktivist / disinfo domain labels (analyze.py no-schema default REL_TYPES)
    "posts_in": "posts in channel",
    "ally_with": "public ally with",
    "predecessor_of": "predecessor of (replaced/deleted by)",
    "defaced": "defaced",
    "co_admin": "co-administers",
    # Generic fallback (an unrecognized label generalizes here, never lost)
    "linked_to": "linked to",
}

# Near-dupe / legacy / provider labels the model or adapters emit → one canonical vocab
# term. Every entry's VALUE must be a REL_VOCAB key (guarded by _assert_synonyms_valid).
REL_SYNONYMS: dict[str, str] = {
    # backend family
    "uses_backend_api": "uses_backend",
    "backend_api": "uses_backend",
    "backend_of": "uses_backend",
    "uses_backend_domain": "uses_backend",
    # DNS / hosting aliases
    "runs_on": "hosted_on",
    "hosted_by": "hosted_on",
    "cdn_host": "routes_through",
    "uses_ns": "uses_nameserver",
    "uses_mx": "uses_mailserver",
    # endpoint aliases
    "exposes_endpoint": "api_endpoint",
    # registration aliases (co-registration timing + registrant identity)
    "registered_same_day": "same_registrant",
    "registered_as": "registered_by",
    # affiliate aliases
    "affiliate_instance_of": "uses_affiliate",
    # cert / geo / account aliases
    "shares_cert": "shares_certificate",
    "geolocated": "geolocated_in",
    "account_found": "linked_account",
    "breach_exposure": "linked_account",
    "same_branding": "same_platform",
    # generic agent / search discovery → the catch-all
    "enriched": "linked_to",
    "enriched_via_agent": "linked_to",
    "discovered_with": "linked_to",
    "linked_via_search": "linked_to",
    "related": "linked_to",
    "related_to": "linked_to",
    "linked": "linked_to",
}

# Co-occurrence "relationships" that are really a NODE PROPERTY, not an edge between two
# nodes (both flagged malicious doesn't relate them). normalize_rel returns None for these.
DROP_RELS: frozenset[str] = frozenset({"flagged_malicious_alongside"})

# Vague labels worth a second pass against the evidence text before falling back to
# linked_to — the BASIS (shared infra / registrant / platform) is the real edge.
_VAGUE = frozenset({"same_campaign", "linked_to"})


def _assert_synonyms_valid() -> None:
    """Every synonym must resolve to a real vocab term — fail loud at import if not."""
    bad = {k: v for k, v in REL_SYNONYMS.items() if v not in REL_VOCAB}
    if bad:
        raise ValueError(f"REL_SYNONYMS values not in REL_VOCAB: {bad}")


_assert_synonyms_valid()


def _slug(rel: str) -> str:
    """Lowercase, collapse any non-alnum run (spaces, punctuation, hyphens) to a single
    underscore, strip edge underscores. So 'Drains To!' / 'drains-to' both normalize to
    'drains_to' before vocab lookup — messy LLM output can't dodge the gate.

    Defensive on type: a non-string rel_type (malformed LLM JSON) returns "" so
    normalize_rel skips the row instead of crashing the whole apply pass. Does NOT
    truncate — length is judged on the full slug by _is_clean_token, so an overlong novel
    label generalizes to linked_to rather than being silently truncated into a collision."""
    if not isinstance(rel, str):
        return ""
    s = re.sub(r"[^a-z0-9]+", "_", rel.strip().lower())
    return s.strip("_")


def _evidence_remap(evidence: str) -> str:
    """A vague label, resolved against the evidence/provenance text to a concrete vocab
    term. The agent passes its TOOL provenance here, so DNS / hosting / registration
    phrasing sharpens a generic linked_to into the real edge instead of leaving it generic.
    Every output is a vocab member; only upgrades a vague label, never downgrades.

    Order matters: the unambiguous directional DNS cases are checked first so 'hosted on
    ASN ... Cloudflare' lands hosted_on, not shared_infra."""
    e = (evidence or "").lower()
    # DNS resolution / hosting — direction is clear from the tool provenance.
    if "a record" in e or "resolves to" in e or "resolved to" in e or "dns a " in e:
        return "resolves_to"
    if "reverse dns" in e or "ptr record" in e or "ptr:" in e:
        return "reverse_dns"
    if "name server" in e or "nameserver" in e or "ns record" in e:
        return "uses_nameserver"
    # hosting needs explicit hosting phrasing — a bare 'asn' is ambiguous ('same ASN'
    # between two domains is shared_infra, not a hosting edge), so don't trigger on it.
    if "hosted on" in e or "hosted by" in e or "hosting provider" in e:
        return "hosted_on"
    # platform / fingerprint
    if "fingerprint" in e or "platform" in e or "/api/" in e or "kit" in e:
        return "same_platform"
    if ("cloudflare" in e or " pop" in e or "shared ip" in e or "same ip" in e
            or "same asn" in e or "shared asn" in e):
        return "shared_infra"
    # registration: a domain->registrar edge ('registered by X') vs a domain<->domain
    # shared-registrant edge (the older 'registr' catch — kept so same_registrant holds).
    if "registered by" in e:
        return "registered_by"
    if "registr" in e:
        return "same_registrant"
    return "linked_to"


_CLEAN_TOKEN_MAX = 40


def normalize_rel(rel: str, evidence: str = "", allow_novel: bool = False) -> str | None:
    """The single binding gate: map ANY proposed edge label to a controlled-vocab term,
    or None to skip. Every edge-write path (agent, promote, analyze, fingerprints) calls
    this — no path writes a raw label.

    Order: slug -> drop co-occurrence flags -> synonym map -> in vocab? -> evidence
    remap for vague labels -> found_via_* prefix -> novel/linked_to.

    allow_novel: the adaptive per-case path (analyze WITH an approved schema, see
    [[per-case-schema-gate]]). When True, a clean snake_case token that is NOT a vocab
    member is kept AS-IS (the domain-fit label) instead of generalized to linked_to.
    Synonyms + co-occurrence drops STILL fire first, so junk cannot ride in on this path.
    Default False keeps the closed behavior for every other path.
    """
    norm = _slug(rel)
    if not norm:
        return None
    if norm in DROP_RELS or norm.endswith("_alongside"):
        return None
    norm = REL_SYNONYMS.get(norm, norm)
    if norm in _VAGUE:
        norm = _evidence_remap(evidence)
    if norm in REL_VOCAB:
        return norm
    if norm.startswith("found_via_"):
        return "linked_to"
    if allow_novel and _is_clean_token(norm):
        return norm  # genuine per-case domain label, synonym/drop-filtered above
    # Unknown label: generalize, never invent a new graph label.
    return "linked_to"


def _is_clean_token(norm: str) -> bool:
    """A short snake_case token: lowercase a-z0-9 + underscores, within length bound.
    _slug already lowercased/underscored/length-capped; this rejects empties and any
    residual non-token characters so only a real domain label survives allow_novel."""
    return bool(norm) and len(norm) <= _CLEAN_TOKEN_MAX and all(
        c.isalnum() or c == "_" for c in norm) and not norm.isdigit()


def vocab_prompt_list() -> str:
    """The pipe-delimited allowed-label string for the agent prompt. Built FROM
    REL_VOCAB so the prompt enum and the landing enum can never drift apart."""
    return "|".join(REL_VOCAB.keys())


def gloss(rel: str) -> str:
    """Human-readable label for a vocab term (panel tooltip / edge legend)."""
    return REL_VOCAB.get(rel, rel)
