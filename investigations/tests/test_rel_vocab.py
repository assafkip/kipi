"""Reproducer + guard for the controlled rel_type vocabulary (issue rel-vocab-validator).

The bug class: free-form LLM edge labels reached the DB and the graph, then got
band-aided one screenshot at a time. This asserts the invariant that ends it —
normalize_rel ALWAYS returns a REL_VOCAB member or None, for every label seen in
last session's bugs, in the live-DB audit, and produced anywhere in code.
"""
from investigations.enrich import rel_vocab as rv


# Last session's known-bad labels + every label from the 2026-06-09 live-DB audit.
KNOWN_BAD = [
    "enriched", "discovered_with", "same_campaign", "backend_api",
    "uses_backend_api", "flagged_malicious_alongside", "frobnicated_with",
    # live audit (typed_relationships + relationships)
    "runs_on", "routes_through", "exposes_endpoint", "registered_same_day",
    "registered_as", "affiliate_instance_of", "enriched_via_agent",
    "same_operator", "shared_infra", "same_platform", "member_of",
    "uses_affiliate", "operated_by", "registered_by", "same_registrant",
    # code producers (_enrich_rel_type / _concrete_rel)
    "shares_cert", "geolocated", "uses_ns", "uses_mx", "cdn_host",
    "account_found", "breach_exposure", "same_branding", "linked_via_search",
    "found_via_perplexity", "related", "related_to", "linked",
]


def test_every_label_maps_to_vocab_or_none():
    """No free-form label survives. Each is a vocab member or an explicit None (skip)."""
    for label in KNOWN_BAD:
        out = rv.normalize_rel(label, evidence="")
        assert out is None or out in rv.REL_VOCAB, f"{label!r} -> {out!r} escaped the vocab"


def test_cooccurrence_flags_are_dropped():
    """Co-occurrence flags aren't edges — they must skip (None), not draw a line."""
    assert rv.normalize_rel("flagged_malicious_alongside") is None
    assert rv.normalize_rel("anything_alongside") is None


def test_unknown_label_generalizes_to_linked_to_never_invents():
    """An unrecognized label is generalized to the catch-all, never passed through raw."""
    assert rv.normalize_rel("totally_made_up_edge") == "linked_to"
    assert rv.normalize_rel("found_via_someprovider") == "linked_to"


def test_empty_and_whitespace_skip():
    assert rv.normalize_rel("") is None
    assert rv.normalize_rel("   ") is None


def test_evidence_remaps_vague_label_to_concrete_vocab():
    """A vague label resolves against evidence to a concrete vocab term."""
    out = rv.normalize_rel("same_campaign", evidence="shared registrar email")
    assert out == "same_registrant"
    out = rv.normalize_rel("same_campaign", evidence="same backend /api/ fingerprint")
    assert out == "same_platform"


def test_evidence_remap_sharpens_dns_and_registration_edges():
    """The agent passes tool provenance as evidence; a generic linked_to with DNS /
    hosting / registration phrasing sharpens to the concrete edge instead of staying
    generic (issue: too many agent edges land as linked_to)."""
    assert rv.normalize_rel("linked_to", evidence="dns A record -> 1.2.3.4") == "resolves_to"
    assert rv.normalize_rel("linked_to", evidence="resolves to 104.21.5.10") == "resolves_to"
    assert rv.normalize_rel("linked_to", evidence="reverse DNS / PTR record") == "reverse_dns"
    assert rv.normalize_rel("linked_to", evidence="uses name server ns1.example") == "uses_nameserver"
    assert rv.normalize_rel("linked_to", evidence="hosted on ASN AS13335 Cloudflare") == "hosted_on"
    assert rv.normalize_rel("linked_to", evidence="registered by NameCheap, Inc.") == "registered_by"
    # a bare 'same ASN' between two domains is shared infra, NOT a hosting edge (Codex)
    assert rv.normalize_rel("linked_to", evidence="same ASN AS13335") == "shared_infra"
    # no recognizable phrasing -> stays the generic catch-all
    assert rv.normalize_rel("linked_to", evidence="mentioned together in a post") == "linked_to"


def test_synonyms_all_resolve_into_vocab():
    """Every synonym target is a real vocab key (import-time guard mirrored here)."""
    for src, dst in rv.REL_SYNONYMS.items():
        assert dst in rv.REL_VOCAB, f"synonym {src!r} -> {dst!r} not in vocab"
        assert rv.normalize_rel(src) in rv.REL_VOCAB


def test_prompt_list_built_from_vocab_cannot_drift():
    """The agent prompt enum is generated FROM REL_VOCAB, so it can't disagree with it."""
    listed = rv.vocab_prompt_list().split("|")
    assert set(listed) == set(rv.REL_VOCAB.keys())
