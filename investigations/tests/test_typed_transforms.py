"""Typed transforms (sp2-watched-types-registry) — feature + bypass.

The Maltego model: "what can run on this node" is a static data lookup, not
a judgment call. Bypass guarantees (the phase gate):
  - every registered adapter declares non-empty watched_types ⊆ TRANSFORM_TYPES
    (a new undeclared adapter cannot even import);
  - the ordered recipe map is consistent BOTH ways: every recipe's adapter
    watches its type, and every adapter appears in >= 1 recipe;
  - the agent's one-hop belt is a declared SUBSET view of the same map —
    one source, not a hand-rolled copy;
  - the runner refuses a known type the adapter does not watch.
Feature: the belt portion of a single-node expand makes ZERO LLM calls.
"""

import tempfile
from pathlib import Path

import pytest

from investigations.enrich import registry, runner
from investigations.enrich.base import EnrichmentError
from investigations.storage import db


# --- bypass: declarations -----------------------------------------------------


def test_every_adapter_declares_watched_types():
    for slug, adapter in registry._REGISTRY.items():
        assert adapter.watched_types, f"{slug} declares no watched_types"
        unknown = set(adapter.watched_types) - registry.TRANSFORM_TYPES
        assert not unknown, f"{slug} watches unknown types {sorted(unknown)}"


def test_registry_import_validation_is_structural():
    with pytest.raises(TypeError):
        registry._validate_registry.__wrapped__ if False else None
        # simulate an undeclared adapter sneaking into the registry
        bad = type("Bad", (), {"watched_types": (), "slug": "bad"})()
        original = dict(registry._REGISTRY)
        try:
            registry._REGISTRY["bad"] = bad
            registry._validate_registry()
        finally:
            registry._REGISTRY.clear()
            registry._REGISTRY.update(original)


def test_declaration_snapshot():
    """Pin every adapter's declaration so a narrowing/widening shows up in
    review as a test diff, never silently (PRD risk: mis-declared types)."""
    snapshot = {slug: tuple(a.watched_types)
                for slug, a in sorted(registry._REGISTRY.items())}
    assert snapshot["crtsh"] == ("domain", "subdomain")
    assert snapshot["ipgeo"] == ("ip", "domain", "subdomain")
    assert snapshot["gravatar"] == ("email",)
    assert snapshot["wallet"] == ("crypto_wallet", "wallet")
    assert snapshot["username"] == ("handle", "username")
    assert snapshot["email"] == ("email",)
    broad = {"perplexity", "tavily", "exa", "apify", "jina"}
    for slug in broad:
        assert len(snapshot[slug]) >= 12, f"{slug} is the research tier — broad"


# --- bypass: recipe-map consistency -------------------------------------------


def test_recipes_consistent_with_declarations():
    for etype, recipes in registry._TRANSFORM_RECIPES.items():
        assert etype in registry.TRANSFORM_TYPES, etype
        for slug, mode in recipes:
            adapter = registry._REGISTRY[slug]
            assert etype in adapter.watched_types, (
                f"recipe {etype} -> {slug} but {slug} does not watch {etype}")


def test_recipe_modes_exist_on_their_adapters():
    """The class fix for three guaranteed-failing menu items codex caught
    (whoisxml reverse_ns on domains, jina 'reader', username on person):
    every recipe's mode must be one the adapter actually implements."""
    for etype, recipes in registry._TRANSFORM_RECIPES.items():
        for slug, mode in recipes:
            if mode is None:
                continue
            adapter_modes = registry._REGISTRY[slug].modes()
            assert mode in adapter_modes, (
                f"recipe {etype} -> {slug}/{mode}: adapter implements "
                f"{adapter_modes} — a menu item that can never run right")


def test_every_adapter_reachable_from_some_recipe():
    in_recipes = {slug for recipes in registry._TRANSFORM_RECIPES.values()
                  for slug, _ in recipes}
    unreachable = set(registry._REGISTRY) - in_recipes
    assert not unreachable, (
        f"adapters no recipe offers (dead transforms): {sorted(unreachable)}")


def test_belt_is_a_subset_view_of_the_map():
    for etype, belt in registry.BELT_RECIPES.items():
        recipes = registry._TRANSFORM_RECIPES[etype]
        for pair in belt:
            assert pair in recipes, (
                f"belt {etype} -> {pair} missing from the transform map — the "
                f"belt must be a subset view, never a second source")


def test_unknown_type_has_no_menu_and_no_refusal():
    assert registry.transforms_for_type("nonsense") == []
    assert registry.transforms_for_type(None) == []
    assert registry.belt_for_type("person_candidate") == []


# --- bypass: the runner gate ----------------------------------------------------


def test_runner_refuses_unwatched_type():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            with pytest.raises(EnrichmentError, match="typed-transform gate"):
                runner.run_and_persist(conn, "wallet", "example.com",
                                       entity_type="domain")


def test_dispatch_gate_blocks_queued_bypass():
    """codex adversarial blocker: start_run + execute_run (and /api/enrich/run,
    which queues with an entity_id) must hit the gate AT DISPATCH — the
    pre-queue check alone was bypassable. The dead run row records the
    refusal."""
    from investigations import store
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            eid = store.apply_mutation(conn, store.entity_upserted(
                "cx", "example.com", "domain", None, actor="agent"))["entity_id"]
            run_id = runner.start_run(conn, "wallet", "example.com",
                                      entity_id=eid)
            with pytest.raises(EnrichmentError, match="typed-transform gate"):
                runner.execute_run(conn, run_id, timeout=1)
            row = conn.execute("SELECT status, error_message FROM enrichment_runs "
                               "WHERE id = ?", (run_id,)).fetchone()
            assert row["status"] == "error"
            assert "typed-transform gate" in row["error_message"]


def test_registry_lookup_revalidates_post_import():
    """codex adversarial: a post-import smuggled adapter (mutable dict) must
    fail at LOOKUP, not just at import."""
    bad = type("Bad", (), {"watched_types": (), "slug": "smuggled"})()
    registry._REGISTRY["smuggled"] = bad
    try:
        with pytest.raises(TypeError):
            registry.get_adapter("smuggled")
    finally:
        registry._REGISTRY.pop("smuggled", None)


def test_belt_tier_is_structurally_deterministic():
    """codex adversarial: the zero-LLM mock could false-pass if a future belt
    recipe added an LLM-backed adapter. Structural pin: every belt slug is in
    the keyless deterministic tier, never the research tier."""
    for etype, belt in registry.BELT_RECIPES.items():
        for slug, _mode in belt:
            assert slug in registry.DETERMINISTIC_SLUGS, (
                f"belt {etype} -> {slug}: the belt is the keyless deterministic "
                f"tier; research/LLM-backed adapters never join it")


def test_runner_legacy_callers_unaffected():
    """No entity_type (or an unknown one) = legacy behavior: the gate stays
    out of the way; the run proceeds to normal execution/recording."""
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            out = runner.run_and_persist(conn, "wallet", "not-a-wallet",
                                         entity_type="mystery_type", timeout=1)
            assert "status" in out  # recorded run (likely failed), not a refusal


# --- feature: zero-LLM enumeration ----------------------------------------------


def test_belt_makes_zero_llm_calls(mp):
    """The deterministic tier IS deterministic: a belt pass calls no LLM
    (the one-hop suggest call is separate, opt-in UX)."""
    from investigations.agent import investigator
    from investigations.llm import client as llm_client

    def _no_llm(*a, **k):
        raise AssertionError("the belt called the LLM — enumeration must be static")
    mp.setattr(llm_client, "ask", _no_llm)
    calls = []
    mp.setattr(runner, "run_and_persist",
               lambda conn, slug, q, **k: calls.append((slug, k.get("mode"))) or
               {"status": "success", "run_id": 1, "results": []})
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            investigator._run_infra_belt(conn, "evil.com", "domain", "cx")
    assert [c[0] for c in calls] == ["crtsh", "infra", "infra"]


def test_slug_charset():
    # The UI's composite 'slug|mode' select value is unambiguous only while
    # slugs stay simple identifiers (codex adversarial). Registry-controlled.
    import re as _re
    for slug in registry._REGISTRY:
        assert _re.fullmatch(r"[a-z0-9_]+", slug), slug
