"""Typosquat adapter (PRD-7) — dnstwist lookalike candidates with a DNS liveness gate.

Wiring + parse, NO network (generation + liveness monkeypatched). Mirrors
test_osint_providers_batch. Pins the T3->T1 gate: only LIVE (resolving) candidates become
promotable child nodes; unconfirmed ones are header-only.

Run: .venv/bin/python -m pytest investigations/tests/test_typosquat.py -q
"""
from investigations.enrich import registry, typosquat, promote
from investigations.agent import osint_mcp, investigator

_LIVE1 = "binance-login.com"
_LIVE2 = "bnance.com"
_DEAD = "binance.net"


def test_registered_keyless():
    assert "typosquat" in registry._REGISTRY
    a = registry.get_adapter("typosquat")
    assert a.slug == "typosquat" and a.env_var is None
    assert a.is_configured() is True and a.cost_per_call_usd == 0.0


def test_watched_types():
    a = registry.get_adapter("typosquat")
    assert a.watched_types == ("domain",)
    assert set(a.watched_types) <= registry.TRANSFORM_TYPES


def test_recipe_presence():
    assert ("typosquat", None) in registry._TRANSFORM_RECIPES["domain"]
    assert "typosquat" in registry.DETERMINISTIC_SLUGS


def test_mcp_and_allowlist_and_persona():
    src = open(osint_mcp.__file__).read()
    assert '_call("typosquat"' in src and "def typosquat(" in src
    assert "mcp__kipi-osint__typosquat" in investigator._KIPI_MCP_TOOLS
    assert "typosquat" in investigator.PERSONA
    # survives the infra-only pass + the scope matcher
    assert "typosquat" in investigator._SCOPE_MATCHER
    assert any("typosquat" in p for p in investigator._INFRA_BELT_PATTERNS)


def test_parse_only_live_promote(monkeypatch):
    monkeypatch.setattr(typosquat, "_generate", lambda d: [
        (_LIVE1, "addition"), (_LIVE2, "omission"), (_DEAD, "tld-swap")])
    monkeypatch.setattr(typosquat, "_is_live", lambda d, t=4: d in (_LIVE1, _LIVE2))
    out = typosquat.TyposquatAdapter().run("binance.com")
    assert out[0].result_type == "document" and "2 live" in out[0].title
    child_titles = [r.title for r in out[1:]]
    assert _LIVE1 in child_titles and _LIVE2 in child_titles
    assert _DEAD not in child_titles, "an unconfirmed candidate must NOT promote (T3->T1 gate)"
    assert _DEAD in out[0].raw_json["unconfirmed"]
    for r in out[1:]:
        assert promote._classify(r.title) == "domain"


def test_not_a_domain():
    out = typosquat.TyposquatAdapter().run("not-a-domain")
    assert len(out) == 1 and "not a domain" in out[0].title
