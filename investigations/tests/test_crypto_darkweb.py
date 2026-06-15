"""Crypto + dark-web reputation / leads (PRD-4) — crypto_abuse, darkweb.

Wiring + parse tests, NO network. Mirrors test_osint_providers_batch. Both adapters are
T3 lead generators: correction #6 (audit O-8) requires the promotable lead rows to carry
confidence="low" so the deterministic promotion gate holds them as hypotheses, never
findings. Tests assert that explicitly.

Run: .venv/bin/python -m pytest investigations/tests/test_crypto_darkweb.py -q
"""
from investigations.enrich import registry, crypto_abuse, darkweb, promote
from investigations.agent import osint_mcp, investigator

NEW = ["crypto_abuse", "darkweb"]
TOOL = {"crypto_abuse": "crypto_abuse", "darkweb": "darkweb_search"}
WATCHED = {"crypto_abuse": ("crypto_wallet", "wallet", "domain"),
           "darkweb": ("domain", "org", "handle")}

_WALLET = "0x" + "a" * 40
_ONION = "duskgytldkxiuqc6.onion"


# --- contract --------------------------------------------------------------

def test_registered_keyless():
    slugs = {a.slug for a in registry.all_adapters()}
    for s in NEW:
        assert s in slugs
        a = registry.get_adapter(s)
        assert a.slug == s and a.env_var is None and a.is_configured() is True


def test_deterministic_tier():
    for s in NEW:
        assert s in registry.DETERMINISTIC_SLUGS


def test_watched_types_subset():
    for s in NEW:
        assert not set(registry.get_adapter(s).watched_types) - registry.TRANSFORM_TYPES


def test_recipe_presence():
    for s in NEW:
        for etype in WATCHED[s]:
            slugs = [slug for slug, _ in registry._TRANSFORM_RECIPES[etype]]
            assert s in slugs, f"{s} missing from {etype} recipe"


def test_mcp_calls_present():
    src = open(osint_mcp.__file__).read()
    for s in NEW:
        assert f'_call("{s}"' in src, f'osint_mcp missing _call("{s}")'


def test_allowlist_and_persona_routing():
    for s in NEW:
        tool = TOOL[s]  # slug for crypto_abuse, verb darkweb_search for darkweb
        assert f"mcp__kipi-osint__{tool}" in investigator._KIPI_MCP_TOOLS
        assert tool in investigator.PERSONA, f"{tool} not routed in PERSONA"
        assert tool in investigator.CASE_PERSONA, f"{tool} not routed in CASE_PERSONA"
    # Both must carry an explicit T3-lead caveat in the playbook.
    assert "T3 LEAD" in investigator.PERSONA or "T3 lead" in investigator.PERSONA


# --- parse (monkeypatched fetch) -------------------------------------------

def test_crypto_abuse_hit_is_low_confidence_lead(monkeypatch):
    monkeypatch.setattr(crypto_abuse, "_load_feed", lambda url, t: [_WALLET])
    out = crypto_abuse.CryptoAbuseAdapter().run(_WALLET)
    assert "[HIT]" in out[0].title
    lead = [r for r in out[1:] if r.title == _WALLET]
    assert lead and lead[0].confidence == "low", "T3 lead row must be low confidence (gate)"


def test_crypto_abuse_clean(monkeypatch):
    monkeypatch.setattr(crypto_abuse, "_load_feed", lambda url, t: [])
    out = crypto_abuse.CryptoAbuseAdapter().run(_WALLET)
    assert len(out) == 1 and "[CLEAN]" in out[0].title


def test_darkweb_hits_are_low_confidence_leads(monkeypatch):
    html = f'<a href="http://{_ONION}/">Some leak market</a>'
    monkeypatch.setattr(darkweb, "_get_text", lambda url, t: html)
    out = darkweb.DarkwebAdapter().run("ransomware")
    assert "onion hit" in out[0].title
    child = [r for r in out[1:] if r.title == _ONION]
    assert child and child[0].confidence == "low", "T3 lead row must be low confidence (gate)"
    assert promote._classify(_ONION) == "domain"


def test_darkweb_empty(monkeypatch):
    monkeypatch.setattr(darkweb, "_get_text", lambda url, t: "<html>no results</html>")
    out = darkweb.DarkwebAdapter().run("nothingmatches")
    assert len(out) == 1 and "0 onion hits" in out[0].title
