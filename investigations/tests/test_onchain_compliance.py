"""On-chain compliance + identity (PRD-1) — OFAC, ENS, wallet labels.

Wiring + parse tests, NO network (RPC / resolver / SDN fetch are monkeypatched;
wallet_labels reads the vendored local dataset). Mirrors test_osint_providers_batch.
Covers: registry membership + keyless contract, watched_types subset, recipe presence
per watched type, MCP _call, investigator allowlist + PERSONA ROUTING (the verb string,
not just the auto-belt slug — PRD-1 audit fix O-2), DETERMINISTIC_SLUGS, and a
monkeypatched parse of each adapter's run().

Run: .venv/bin/python -m pytest investigations/tests/test_onchain_compliance.py -q
"""
from investigations.enrich import registry, ofac, ens, wallet_labels
from investigations.agent import osint_mcp, investigator

NEW = ["ofac", "ens", "wallet_labels"]
TOOL = {"ofac": "ofac_screen", "ens": "ens_resolve", "wallet_labels": "wallet_labels"}
WATCHED = {
    "ofac": ("crypto_wallet", "wallet", "person", "org"),
    "ens": ("crypto_wallet", "wallet", "handle"),
    "wallet_labels": ("crypto_wallet", "wallet"),
}
_VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
_TORNADO = "0x8589427373D6D84E98730D7795D8f6f8731FDA16"
_TC_ROUTER = "0x722122df12d4e14e13ac3b6895a86e84145b6967"  # in the vendored labels


# --- contract --------------------------------------------------------------

def test_all_registered_keyless():
    slugs = {a.slug for a in registry.all_adapters()}
    for s in NEW:
        assert s in slugs, f"{s} not registered"
        a = registry.get_adapter(s)
        assert a.slug == s
        assert a.env_var is None, f"{s} should be keyless"
        assert a.is_configured() is True, f"{s} keyless -> always configured"


def test_deterministic_tier():
    for s in NEW:
        assert s in registry.DETERMINISTIC_SLUGS, f"{s} should be in the keyless free tier"


def test_watched_types_subset_of_vocab():
    for s in NEW:
        unknown = set(registry.get_adapter(s).watched_types) - registry.TRANSFORM_TYPES
        assert not unknown, f"{s} watches unknown types {unknown}"


def test_each_in_a_recipe_for_every_watched_type():
    for s in NEW:
        for etype in WATCHED[s]:
            slugs = [slug for slug, _ in registry._TRANSFORM_RECIPES.get(etype, [])]
            assert s in slugs, f"{s} watches {etype} but is not in its recipe"


def test_mcp_call_present():
    src = open(osint_mcp.__file__).read()
    for s in NEW:
        assert f'_call("{s}"' in src, f'osint_mcp missing _call("{s}")'


def test_allowlist_and_persona_routing():
    for s in NEW:
        tool = TOOL[s]
        assert f"mcp__kipi-osint__{tool}" in investigator._KIPI_MCP_TOOLS, f"{s} not in allowlist"
        # O-2 fix: assert the VERB string is in the playbook (not just the auto-belt slug).
        assert tool in investigator.PERSONA, f"{tool} verb not routed in PERSONA"
        assert tool in investigator.CASE_PERSONA, f"{tool} verb not routed in CASE_PERSONA"
    # wallet_labels must carry an explicit T3 / tag-not-finding caveat in the playbook.
    assert "T3" in investigator.PERSONA and "wallet_labels" in investigator.PERSONA
    persona_lower = investigator.PERSONA.lower()
    assert "never a finding" in persona_lower or "never a finding" in persona_lower or \
        "tag only" in persona_lower, "wallet_labels missing T3 'tag only/never a finding' caveat"


# --- parse (monkeypatched fetch / resolver) --------------------------------

def test_ofac_wallet_sanctioned(monkeypatch):
    monkeypatch.setattr(ofac, "_eth_call_sanctioned", lambda addr, timeout: True)
    out = ofac.OfacAdapter().run(_TORNADO)
    assert out[0].result_type == "document" and "SANCTIONED" in out[0].title
    assert out[0].raw_json["sanctioned"] is True
    # promotable indicator child, title = bare address so _classify tags it.
    assert any(r.title == _TORNADO and r.result_type == "profile" for r in out[1:])


def test_ofac_wallet_clean(monkeypatch):
    monkeypatch.setattr(ofac, "_eth_call_sanctioned", lambda addr, timeout: False)
    out = ofac.OfacAdapter().run(_TORNADO)
    assert len(out) == 1 and out[0].raw_json["sanctioned"] is False


def test_ofac_name_match(monkeypatch):
    monkeypatch.setattr(ofac, "_load_sdn_names",
                        lambda timeout: ["TORNADO CASH", "SOME OTHER ENTITY"])
    out = ofac.OfacAdapter().run("tornado")
    assert out[0].raw_json["sanctioned"] is True
    assert "TORNADO CASH" in out[0].raw_json["matches"]


def test_ens_forward(monkeypatch):
    monkeypatch.setattr(ens, "_resolve",
                        lambda term, timeout: {"address": _VITALIK, "name": "vitalik.eth"})
    out = ens.EnsAdapter().run("vitalik.eth")
    assert out[0].raw_json["address"] == _VITALIK
    assert out[0].raw_json["crosslink"]["rel"] == "resolves_to"
    # the resolved 0x is a promotable crypto_wallet child; the .eth name is NEVER a child.
    assert any(r.title == _VITALIK for r in out[1:])
    assert not any(str(r.title).endswith(".eth") for r in out[1:]), \
        "the .eth name must not be a standalone promotable child (would mis-classify as domain)"


def test_ens_reverse(monkeypatch):
    monkeypatch.setattr(ens, "_resolve",
                        lambda term, timeout: {"address": _VITALIK, "name": "vitalik.eth"})
    out = ens.EnsAdapter().run(_VITALIK)
    assert len(out) == 1, "reverse emits the crosslink header only, no standalone child"
    assert out[0].raw_json["name"] == "vitalik.eth"
    assert out[0].raw_json["crosslink"]["crypto_wallet"] == _VITALIK


def test_wallet_labels_hit():
    out = wallet_labels.WalletLabelsAdapter().run(_TC_ROUTER)
    assert len(out) == 1, "label is a single tag document, no promotable child"
    assert out[0].confidence == "low", "T3 tag must be low confidence"
    assert "mixer" in out[0].raw_json["labels"]
    assert out[0].raw_json["tier"] == "T3"


def test_wallet_labels_miss():
    out = wallet_labels.WalletLabelsAdapter().run("0x" + "1" * 40)
    assert len(out) == 1 and out[0].raw_json["labels"] == []
