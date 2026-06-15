"""On-chain breadth + clustering (PRD-3) — Blockchair, WalletExplorer, TON.

Wiring + parse tests, NO network. Mirrors test_osint_providers_batch. Pins two routing
guards: walletexplorer output is a T3 lead (low confidence, no crypto_wallet node), and
promote._classify("EQ...") == "crypto_wallet" (the TON orphan-trap guard).

Run: .venv/bin/python -m pytest investigations/tests/test_onchain_breadth.py -q
"""
from investigations.enrich import registry, blockchair, walletexplorer, wallet_ton, promote
from investigations.agent import osint_mcp, investigator

NEW = ["blockchair", "walletexplorer", "wallet_ton"]
TOOL = {"blockchair": "blockchair_tx", "walletexplorer": "wallet_cluster",
        "wallet_ton": "ton_tx"}

_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"          # genesis (detect -> btc)
_LTC = "LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL"          # detect -> litecoin
_LTC_CP = "LhJ9X5vXgRtF8kY2mNpQ3wZ7bC4dE6fGy"
_TON = "EQ" + "A" * 46
_TON_CP = "UQ" + "B" * 46


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
        for etype in ("crypto_wallet", "wallet"):
            slugs = [slug for slug, _ in registry._TRANSFORM_RECIPES[etype]]
            assert s in slugs, f"{s} missing from {etype} recipe"


def test_mcp_calls_present():
    src = open(osint_mcp.__file__).read()
    for s in NEW:
        assert f'_call("{s}"' in src, f'osint_mcp missing _call("{s}")'


def test_allowlist_and_persona_routing():
    for s in NEW:
        tool = TOOL[s]
        assert f"mcp__kipi-osint__{tool}" in investigator._KIPI_MCP_TOOLS
        assert tool in investigator.PERSONA, f"{tool} not routed in PERSONA"
        assert tool in investigator.CASE_PERSONA, f"{tool} not routed in CASE_PERSONA"


# --- TON orphan-trap guard (the blocking gate) -----------------------------

def test_classify_learns_ton():
    assert promote._classify(_TON) == "crypto_wallet"
    assert promote._classify(_TON_CP) == "crypto_wallet"


# --- parse (monkeypatched fetch) -------------------------------------------

def test_blockchair_parse(monkeypatch):
    canned = {"data": {_LTC: {
        "address": {"balance": 5000, "transaction_count": 3, "received": 9000, "spent": 4000},
        "transactions": [{"sender": _LTC, "recipient": _LTC_CP}]}}}
    monkeypatch.setattr(blockchair, "_get_json", lambda url, t, label: canned)
    out = blockchair.BlockchairAdapter().run(_LTC)
    assert out[0].result_type == "document" and "litecoin" in out[0].title
    assert any(r.title == _LTC_CP for r in out[1:])


def test_walletexplorer_is_t3_lead(monkeypatch):
    monkeypatch.setattr(walletexplorer, "_get_json",
                        lambda url, t: {"label": "Binance.com", "wallet_id": "0001"})
    out = walletexplorer.WalletExplorerAdapter().run(_BTC)
    assert "T3 LEAD" in out[0].summary
    # No result may be a promotable crypto_wallet node, and all stay low confidence.
    assert all(r.confidence == "low" for r in out)
    assert not any(promote._classify(r.title) == "crypto_wallet" for r in out), \
        "walletexplorer must not emit a promotable wallet node (it's a T3 org lead)"


def test_walletexplorer_rejects_non_btc():
    import pytest
    with pytest.raises(Exception):
        walletexplorer.WalletExplorerAdapter().run(_LTC)


def test_ton_parse(monkeypatch):
    def fake(url, timeout):
        if "/events" in url:
            return {"events": [{"actions": [
                {"TonTransfer": {"sender": {"address": _TON},
                                 "recipient": {"address": _TON_CP}}}]}]}
        return {"balance": 5_000_000_000}  # 5 TON in nano
    monkeypatch.setattr(wallet_ton, "_get_json", fake)
    out = wallet_ton.WalletTonAdapter().run(_TON)
    assert "TON wallet" in out[0].title
    child = [r for r in out[1:] if r.title == _TON_CP]
    assert child and promote._classify(child[0].title) == "crypto_wallet"
