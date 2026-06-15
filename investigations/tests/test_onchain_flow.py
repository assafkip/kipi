"""On-chain value flow + multi-chain (PRD-2) — ERC-20 token flow, Tron, Solana.

Wiring + parse tests, NO network (HTTP/RPC fetches monkeypatched). Mirrors
test_osint_providers_batch. Also pins the promote._classify orphan fix: Tron + Solana
counterparty addresses must promote to crypto_wallet, with NO regression for
handle/domain/email.

Run: .venv/bin/python -m pytest investigations/tests/test_onchain_flow.py -q
"""
from investigations.enrich import registry, tron, solana, wallet, promote
from investigations.enrich import base as enrich_base
from investigations.agent import osint_mcp, investigator

NEW = ["tron", "solana"]
TOOL = {"tron": "tron_wallet", "solana": "solana_wallet"}

# Real-format addresses (match the adapter / _classify regexes).
_TRON_SELF = "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC"
_TRON_CP = "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"
_SOL_SELF = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
_SOL_CP = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_EVM = "0x" + "a" * 40


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


def test_wallet_has_erc20_mode():
    assert "erc20" in wallet.WalletAdapter().modes()


def test_mcp_calls_present():
    src = open(osint_mcp.__file__).read()
    assert '_call("tron"' in src and '_call("solana"' in src
    assert '_call("wallet", address, mode="erc20")' in src


def test_allowlist_and_persona_routing():
    for tool in ("tron_wallet", "solana_wallet", "wallet_tokens"):
        assert f"mcp__kipi-osint__{tool}" in investigator._KIPI_MCP_TOOLS
        assert tool in investigator.PERSONA, f"{tool} not routed in PERSONA"
        assert tool in investigator.CASE_PERSONA, f"{tool} not routed in CASE_PERSONA"


# --- promote._classify orphan fix ------------------------------------------

def test_classify_learns_tron_and_solana():
    assert promote._classify(_TRON_SELF) == "crypto_wallet"
    assert promote._classify(_SOL_SELF) == "crypto_wallet"
    assert promote._classify(_EVM) == "crypto_wallet"  # unchanged


def test_classify_no_regression():
    assert promote._classify("@somehandle") == "handle"
    assert promote._classify("example.com") == "domain"
    assert promote._classify("ops@example.com") == "email"


# --- parse (monkeypatched fetch) -------------------------------------------

def test_tron_parse(monkeypatch):
    canned = {"success": True, "data": [
        {"from": _TRON_SELF, "to": _TRON_CP, "token_info": {"symbol": "USDT"}}]}
    monkeypatch.setattr(tron, "_get_json", lambda url, t, label: canned)
    out = tron.TronAdapter().run(_TRON_SELF)
    assert out[0].result_type == "document" and "Tron wallet" in out[0].title
    child = [r for r in out[1:] if r.title == _TRON_CP]
    assert child and "USDT" in child[0].summary
    assert promote._classify(child[0].title) == "crypto_wallet"


def test_solana_parse(monkeypatch):
    def fake_rpc(method, params, timeout):
        if method == "getSignaturesForAddress":
            return [{"signature": "sig1"}]
        return {"transaction": {"message": {"accountKeys": [_SOL_SELF, _SOL_CP]}}}
    monkeypatch.setattr(solana, "_rpc", fake_rpc)
    out = solana.SolanaAdapter().run(_SOL_SELF)
    assert out[0].result_type == "document" and "Solana wallet" in out[0].title
    child = [r for r in out[1:] if r.title == _SOL_CP]
    assert child
    assert promote._classify(child[0].title) == "crypto_wallet"


def test_erc20_parse(monkeypatch):
    monkeypatch.setattr(enrich_base, "resolve_key", lambda slug, env: "FAKEKEY")
    canned = {"result": [
        {"from": _EVM, "to": "0x" + "b" * 40, "tokenSymbol": "USDT"}]}
    monkeypatch.setattr(wallet, "_get_json", lambda url, t, label: canned)
    out = wallet.WalletAdapter().run(_EVM, mode="erc20")
    assert "ERC-20 flow" in out[0].title and "USDT" in out[0].raw_json["tokens"]
    child = [r for r in out[1:] if r.title == "0x" + "b" * 40]
    assert child and "USDT" in child[0].summary


def test_erc20_needs_key(monkeypatch):
    monkeypatch.setattr(enrich_base, "resolve_key", lambda slug, env: "")
    out = wallet.WalletAdapter().run(_EVM, mode="erc20")
    assert len(out) == 1 and "[needs key]" in out[0].title
