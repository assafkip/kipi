"""Wiring + parsing tests for the Flowsint-inspired enrichers (no network calls).

Covers: registry membership, keyless contract, mode/detection units, MCP wrapping,
investigator allowlist, and provider-catalog seeding.

Run: .venv/bin/python -m investigations.tests.test_flowsint_adapters
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.enrich.registry import get_adapter, all_adapters
from investigations.enrich import gravatar, wallet, username
from investigations.agent import investigator
import investigations.agent.osint_mcp as osint_mcp

NEW = ["gravatar", "ipgeo", "username", "wallet"]


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_registered_and_keyless():
    slugs = {a.slug for a in all_adapters()}
    for s in NEW:
        _check(f"{s} registered", s in slugs)
        _check(f"{s} slug roundtrip", get_adapter(s).slug == s)
        # All four are keyless at the adapter level (wallet ETH self-guards internally).
        _check(f"{s} env_var is None (keyless)", get_adapter(s).env_var is None)
        _check(f"{s} is_configured True", get_adapter(s).is_configured() is True)
        _check(f"{s} advertises modes", bool(get_adapter(s).modes()))


def test_gravatar_hash():
    # Canonical Gravatar example: the MD5 of the trimmed, lowercased email.
    _check("gravatar md5 of known email",
           gravatar._email_hash(" MyEmailAddress@example.com ")
           == "0bc83cb571cd1c50ba6f3e8a78ef1346")


def test_wallet_detection():
    _check("eth detected", wallet.detect_chain("0x" + "a" * 40) == "eth")
    _check("btc bech32 detected", wallet.detect_chain("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == "btc")
    # bech32 is case-insensitive (BIP173) — uppercase BC1 is a valid BTC address.
    _check("btc bech32 UPPERCASE detected", wallet.detect_chain("BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ") == "btc")
    _check("bech32 uppercase normalized to lowercase for query",
           wallet._normalize_btc("BC1QXYZ") == "bc1qxyz")
    _check("btc legacy detected", wallet.detect_chain("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "btc")
    _check("base58 case preserved (case-sensitive)",
           wallet._normalize_btc("1A1zP1eP") == "1A1zP1eP")
    _check("garbage -> None", wallet.detect_chain("not-an-address") is None)
    # ETH with no key returns a clear result, never raises (keyless seatbelt).
    out = get_adapter("wallet")._eth("0x" + "b" * 40, timeout=5)
    _check("eth no-key returns one result", len(out) == 1)
    _check("eth no-key names the key", "ETHERSCAN_API_KEY" in out[0].summary)


def test_eth_surfaces_etherscan_error():
    """Etherscan returns errors as a non-numeric string in `result`; the adapter must
    raise, not silently report 0 ETH at high confidence."""
    import os as _os
    from investigations.enrich import wallet as w
    _os.environ["ETHERSCAN_API_KEY"] = "TESTKEY"
    orig = w._get_json
    w._get_json = lambda url, timeout, label: {
        "status": "0", "message": "NOTOK", "result": "Max rate limit reached"}
    try:
        try:
            w.WalletAdapter()._eth("0x" + "c" * 40, timeout=5)
        except Exception as exc:
            s = str(exc).lower()
            _check("eth error-string surfaced (not faked as 0)",
                   "etherscan" in s and ("notok" in s or "rate limit" in s))
        else:
            raise AssertionError("eth should raise on an Etherscan error-string result")
    finally:
        w._get_json = orig
        _os.environ.pop("ETHERSCAN_API_KEY", None)


def test_username_validation():
    try:
        username.UsernameAdapter().run("bad handle with spaces")
    except Exception as exc:
        _check("username rejects bad handle", "handle" in str(exc).lower())
    else:
        raise AssertionError("username should reject a handle with spaces")


def test_mcp_wraps_each():
    src = Path(osint_mcp.__file__).read_text()
    for s in NEW:
        _check(f"MCP server wraps '{s}'", f'_call("{s}"' in src)


def test_investigator_allowlist():
    for t in ["mcp__kipi-osint__gravatar", "mcp__kipi-osint__ipgeo",
              "mcp__kipi-osint__username_sweep", "mcp__kipi-osint__wallet_tx"]:
        _check(f"allowed: {t}", t in investigator.ALLOWED_TOOLS)
    for s in NEW:
        _check(f"persona names '{s}'", s in investigator.PERSONA)


def test_seeded_into_catalog():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            rows = {r["slug"]: r for r in conn.execute(
                "SELECT slug, env_var, category FROM osint_providers")}
        for s in NEW:
            _check(f"{s} seeded", s in rows)
            _check(f"{s} seeded keyless", rows[s]["env_var"] is None)


def main():
    test_registered_and_keyless()
    test_gravatar_hash()
    test_wallet_detection()
    test_eth_surfaces_etherscan_error()
    test_username_validation()
    test_mcp_wraps_each()
    test_investigator_allowlist()
    test_seeded_into_catalog()
    print("\nPASS: test_flowsint_adapters")


if __name__ == "__main__":
    main()
