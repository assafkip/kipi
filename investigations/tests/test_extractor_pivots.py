"""Web/crypto fingerprint extraction + pivot templates (fraud schema gap fix).

Run: .venv/bin/python -m investigations.tests.test_extractor_pivots
"""
from investigations.ingest.extractor import extract_all
from investigations import analyze


def _types(text):
    out = {}
    for e in extract_all(text):
        out.setdefault(e.entity_type, []).append(e.canonical)
    return out


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


CRYPTO = """
GA tag G-ABCD1234XY and GTM-ABC123 and UA-12345678-1 are shared across the cluster.
TRXDrop hardcodes WalletConnect projectId fbf5b42d9006502246e73447f5d50e33.
Solana receiving address 7EYnhQoR9YM3N7UoaKRoA44Uy8JeaZV3qbVbS1NXW4 listed.
XRP wallet with destinationTag rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh.
TRON address TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC drains funds.
EVM wallet 0x1111111111111111111111111111111111111111 receives.
Built on Nuxt with connect-wallet and ethers.js.
"""

# Same shapes, but NO chain/service keywords anywhere → gates must suppress them.
PLAIN = """
The committee reviewed document 7EYnhQoR9YM3N7UoaKRoA44Uy8JeaZV3qbVbS1NXW4 yesterday.
A reference code fbf5b42d9006502246e73447f5d50e33 was noted in the minutes.
Nothing technical was discussed at all during the quarterly meeting.
"""


def test_new_fingerprint_types():
    t = _types(CRYPTO)
    _check("GA/GTM/UA tracking tags extracted",
           {"g-abcd1234xy", "gtm-abc123", "ua-12345678-1"} <= set(t.get("tracking_tag", [])))
    _check("walletconnect_id extracted (gated on projectId)",
           "fbf5b42d9006502246e73447f5d50e33" in t.get("walletconnect_id", []))
    wallets = set(t.get("crypto_wallet", []))
    _check("Solana address extracted", "7EYnhQoR9YM3N7UoaKRoA44Uy8JeaZV3qbVbS1NXW4" in wallets)
    _check("XRP address extracted", "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh" in wallets)
    _check("TRON address extracted", "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC" in wallets)
    _check("EVM address extracted", "0x1111111111111111111111111111111111111111" in wallets)
    _check("tech_stack fingerprints extracted",
           {"nuxt", "connect-wallet", "ethers.js"} <= set(t.get("tech_stack", [])))


def test_gating_suppresses_false_positives():
    t = _types(PLAIN)
    _check("no base58 wallet false-positive without chain keywords",
           "7EYnhQoR9YM3N7UoaKRoA44Uy8JeaZV3qbVbS1NXW4" not in t.get("crypto_wallet", []))
    _check("32-hex falls to md5 (not walletconnect) without WC keywords",
           "fbf5b42d9006502246e73447f5d50e33" not in t.get("walletconnect_id", []) and
           "fbf5b42d9006502246e73447f5d50e33" in t.get("hash_md5", []))


SAAS_WHOIS = """A live-chat widget (JivoSite, account ID Y0q86ZSjlX) was added to the page.
Registrar: PDR Ltd. d/b/a PublicDomainRegistry.com
Name Server: alan.ns.cloudflare.com
"""


def test_saas_and_whois():
    t = _types(SAAS_WHOIS)
    _check("SaaS service-account id extracted", "Y0q86ZSjlX" in t.get("saas_service_account", []))
    _check("WHOIS registrar extracted",
           any("pdr ltd" in r for r in t.get("registrar", [])))
    _check("WHOIS nameserver extracted", "alan.ns.cloudflare.com" in t.get("nameserver", []))


def test_pivot_templates_exist():
    _check("tracking_tag has pivot links", "tracking_tag" in analyze.PIVOT_TEMPLATES)
    _check("walletconnect_id has pivot links", "walletconnect_id" in analyze.PIVOT_TEMPLATES)
    # The pivot URL actually substitutes the value.
    label, tpl = analyze.PIVOT_TEMPLATES["tracking_tag"][0]
    _check("tracking_tag pivot substitutes the value", "{value}" in tpl)


def test_phone_rejects_bare_numeric_runs():
    # Bare digit runs (counters, transaction IDs, timestamps) are NOT phones —
    # they used to flood the graph as junk nodes. A real phone carries a '+'
    # or formatting separators.
    t = _types("call +1 (415) 555-0199 or 020 7946 0958. ref 000000000 "
               "txid 276516686 counter 019013683.")
    phones = t.get("phone", [])
    _check("junk numeric runs are not phones",
           not any(p in ("000000000", "276516686", "019013683") for p in phones))
    _check("real formatted phone still extracted",
           any("4155550199" in p for p in phones))
    # A bare digit run IS a phone when a phone/tel label sits right before it
    # (structured-scrape "Phone: 4155550199" shape) — must not be dropped.
    labeled = _types("Phone: 4155550199  tel no: 02079460958 "
                     "mobile phone number: 13105550147")
    lp = labeled.get("phone", [])
    _check("label-prefixed bare phones kept", "4155550199" in lp and "13105550147" in lp)
    # ...but a label-suffix of an unrelated word must NOT count (Hotel/recall).
    decoy = _types("Hotel: 000000001  recall: 000000002")
    _check("word-suffix decoy labels rejected", not decoy.get("phone"))


def test_base58_wallet_case_preserved_no_forged_twin():
    # base58 (1.../3...) is case-sensitive — lowercasing forges an invalid
    # duplicate. EVM/bech32 are case-insensitive and still lowercase (dedupe).
    t = _types("btc 1muskDgU9ZVSYBbyp52iwp5ksugscMfYv "
               "eth 0xAbCdEf0123456789aBcDeF0123456789AbCdEf01 bc1qqu75xepdcu377lr")
    wallets = t.get("crypto_wallet", [])
    _check("base58 case preserved", "1muskDgU9ZVSYBbyp52iwp5ksugscMfYv" in wallets)
    _check("no lowercased base58 twin", "1muskdgu9zvsybbyp52iwp5ksugscmfyv" not in wallets)
    _check("EVM lowercased", "0xabcdef0123456789abcdef0123456789abcdef01" in wallets)
    _check("bech32 (already lowercase) kept", "bc1qqu75xepdcu377lr" in wallets)


def main():
    test_new_fingerprint_types()
    test_gating_suppresses_false_positives()
    test_saas_and_whois()
    test_pivot_templates_exist()
    test_phone_rejects_bare_numeric_runs()
    test_base58_wallet_case_preserved_no_forged_twin()
    print("\nPASS: test_extractor_pivots")


if __name__ == "__main__":
    main()
