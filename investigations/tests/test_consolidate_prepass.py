"""Unit tests for consolidate's deterministic pre-pass — the code that types
self-labeled platform IDs + junk by rule so the LLM only sees genuine unknowns.

Pure-function tests (no DB, no LLM): they lock in the classification rules that
shrink a 3,300-entity pool to the ~800 the model actually needs to judge."""
from investigations import consolidate as C


CAT_FLOWER_SCHEMA = {
    "domain": "AI-image e-commerce seed-scam ecosystem",
    "roles": [
        {"name": "prime_merchant", "actor": True},
        {"name": "promoter", "actor": True},
        {"name": "fingerprint"},
        {"name": "noise"},
    ],
}


def test_platform_ids_type_as_fingerprint():
    for name in [
        "Shopify shop ID 65536098349",
        "Shopify theme ID 147114164269",
        "Etsy listing ID 4399092912",
        "eBay listing ID 396360834",
        "Shein goods ID 2594381020",
        "Facebook Ad ID 234646047",
        "Google Ads conversion ID 8842",
        "Ergo88 (Etsy shop ID 61612)",
    ]:
        assert C._pretype(name, "fingerprint") == "fingerprint", name


def test_bare_numeric_platform_ids_type_as_fingerprint():
    # The extractor dumps raw platform IDs into the 'phone' bucket as bare numbers.
    for name in ["65536098349", "4424008193530", "234646047", "+1 703 925-6999"]:
        assert C._pretype(name, "fingerprint") == "fingerprint", name


def test_bare_date_numbers_type_as_noise():
    for name in ["20260424", "2026-04-24", "19991231"]:
        assert C._pretype(name, "fingerprint") == "noise", name


def test_numeric_with_letters_stays_for_llm():
    # "TikTok burner user491…" is a real actor, not an artifact — must NOT auto-type.
    assert C._pretype("TikTok burner user49145311615666", "fingerprint") is None


def test_extractor_junk_types_as_noise():
    for name in [
        "20260424 (report date mis-parsed as phone)",
        "+1 703 925-6999 (registrar privacy-proxy phone)",
        "@media",
        "@import",
        "x",            # len <= 2
    ]:
        assert C._pretype(name, "fingerprint") == "noise", name


def test_real_actors_go_to_the_llm():
    # Handles / domains that need context judgment must NOT be auto-typed.
    for name in [
        "@menlytkn3ik",
        "haiyiplants.com",
        "bloomingseeds1",
        "@hey.look.its.kate",
        "menlytkn3ik",
    ]:
        assert C._pretype(name, "fingerprint") is None, name


def test_no_fingerprint_role_means_platform_ids_defer_to_llm():
    # Without a fingerprint-style role available, a platform ID is NOT force-typed.
    assert C._pretype("Shopify shop ID 65536098349", None) is None
    # Junk is still noise regardless of fp_role (schema-independent).
    assert C._pretype("@media", None) == "noise"


def test_fingerprint_role_resolution():
    assert C._fingerprint_role(CAT_FLOWER_SCHEMA) == "fingerprint"
    assert C._fingerprint_role({"roles": [{"name": "ioc"}, {"name": "operator"}]}) == "ioc"
    assert C._fingerprint_role({"roles": [{"name": "promoter", "actor": True}]}) is None
    assert C._fingerprint_role(None) is None


def test_norm_key_collapses_case_and_url_but_not_at():
    assert C._norm_key("https://t.me/Example_channel/") == C._norm_key("t.me/example_channel")
    assert C._norm_key("HaiyiPlants.com") == C._norm_key("haiyiplants.com")
    assert C._norm_key("www.example.com") == C._norm_key("example.com")
    # '@handle' must NOT collapse into a same-named domain/wallet — that stays the LLM's call.
    assert C._norm_key("@bitcoin") != C._norm_key("bitcoin")
