"""OSINT providers batch (PRD prd-osint-providers-batch) — AbuseIPDB, urlscan, OTX, HIBP.

Wiring + parse tests, NO network. Covers: registry membership, env/keyless contract,
watched_types ⊆ TRANSFORM_TYPES, recipe presence, MCP-tool + allowlist + PERSONA wiring, and
a mocked-_get parse of each adapter's run() (header document + promotable nodes). The
authoritative drift guards live in test_typed_transforms + test_investigator_tools; this file
adds the per-adapter behavior.

Run: .venv/bin/python -m pytest investigations/tests/test_osint_providers_batch.py -q
"""
from investigations.enrich import registry, abuseipdb, urlscan, otx, hibp
from investigations.enrich.base import NotConfiguredError
from investigations.agent import osint_mcp, investigator

NEW = ["abuseipdb", "urlscan", "otx", "hibp"]
ENV = {"abuseipdb": "ABUSEIPDB_API_KEY", "urlscan": "URLSCAN_API_KEY",
       "otx": "OTX_API_KEY", "hibp": "HIBP_API_KEY"}
TOOL = {"abuseipdb": "abuseipdb", "urlscan": "urlscan", "otx": "otx", "hibp": "hibp"}


# --- contract --------------------------------------------------------------

def test_all_registered_with_env():
    slugs = {a.slug for a in registry.all_adapters()}
    for s in NEW:
        assert s in slugs, f"{s} not registered"
        assert registry.get_adapter(s).slug == s
        assert registry.get_adapter(s).env_var == ENV[s]


def test_keyless_vs_keyed():
    # urlscan search works keyless; the other three need a key.
    assert registry.get_adapter("urlscan").is_configured() is True
    for s in ("abuseipdb", "otx", "hibp"):
        a = registry.get_adapter(s)
        # No DB key + no env var in a bare test env → not configured.
        assert a.is_configured() is False, f"{s} should be unconfigured without a key"


def test_unconfigured_get_key_raises(monkeypatch):
    for s in ("abuseipdb", "otx", "hibp"):
        monkeypatch.delenv(ENV[s], raising=False)
        try:
            registry.get_adapter(s).get_key()
            assert False, f"{s}.get_key() should raise without a key"
        except NotConfiguredError:
            pass


def test_watched_types_subset_of_vocab():
    for s in NEW:
        unknown = set(registry.get_adapter(s).watched_types) - registry.TRANSFORM_TYPES
        assert not unknown, f"{s} watches unknown types {unknown}"


def test_each_in_a_recipe_for_every_watched_type():
    for s in NEW:
        a = registry.get_adapter(s)
        for etype in a.watched_types:
            slugs = [slug for slug, _ in registry._TRANSFORM_RECIPES.get(etype, [])]
            assert s in slugs, f"{s} watches {etype} but is not in its recipe"


def test_mcp_allowlist_and_persona_wired():
    src = open(osint_mcp.__file__).read()
    for s in NEW:
        assert f'_call("{s}"' in src, f"osint_mcp missing _call(\"{s}\")"
        assert f"mcp__kipi-osint__{TOOL[s]}" in investigator._KIPI_MCP_TOOLS, f"{s} not in allowlist"
        assert s in investigator.PERSONA, f"{s} not named in PERSONA"


# --- mocked-_get parse -----------------------------------------------------

def test_abuseipdb_parse(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    monkeypatch.setattr(abuseipdb, "_get", lambda url, key, timeout: {"data": {
        "abuseConfidenceScore": 100, "totalReports": 42, "usageType": "Data Center",
        "isp": "EvilHost", "countryCode": "RU", "domain": "evil.com",
        "hostnames": ["a.evil.com"], "isTor": False, "lastReportedAt": "2026-01-01T00:00:00Z"}})
    out = abuseipdb.AbuseIPDBAdapter().run("1.2.3.4")
    assert out[0].result_type == "document" and "100/100" in out[0].summary
    titles = {r.title for r in out[1:]}
    assert {"evil.com", "a.evil.com"} <= titles


def test_urlscan_parse_keyless(monkeypatch):
    monkeypatch.setattr(urlscan, "_get", lambda url, key, timeout: {"total": 1, "results": [
        {"page": {"domain": "evil.com", "ip": "1.2.3.4", "server": "nginx"},
         "task": {"time": "2026-01-01T00:00:00Z", "url": "http://evil.com"}}]})
    out = urlscan.UrlscanAdapter().run("evil.com")
    assert out[0].result_type == "document" and "1 scan" in out[0].summary
    titles = {r.title for r in out[1:]}
    assert "evil.com" in titles and "1.2.3.4" in titles


def test_otx_detects_type_and_parses(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "k")

    def fake_get(otype, indicator, section, key, timeout):
        if section == "general":
            return {"pulse_info": {"count": 2, "pulses": [{"name": "Campaign X", "tags": ["apt"]}]}}
        return {"passive_dns": [{"hostname": "evil.com", "record_type": "A"}]}
    monkeypatch.setattr(otx, "_get", fake_get)
    # IPv4 indicator -> general + passive_dns (a DNS type)
    out = otx.OTXAdapter().run("1.2.3.4")
    assert out[0].result_type == "document" and "2 OTX pulse" in out[0].summary
    assert any(r.title == "evil.com" for r in out[1:])
    # a file hash -> general only (no passive_dns section, no nodes)
    out_hash = otx.OTXAdapter().run("a" * 64)
    assert len(out_hash) == 1 and out_hash[0].result_type == "document"


def test_otx_type_detection():
    assert otx._detect_type("1.2.3.4") == "IPv4"
    assert otx._detect_type("http://evil.com/x") == "url"
    assert otx._detect_type("a" * 32) == "file"
    assert otx._detect_type("a" * 64) == "file"
    assert otx._detect_type("evil.com") == "domain"
    assert otx._detect_type("a.b.evil.com") == "hostname"


def test_hibp_email_keyed_and_domain_keyless(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    monkeypatch.setattr(hibp, "_get", lambda url, headers, timeout: [
        {"Name": "LinkedIn", "BreachDate": "2012-05-05", "PwnCount": 164}])
    out = hibp.HIBPAdapter().run("bob@evil.com")
    assert out[0].result_type == "document" and "LinkedIn" in out[0].summary
    assert all(r.result_type == "document" for r in out)  # document-only, no nodes
    # domain mode (catalog filter) — same mock, still document-only
    out_d = hibp.HIBPAdapter().run("evil.com")
    assert out_d[0].result_type == "document" and "recorded against this site" in out_d[0].title
    assert "site context" in out_d[0].summary


def test_urlscan_query_handles_ip_in_url_and_ipv6():
    assert urlscan._build_query("http://1.2.3.4:8080/a") == "ip:1.2.3.4"
    assert urlscan._build_query("1.2.3.4") == "ip:1.2.3.4"
    assert urlscan._build_query("https://[2001:db8::1]:443/x") == "ip:2001:db8::1"
    assert urlscan._build_query("https://evil.com:443/path") == "domain:evil.com"
    assert urlscan._build_query("evil.com") == "domain:evil.com"


def test_adapters_survive_null_fields(monkeypatch):
    # explicit-null numeric fields must not crash the score/count comparisons (Codex impl).
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    monkeypatch.setattr(abuseipdb, "_get", lambda url, key, timeout: {"data": {
        "abuseConfidenceScore": None, "totalReports": None, "hostnames": None, "domain": None}})
    assert abuseipdb.AbuseIPDBAdapter().run("1.2.3.4")[0].result_type == "document"

    monkeypatch.setenv("OTX_API_KEY", "k")
    monkeypatch.setattr(otx, "_get", lambda *a: {
        "pulse_info": {"count": None, "pulses": None, "related": {"alienvault": None}}}
        if a[2] == "general" else {"passive_dns": None})
    assert otx.OTXAdapter().run("evil.com")[0].result_type == "document"


def test_hibp_email_requires_key(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    try:
        hibp.HIBPAdapter().run("bob@evil.com")
        assert False, "HIBP email mode should require a key"
    except NotConfiguredError:
        pass


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
