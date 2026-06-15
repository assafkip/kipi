"""Existing-adapter hardening + keyed lookups (PRD-6).

greynoise / opencorporates / git_osint (new adapters) + holehe (email mode) + dns_deep
(infra mode) + username hardening. NO network (all fetches monkeypatched). Mirrors
test_osint_providers_batch. Pins audit fixes: promote_as honor (O-7/#4) and low-confidence
lead rows for holehe + git_osint (O-8/#6).

Run: .venv/bin/python -m pytest investigations/tests/test_adapter_hardening_batch.py -q
"""
import pytest

from investigations.enrich import (registry, greynoise, opencorporates, git_osint,
                                    email_intel, infra, username, promote)
from investigations.enrich import base as enrich_base
from investigations.agent import osint_mcp, investigator

NEW = ["greynoise", "opencorporates", "git_osint"]
TOOL = {"greynoise": "greynoise", "opencorporates": "opencorporates", "git_osint": "git_emails"}
ENV = {"greynoise": "GREYNOISE_API_KEY", "opencorporates": "OPENCORPORATES_API_KEY",
       "git_osint": None}
WATCHED = {"greynoise": ("ip",), "opencorporates": ("org", "person"),
           "git_osint": ("url", "handle")}


# --- contract (new adapters) ----------------------------------------------

def test_registered_with_env():
    slugs = {a.slug for a in registry.all_adapters()}
    for s in NEW:
        assert s in slugs
        assert registry.get_adapter(s).env_var == ENV[s]


def test_watched_types_subset():
    for s in NEW:
        assert not set(registry.get_adapter(s).watched_types) - registry.TRANSFORM_TYPES


def test_recipe_presence():
    for s in NEW:
        for etype in WATCHED[s]:
            slugs = [slug for slug, _ in registry._TRANSFORM_RECIPES[etype]]
            assert s in slugs, f"{s} missing from {etype} recipe"


def test_mcp_and_extend_calls_present():
    src = open(osint_mcp.__file__).read()
    for s in NEW:
        assert f'_call("{s}"' in src
    assert '_call("email", email, mode="holehe")' in src
    assert '_call("infra", domain, mode="dns_deep")' in src


def test_allowlist_and_persona_routing():
    verbs = ["greynoise", "opencorporates", "git_emails", "holehe", "dns_deep"]
    for v in verbs:
        assert f"mcp__kipi-osint__{v}" in investigator._KIPI_MCP_TOOLS
        assert v in investigator.PERSONA, f"{v} not routed in PERSONA"
        assert v in investigator.CASE_PERSONA, f"{v} not routed in CASE_PERSONA"
    infra_crew = next(c for c in investigator.ROLE_AGENTS if c["role"] == "infra")
    assert "mcp__kipi-osint__greynoise" in infra_crew["tools"]
    assert "mcp__kipi-osint__opencorporates" in infra_crew["tools"]


# --- greynoise -------------------------------------------------------------

def test_greynoise_needs_key(monkeypatch):
    monkeypatch.setattr(greynoise, "resolve_key", lambda slug, env: "")
    out = greynoise.GreyNoiseAdapter().run("1.2.3.4")
    assert len(out) == 1 and "[needs key]" in out[0].title


def test_greynoise_parse(monkeypatch):
    monkeypatch.setattr(greynoise, "resolve_key", lambda slug, env: "KEY")
    monkeypatch.setattr(greynoise, "_get", lambda ip, key, t: {
        "ip": ip, "noise": True, "riot": False, "classification": "malicious", "name": "Mirai"})
    out = greynoise.GreyNoiseAdapter().run("1.2.3.4")
    assert "malicious" in out[0].title and out[0].raw_json["classification"] == "malicious"


# --- opencorporates + promote_as honor -------------------------------------

def test_opencorporates_officer_promote_as(monkeypatch):
    monkeypatch.setattr(opencorporates, "resolve_key", lambda slug, env: "KEY")
    monkeypatch.setattr(opencorporates, "_get", lambda path, params, t: {
        "results": {"officers": [{"officer": {
            "name": "Jane Doe", "position": "director", "jurisdiction_code": "gb",
            "opencorporates_url": "https://opencorporates.com/officers/1",
            "company": {"name": "Acme Ltd"}}}]}})
    out = opencorporates.OpenCorporatesAdapter().run("Jane Doe", mode="officer")
    child = [r for r in out[1:] if r.title == "Jane Doe"]
    assert child and child[0].raw_json["promote_as"] == "person"


def test_promote_as_hint():
    assert promote._promote_as_hint({"promote_as": "person"}) == "person"
    assert promote._promote_as_hint('{"promote_as": "org"}') == "org"
    assert promote._promote_as_hint({"promote_as": "bogus"}) is None
    assert promote._promote_as_hint({}) is None


# --- git_osint (low-confidence leads + git-missing guard) -------------------

def test_git_osint_low_confidence_leads(monkeypatch):
    monkeypatch.setattr(git_osint.shutil, "which", lambda b: "/usr/bin/git")
    monkeypatch.setattr(git_osint, "_mine_repo",
                        lambda url, timeout=90: [("alice@example.com", "Alice")])
    out = git_osint.GitOsintAdapter().run("https://github.com/x/y")
    lead = [r for r in out[1:] if r.title == "alice@example.com"]
    assert lead and lead[0].confidence == "low"
    assert promote._classify("alice@example.com") == "email"


def test_git_osint_needs_git(monkeypatch):
    monkeypatch.setattr(git_osint.shutil, "which", lambda b: None)
    with pytest.raises(Exception):
        git_osint.GitOsintAdapter().run("https://github.com/x/y")


# --- holehe (extend, low-confidence leads) ---------------------------------

def test_holehe_mode(monkeypatch):
    assert "holehe" in email_intel.EmailIntelAdapter().modes()
    monkeypatch.setattr(email_intel, "_holehe_scan", lambda email: [
        {"name": "Twitter", "exists": True}, {"name": "Foo", "exists": False}])
    out = email_intel.EmailIntelAdapter().run("a@b.com", mode="holehe")
    assert "registered on 1 site" in out[0].title
    assert out[1].confidence == "low"  # lead row stays gated


# --- dns_deep (extend) -----------------------------------------------------

def test_dns_deep_mode(monkeypatch):
    assert "dns_deep" in infra.InfraAdapter().modes()

    def fake_run(cmd, timeout):
        s = " ".join(cmd)
        if "_dmarc" in s:
            return "v=DMARC1; p=reject"
        if "TXT" in s:
            return "v=spf1 include:_spf.google.com ~all"
        if "MX" in s:
            return "1 aspmx.l.google.com."
        if "NS" in s:
            return "ns1.google.com.\nns2.google.com."
        return ""  # AXFR refused
    monkeypatch.setattr(infra, "_run", fake_run)
    monkeypatch.setattr(email_intel, "identify_provider", lambda hosts: "Google Workspace")
    out = infra.InfraAdapter().run("google.com", mode="dns_deep")
    assert "DNS deep" in out[0].title
    assert "DMARC1" in out[0].raw_json["dmarc"] and out[0].raw_json["axfr_open"] is False
    provider = [r for r in out[1:] if r.title == "Google Workspace"]
    assert provider and provider[0].raw_json["promote_as"] == "org"


# --- username hardening ----------------------------------------------------

def test_username_status_absent_detector(monkeypatch):
    det = ("status_absent", "User not found")
    monkeypatch.setattr(username, "_fetch", lambda url, t: (200, "Sorry, User not found here"))
    assert username._check("X", "https://x/{u}", det, "bob")["present"] is False
    monkeypatch.setattr(username, "_fetch", lambda url, t: (200, "Bob's real profile page"))
    assert username._check("X", "https://x/{u}", det, "bob")["present"] is True
    monkeypatch.setattr(username, "_fetch", lambda url, t: (404, ""))
    assert username._check("X", "https://x/{u}", det, "bob")["present"] is False


def test_wmn_loader_and_all_sites():
    wmn = username._load_wmn()
    names = {n for n, _, _ in wmn}
    assert "Pinterest" in names  # an m_string entry from the vendored snapshot
    by_name = {n: d for n, _, d in wmn}
    assert by_name["Pinterest"][0] == "status_absent"
    assert by_name["About.me"][0] == "contains"  # an e_string entry
    all_names = {n for n, _, _ in username._all_sites()}
    assert "GitHub" in all_names and "Pinterest" in all_names  # curated + wmn merged
