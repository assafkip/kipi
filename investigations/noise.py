"""Deterministic graph-noise gate: entities that pollute the graph and erode trust but
are not the investigation's target. Mirrors cdn_ranges.is_cdn_ip (IP noise) for two more
classes the founder flagged (2026-06-11):

  - bare-number "phones": the agent types affiliate / tracking / URL-path IDs (164736471)
    as phone. A real phone carries a '+' country prefix or formatting separators; a bare
    digit run is an ID, never a phone.
  - boilerplate / reference domains: registry + WHOIS infrastructure that EVERY lookup
    references (iana.org, whois.verisign-grs.com), and security-news / journalist domains
    that report ON a scam rather than being its infrastructure (krebsonsecurity.com).

Used by _promotion_gate to keep these off the auto-built graph (they still land as leads).
Conservative by design: social / code-host domains (a scammer's real account) are NOT
gated here — only lookup boilerplate and known reporting outlets.
"""
from __future__ import annotations

import re

# Registry / WHOIS / registrar boilerplate — present in essentially every whois/RDAP
# response, never the target. Matched on host + registrable domain.
_BOILERPLATE_DOMAINS = {
    "iana.org", "icann.org", "verisign-grs.com", "verisign.com", "pir.org",
    "publicinterestregistry.org", "internic.net", "afilias.net", "identitydigital.com",
    "centralnic.com", "markmonitor.com", "cscglobal.com", "csc.com", "registry.google",
    "gandi.net", "namecheap.com", "godaddy.com", "publicdomainregistry.com",
    "tucows.com", "enom.com", "key-systems.net", "namesilo.com", "dynadot.com",
    # ccTLD registry NICs: a whois of any .is domain returns ISNIC's own contacts
    # (iana-contact@isnic.is, +354 578 2030) — the registry's details, never the target.
    "isnic.is",
}
# Lookup / tooling services the AGENT ITSELF uses — their hostnames appear in tool output
# (the crt.sh query URL, an ip-api lookup link, a pydantic traceback's docs URL) and are
# parser exhaust, never target infrastructure (trump-demo dig, 2026-06-11).
_LOOKUP_TOOL_DOMAINS = {
    "crt.sh", "ip-api.com", "pydantic.dev",
}
# Security-news / threat-reporting outlets — they cover scams, they are not the scam infra.
_REFERENCE_DOMAINS = {
    "krebsonsecurity.com", "bleepingcomputer.com", "thehackernews.com", "therecord.media",
    "scamadviser.com", "scamwatch.gov.au", "ic3.gov", "ftc.gov", "securityweek.com",
    "darkreading.com", "welivesecurity.com", "malwarebytes.com", "trendmicro.com",
    "kaspersky.com", "sophos.com", "wikipedia.org",
    # Phishing/abuse blocklists + research feeds: these REPORT ON scams (or take them down),
    # they are not the scam's own infrastructure. An analyst would never pivot into them as a
    # target — pivoting there builds a "waste of time" cluster (founder, 2026-06-11).
    "phishdestroy.io", "phishtank.com", "phishtank.org", "openphish.com",
    "abuse.ch", "urlhaus.abuse.ch", "threatfox.abuse.ch", "urlscan.io",
    "virustotal.com", "spamhaus.org",
    # Writeups reporting ON a phishing kit / scam (krebsonsecurity-class, just smaller):
    # a personal-blog kit analysis and a college course post — sources, not infrastructure.
    "thereallo.dev", "fullcoll.edu",
}
_BOILERPLATE_DOMAINS |= {"globaldomaingroup.com", "name-services.com", "registrar-servers.com"}
_NOISE_DOMAINS = _BOILERPLATE_DOMAINS | _REFERENCE_DOMAINS | _LOOKUP_TOOL_DOMAINS

# Registry contact phone numbers (normalized digits) — published in every whois answer
# for that registry's TLD, the registry's switchboard, never the target's number.
_BOILERPLATE_PHONE_DIGITS = {
    "3545782030",   # ISNIC (.is registry), +354 578 2030
}

# Shared DNS-provider nameservers — boilerplate like CDN IPs (millions of unrelated domains
# point at the same ns hosts, so the ns is never the target). Matched as a host substring.
_NAMESERVER_MARKERS = (
    "ns.cloudflare.com", "awsdns", "nsone.net", "dnsmadeeasy.com", "googledomains.com",
    "azure-dns.", "domaincontrol.com", "registrar-servers.com", "name-services.com",
    "dns.he.net", "ns.namecheap.com",
)


def _host(value: str) -> str:
    """Bare host from a domain or URL value (strip scheme, path, query, userinfo, port,
    www., and surrounding dots)."""
    s = (value or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s)   # scheme
    s = s.split("/")[0].split("?")[0].split("#")[0]
    s = s.split("@")[-1]                             # userinfo
    s = s.split(":")[0]                              # port
    s = s.strip(".")
    return re.sub(r"^www\.", "", s)


def _registrable(host: str) -> str:
    """Crude registrable domain (last two labels). The denylist holds no multi-part TLDs,
    so the simple two-label form is safe for matching."""
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_noise_domain(value: str) -> bool:
    """A registry/WHOIS/registrar boilerplate domain, a WHOIS-server host, or a known
    threat-reporting outlet — graph noise, not target infrastructure."""
    host = _host(value)
    if not host:
        return False
    if host.startswith("whois.") or ".whois-servers." in host:
        return True
    if any(m in host for m in _NAMESERVER_MARKERS):
        return True
    reg = _registrable(host)
    return host in _NOISE_DOMAINS or reg in _NOISE_DOMAINS


def is_real_phone(value: str) -> bool:
    """True only for a value shaped like a real phone number. A bare digit run with no
    '+' prefix and no formatting separators (164736471) is an ID / tracking number, NOT a
    phone — mirrors the extractor's _looks_like_phone, applied to agent findings."""
    s = (value or "").strip()
    digits = re.sub(r"[\s().+\-]", "", s)
    if not digits.isdigit() or not (7 <= len(digits) <= 15):
        return False
    # NANP (+1) numbers are exactly 11 digits (1 + 10). A shorter '+1...' run is a
    # truncated id wearing a plus (+1703925 — 7 digits of a timestamp), not a phone.
    if s.startswith("+1") and len(digits) != 11:
        return False
    return s.startswith("+") or bool(re.search(r"[\s().\-]", s))


def is_boilerplate_phone(value: str) -> bool:
    """A registry's own published contact number (whois boilerplate) — a real phone,
    but never the target's. Matched on normalized digits, with or without country '+'."""
    digits = re.sub(r"[\s().+\-]", "", value or "")
    return digits in _BOILERPLATE_PHONE_DIGITS
