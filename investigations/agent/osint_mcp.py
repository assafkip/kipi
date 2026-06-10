"""kipi-osint MCP server — exposes kipi's OSINT adapters as MCP tools.

This is the "MCP plugin" the investigator agent (and any MCP client) uses. Rather
than copying 4_points/huntkit's osint-infra + threat-intel servers as a fourth
fork (the drift the 4_points review warned about), it wraps kipi's OWN enrich
adapters — one source of truth. Same capability: cert transparency, WHOIS/DNS,
VirusTotal, abuse.ch, search.

Run standalone (stdio):  python -m investigations.agent.osint_mcp
Registered in .mcp.json as "kipi-osint" so `claude --mcp-config` picks it up.
Keyless tools (crtsh/whois/dns) work with no setup; keyed tools read the
key from the kipi DB or the env var, same as the web Enrich panel.
"""
from __future__ import annotations

import re

from mcp.server.fastmcp import FastMCP

from investigations.enrich import registry

mcp = FastMCP("kipi-osint")

# Perplexity's cheap default `sonar` model whiffs on multi-entity / attribution
# research -- it latches onto surface keywords and won't reconcile a network.
# Deterministically escalate to `reasoning` (sonar-reasoning-pro) for those queries.
# Replay D2 (replay-4points-case031): sonar returned sewing/color-blocking pages for
# the *ColorDSGN kit; reasoning matched 4_points (Bitdefender domains + Russian nexus).
_ATTRIBUTION_SIGNALS = (
    "network", "attribution", "linked", "tied to", "same operator", "cluster",
    "registrar", "infrastructure", "nexus", "campaign", "other domains",
    "related domains", "who is behind", "who operates", "russian", "kit",
    "shared", "connected to", "belong to", "part of",
)
_DOMAIN_RE = re.compile(r"\b[a-z0-9-]+\.[a-z]{2,}\b")


def _perplexity_mode(query: str) -> str | None:
    """Pick the perplexity model deterministically. `reasoning` for attribution /
    network research (an attribution keyword, or 2+ distinct domains in one query);
    else the cheap `sonar` default (None). No model judgment involved."""
    q = (query or "").lower()
    if any(sig in q for sig in _ATTRIBUTION_SIGNALS):
        return "reasoning"
    if len(set(_DOMAIN_RE.findall(q))) >= 2:
        return "reasoning"
    return None


def _call(slug: str, query: str, mode: str | None = None) -> str:
    """Run one adapter, format results as text. Errors come back as text (not
    exceptions) so the agent sees the failure and can pivot."""
    try:
        adapter = registry.get_adapter(slug)
    except KeyError:
        return f"ERROR: unknown provider {slug}"
    try:
        results = adapter.run(query, mode=mode)
    except Exception as exc:  # EnrichmentError + anything the provider throws
        return f"ERROR ({slug}): {exc}"
    if not results:
        return f"(no results from {slug} for {query!r})"
    out = []
    for r in results:
        block = [f"## {r.title}"]
        if getattr(r, "url", None):
            block.append(f"URL: {r.url}")
        if getattr(r, "confidence", None):
            block.append(f"confidence: {r.confidence}")
        block.append(r.summary or "")
        out.append("\n".join(block))
    return "\n\n".join(out)


@mcp.tool()
def crtsh_subdomains(domain: str) -> str:
    """Certificate-transparency lookup: every hostname ever issued a cert for a
    domain. Fast keyless subdomain + related-infra enumeration. Arg: a domain."""
    return _call("crtsh", domain)


@mcp.tool()
def whois_lookup(target: str) -> str:
    """WHOIS registration for a domain or IP (registrar, registrant, dates,
    nameservers / netblock owner). Keyless."""
    return _call("infra", target, mode="whois")


@mcp.tool()
def dns_lookup(target: str) -> str:
    """DNS records (A / AAAA / MX / TXT / NS) for a domain. Keyless."""
    return _call("infra", target, mode="dns")


@mcp.tool()
def reverse_dns(ip_address: str) -> str:
    """Reverse-DNS (PTR) for an IP address. Keyless."""
    return _call("infra", ip_address, mode="reverse")


@mcp.tool()
def virustotal(indicator: str) -> str:
    """VirusTotal reputation + detection stats for a domain, IP, hash, or URL.
    Needs VIRUSTOTAL_API_KEY (or a key stored in the Enrich panel)."""
    return _call("virustotal", indicator)


@mcp.tool()
def abusech(indicator: str) -> str:
    """abuse.ch URLhaus + ThreatFox: is a host/URL a known malware point or IOC?
    Needs ABUSECH_AUTH_KEY."""
    return _call("abusech", indicator)


@mcp.tool()
def reverse_whois(registrant: str) -> str:
    """Reverse-WHOIS: every domain whose WHOIS record contains a registrant term
    (email / name / org) — turns one registrant email into the operator's FULL domain
    portfolio. Needs WHOISXML_API_KEY. Arg: an email / name / org string."""
    return _call("whoisxml", registrant, mode="reverse_whois")


@mcp.tool()
def dns_history(domain: str) -> str:
    """Historical (passive) DNS: the A-records a domain resolved to OVER TIME, even if
    it's dead now. A dead seed's old IP is the link to its live cluster — run this when
    live DNS is empty. Needs WHOISXML_API_KEY. Arg: a domain."""
    return _call("whoisxml", domain, mode="dns_history")


@mcp.tool()
def breach_intel(indicator: str) -> str:
    """Breach / infostealer exposure for a DOMAIN (employees/users compromised) or an
    EMAIL/login (stealer records). HudsonRock Cavalier, free + keyless. Run this in the
    cheap first tier (before paid scraping) — it's often the highest-signal early pivot."""
    return _call("breach", indicator)


@mcp.tool()
def shodan_host(target: str) -> str:
    """Shodan host intelligence: open PORTS, running SERVICES + banners, hostnames, and
    known CVEs for an IP (or a domain, resolved to its IP). Works KEYLESS (InternetDB);
    add SHODAN_API_KEY for banners + org/ASN. Arg: an IP or domain."""
    return _call("shodan", target)


@mcp.tool()
def censys_host(target: str) -> str:
    """Censys host intelligence: services, ports, transport, TLS/cert data, autonomous
    system, and DNS names for an IP (or a domain, resolved to its IP). Needs a Censys
    API ID + secret (enter as 'id:secret' on the Enrich page). Arg: an IP or domain."""
    return _call("censys", target)


@mcp.tool()
def enumerate_infra(case: str, seeds: list[str] | None = None) -> str:
    """Run the ENTIRE deterministic infra sweep for a case in ONE call: every seed gets
    its type belt (crt.sh + whois/RDAP + DNS for domains; reverse-DNS + geo/ASN for IPs;
    reverse-whois for emails), the implied edges land automatically (resolves_to,
    registered_by, has_subdomain), and the tier-2 infra it surfaces gets one belt pass.
    Use this INSTEAD of calling whois_lookup / dns_lookup / crtsh_subdomains entity by
    entity — the nodes and edges are persisted for you; spend your turns on judgment.
    `seeds` narrows the sweep (default: the case's pivotable roster)."""
    from investigations.enrich import enumerate as enum_mod
    from investigations.storage import db
    try:
        with db.connect() as conn:
            if not conn.execute("SELECT 1 FROM investigations WHERE slug = ?",
                                (case,)).fetchone():
                known = [r["slug"] for r in conn.execute("SELECT slug FROM investigations")]
                return (f"ERROR: unknown case '{case}'. Known cases: "
                        f"{', '.join(known) or '(none)'}")
            out = enum_mod.enumerate_infra(conn, case, seeds=seeds)
    except Exception as exc:
        return f"ERROR (enumerate_infra): {exc}"
    head = (f"Enumerated {len(out['seeds'])} seed(s) + {len(out['tier2'])} tier-2 "
            f"entit(ies); {out['results']} lookup result(s) landed as nodes/edges/"
            f"properties already — do NOT re-run these lookups.")
    skipped = (f"\nNo infra recipe (pivot these yourself): "
               f"{', '.join(out['skipped_no_recipe'])}" if out["skipped_no_recipe"] else "")
    return f"{head}{skipped}\n\n## Infra digest\n{out['digest'] or '(no results)'}"


@mcp.tool()
def web_search(query: str) -> str:
    """Cited web search (Perplexity) for who/what/network questions about a target.
    Needs PERPLEXITY_API_KEY. Auto-escalates to the reasoning model for
    attribution/network questions (an attribution keyword, or 2+ domains)."""
    return _call("perplexity", query, mode=_perplexity_mode(query))


@mcp.tool()
def tavily_search(query: str) -> str:
    """Tavily web search + extract — broad, fast results for a target's footprint.
    Needs TAVILY_API_KEY."""
    return _call("tavily", query)


@mcp.tool()
def exa_search(query: str) -> str:
    """Exa semantic/neural search — find pages by meaning, good for people / orgs /
    obscure references. Needs EXA_API_KEY."""
    return _call("exa", query)


@mcp.tool()
def jina_read(url: str) -> str:
    """Jina Reader — fetch + clean a page to readable text (better than raw HTML for
    a key page). Needs JINA_API_KEY."""
    return _call("jina", url)


@mcp.tool()
def gravatar(email: str) -> str:
    """Gravatar profile for an EMAIL: display name, username, bio, and the social
    accounts the owner linked (each a pivot). Keyless. Arg: an email address."""
    return _call("gravatar", email)


@mcp.tool()
def email_triage(email: str) -> str:
    """Email address triage: MX records, SPF posture, DMARC policy, mail-provider
    identification, disposable-domain flag. Keyless DNS only. Arg: user@domain."""
    return _call("email", email, mode="triage")


@mcp.tool()
def email_headers(raw_headers: str) -> str:
    """Raw email headers -> the Received hop chain + every public source IP as a
    pivot (feed them into dns/RDAP/virustotal). Flags the ORIGIN IP. Keyless.
    Arg: the full raw header block pasted as text."""
    return _call("email", raw_headers, mode="headers")


@mcp.tool()
def ipgeo(target: str) -> str:
    """IP geolocation + ASN: country/city, ISP, org, and autonomous system (who owns the
    netblock) for an IP — or a domain, resolved to its IP first. Keyless. Arg: IP or domain."""
    return _call("ipgeo", target)


@mcp.tool()
def username_sweep(handle: str) -> str:
    """Username presence across a curated platform set (GitHub, GitLab, Reddit, Keybase,
    HackerNews, DevTo, Medium, YouTube, Telegram, Gravatar). Keyless; bot-walled sites
    (X / IG / TikTok) omitted. Arg: a bare handle (no @)."""
    return _call("username", handle)


@mcp.tool()
def wallet_tx(address: str) -> str:
    """Crypto wallet balance + transaction counterparties. BTC (mempool.space) is keyless;
    ETH (Etherscan) needs ETHERSCAN_API_KEY. Counterparty addresses are promotable pivots.
    Arg: a BTC or ETH address."""
    return _call("wallet", address)


@mcp.tool()
def social_scrape(target: str, platform: str = "") -> str:
    """Pull a creator's REAL content from a content platform — profile + recent posts
    (+ transcript for YouTube). Use this on a TikTok / YouTube / Twitter-X / Instagram
    profile URL or @handle instead of treating it as a bare link. `target` = a profile
    URL or @handle; `platform` (tiktok|youtube|twitter|instagram) is optional when
    `target` is a full URL. Needs an Apify key. Content platforms are the richest
    source on a creator/operator — this is how you read them."""
    from investigations.enrich import social
    r = social.resolve(target, platform or None)
    if not r:
        return ("ERROR: not a recognized content-platform target. Pass a full profile "
                "URL (tiktok.com/@x, youtube.com/@x, x.com/x, instagram.com/x) or an "
                "@handle WITH platform=tiktok|youtube|twitter|instagram.")
    return _call("apify", r["query"], mode=r["actor"])


if __name__ == "__main__":
    mcp.run()
