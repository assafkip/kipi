"""Adapter registry — single point of lookup."""
from __future__ import annotations

from investigations.enrich.base import Adapter
from investigations.enrich.perplexity import PerplexityAdapter
from investigations.enrich.tavily import TavilyAdapter
from investigations.enrich.exa import ExaAdapter
from investigations.enrich.apify import ApifyAdapter
from investigations.enrich.jina import JinaAdapter
from investigations.enrich.virustotal import VirusTotalAdapter
from investigations.enrich.abusech import AbuseChAdapter
from investigations.enrich.crtsh import CrtShAdapter
from investigations.enrich.infra import InfraAdapter
from investigations.enrich.whoisxml import WhoisXMLAdapter
from investigations.enrich.breach import BreachAdapter
from investigations.enrich.shodan import ShodanAdapter
from investigations.enrich.censys import CensysAdapter
# Flowsint-inspired enrichers (native, no Flowsint dependency) — gaps kipi lacked.
from investigations.enrich.gravatar import GravatarAdapter
from investigations.enrich.ipgeo import IpGeoAdapter
from investigations.enrich.username import UsernameAdapter
from investigations.enrich.wallet import WalletAdapter
# Email triage + header->IP pivot (the MailTrace checklist, native + keyless).
from investigations.enrich.email_intel import EmailIntelAdapter


_REGISTRY: dict[str, Adapter] = {
    "perplexity": PerplexityAdapter(),
    "tavily": TavilyAdapter(),
    "exa": ExaAdapter(),
    "apify": ApifyAdapter(),
    "jina": JinaAdapter(),
    # Threat-intel + infra recon, ported from huntkit's MCP servers.
    "virustotal": VirusTotalAdapter(),
    "abusech": AbuseChAdapter(),
    "crtsh": CrtShAdapter(),
    "infra": InfraAdapter(),
    # Reverse-WHOIS + historical (passive) DNS — the two pivots the agent lacked.
    "whoisxml": WhoisXMLAdapter(),
    # Breach / infostealer exposure (HudsonRock Cavalier, free) — the Level-1.5 tier.
    "breach": BreachAdapter(),
    # Host intelligence — open ports / services / certs / CVEs by IP.
    "shodan": ShodanAdapter(),
    "censys": CensysAdapter(),
    # Flowsint-inspired: email->profile, IP->geo/ASN, handle->presence, wallet->tx.
    "gravatar": GravatarAdapter(),
    "ipgeo": IpGeoAdapter(),
    "username": UsernameAdapter(),
    "wallet": WalletAdapter(),
    # Email triage (MX/SPF/DMARC/provider/disposable) + raw-header -> source-IP pivot.
    "email": EmailIntelAdapter(),
}


def get_adapter(slug: str) -> Adapter:
    if slug not in _REGISTRY:
        raise KeyError(f"unknown adapter slug: {slug}. Known: {list(_REGISTRY)}")
    return _REGISTRY[slug]


def all_adapters() -> list[Adapter]:
    return list(_REGISTRY.values())


def configured_adapters() -> list[Adapter]:
    return [a for a in _REGISTRY.values() if a.is_configured()]
