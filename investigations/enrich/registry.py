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
# IP reputation, scan search, threat pulses, breach exposure (PRD osint-providers-batch).
from investigations.enrich.abuseipdb import AbuseIPDBAdapter
from investigations.enrich.urlscan import UrlscanAdapter
from investigations.enrich.otx import OTXAdapter
from investigations.enrich.hibp import HIBPAdapter
# Flowsint-inspired enrichers (native, no Flowsint dependency) — gaps kipi lacked.
from investigations.enrich.gravatar import GravatarAdapter
from investigations.enrich.ipgeo import IpGeoAdapter
from investigations.enrich.username import UsernameAdapter
from investigations.enrich.wallet import WalletAdapter
# Email triage + header->IP pivot (the MailTrace checklist, native + keyless).
from investigations.enrich.email_intel import EmailIntelAdapter
# On-chain compliance + identity (PRD-1): sanctions screening, ENS, wallet labels.
from investigations.enrich.ofac import OfacAdapter
from investigations.enrich.ens import EnsAdapter
from investigations.enrich.wallet_labels import WalletLabelsAdapter
# On-chain value flow + multi-chain (PRD-2): ERC-20 (wallet ext) + Tron + Solana.
from investigations.enrich.tron import TronAdapter
from investigations.enrich.solana import SolanaAdapter
# On-chain breadth + clustering (PRD-3): multi-chain balance, BTC cluster, TON.
from investigations.enrich.blockchair import BlockchairAdapter
from investigations.enrich.walletexplorer import WalletExplorerAdapter
from investigations.enrich.wallet_ton import WalletTonAdapter
# Crypto + dark-web reputation / leads (PRD-4): scam blocklists + Ahmia onion search.
from investigations.enrich.crypto_abuse import CryptoAbuseAdapter
from investigations.enrich.darkweb import DarkwebAdapter
# Non-crypto primitives (PRD-5): EXIF metadata, ASN/netblock owner, phone intel.
from investigations.enrich.exif import ExifAdapter
from investigations.enrich.asn import AsnAdapter
from investigations.enrich.phone import PhoneAdapter
# Existing-adapter hardening + keyed lookups (PRD-6): scanner class, registry, git emails.
from investigations.enrich.greynoise import GreyNoiseAdapter
from investigations.enrich.opencorporates import OpenCorporatesAdapter
from investigations.enrich.git_osint import GitOsintAdapter
# Tradecraft + lookalike hunting (PRD-7): dnstwist typosquat candidates.
from investigations.enrich.typosquat import TyposquatAdapter


# The canonical entity-type vocabulary for transforms (sp2, binding from
# prd-spine-phase2). Declarations and recipes must be subsets — validated at
# import, so a typo is a red test, never an empty menu or a false refusal.
TRANSFORM_TYPES = frozenset({
    "domain", "subdomain", "url", "ip", "email", "phone", "handle", "person",
    "org", "telegram_channel", "crypto_wallet", "wallet", "asn", "indicator",
    "hash_sha256", "hash_md5", "username", "fingerprint",
})

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
    # IP reputation, scan-search, threat pulses, breach exposure (PRD osint-providers-batch).
    "abuseipdb": AbuseIPDBAdapter(),
    "urlscan": UrlscanAdapter(),
    "otx": OTXAdapter(),
    "hibp": HIBPAdapter(),
    # Flowsint-inspired: email->profile, IP->geo/ASN, handle->presence, wallet->tx.
    "gravatar": GravatarAdapter(),
    "ipgeo": IpGeoAdapter(),
    "username": UsernameAdapter(),
    "wallet": WalletAdapter(),
    # Email triage (MX/SPF/DMARC/provider/disposable) + raw-header -> source-IP pivot.
    "email": EmailIntelAdapter(),
    # On-chain compliance + identity (PRD-1): sanctions, ENS name<->address, labels.
    "ofac": OfacAdapter(),
    "ens": EnsAdapter(),
    "wallet_labels": WalletLabelsAdapter(),
    # On-chain value flow + multi-chain (PRD-2): Tron TRC-20, Solana (ERC-20 is a wallet mode).
    "tron": TronAdapter(),
    "solana": SolanaAdapter(),
    # On-chain breadth + clustering (PRD-3): multi-chain balance, BTC cluster, TON.
    "blockchair": BlockchairAdapter(),
    "walletexplorer": WalletExplorerAdapter(),
    "wallet_ton": WalletTonAdapter(),
    # Crypto + dark-web reputation / leads (PRD-4): T3 lead generators.
    "crypto_abuse": CryptoAbuseAdapter(),
    "darkweb": DarkwebAdapter(),
    # Non-crypto primitives (PRD-5): EXIF metadata, ASN/netblock owner, phone intel.
    "exif": ExifAdapter(),
    "asn": AsnAdapter(),
    "phone": PhoneAdapter(),
    # Existing-adapter hardening + keyed lookups (PRD-6): scanner class, registry, git emails.
    "greynoise": GreyNoiseAdapter(),
    "opencorporates": OpenCorporatesAdapter(),
    "git_osint": GitOsintAdapter(),
    # Tradecraft + lookalike hunting (PRD-7): dnstwist typosquat candidates.
    "typosquat": TyposquatAdapter(),
}


def _validate_registry() -> None:
    """Every registered adapter MUST declare a non-empty watched_types subset
    of TRANSFORM_TYPES — an undeclared adapter is structurally uncallable
    (import fails here, and the bypass test goes red)."""
    for slug, adapter in _REGISTRY.items():
        if not adapter.watched_types:
            raise TypeError(
                f"adapter {slug!r} declares no watched_types — every transform "
                f"must state the entity types it consumes (sp2 registry contract)")
        unknown = set(adapter.watched_types) - TRANSFORM_TYPES
        if unknown:
            raise TypeError(
                f"adapter {slug!r} watches unknown entity types {sorted(unknown)} "
                f"— extend TRANSFORM_TYPES deliberately or fix the typo")


_validate_registry()


# The ordered recipe map — THE static Maltego-style lookup. Order is menu and
# belt order: deterministic/keyless tier first, then keyed lookups, then the
# broad research tier. Cross-validated against watched_types by the bypass
# test (recipes are a subset of declarations; every adapter appears).
_TRANSFORM_RECIPES: dict[str, list[tuple[str, str | None]]] = {
    "domain":    [("crtsh", None), ("typosquat", None), ("infra", "whois"), ("infra", "dns"),
                  ("shodan", None), ("censys", None), ("ipgeo", None),
                  ("virustotal", None), ("abusech", "urlhaus"),
                  ("whoisxml", "dns_history"), ("breach", None),
                  ("urlscan", None), ("otx", None), ("hibp", None),
                  ("crypto_abuse", None), ("darkweb", None),
                  ("jina", "read"), ("tavily", None), ("exa", None),
                  ("perplexity", None), ("apify", None)],
    "subdomain": [("crtsh", None), ("infra", "whois"), ("infra", "dns"),
                  ("shodan", None), ("censys", None), ("ipgeo", None),
                  ("virustotal", None), ("abusech", "urlhaus"),
                  ("whoisxml", "dns_history"),
                  ("urlscan", None), ("otx", None),
                  ("jina", "read"), ("tavily", None), ("exa", None),
                  ("perplexity", None), ("apify", None)],
    "ip":        [("infra", "reverse"), ("ipgeo", None), ("asn", None),
                  ("shodan", None), ("censys", None), ("virustotal", None),
                  ("abusech", "threatfox"),
                  ("abuseipdb", None), ("greynoise", None), ("urlscan", None), ("otx", None),
                  ("tavily", None), ("exa", None), ("perplexity", None),
                  ("apify", None), ("jina", None)],
    "url":       [("virustotal", None), ("abusech", "urlhaus"),
                  ("urlscan", None), ("otx", None), ("git_osint", None),
                  ("jina", "read"), ("tavily", None), ("exa", None),
                  ("perplexity", None), ("apify", None)],
    "email":     [("gravatar", None), ("email", None),
                  ("whoisxml", "reverse_whois"), ("breach", None),
                  ("hibp", None),
                  ("tavily", None), ("exa", None), ("perplexity", None),
                  ("apify", None), ("jina", None)],
    "phone":     [("phone", None), ("tavily", None), ("exa", None), ("perplexity", None),
                  ("apify", None), ("jina", None)],
    "handle":    [("ens", None), ("username", None), ("git_osint", None), ("darkweb", None),
                  ("tavily", None), ("exa", None),
                  ("perplexity", None), ("apify", None), ("jina", None)],
    "username":  [("username", None), ("tavily", None), ("exa", None),
                  ("perplexity", None), ("apify", None), ("jina", None)],
    "person":    [("ofac", None), ("opencorporates", None), ("whoisxml", "reverse_whois"),
                  ("tavily", None), ("exa", None), ("perplexity", None),
                  ("apify", None), ("jina", None)],
    "org":       [("ofac", None), ("opencorporates", None), ("whoisxml", "reverse_whois"),
                  ("darkweb", None),
                  ("tavily", None), ("exa", None), ("perplexity", None), ("apify", None),
                  ("jina", None)],
    "telegram_channel": [("tavily", None), ("exa", None),
                         ("perplexity", None), ("apify", None),
                         ("jina", None)],
    "crypto_wallet": [("ens", None), ("ofac", None), ("wallet_labels", None),
                      ("wallet", None), ("solana", None), ("tron", None),
                      ("wallet_ton", None), ("blockchair", None), ("walletexplorer", None),
                      ("crypto_abuse", None),
                      ("tavily", None), ("exa", None),
                      ("perplexity", None), ("apify", None), ("jina", None)],
    "wallet":    [("ens", None), ("ofac", None), ("wallet_labels", None),
                  ("wallet", None), ("solana", None), ("tron", None),
                  ("wallet_ton", None), ("blockchair", None), ("walletexplorer", None),
                  ("crypto_abuse", None),
                  ("tavily", None), ("exa", None),
                  ("perplexity", None), ("apify", None), ("jina", None)],
    "asn":       [("asn", None), ("tavily", None), ("exa", None), ("perplexity", None),
                  ("apify", None), ("jina", None)],
    "indicator": [("exif", None), ("virustotal", None), ("abusech", "threatfox"),
                  ("otx", None), ("tavily", None), ("exa", None), ("perplexity", None),
                  ("apify", None), ("jina", None)],
    "hash_sha256": [("virustotal", None), ("abusech", "threatfox"), ("otx", None)],
    "hash_md5":  [("virustotal", None), ("abusech", "threatfox"), ("otx", None)],
    "fingerprint": [("exif", None), ("tavily", None), ("exa", None), ("perplexity", None),
                    ("apify", None), ("jina", None)],
}

# The keyless deterministic tier — flags menu items the analyst can run free.
DETERMINISTIC_SLUGS = ("crtsh", "infra", "ipgeo", "whoisxml",
                       "ens", "ofac", "wallet_labels", "solana", "tron",
                       "blockchair", "walletexplorer", "wallet_ton",
                       "crypto_abuse", "darkweb",
                       "asn", "phone", "exif", "git_osint", "typosquat")

# The agent's one-hop infra belt: a DECLARED SUBSET view of the transform map
# (cross-validated by the bypass test). Content + order are the pre-sp2 belt,
# byte-identical — pinned by test_infra_belt_by_type +
# test_quick_investigate_is_one_hop. Keyless ones always run; keyed ones
# (ipgeo / whoisxml) gate on configuration inside the belt runner.
BELT_RECIPES: dict[str, list[tuple[str, str | None]]] = {
    "domain":    [("crtsh", None), ("infra", "whois"), ("infra", "dns")],
    "subdomain": [("crtsh", None), ("infra", "whois"), ("infra", "dns")],
    "ip":        [("infra", "reverse"), ("ipgeo", None)],
    "email":     [("whoisxml", "reverse_whois")],
}


def belt_for_type(entity_type: str | None) -> list[tuple[str, str | None]]:
    """The deterministic one-hop belt for a node type ([] = no infra recipe)."""
    return list(BELT_RECIPES.get((entity_type or "").lower(), []))


def transforms_for_type(entity_type: str | None) -> list[dict]:
    """The Maltego lookup: what can run on a node of this type, in menu order.
    Unknown/missing type -> [] (an untyped node has no menu; never a refusal)."""
    recipes = _TRANSFORM_RECIPES.get((entity_type or "").lower(), [])
    out = []
    configured_cache: dict[str, bool] = {}  # is_configured() hits SQLite for
    # keyed adapters — resolve each slug ONCE per call, not once per recipe
    # row (codex adversarial: menu polling would churn the DB otherwise).
    for slug, mode in recipes:
        adapter = _REGISTRY[slug]
        display = adapter.display_name or slug
        if mode and mode != "default":
            display = f"{display} ({mode})"
        if slug not in configured_cache:
            configured_cache[slug] = adapter.is_configured()
        out.append({"slug": slug, "mode": mode, "display": display,
                    "configured": configured_cache[slug],
                    "deterministic": slug in DETERMINISTIC_SLUGS})
    return out


def _validate_adapter(slug: str, adapter: Adapter) -> Adapter:
    """Per-lookup revalidation: import-time checking alone leaves the mutable
    registry open to post-import smuggling (codex adversarial). Cheap, runs
    on every get."""
    if not getattr(adapter, "watched_types", ()):
        raise TypeError(f"adapter {slug!r} declares no watched_types")
    unknown = set(adapter.watched_types) - TRANSFORM_TYPES
    if unknown:
        raise TypeError(f"adapter {slug!r} watches unknown types {sorted(unknown)}")
    return adapter


def get_adapter(slug: str) -> Adapter:
    if slug not in _REGISTRY:
        raise KeyError(f"unknown adapter slug: {slug}. Known: {list(_REGISTRY)}")
    return _validate_adapter(slug, _REGISTRY[slug])


def all_adapters() -> list[Adapter]:
    return list(_REGISTRY.values())


def configured_adapters() -> list[Adapter]:
    return [a for a in _REGISTRY.values() if a.is_configured()]
