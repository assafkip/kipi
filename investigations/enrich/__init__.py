"""OSINT enrichment module.

Adapters wrap each external provider (Perplexity, Tavily, Exa, Apify, Jina)
in a normalized interface so the webapp + CLI can call any tool the same way.
See investigations/enrich/base.py for the contract.
"""
from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError
from investigations.enrich.registry import get_adapter, all_adapters, configured_adapters

__all__ = [
    "Adapter", "EnrichmentResult", "EnrichmentError",
    "get_adapter", "all_adapters", "configured_adapters",
]
