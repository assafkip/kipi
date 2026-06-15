"""Base classes for OSINT enrichment adapters.

Every adapter inherits from `Adapter` and implements `run(query, mode)`.
Returns a list of `EnrichmentResult` so the storage + display layer can
treat all providers uniformly.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def resolve_key(slug: str, env_var: str | None) -> str:
    """Resolve a provider API key: locally-stored DB key first, env var fallback.

    The DB key is set via the Enrich UI and persisted in the (gitignored) SQLite
    file. Falls back to the environment variable so existing env-based setups
    keep working. Returns "" when neither is set.
    """
    # Local import: db must not be imported at adapter module-load time.
    from investigations.storage import db

    if slug:
        try:
            with db.connect(migrate=False) as conn:
                row = conn.execute(
                    "SELECT api_key FROM osint_providers WHERE slug = ?", (slug,)
                ).fetchone()
            if row and row["api_key"] and row["api_key"].strip():
                return row["api_key"].strip()
        except Exception:
            pass  # DB unavailable / column missing → fall through to env var
    if env_var:
        return os.environ.get(env_var, "").strip()
    return ""


def key_source(slug: str, env_var: str | None) -> str:
    """Where the active key comes from: 'db', 'env', or 'none'. Never the key."""
    from investigations.storage import db
    if slug:
        try:
            with db.connect(migrate=False) as conn:
                row = conn.execute(
                    "SELECT api_key FROM osint_providers WHERE slug = ?", (slug,)
                ).fetchone()
            if row and row["api_key"] and row["api_key"].strip():
                return "db"
        except Exception:
            pass
    if env_var and os.environ.get(env_var, "").strip():
        return "env"
    return "none"


class EnrichmentError(RuntimeError):
    """Raised by adapter run() when a provider call fails."""


class NotConfiguredError(EnrichmentError):
    """Raised when the adapter's required env var is unset."""


@dataclass
class EnrichmentResult:
    """One result item from an enrichment run.

    Normalized so the UI can render Perplexity citations, Tavily search hits,
    Apify scraped profiles, Jina extracted pages — all the same way.
    """
    result_type: str             # 'answer' | 'url' | 'profile' | 'channel' | 'document' | 'tweet'
    title: str
    summary: str
    url: str | None = None
    raw_json: dict | None = None
    confidence: str = "medium"   # 'high' | 'medium' | 'low'


class Adapter:
    """Base adapter contract. Subclasses set class attrs + implement run()."""

    slug: str = ""
    display_name: str = ""
    env_var: str | None = None
    category: str = "search"
    cost_per_call_usd: float | None = None
    # The entity types this adapter can act on (the Maltego input-entity
    # filter). MUST be a non-empty subset of registry.TRANSFORM_TYPES — the
    # registry validates at import, so an undeclared adapter is structurally
    # uncallable (sp2-watched-types-registry).
    watched_types: tuple = ()

    def is_configured(self) -> bool:
        """True iff a key is available — locally-stored DB key or env var."""
        if not self.env_var:
            return True  # No key required (rare — most adapters need one)
        return bool(resolve_key(self.slug, self.env_var))

    def get_key(self) -> str:
        """Fetch the API key (DB first, env fallback); raise if missing."""
        key = resolve_key(self.slug, self.env_var)
        if not key:
            raise NotConfiguredError(
                f"{self.display_name} not configured — add a key on the Enrich "
                f"page or set ${self.env_var}"
            )
        return key

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        """Execute the enrichment query. Subclasses MUST override."""
        raise NotImplementedError(f"{self.slug}: run() not implemented")

    def modes(self) -> list[str]:
        """Available provider-specific subcommands (e.g. ['search', 'deep'])."""
        return ["default"]
