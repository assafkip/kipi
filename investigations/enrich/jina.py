"""Jina adapter — Reader / Search / Deepsearch.

Works KEYLESS (r.jina.ai / s.jina.ai accept anonymous calls, rate-limited); a
JINA_API_KEY raises the limits. So Jina stays usable even with no key, and a bad
key or a single blocked URL degrades gracefully instead of hard-failing the run:
a keyed 401/403/429 retries keyless, and a final failure returns a low-confidence
"couldn't read" note (one result the agent can move past) rather than an exception.
"""
from __future__ import annotations

import urllib.request
import urllib.error
import urllib.parse

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError, resolve_key


JINA_READER_BASE = "https://r.jina.ai/"
JINA_SEARCH_BASE = "https://s.jina.ai/"


def _fetch(url: str, key: str, timeout: int) -> str:
    """GET a Jina endpoint. If a key is present and the keyed call is rejected
    (401/403/429), retry once KEYLESS. Raises EnrichmentError only if both fail."""
    attempts = [key] if key else [""]
    if key:
        attempts.append("")  # keyless fallback for a bad/blocked key
    last = ""
    for k in attempts:
        headers = {"Accept": "application/json", "X-Return-Format": "markdown"}
        if k:
            headers["Authorization"] = f"Bearer {k}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code in (401, 403, 429) and k:
                continue  # keyed call rejected → try keyless
            break
        except urllib.error.URLError as exc:
            last = f"network error: {exc.reason}"
            break
    raise EnrichmentError(f"Jina {last}")


class JinaAdapter(Adapter):
    slug = "jina"
    display_name = "Jina Reader / Search"
    env_var = "JINA_API_KEY"
    category = "reader"
    cost_per_call_usd = 0.001

    def is_configured(self) -> bool:
        return True  # keyless works; a key only raises rate limits

    def modes(self) -> list[str]:
        return ["read", "search", "deepsearch"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        key = resolve_key(self.slug, self.env_var)
        m = (mode or "read").lower()
        if m == "read":
            try:
                text = _fetch(JINA_READER_BASE + query, key, timeout)
            except EnrichmentError as exc:
                # A single blocked/unreadable URL is not a run-killer — let the agent
                # fall back to the browser instead of treating Jina as broken.
                return [EnrichmentResult(
                    result_type="document", title=f"Jina reader: {query} [unavailable]",
                    summary=f"Could not read this URL via Jina ({exc}). Try the browser.",
                    url=query, confidence="low")]
            return [EnrichmentResult(
                result_type="document", title=f"Jina reader: {query}",
                summary=text[:3000], url=query, confidence="high")]
        if m == "search":
            text = _fetch(JINA_SEARCH_BASE + urllib.parse.quote(query), key, timeout)
            return [EnrichmentResult(
                result_type="answer", title=f"Jina search: {query[:80]}",
                summary=text[:3000], confidence="medium")]
        # deepsearch — endpoint differs across plans; fall back to search.
        return self.run(query, mode="search", timeout=timeout)
