"""Dark-web search adapter — Ahmia .onion index (T3 leads, no Tor client).

Gives kipi its first dark-web surface for hacktivist + leak-market / financial-fraud
cases. Searches the Ahmia clearnet index (ahmia.fi) for a domain, org, or handle and
returns the matching `.onion` hosts as LOW-confidence leads (the deterministic promotion
gate keeps them as hypotheses, never written findings — a search hit is T3).

Keyless. Ahmia returns HTML, so onion hosts are regexed out of the page (defensive: a
blocked/empty page yields a header doc with 0 hits, never a crash). Real network failures
raise EnrichmentError.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_AHMIA = "https://ahmia.fi/search/?q="
_ONION_RE = re.compile(r"\b([a-z2-7]{16,56}\.onion)\b", re.IGNORECASE)


def _get_text(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"Ahmia HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"Ahmia network error: {exc}")


class DarkwebAdapter(Adapter):
    slug = "darkweb"
    watched_types = ("domain", "org", "handle")
    display_name = "Ahmia .onion search (T3 leads)"
    env_var = None  # keyless
    category = "search"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        q = (query or "").strip()
        if not q:
            raise EnrichmentError("darkweb: empty query")
        html = _get_text(_AHMIA + urllib.parse.quote(q), timeout)
        seen: list[str] = []
        for host in _ONION_RE.findall(html):
            h = host.lower()
            if h not in seen:
                seen.append(h)
        if not seen:
            return [EnrichmentResult(
                result_type="document",
                title=f"Ahmia: {q} — 0 onion hits",
                summary="No .onion results for this query (or Ahmia returned nothing).",
                raw_json={"query": q, "hits": [], "tier": "T3"},
                confidence="low")]
        header = EnrichmentResult(
            result_type="document",
            title=f"Ahmia: {q} — {len(seen)} onion hit(s)",
            summary=("T3 LEADS — .onion sites matching the query (hypothesis queue, not "
                     "findings):\n" + "\n".join(f"- {h}" for h in seen[:25])),
            url=f"https://ahmia.fi/search/?q={urllib.parse.quote(q)}",
            raw_json={"query": q, "hits": seen, "tier": "T3", "lead": True},
            confidence="medium")
        # Each .onion host is a LOW-confidence domain lead (gate holds it as a hypothesis).
        rows = [EnrichmentResult(
            result_type="profile", title=h,
            summary=f"Ahmia .onion hit for '{q}' (T3 lead — unverified).",
            confidence="low") for h in seen]
        return [header] + rows
