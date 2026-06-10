"""Apify adapter — run any of 55+ ready-made actors.

Mode is the actor slug (`apify/web-scraper`, `nasta/linkedin-profile-scraper`, etc.).
The query passed in is JSON-encoded actor input — or just a URL / handle that
the adapter wraps in the actor's expected input shape.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
import time

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError


APIFY_API_BASE = "https://api.apify.com/v2"


# Common-case input shapes for a few high-value actors. If the user passes a
# bare URL/handle, we wrap it in the actor's expected shape. If they pass
# raw JSON (starts with {), we use it as-is.
ACTOR_INPUT_BUILDERS = {
    "apify/web-scraper": lambda q: {"startUrls": [{"url": q}], "globs": [{"glob": q}]},
    "apify/website-content-crawler": lambda q: {"startUrls": [{"url": q}], "maxCrawlPages": 5},
    "apify/google-search-scraper": lambda q: {"queries": q, "maxPagesPerQuery": 1, "resultsPerPage": 10},
    "apify/instagram-profile-scraper": lambda q: {"usernames": [q.lstrip("@")]},
    "apify/twitter-scraper-lite": lambda q: {"searchTerms": [q], "maxItems": 20},
    "curious_coder/twitter-scraper": lambda q: {"searchTerms": [q], "maxItems": 20},
    "nasta/linkedin-profile-scraper": lambda q: {"urls": [q] if q.startswith("http") else [f"https://www.linkedin.com/in/{q}"]},
    # Content platforms (resolved by enrich.social): pull profile + recent posts.
    "clockworks/tiktok-profile-scraper": lambda q: {
        "profiles": [q.lstrip("@")], "resultsPerPage": 10,
        "shouldDownloadVideos": False, "shouldDownloadCovers": False},
    "streamers/youtube-scraper": lambda q: {
        "startUrls": [{"url": q}], "maxResults": 10, "maxResultsShorts": 5,
        "subtitles": True},   # subtitles=transcript, the richest creator signal
}


class ApifyAdapter(Adapter):
    slug = "apify"
    display_name = "Apify Actors (LinkedIn, IG, Telegram, Twitter, Google Maps, +50)"
    env_var = "APIFY_TOKEN"  # Apify's documented standard; matches project .mcp.json
    category = "scrape"
    cost_per_call_usd = 0.10  # rough estimate, varies wildly per actor

    def modes(self) -> list[str]:
        # Surface the 5 most common; user can supply any actor id as the mode
        return list(ACTOR_INPUT_BUILDERS.keys())[:5] + ["other-actor"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 180) -> list[EnrichmentResult]:
        token = self.get_key()
        actor = mode or "apify/web-scraper"
        # Build actor input
        if query.lstrip().startswith("{"):
            try:
                actor_input = json.loads(query)
            except json.JSONDecodeError as exc:
                raise EnrichmentError(f"Apify: query looks like JSON but failed to parse: {exc}")
        elif actor in ACTOR_INPUT_BUILDERS:
            actor_input = ACTOR_INPUT_BUILDERS[actor](query)
        else:
            # Unknown actor — wrap query as bare {"input": query}; user can pass raw JSON instead
            actor_input = {"input": query}

        # Start a synchronous actor run (timeout fits in our 180s budget)
        actor_safe = actor.replace("/", "~")
        url = f"{APIFY_API_BASE}/acts/{actor_safe}/run-sync-get-dataset-items?token={token}&timeout=120"
        body = json.dumps(actor_input).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read().decode("utf-8")
                items = json.loads(payload) if payload.strip() else []
        except urllib.error.HTTPError as exc:
            raise EnrichmentError(f"Apify HTTP {exc.code} on actor {actor}: {exc.read().decode('utf-8', errors='replace')[:300]}")
        except urllib.error.URLError as exc:
            raise EnrichmentError(f"Apify network error on actor {actor}: {exc}")

        results = []
        for item in items[:25] if isinstance(items, list) else []:
            title = (
                item.get("title") or item.get("name") or item.get("username")
                or item.get("url") or item.get("text", "")[:80] or actor
            )
            summary = (
                item.get("description") or item.get("bio") or item.get("text")
                or json.dumps(item)[:500]
            )
            results.append(EnrichmentResult(
                result_type="profile" if "username" in item else "document",
                title=str(title)[:200],
                summary=str(summary)[:600],
                url=item.get("url") or item.get("link"),
                raw_json=item,
                confidence="medium",
            ))
        return results
