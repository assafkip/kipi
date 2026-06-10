"""Content-platform resolution: a profile URL / @handle on TikTok, YouTube, Twitter/X,
or Instagram → the right Apify actor + input, so the investigator pulls the ACTUAL
content (profile + recent posts + transcript), not just the bare link.

Closes the "a YouTube/TikTok URL is just a domain" gap. Deterministic mapping only —
the network call happens in the apify adapter; this module just decides which actor to
run and how to phrase the input. The agent reaches it via the `social_scrape` MCP tool.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# platform -> the Apify actor that pulls a creator's profile + recent posts.
PLATFORM_ACTORS = {
    "tiktok": "clockworks/tiktok-profile-scraper",
    "youtube": "streamers/youtube-scraper",
    "twitter": "curious_coder/twitter-scraper",
    "instagram": "apify/instagram-profile-scraper",
}


def _host(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    host = (urlparse(t).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def detect_platform(target: str) -> str | None:
    """Identify the content platform from a URL. A bare @handle has no host, so it
    returns None — pass `platform=` explicitly for those."""
    t = (target or "").strip()
    if not t or t.startswith("@"):
        return None
    host = _host(t)
    if host.endswith("tiktok.com"):
        return "tiktok"
    if host.endswith("youtube.com") or host.endswith("youtu.be"):
        return "youtube"
    if host.endswith("twitter.com") or host == "x.com" or host.endswith(".x.com"):
        return "twitter"
    if host.endswith("instagram.com"):
        return "instagram"
    return None


def extract_username(target: str, platform: str) -> str:
    """The handle from a profile URL or @handle. For tiktok/twitter/instagram the
    first path segment is the username (tiktok prefixes it with @)."""
    t = (target or "").strip()
    if t.startswith("@"):
        return t[1:].split("/")[0]
    m = re.search(r"https?://[^/]+/(@?[^/?#]+)", t if "://" in t else "https://" + t)
    if m:
        return m.group(1).lstrip("@")
    return t.lstrip("@")


def resolve(target: str, platform: str | None = None) -> dict | None:
    """Map a target to {platform, actor, query}. `query` is phrased for that actor's
    input builder (handle for tiktok/instagram, a `from:` search for twitter, the URL
    for youtube). Returns None if it isn't a recognized content platform."""
    target = (target or "").strip()
    if not target:
        return None
    platform = (platform or detect_platform(target) or "").lower() or None
    if platform not in PLATFORM_ACTORS:
        return None
    actor = PLATFORM_ACTORS[platform]
    if platform == "youtube":
        # The youtube actor takes a URL; build one from a bare @handle.
        query = target if target.startswith("http") else f"https://www.youtube.com/{target.lstrip('/')}"
    elif platform == "twitter":
        user = extract_username(target, "twitter")
        query = f"from:{user}" if user else target
    else:  # tiktok / instagram — a bare username
        query = extract_username(target, platform) or target.lstrip("@")
    return {"platform": platform, "actor": actor, "query": query}
