"""Content-platform scrape: a YouTube/TikTok/Twitter/Instagram URL → real content.

Run: .venv/bin/python -m investigations.tests.test_social_scrape

No network — the Apify call is stubbed. Proves platform detection, actor mapping,
input shapes, the MCP tool plumbing, and the agent wiring (allowed + in the persona).
"""
from investigations.enrich import social
from investigations.enrich.apify import ACTOR_INPUT_BUILDERS
from investigations.agent import investigator, osint_mcp


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def test_detect_and_resolve():
    cases = {
        "https://www.tiktok.com/@scam_guru": ("tiktok", "clockworks/tiktok-profile-scraper", "scam_guru"),
        "https://youtube.com/@CryptoKing": ("youtube", "streamers/youtube-scraper", "https://youtube.com/@CryptoKing"),
        "https://youtu.be/abc123": ("youtube", "streamers/youtube-scraper", "https://youtu.be/abc123"),
        "https://x.com/whale_alert": ("twitter", "curious_coder/twitter-scraper", "from:whale_alert"),
        "https://twitter.com/whale_alert": ("twitter", "curious_coder/twitter-scraper", "from:whale_alert"),
        "https://www.instagram.com/influencer": ("instagram", "apify/instagram-profile-scraper", "influencer"),
    }
    for target, (plat, actor, query) in cases.items():
        r = social.resolve(target)
        _check(f"{target} → {plat}", r and r["platform"] == plat)
        _check(f"{target} → actor {actor}", r["actor"] == actor)
        _check(f"{target} → query {query!r}", r["query"] == query)


def test_bare_handle_needs_platform():
    _check("bare @handle alone → unresolved (no host to detect)",
           social.resolve("@scam_guru") is None)
    _check("bare @handle + explicit platform resolves",
           (social.resolve("@scam_guru", "tiktok") or {}).get("query") == "scam_guru")
    _check("a plain domain is not a content platform", social.resolve("evil.com") is None)


def test_actor_input_shapes():
    # The new content actors have input builders so a bare handle/URL is wrapped right.
    tt = ACTOR_INPUT_BUILDERS["clockworks/tiktok-profile-scraper"]("scam_guru")
    _check("tiktok input carries the profile", tt.get("profiles") == ["scam_guru"])
    yt = ACTOR_INPUT_BUILDERS["streamers/youtube-scraper"]("https://youtube.com/@c")
    _check("youtube input carries the start URL",
           yt.get("startUrls") == [{"url": "https://youtube.com/@c"}])
    _check("youtube input asks for subtitles (transcript)", yt.get("subtitles") is True)


def test_mcp_tool_runs_the_right_actor(mp):
    # social_scrape resolves the platform then calls the apify adapter with that actor.
    captured = {}

    class _FakeApify:
        def run(self, query, mode=None):
            captured["query"] = query
            captured["actor"] = mode
            from investigations.enrich.base import EnrichmentResult
            return [EnrichmentResult(result_type="profile", title="@scam_guru",
                                     summary="bio: send ETH to double it", confidence="medium")]

    from investigations.enrich import registry
    mp.setattr(registry, "get_adapter", lambda slug: _FakeApify() if slug == "apify" else registry.get_adapter(slug))
    out = osint_mcp.social_scrape("https://www.tiktok.com/@scam_guru")
    _check("ran the tiktok actor", captured.get("actor") == "clockworks/tiktok-profile-scraper")
    _check("passed the resolved handle", captured.get("query") == "scam_guru")
    _check("returned the scraped content (not a bare link)", "send ETH to double it" in out)
    bad = osint_mcp.social_scrape("evil.com")
    _check("non-platform target → helpful error", bad.startswith("ERROR"))


def test_wiring():
    _check("social_scrape is an allowed agent tool",
           "mcp__kipi-osint__social_scrape" in investigator.ALLOWED_TOOLS)
    _check("MCP server defines social_scrape", hasattr(osint_mcp, "social_scrape"))
    _check("per-target persona points to social_scrape", "social_scrape" in investigator.PERSONA)
    _check("case persona points to social_scrape", "social_scrape" in investigator.CASE_PERSONA)
    # Gated off when apify has no key (rides on the apify adapter).
    import investigations.agent.investigator as inv
    orig = inv._dead_slugs
    inv._dead_slugs = lambda: {"apify"}
    try:
        live = inv._live_allowed_tools()
    finally:
        inv._dead_slugs = orig
    _check("social_scrape dropped when apify has no key",
           "mcp__kipi-osint__social_scrape" not in live)


def test_case_task_surfaces_content_links():
    # End-to-end: a TikTok URL dropped as evidence → extracted as a url entity →
    # surfaced in the case task as a social_scrape target.
    import tempfile
    from pathlib import Path
    from investigations.storage import db
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx",
                                 "lead: https://www.tiktok.com/@scam_guru")
            e = db.upsert_entity(conn, "https://www.tiktok.com/@scam_guru", "url", r)
            db.add_mention(conn, e, r, "https://www.tiktok.com/@scam_guru", "c")
            conn.commit()
            links = investigator._content_platform_links(conn, "cx")
            _check("case content-link finder picks up the tiktok url",
                   any(p == "tiktok" for _, p in links))
            task = investigator._build_case_task(conn, "cx")
            _check("case task tells the agent to social_scrape the link",
                   "social_scrape" in task and "tiktok.com/@scam_guru" in task)


def main():
    test_detect_and_resolve()
    test_bare_handle_needs_platform()
    test_actor_input_shapes()
    test_case_task_surfaces_content_links()
    mp = _MP()
    try:
        test_mcp_tool_runs_the_right_actor(mp)
    finally:
        mp.undo()
    test_wiring()
    print("\nPASS: test_social_scrape")


if __name__ == "__main__":
    main()
