"""The investigator agent is allowed every configured MCP tool it needs.

Run: .venv/bin/python -m investigations.tests.test_agent_tool_coverage

Closes the gap where the agent recommended Playwright (to render JS scam pages) but
wasn't allowed to use it. Asserts the .mcp.json servers (playwright/reddit/apify) are
in the allowlist, the dangerous browser tools are NOT, the persona tells the agent to
render JS pages, and keyless tools survive when a keyed provider is missing.
"""
from investigations.agent import investigator


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_browser_tools_allowed():
    allow = set(investigator.ALLOWED_TOOLS)
    for t in ("browser_navigate", "browser_snapshot", "browser_evaluate",
              "browser_wait_for", "browser_take_screenshot", "browser_network_requests",
              "browser_click"):
        _check(f"playwright {t} allowed", f"mcp__playwright__{t}" in allow)


def test_dangerous_browser_tools_excluded():
    allow = set(investigator.ALLOWED_TOOLS)
    for t in ("browser_run_code_unsafe", "browser_file_upload"):
        _check(f"{t} NOT allowed (host-code / upload risk)",
               f"mcp__playwright__{t}" not in allow)


def test_reddit_and_apify_read_tools_allowed():
    allow = set(investigator.ALLOWED_TOOLS)
    for t in ("reddit_get_user_posts", "reddit_get_post", "reddit_get_subreddit_posts",
              "reddit_search_subreddit"):
        _check(f"reddit {t} allowed", f"mcp__reddit__{t}" in allow)
    for t in ("get-actor-output", "get-actor-run", "curious_coder-slash-twitter-scraper"):
        _check(f"apify {t} allowed", f"mcp__apify__{t}" in allow)


def test_persona_says_render_js():
    for name, p in (("per-target", investigator.PERSONA), ("case", investigator.CASE_PERSONA)):
        _check(f"{name} persona drives the browser on JS pages", "browser_navigate" in p)
    _check("case persona says don't stop at 'JS constraint'",
           "JS constraint" in investigator.CASE_PERSONA or "render it" in investigator.CASE_PERSONA)


def test_keyless_tools_survive_dead_keyed_provider():
    orig = investigator._dead_slugs
    investigator._dead_slugs = lambda: {"apify", "perplexity"}
    try:
        live = investigator._live_allowed_tools()
    finally:
        investigator._dead_slugs = orig
    _check("apify tools dropped when apify has no key",
           not any("apify" in t for t in live))
    _check("perplexity tool dropped when no key",
           "mcp__perplexity__perplexity_ask" not in live)
    _check("playwright (keyless) survives", sum(1 for t in live if "playwright" in t) == 13)
    _check("reddit (keyless) survives", sum(1 for t in live if "reddit" in t) == 6)


def main():
    test_browser_tools_allowed()
    test_dangerous_browser_tools_excluded()
    test_reddit_and_apify_read_tools_allowed()
    test_persona_says_render_js()
    test_keyless_tools_survive_dead_keyed_provider()
    print("\nPASS: test_agent_tool_coverage")


if __name__ == "__main__":
    main()
