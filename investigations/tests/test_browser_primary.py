"""4pa-06 — browser is a PRIMARY forensics move on JS-heavy scam pages.

The old persona framed the headless browser as an EXPENSIVE last resort ("only
when jina/WebFetch fails"), so the agent missed the wallet/payment/affiliate
endpoints injected by client-side JS (the 4_points script.js depth). This asserts
the persona now promotes browser_network_requests + browser_evaluate as a primary
move, not a fallback.

Run: .venv/bin/python -m investigations.tests.test_browser_primary
"""
import investigations.agent.investigator as inv


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _personas() -> list[tuple[str, str]]:
    return [
        ("per-target persona", inv._build_persona().lower()),
        ("case persona", inv.CASE_PERSONA.lower()),
        ("crew page role", next(r["job"] for r in inv.ROLE_AGENTS if r["role"] == "page").lower()),
    ]


def test_browser_named_as_primary():
    for name, text in _personas():
        _check(f"{name} names browser_network_requests", "browser_network_requests" in text)
        _check(f"{name} names browser_evaluate", "browser_evaluate" in text)
        _check(f"{name} frames the browser as primary, not last-resort",
               "primary" in text)


def test_no_browser_last_resort_framing():
    # The specific old anti-pattern strings must be gone.
    for name, text in _personas():
        _check(f"{name} dropped 'expensive fallback' framing",
               "expensive fallback" not in text and "browser is the expensive" not in text)


def main():
    test_browser_named_as_primary()
    test_no_browser_last_resort_framing()
    print("PASS test_browser_primary: every persona promotes browser_network_requests + "
          "browser_evaluate as a primary move on JS-heavy scam pages")


if __name__ == "__main__":
    main()
