"""PRD-04: the agent must DO the pivots it can (open-source), and only recommend the
ones it genuinely can't. Tests the deterministic pivot classifier.

Run: .venv/bin/python -m investigations.tests.test_pivots
"""
from investigations.agent import pivots


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_osint_pivot_is_actionable():
    p = pivots.classify_pivot({"entity": "evil-doubler.io",
                               "why": "run whois + DNS to find the registrant"})
    _check("OSINT-able domain pivot → actionable now", p["actionable_now"] is True)
    _check("no blocker reason", p["reason"] == "")


def test_subpoena_pivot_is_blocked():
    p = pivots.classify_pivot({"entity": "0xWALLET",
                               "why": "subpoena the exchange for the KYC identity"})
    _check("subpoena pivot → not actionable", p["actionable_now"] is False)
    _check("reason names legal process", "legal" in p["reason"])


def test_internal_data_pivot_is_blocked():
    p = pivots.classify_pivot({"entity": "user123",
                               "why": "pull the platform's internal access logs"})
    _check("internal-data pivot → blocked", p["actionable_now"] is False)
    _check("reason names internal/first-party", "internal" in p["reason"])


def test_missing_key_pivot_is_blocked_when_tool_not_configured():
    p = pivots.classify_pivot({"entity": "1.2.3.4", "why": "check it on virustotal"},
                              configured_tools=set())
    _check("missing-key pivot → blocked", p["actionable_now"] is False)
    _check("reason names the key", "virustotal" in p["reason"])


def test_missing_key_pivot_is_actionable_when_tool_configured():
    p = pivots.classify_pivot({"entity": "1.2.3.4", "why": "check it on virustotal"},
                              configured_tools={"virustotal"})
    _check("configured-key pivot → actionable", p["actionable_now"] is True)


def test_no_entity_is_not_actionable():
    p = pivots.classify_pivot({"entity": "", "why": "keep digging somewhere"})
    _check("no concrete target → not actionable", p["actionable_now"] is False)


def test_classify_all_splits_and_filters_junk():
    out = pivots.classify_all([
        {"entity": "a.com", "why": "dns"},
        {"entity": "b", "why": "subpoena the registrar"},
        "not-a-dict",
    ])
    _check("non-dicts dropped", len(out) == 2)
    _check("split correct", [o["actionable_now"] for o in out] == [True, False])


def main():
    test_osint_pivot_is_actionable()
    test_subpoena_pivot_is_blocked()
    test_internal_data_pivot_is_blocked()
    test_missing_key_pivot_is_blocked_when_tool_not_configured()
    test_missing_key_pivot_is_actionable_when_tool_configured()
    test_no_entity_is_not_actionable()
    test_classify_all_splits_and_filters_junk()
    print("\nPASS: test_pivots")


if __name__ == "__main__":
    main()
