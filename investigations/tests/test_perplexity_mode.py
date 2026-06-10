"""Deterministic perplexity model escalation (D2, replay-4points-case031).

The agent's web_search was hard-locked to the cheap `sonar` model, which whiffed on
network/attribution research. `_perplexity_mode` escalates to `reasoning` for those
queries deterministically (no model judgment), keeping `sonar` for simple lookups.

Run: .venv/bin/python -m investigations.tests.test_perplexity_mode
"""
from investigations.agent.osint_mcp import _perplexity_mode


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} -> {want!r}")


def test_attribution_queries_escalate():
    # the exact 4_points-style query that sonar failed on
    q = ("Crypto scam sites trumpstake.us and trumpfundus.com use /trumpColorDSGN/ "
         "and /muskColorDSGN/ - a multi-celebrity scam kit. What other domains belong "
         "to this network? Any Russian infrastructure nexus?")
    _check("kit+network+russian", _perplexity_mode(q), "reasoning")
    _check("who is behind", _perplexity_mode("who is behind trumpstake.us"), "reasoning")
    _check("two domains", _perplexity_mode("compare muskrise.io and trumpstake.us"), "reasoning")
    _check("registrar pivot", _perplexity_mode("what domains share this registrar"), "reasoning")


def test_simple_lookups_stay_cheap():
    _check("single what-is", _perplexity_mode("What is trumpfundus.com? Scam site?"), None)
    _check("plain question", _perplexity_mode("is this address a known scam"), None)
    _check("empty", _perplexity_mode(""), None)


def main():
    test_attribution_queries_escalate()
    test_simple_lookups_stay_cheap()
    print("\nPASS: test_perplexity_mode")


if __name__ == "__main__":
    main()
