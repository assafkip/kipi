"""The brief leads with the ACTIVE threat, not the dead seed.

Run: .venv/bin/python -m investigations.tests.test_brief_prioritization

Fixes the report burying the live Contabo scam under the dormant PDR tier just because
the dormant one had more findings.
"""
from investigations import synthesize


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_operational_status_split():
    findings = [
        {"title": "trump-2026.io", "summary": "[domain] no DNS records, currently down"},
        {"title": "gettrump.co", "summary": "[domain] resolves, hosted on Contabo, operating"},
        {"title": "streetplug.me", "summary": "[domain] live, active scam page reachable"},
        {"title": "167.86.67.26", "summary": "[ip] hosting three live scam domains"},
        {"title": "PDR Ltd", "summary": "registrar, not a host"},  # not host-ish → ignored
    ]
    active, dead = synthesize._operational_status(findings)
    _check("live domains detected", set(active) >= {"gettrump.co", "streetplug.me", "167.86.67.26"})
    _check("dead domain detected", "trump-2026.io" in dead)
    _check("dead one NOT marked live", "trump-2026.io" not in active)
    _check("non-host (registrar) ignored", "pdr ltd" not in active and "pdr ltd" not in dead)


def test_dead_cue_wins_conflict():
    findings = [{"title": "x.io", "summary": "was live last month but now down, no DNS, dead"}]
    active, dead = synthesize._operational_status(findings)
    _check("conflicting cues → dead wins (don't headline a dead site)",
           "x.io" in dead and "x.io" not in active)


def test_prompt_surfaces_active_as_headline():
    data = {"reports": [], "hubs_by_role": {}, "dossiers": {},
            "active_infra": ["gettrump.co", "streetplug.me"], "dead_infra": ["trump-2026.io"]}
    p = synthesize._build_prompt(data)
    _check("prompt shows the LIVE block", "LIVE / OPERATING NOW: gettrump.co" in p)
    _check("prompt shows the DEAD block", "DEAD / DORMANT: trump-2026.io" in p)
    _check("prompt orders the active tier as the headline", "HEADLINE" in p)


def test_no_status_block_when_empty():
    p = synthesize._build_prompt({"reports": [], "hubs_by_role": {}, "dossiers": {}})
    _check("no operational-status block when there's no infra", "OPERATIONAL STATUS" not in p)


def test_system_prompt_has_urgency_rule():
    s = synthesize.SYSTEM
    _check("SYSTEM prioritizes by operational urgency", "OPERATIONAL URGENCY" in s)
    _check("SYSTEM says lead with what's live", "LIVE and operating NOW" in s)
    _check("SYSTEM says dead infra is context, not the lede",
           "never\n  the lede" in s or "never the lede" in s or "is CONTEXT" in s)


def main():
    test_operational_status_split()
    test_dead_cue_wins_conflict()
    test_prompt_surfaces_active_as_headline()
    test_no_status_block_when_empty()
    test_system_prompt_has_urgency_rule()
    print("\nPASS: test_brief_prioritization")


if __name__ == "__main__":
    main()
