"""k4p-03 reproducer: the synthesis brief reaches 4_points report quality — Key
Judgments + per-target dossiers + A–F graded evidence — instead of a flat one-line
fact list (the 'disjointed' brief).

Deterministic: tests the SYSTEM output contract + the prompt builder (which feeds the
synthesizer per-TARGET grouped dossiers). The LLM call itself is not under test.

Run: .venv/bin/python -m investigations.tests.test_synthesis_dossiers
"""
from investigations import synthesize


def _ok(label, cond):
    assert cond, f"{label}: FAILED"
    print(f"  ok  {label}")


def test_system_requires_4points_report_shape():
    s = synthesize.SYSTEM
    _ok("SYSTEM requires Key judgments (KJ structure)", "Key judgments" in s and "KJ-1" in s)
    _ok("SYSTEM requires per-target dossiers", "Target dossiers" in s)
    _ok("SYSTEM requires A–F graded evidence", "A–F" in s and "Reliability" in s)


def _data():
    return {
        "objective": "map the trump-casino scam network",
        "active_infra": ["trumpfundus.com"], "dead_infra": [],
        "reports": [{"title": "Seed", "ingested_at": "2026-06-08", "source_path": "s.md"}],
        "hubs_by_role": {},
        "assessments": [{"attributed_actor": "Markk Bennett", "overall_confidence": "medium",
                         "best_judgment": "operator of the trump scam cluster"}],
        "agent_findings": [
            {"title": "trumpfundus.com", "summary": "Solana drainer, VT malicious", "confidence": "high"},
            {"title": "trumpfundus.com", "summary": "Cloudflare-masked origin", "confidence": "medium"},
            {"title": "trumpstake.us", "summary": "registrant Markk Bennett via WHOIS", "confidence": "high"},
        ],
        "agent_leads": [],
        "dossiers": {},
    }


def test_prompt_feeds_per_target_dossiers():
    prompt = synthesize._build_prompt(_data())
    _ok("prompt emits a per-target dossier section", "WORKED TARGET DOSSIERS" in prompt)
    _ok("dossier grouped for target trumpfundus.com", "DOSSIER: trumpfundus.com" in prompt)
    _ok("dossier grouped for target trumpstake.us", "DOSSIER: trumpstake.us" in prompt)
    # The two findings on trumpfundus.com are grouped UNDER its dossier, not scattered.
    fundus = prompt.split("DOSSIER: trumpfundus.com")[1].split("DOSSIER:")[0]
    _ok("a target's findings are grouped under its dossier (>=2 lines)",
        fundus.count("- [") >= 2)
    _ok("findings keep their confidence (basis for A–F grading)", "[high]" in prompt)


def test_no_silent_truncation():
    """Codex k4p-03 regression: overflow must be announced, not dropped silently."""
    d = _data()
    d["agent_findings"] = [{"title": "busy.com", "summary": f"finding {i}", "confidence": "high"}
                           for i in range(30)]
    prompt = synthesize._build_prompt(d)
    _ok("a >20-finding target announces the omitted count (no silent cap)",
        "more finding(s) on this target omitted" in prompt)


if __name__ == "__main__":
    test_system_requires_4points_report_shape()
    test_prompt_feeds_per_target_dossiers()
    test_no_silent_truncation()
    print("\nall green")
