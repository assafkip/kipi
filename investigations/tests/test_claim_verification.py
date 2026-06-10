"""Claim-level corroboration (replay D5): a finding/edge that asserts a HARD fact
(date / IPv4 / email / wallet) must have that fact in a real tool RESULT — the agent's
prose provenance is not a source. Verifies existence of the entity was already checked
(_attribute_findings.source_count); this adds checking the ASSERTION.

Real bug this guards (run 18, trumpstake.us): the agent claimed "registered 2025-12-22
via whois_lookup" with confidence high; NO whois result contained the date (it came from
dns_history), and step_ref pointed at a Cloudflare-IP whois. Entity-corroboration graded
it A/B and it auto-promoted. Claim-corroboration catches + re-points it.

Run: .venv/bin/python -m investigations.tests.test_claim_verification
"""
from investigations.agent import investigator as inv


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_hard_token_extraction():
    t = inv._claim_hard_tokens
    _check("ISO date", "2025-12-22" in t("registered 2025-12-22 via namecheap"))
    _check("IPv4", "104.21.42.70" in t("resolves to 104.21.42.70"))
    _check("email", "markk.bennett.2025@gmail.com" in t("contact markk.bennett.2025@gmail.com"))
    _check("eth wallet", ("0x" + "a"*40) in t("payout 0x" + "A"*40))
    _check("soft claim has no hard tokens", t("fake Trump casino impersonation") == set())


# Two tool steps: a whois on the domain that (pre-D1-fix) lacks the date, and a
# dns_history step that DOES contain it. Mirrors the real run 18 shape.
STEPS = [
    {"n": 8, "type": "tool", "tool": "whois_lookup",
     "input": "target=trumpstake.us",
     "result": "[RDAP]\nDomain: TRUMPSTAKE.US\nnameservers: cartman.ns.cloudflare.com"},
    {"n": 9, "type": "tool", "tool": "whois_lookup",
     "input": "target=172.67.202.229",
     "result": "## WHOIS/RDAP: 172.67.202.229\norganisation: Cloudflare"},
    {"n": 61, "type": "tool", "tool": "dns_history",
     "input": "trumpstake.us",
     "result": "trumpstake.us resolved here historically (2025-12-22 -> 2026-05-20)."},
]


def test_real_fact_is_repointed_not_flagged():
    """The date IS in a tool result (dns_history), just not the cited whois → corroborated,
    and step_ref is RE-POINTED to the step that actually contains it."""
    parsed = {"findings": [{
        "entity": "trumpstake.us", "entity_type": "domain",
        "claim": "registered 2025-12-22 via whois", "confidence": "high",
        "provenance": "whois_lookup: WHOIS shows recent registration"}]}
    inv._attribute_findings(parsed, STEPS)
    f = parsed["findings"][0]
    _check("claim not flagged unverified (date is in dns_history)", f.get("claim_unverified") is False)
    _check("step_ref re-pointed to the step that has the date (61)", f.get("step_ref") == 61)
    _check("step_tool corrected to dns_history", f.get("step_tool") == "dns_history")


def test_fabricated_fact_is_flagged():
    """A claim asserting a date that NO tool result contains → claim_unverified=True."""
    parsed = {"findings": [{
        "entity": "trumpstake.us", "entity_type": "domain",
        "claim": "registered 1999-01-01 by the FSB", "confidence": "high",
        "provenance": "whois_lookup: definitely real"}]}
    inv._attribute_findings(parsed, STEPS)
    f = parsed["findings"][0]
    _check("fabricated date flagged unverified", f.get("claim_unverified") is True)
    grade, _ = inv._grade_finding(f)
    _check("unverified claim graded D", grade == "D")
    may, _ = inv._promotion_gate(f)
    _check("unverified claim is NOT promoted to the graph", may is False)


def test_relationship_corroboration_flag():
    """An edge between two entities BOTH observed in tool results is corroborated; an edge
    to an entity NO tool ever returned is not."""
    parsed = {"relationships": [
        {"src": "trumpstake.us", "dst": "172.67.202.229", "rel_type": "resolves_to", "confidence": "high"},
        {"src": "trumpstake.us", "dst": "invented-by-agent.example", "rel_type": "linked_to", "confidence": "high"},
    ]}
    inv._attribute_findings(parsed, STEPS)
    _check("edge between two observed entities → corroborated", parsed["relationships"][0]["corroborated"] is True)
    _check("edge to an unobserved (invented) entity → not corroborated", parsed["relationships"][1]["corroborated"] is False)


def test_qa_citation_verification():
    """ask._verify_citations flags an answer sentence whose cited passage doesn't contain
    the hard fact it asserts; leaves a faithfully-cited one alone."""
    from investigations import ask
    passages = [
        {"text": "trumpstake.us first resolved on 2025-12-22 per passive DNS."},  # [1]
        {"text": "The site impersonates a Trump casino brand."},                  # [2]
    ]
    # sentence 1 cites [1] for a date [1] actually contains → supported
    # sentence 2 cites [2] for a date [2] does NOT contain → unsupported
    ans = "It resolved on 2025-12-22 [1]. It was registered on 2019-05-01 [2]."
    bad = ask._verify_citations(ans, passages)
    flagged = {b["sentence"] for b in bad}
    _check("faithful date citation NOT flagged", not any("2025-12-22" in s for s in flagged))
    _check("unsupported date citation IS flagged", any("2019-05-01" in s for s in flagged))
    _check("the flag names the missing fact",
           any("2019-05-01" in b["unsupported_facts"] for b in bad))


def test_full_result_beats_600char_truncation_and_is_dropped():
    """A fact past char 600 of a verbose tool result: it's in `result_full` (verification)
    but not the short `result` (display). The claim must still corroborate, and result_full
    must be dropped after attribution so it never persists."""
    padding = "x" * 900  # pushes the date out of the 600-char preview
    step = {"n": 3, "type": "tool", "tool": "whois_lookup", "input": "target=trumpstake.us",
            "result": ("registrar lines " + padding)[:600],
            "result_full": "registrar lines " + padding + " Creation Date: 2025-12-22"}
    parsed = {"findings": [{
        "entity": "trumpstake.us", "entity_type": "domain",
        "claim": "registered 2025-12-22", "confidence": "high", "provenance": "whois"}]}
    inv._attribute_findings(parsed, [step])
    f = parsed["findings"][0]
    _check("fact past char 600 found via result_full (not over-gated)", f.get("claim_unverified") is False)
    _check("step_ref points at the step that has the fact", f.get("step_ref") == 3)
    _check("result_full dropped after attribution (won't persist)", "result_full" not in step)


def test_role_evidence_check():
    """consolidate flags an actor role whose reason cites a hard fact (wallet) absent from
    the entity's mentions; leaves a grounded reason and a soft reason alone."""
    import tempfile
    from pathlib import Path
    from investigations import consolidate
    from investigations.storage import db
    wallet = "0x" + "b" * 40
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "cx", "body")
            e = db.upsert_entity(conn, "shady_promoter", "person", r)
            db.add_mention(conn, e, r, "shady_promoter", "promotes the token aggressively on telegram")
            conn.commit()

            # reason cites a wallet that is NOT in the entity's mentions → flagged
            consolidate._apply_cluster(conn, {
                "canonical_id": e, "canonical_name": "shady_promoter", "role": "operator",
                "sub_role": "promoter", "sub_role_reason": f"controls payout wallet {wallet}",
                "merge_ids": [], "reason": ""}, actor_roles={"operator"})
            got = conn.execute("SELECT sub_role_reason FROM entities WHERE id=?", (e,)).fetchone()[0]
            _check("role reason citing an absent wallet is marked UNVERIFIED", "{{UNVERIFIED" in (got or ""))

            # reason whose fact IS in the mentions → not flagged
            db.add_mention(conn, e, r, "shady_promoter", f"seen moving funds to {wallet} repeatedly")
            conn.commit()
            consolidate._apply_cluster(conn, {
                "canonical_id": e, "canonical_name": "shady_promoter", "role": "operator",
                "sub_role": "promoter", "sub_role_reason": f"controls payout wallet {wallet}",
                "merge_ids": [], "reason": ""}, actor_roles={"operator"})
            got = conn.execute("SELECT sub_role_reason FROM entities WHERE id=?", (e,)).fetchone()[0]
            _check("grounded role reason is NOT flagged", "{{UNVERIFIED" not in (got or ""))

            # soft reason (no hard token) → never flagged
            consolidate._apply_cluster(conn, {
                "canonical_id": e, "canonical_name": "shady_promoter", "role": "operator",
                "sub_role": "promoter", "sub_role_reason": "appears central to the operation",
                "merge_ids": [], "reason": ""}, actor_roles={"operator"})
            got = conn.execute("SELECT sub_role_reason FROM entities WHERE id=?", (e,)).fetchone()[0]
            _check("soft role reason is not flagged (no hard token to check)", "{{UNVERIFIED" not in (got or ""))


def main():
    test_hard_token_extraction()
    test_real_fact_is_repointed_not_flagged()
    test_fabricated_fact_is_flagged()
    test_relationship_corroboration_flag()
    test_qa_citation_verification()
    test_full_result_beats_600char_truncation_and_is_dropped()
    test_role_evidence_check()
    print("\nPASS: test_claim_verification")


if __name__ == "__main__":
    main()
