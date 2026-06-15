"""Live-run visibility: the chat step trail + provisional-node overlay are fed by
_step_entities / _decorate_step, which mine each TOOL step's input+result with the
same deterministic extract_all() the ingest path uses.

Run: .venv/bin/python3 -m investigations.tests.test_step_visibility
 or: .venv/bin/python3 -m pytest investigations/tests/test_step_visibility.py -q

These are the OFFLINE acceptance criteria. The live behavior (SSE timing, result
re-emit, nodes popping onto the canvas) is proven by a real warm dig after restart —
offline fakes can't reproduce stream timing (see memory: warm-path-needs-live-smoke).
"""
from investigations.webapp.app import _step_entities, _decorate_step, _step_discovery

# 40 hex chars → an 0x ETH wallet the extractor recognizes.
_WALLET = "0x" + "a" * 40


def test_tool_step_extracts_domain_and_wallet():
    step = {"type": "tool", "tool": "virustotal", "input": "trumpfundus.com",
            "result": f"siblings: promo.net giveaway.org wallet {_WALLET}"}
    vals = {e["value"] for e in _step_entities(step)}
    assert "trumpfundus.com" in vals      # from input
    assert "promo.net" in vals            # from result
    assert "giveaway.org" in vals
    assert any(v.startswith("0x") for v in vals)  # wallet from result


def test_non_tool_steps_yield_nothing():
    # Reasoning narration mentions a domain but must not pollute the overlay.
    assert _step_entities({"type": "reasoning", "text": "checking trumpfundus.com"}) == []
    assert _step_entities({"type": "redirect", "text": "also look at promo.net"}) == []


def test_empty_input_and_result_is_empty():
    assert _step_entities({"type": "tool", "tool": "bash", "input": "", "result": None}) == []


def test_entities_are_deduped():
    step = {"type": "tool", "tool": "dns", "input": "promo.net",
            "result": "promo.net promo.net resolves to 1.2.3.4"}
    ents = _step_entities(step)
    domains = [e for e in ents if e["value"] == "promo.net"]
    assert len(domains) == 1


def test_entities_capped_at_25():
    many = " ".join(f"site{i}.com" for i in range(60))
    ents = _step_entities({"type": "tool", "tool": "x", "input": "", "result": many})
    assert len(ents) <= 25


def test_decorate_step_attaches_entities_and_preserves_fields():
    d = _decorate_step({"type": "tool", "tool": "dns", "input": "x.com",
                        "result": None, "seq": 7})
    assert d["seq"] == 7 and d["tool"] == "dns"          # original fields kept
    assert "entities" in d
    assert any(e["value"] == "x.com" for e in d["entities"])


def test_result_only_arrives_after_fill():
    # Before the tool returns, only the input entity is known; the result entities show
    # once warm_session fills `result` in place (that's why the SSE re-emits on fill).
    before = {"type": "tool", "tool": "whois", "input": "promo.net", "result": None}
    after = {**before, "result": "registrant also owns giveaway.org"}
    assert {e["value"] for e in _step_entities(before)} == {"promo.net"}
    assert "giveaway.org" in {e["value"] for e in _step_entities(after)}


def test_discovery_splits_anchor_from_found():
    # crtsh on trumpfundus.com surfaces sibling domains: anchor = the looked-up domain,
    # found = the siblings (anchor excluded), so the overlay can draw anchor→found edges.
    step = {"type": "tool", "tool": "bash",
            "input": "./invctl osint-tool crtsh trumpfundus.com",
            "result": "hostnames: trumpfundus.com promo.net giveaway.org"}
    d = _step_discovery(step)
    assert d["anchor"]["value"] == "trumpfundus.com"
    found = {e["value"] for e in d["found"]}
    assert "promo.net" in found and "giveaway.org" in found
    assert "trumpfundus.com" not in found        # anchor never duplicated into found


def test_discovery_no_anchor_when_input_has_no_entity():
    d = _step_discovery({"type": "tool", "tool": "x", "input": "list all",
                         "result": "found evil.xyz"})
    assert d["anchor"] is None
    assert {e["value"] for e in d["found"]} == {"evil.xyz"}


def test_live_dig_drops_person_candidate_narration():
    # The live dig runs over TOOL NARRATION, where the proper-name regex matches UI/HTTP
    # boilerplate ("Page Title", "Not Found") as person_candidate. The graph excludes that
    # type from display, so the writer must not draw edges to it (trump-demo phantom edges).
    step = {"type": "tool", "tool": "playwright",
            "input": "navigate https://trumpfundus.com/api/mammoth/auth/check",
            "result": "Ran Playwright. Page Title: Not Found. Found wallet 0x" + "ab"*20}
    d = _step_discovery(step)
    found = {e["value"] for e in d["found"]}
    assert "Ran Playwright" not in found and "Page Title" not in found and "Not Found" not in found
    assert any(v.startswith("0x") for v in found)   # the real wallet still lands


def test_decorate_step_carries_discovery():
    d = _decorate_step({"type": "tool", "tool": "whois", "input": "promo.net",
                        "result": "registrant also owns giveaway.org"})
    assert d["discovery"]["anchor"]["value"] == "promo.net"
    assert any(e["value"] == "giveaway.org" for e in d["discovery"]["found"])


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run()
