"""Agent step tracking: real steps are extracted from the stream-json event log,
and each finding is attributed to the step that produced it.

Run: .venv/bin/python -m investigations.tests.test_step_tracking
"""
from investigations.agent import investigator


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


# A synthetic stream-json event log: two tool calls (dns + crtsh) with results,
# one reasoning block, plus the noise (system/init) the real CLI emits.
EVENTS = [
    {"type": "system", "subtype": "hook"},
    {"type": "assistant", "message": {"content": [
        {"type": "text", "text": "Starting with DNS on the domain."},
        {"type": "tool_use", "id": "t1", "name": "mcp__kipi-osint__dns_lookup",
         "input": {"domain": "evil.com"}},
    ]}},
    {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t1",
         "content": [{"type": "text", "text": "A 9.9.9.9; NS ns1.evil.com"}]},
    ]}},
    {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "t2", "name": "mcp__kipi-osint__crtsh_subdomains",
         "input": {"domain": "evil.com"}},
    ]}},
    {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t2",
         "content": "found sub.evil.com"},
    ]}},
    {"type": "result", "result": "done", "num_turns": 4, "total_cost_usd": 0.05},
]


def test_extract_steps():
    steps = investigator._extract_steps(EVENTS)
    tool_steps = [s for s in steps if s["type"] == "tool"]
    reasoning = [s for s in steps if s["type"] == "reasoning"]
    _check("3 steps total (1 reasoning + 2 tools)", len(steps) == 3)
    _check("one reasoning step", len(reasoning) == 1)
    _check("two tool steps", len(tool_steps) == 2)
    _check("step numbers are 1..3 in order", [s["n"] for s in steps] == [1, 2, 3])
    _check("dns tool shortened", tool_steps[0]["tool"] == "dns_lookup")
    _check("dns input captured", "evil.com" in tool_steps[0]["input"])
    _check("dns result joined by tool_use_id", "9.9.9.9" in (tool_steps[0]["result"] or ""))
    _check("crtsh result joined", "sub.evil.com" in (tool_steps[1]["result"] or ""))


def test_attribute_findings():
    steps = investigator._extract_steps(EVENTS)
    parsed = {"findings": [
        # provenance points at dns, and the IP shows up in the dns result -> step 2.
        {"entity": "9.9.9.9", "entity_type": "ip", "claim": "resolves",
         "confidence": "high", "provenance": "dns: evil.com", "unvalidated": False},
        # crtsh subdomain -> step 3.
        {"entity": "sub.evil.com", "entity_type": "subdomain", "claim": "CT",
         "confidence": "medium", "provenance": "crtsh: evil.com", "unvalidated": False},
        # nothing the agent actually did -> no attribution (stays None, honest).
        {"entity": "ghost.example", "entity_type": "domain", "claim": "guess",
         "confidence": "low", "provenance": "intuition", "unvalidated": True},
    ]}
    investigator._attribute_findings(parsed, steps)
    f = parsed["findings"]
    _check("dns finding attributed to the dns tool step", f[0]["step_ref"] == 2)
    _check("dns finding step_tool is dns_lookup", f[0]["step_tool"] == "dns_lookup")
    _check("crtsh finding attributed to the crtsh step", f[1]["step_ref"] == 3)
    _check("crtsh finding step_tool is crtsh_subdomains", f[1]["step_tool"] == "crtsh_subdomains")
    _check("unbacked finding has no step_ref", f[2]["step_ref"] is None)


def test_build_process_carries_steps():
    steps = investigator._extract_steps(EVENTS)
    parsed = {"findings": [], "summary": "wrap"}
    proc = investigator._build_process(parsed, "narration text", {"num_turns": 4,
                                       "total_cost_usd": 0.05}, False, steps)
    _check("process carries the real steps", proc["steps"] == steps)
    _check("tools_used derived from real tool calls",
           proc["tools_used"] == ["dns_lookup", "crtsh_subdomains"])
    _check("turns + cost passed through", proc["turns"] == 4 and proc["cost_usd"] == 0.05)


def test_salvage_last_assistant_text():
    # No 'result' event (capped run) -> salvage the last assistant text.
    capped = EVENTS[:4]  # drops the final result event
    _check("salvages last assistant text", investigator._last_assistant_text(capped) != "")


if __name__ == "__main__":
    test_extract_steps()
    test_attribute_findings()
    test_build_process_carries_steps()
    test_salvage_last_assistant_text()
    print("\nPASS: test_step_tracking")
