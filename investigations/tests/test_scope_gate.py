"""Deterministic scope gate (RULE-112, leads-first): the agent may investigate targets in
the case roster; a newly-surfaced target is denied (→ lead), so the agent can't autonomously
chase the network. Code, not a prompt.

Run: .venv/bin/python -m investigations.tests.test_scope_gate
"""
from investigations.agent import scope

ROSTER = scope.normalize_roster(
    ["trumpstake.us", "trumpfundus.com", "https://trumpstake.us/", "193.23.209.17",
     "support@trumpstake.us"])


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_in_roster_allowed():
    a, _ = scope.gate("mcp__kipi-osint__whois_lookup", {"target": "trumpstake.us"}, ROSTER)
    _check("whois on a roster domain → allowed", a is True)
    a, _ = scope.gate("mcp__kipi-osint__dns_lookup", {"target": "www.trumpstake.us"}, ROSTER)
    _check("www.<roster domain> → allowed (subdomain)", a is True)
    a, _ = scope.gate("mcp__playwright__browser_navigate", {"url": "https://trumpfundus.com/claim"}, ROSTER)
    _check("browser on a roster domain (with path) → allowed", a is True)
    a, _ = scope.gate("Bash", {"command": "./invctl osint-tool infra 193.23.209.17"}, ROSTER)
    _check("belt infra on a roster IP → allowed", a is True)


def test_out_of_roster_denied():
    a, why = scope.gate("mcp__kipi-osint__whois_lookup", {"target": "gambler-panel.com"}, ROSTER)
    _check("whois on a NEW domain → denied", a is False)
    _check("denial says lead + names the target", "lead" in why.lower() and "gambler-panel.com" in why)
    a, _ = scope.gate("mcp__playwright__browser_navigate", {"url": "https://solvoucher.com"}, ROSTER)
    _check("browser on a NEW domain → denied", a is False)
    a, _ = scope.gate("Bash", {"command": "./invctl osint-tool whois stakeus-hq.com 2>&1 | head"}, ROSTER)
    _check("belt whois on a NEW domain → denied", a is False)


def test_search_enumeration_bounded():
    # search NAMING an out-of-scope domain = enumerating the network → deny (4_points [066])
    a, why = scope.gate("Bash", {"command": "./invctl osint-tool perplexity \"stakekronx.us crypto scam canada\""}, ROSTER)
    _check("search naming an out-of-scope domain → denied (enumeration)", a is False and "lead" in why.lower())
    a, _ = scope.gate("mcp__perplexity__perplexity_ask", {"query": "muskrise.io operator attribution"}, ROSTER)
    _check("MCP search naming a new domain → denied", a is False)


def test_search_attribution_and_general_allowed():
    # search ABOUT an in-scope domain = attribution → allow (4_points [058]/[059])
    a, _ = scope.gate("Bash", {"command": "./invctl osint-tool perplexity \"trumpstake.us scam kit operator\""}, ROSTER)
    _check("search about an in-scope domain → allowed (attribution)", a is True)
    a, _ = scope.gate("mcp__kipi-osint__web_search", {"query": "Solana drainer methodology airdrop fraud"}, ROSTER)
    _check("general search naming no domain → allowed", a is True)


def test_enumeration_is_always_a_lead():
    # reverse_whois / dns_history EXPAND the network → always a lead, even on an in-roster
    # entity. The deny message must name the real ENTITY, not the mode word (follow-up #1).
    a, why = scope.gate("mcp__kipi-osint__reverse_whois", {"registrant": "support@trumpstake.us"}, ROSTER)
    _check("MCP reverse_whois (in-roster registrant) → denied as enumeration", a is False)
    _check("message names the registrant entity + says lead",
           "support@trumpstake.us" in why and "lead" in why.lower())
    a, _ = scope.gate("mcp__kipi-osint__dns_history", {"domain": "trumpstake.us"}, ROSTER)
    _check("MCP dns_history (in-roster domain) → denied as enumeration", a is False)
    # belt forms: all three argument orders extract the email, never the mode keyword
    for cmd in ("./invctl osint-tool whoisxml support@trumpstake.us --mode reverse_whois",
                "./invctl osint-tool whoisxml --mode reverse_whois support@trumpstake.us",
                "./invctl osint-tool whoisxml reverse_whois support@trumpstake.us"):
        a, why = scope.gate("Bash", {"command": cmd}, ROSTER)
        _check(f"belt whoisxml denied + names the email: {cmd[20:50]}…",
               a is False and "support@trumpstake.us" in why)


def test_reverse_dns_ip_address_key_is_read():
    # reverse_dns's input key is `ip_address` (not `ip`) — it used to slip the gate (#2)
    a, _ = scope.gate("mcp__kipi-osint__reverse_dns", {"ip_address": "193.23.209.17"}, ROSTER)
    _check("reverse_dns on a roster IP → allowed (ip_address key now read)", a is True)
    a, _ = scope.gate("mcp__kipi-osint__reverse_dns", {"ip_address": "8.8.8.8"}, ROSTER)
    _check("reverse_dns on a NEW IP → denied (ip_address key now read)", a is False)


def test_jina_bounded_like_a_read():
    a, _ = scope.gate("Bash", {"command": "./invctl osint-tool jina https://urlscan.io/result/abc"}, ROSTER)
    _check("jina reading a research site (out-of-scope) → denied", a is False)
    a, _ = scope.gate("mcp__kipi-osint__jina_read", {"url": "https://trumpstake.us/claim"}, ROSTER)
    _check("jina reading an in-scope domain → allowed", a is True)


def test_internal_always_allowed():
    a, _ = scope.gate("Bash", {"command": "echo hello"}, ROSTER)
    _check("non-osint bash → allowed", a is True)
    a, _ = scope.gate("ToolSearch", {"query": "select:whois_lookup"}, ROSTER)
    _check("ToolSearch → allowed", a is True)


def test_hook_script_end_to_end():
    """The actual PreToolUse hook (scope_hook.py) run as a subprocess: denies an out-of-
    roster target, allows an in-roster one, and is a no-op when no roster env is set (deep)."""
    import subprocess, tempfile, os, json as _json
    from pathlib import Path
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    hook = os.path.join(root, "investigations", "agent", "scope_hook.py")
    with tempfile.TemporaryDirectory() as d:
        rp = Path(d) / "roster.txt"
        rp.write_text("trumpstake.us\ntrumpfundus.com\n")
        env = {**os.environ, "KIPI_SCOPE_ROSTER": str(rp)}
        deny_ev = _json.dumps({"tool_name": "mcp__kipi-osint__whois_lookup",
                               "tool_input": {"target": "gambler-panel.com"}})
        r = subprocess.run(["python3", hook], input=deny_ev, env=env, capture_output=True, text=True)
        _check("hook DENIES an out-of-roster target", '"deny"' in r.stdout and "gambler-panel.com" in r.stdout)
        ok_ev = _json.dumps({"tool_name": "mcp__kipi-osint__whois_lookup",
                             "tool_input": {"target": "trumpstake.us"}})
        r2 = subprocess.run(["python3", hook], input=ok_ev, env=env, capture_output=True, text=True)
        _check("hook ALLOWS an in-roster target (no output)", r2.stdout.strip() == "")
        env_no = {k: v for k, v in os.environ.items() if k != "KIPI_SCOPE_ROSTER"}
        r3 = subprocess.run(["python3", hook], input=deny_ev, env=env_no, capture_output=True, text=True)
        _check("no roster env → no-op (deep is unbounded)", r3.stdout.strip() == "")


def test_settings_builder():
    from investigations.agent import investigator as inv
    sp, rp = inv._build_scope_settings(["trumpstake.us", "1.2.3.4"])
    import json, os
    cfg = json.load(open(sp))
    hook = cfg["hooks"]["PreToolUse"][0]
    _check("settings has a PreToolUse command hook → scope_hook.py",
           "scope_hook.py" in hook["hooks"][0]["command"])
    _check("matcher covers the investigation tools", "whois_lookup" in hook["matcher"] and "Bash" in hook["matcher"])
    _check("roster file written with the entities", "trumpstake.us" in open(rp).read())
    os.remove(sp); os.remove(rp)


def main():
    test_in_roster_allowed()
    test_out_of_roster_denied()
    test_search_enumeration_bounded()
    test_search_attribution_and_general_allowed()
    test_enumeration_is_always_a_lead()
    test_reverse_dns_ip_address_key_is_read()
    test_jina_bounded_like_a_read()
    test_internal_always_allowed()
    test_hook_script_end_to_end()
    test_settings_builder()
    print("\nPASS: test_scope_gate")


if __name__ == "__main__":
    main()
