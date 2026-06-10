"""Every OSINT skill the system HAS must be connected to the investigator agent and
named in its persona, so every run can apply the full belt. This is the drift guard:
add an adapter to the registry and forget to wire it → this test fails.

Run: .venv/bin/python -m investigations.tests.test_investigator_tools
"""
from pathlib import Path

from investigations.enrich import registry
from investigations.agent import investigator
import investigations.agent.osint_mcp as osint_mcp


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


# apify is reached via the project .mcp.json apify MCP (+ the Bash belt), not the
# kipi-osint wrapper — so it's exempt from the MCP-coverage check only.
_MCP_EXEMPT = {"apify"}


def test_persona_names_every_adapter():
    persona = investigator.PERSONA
    for a in registry.all_adapters():
        _check(f"persona tells the agent about '{a.slug}'", a.slug in persona)


def test_mcp_server_wraps_every_adapter():
    src = Path(osint_mcp.__file__).read_text()
    for a in registry.all_adapters():
        if a.slug in _MCP_EXEMPT:
            continue
        _check(f"kipi-osint MCP wraps '{a.slug}'", f'_call("{a.slug}"' in src)


def test_belt_allows_every_provider():
    # The Bash wildcard reaches EVERY registry provider via ./invctl osint-tool.
    _check("bash belt allows all osint-tool providers",
           "Bash(./invctl osint-tool:*)" in investigator.ALLOWED_TOOLS)
    # And each kipi-osint MCP tool is explicitly allowed.
    for t in investigator._KIPI_MCP_TOOLS:
        _check(f"allowed: {t}", t in investigator.ALLOWED_TOOLS)


def test_persona_demands_full_application():
    p = investigator.PERSONA.lower()
    _check("persona mandates running every applicable tool",
           "every applicable tool" in p or "exhaust the belt" in p)
    _check("persona treats a thin run as a failure", "failure" in p)


def test_mcp_config_is_cwd_independent():
    # The kipi-osint server is launched with `python -m investigations.agent.osint_mcp`,
    # which only resolves when ROOT is importable. claude may spawn it from any cwd, so
    # the spec MUST pin cwd + PYTHONPATH — without it the server crashed ("No module
    # named investigations") and every mcp__kipi-osint__* call errored "No such tool".
    import json
    from investigations.agent.investigator import _build_mcp_config, ROOT
    spec = json.loads(_build_mcp_config().read_text())["mcpServers"]["kipi-osint"]
    _check("kipi-osint spec pins cwd to ROOT", spec.get("cwd") == str(ROOT))
    _check("kipi-osint spec puts ROOT on PYTHONPATH",
           spec.get("env", {}).get("PYTHONPATH") == str(ROOT))


def main():
    test_persona_names_every_adapter()
    test_mcp_server_wraps_every_adapter()
    test_belt_allows_every_provider()
    test_persona_demands_full_application()
    test_mcp_config_is_cwd_independent()
    print("\nPASS: test_investigator_tools")


if __name__ == "__main__":
    main()
