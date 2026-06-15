"""kipi-graph in-process SDK tools: the warm agent can act on the graph.

prd-chat-graph-tools / issue-chat-graph-tools. Offline + deterministic: tool
handlers are awaited directly against a temp DB; the warm factory is exercised
with a captured-options fake (no SDK client, no network).

Run: .venv/bin/python3 -m investigations.tests.test_graph_tools

Asserts every acceptance criterion:
  - the 7 expected SHORT tool names; GRAPH_TOOL_NAMES are their mcp__kipi-graph__
    fully-qualified forms (the live mcp__<server>__<tool> convention)
  - build_graph_server(case) builds an sdk server named kipi-graph
  - graph_add_node's handler creates the entity; graph_hide's soft-hides it
    (deterministic mutation via graph_chat.execute)
  - is_graph_tool matches mcp__kipi-graph__* and nothing else
  - warm_session._default_client_factory adds the kipi-graph server to
    mcp_servers and GRAPH_TOOL_NAMES to allowed_tools
"""
import asyncio
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.agent import graph_tools


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_names_and_convention():
    expected_short = ["graph_detail", "graph_connections", "graph_find",
                      "graph_add_node", "graph_add_edge", "graph_hide", "graph_unhide"]
    _check("7 expected short tool names", list(graph_tools._TOOLS) == expected_short)
    _check("GRAPH_TOOL_NAMES are the mcp__kipi-graph__ forms",
           graph_tools.GRAPH_TOOL_NAMES == [f"mcp__kipi-graph__{n}" for n in expected_short])
    cfg = graph_tools.build_graph_server("case-x")
    _check("build_graph_server returns an sdk server named kipi-graph",
           isinstance(cfg, dict) and cfg.get("type") == "sdk" and cfg.get("name") == "kipi-graph")


def test_is_graph_tool():
    _check("matches a graph tool", graph_tools.is_graph_tool("mcp__kipi-graph__graph_add_node"))
    _check("rejects a non-graph tool", not graph_tools.is_graph_tool("mcp__kipi-osint__dns_lookup"))
    _check("rejects None", not graph_tools.is_graph_tool(None))


def test_handlers_mutate_deterministically():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        # The case must exist (a report attaches it) for add_node to resolve.
        with db.connect(dbp) as conn:
            db.insert_report(conn, "r.md", "h", "markdown", "R", "case-g", "x")
            conn.commit()
        orig = db.connect
        db.connect = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
        try:
            add = graph_tools._make_handler("add_node", "case-g")
            out = asyncio.run(add({"name": "evil.com"}))
            _check("add_node handler returns text content",
                   out["content"][0]["type"] == "text" and out["content"][0]["text"])
            with db.connect(dbp) as conn:
                row = conn.execute(
                    "SELECT id, hidden FROM entities WHERE canonical_name = ?", ("evil.com",)).fetchone()
            _check("add_node created the entity (deterministic write)", row is not None)
            _check("new entity is visible", not row["hidden"])

            hide = graph_tools._make_handler("hide", "case-g")
            asyncio.run(hide({"target": "evil.com"}))
            with db.connect(dbp) as conn:
                row2 = conn.execute(
                    "SELECT hidden FROM entities WHERE canonical_name = ?", ("evil.com",)).fetchone()
            _check("hide handler soft-hides the entity (row stays, hidden=1)",
                   row2 is not None and row2["hidden"] == 1)

            # A bad arg type must return a tool error, NOT raise (so it can't
            # abort the warm turn). graph_find would .strip() a non-string.
            bad = graph_tools._make_handler("find", "case-g")
            out = asyncio.run(bad({"query": 123}))
            _check("bad arg returns is_error content, never raises", out.get("is_error") is True)
            # Non-dict args are normalized, not crashed.
            out2 = asyncio.run(graph_tools._make_handler("find", "case-g")(None))
            _check("non-dict args handled", out2["content"][0]["type"] == "text")
        finally:
            db.connect = orig


def test_agent_add_node_clears_admission_gate_analyst_is_not_gated():
    """The agent's graph_add_node is a graph-CREATION path: it must clear the same
    admission gate as every other one (RCA rca-recurring-graph-noise), and its rows
    land as 'osint' provenance — never 'analyst'. The ANALYST's own add is never
    gated and lands as 'analyst' (top authority)."""
    from investigations.webapp import graph_chat
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            db.insert_report(conn, "r.md", "h", "markdown", "R", "case-g", "x")
            conn.commit()
        orig = db.connect
        db.connect = lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate)
        try:
            add = graph_tools._make_handler("add_node", "case-g")
            # junk (registry boilerplate) via the AGENT tool → rejected, no row
            out = asyncio.run(add({"name": "isnic.is", "node_type": "domain"}))
            _check("agent junk add is refused with a reason",
                   "Not adding" in out["content"][0]["text"])
            with db.connect(dbp) as conn:
                row = conn.execute("SELECT 1 FROM entities WHERE canonical_name = 'isnic.is'"
                                   ).fetchone()
            _check("agent junk add created NO entity", row is None)
            # real entity via the AGENT tool → created, provenance osint
            asyncio.run(add({"name": "scam-target.com", "node_type": "domain"}))
            with db.connect(dbp) as conn:
                row = conn.execute("SELECT provenance FROM entities WHERE canonical_name = "
                                   "'scam-target.com'").fetchone()
            _check("agent add lands with osint provenance, never analyst",
                   row is not None and row["provenance"] == "osint")
            # the SAME junk via the ANALYST router → allowed, analyst provenance
            with db.connect(dbp) as conn:
                out = graph_chat.execute(conn, "add_node",
                                         {"name": "isnic.is", "node_type": "domain"},
                                         "case-g", None)   # default actor="analyst"
                row = conn.execute("SELECT provenance FROM entities WHERE canonical_name = "
                                   "'isnic.is'").fetchone()
            _check("analyst add is never gated (top authority)", row is not None)
            _check("analyst add lands with analyst provenance",
                   row["provenance"] == "analyst")
        finally:
            db.connect = orig


def test_factory_wires_graph_server_and_allowlist():
    # Capture the ClaudeAgentOptions the factory builds, without a real client.
    import claude_agent_sdk as sdk
    from investigations.agent import warm_session as ws

    captured = {}

    class _FakeClient:
        def __init__(self, options=None):
            captured["options"] = options

    orig = sdk.ClaudeSDKClient
    sdk.ClaudeSDKClient = _FakeClient
    try:
        # case "default" short-circuits the (separately-tracked) bounded-roster
        # path; the graph wiring under test is independent of scope.
        ws._default_client_factory("default")
    finally:
        sdk.ClaudeSDKClient = orig

    opts = captured.get("options")
    _check("factory built options", opts is not None)
    _check("kipi-graph server added to mcp_servers", "kipi-graph" in opts.mcp_servers)
    _check("all GRAPH_TOOL_NAMES added to allowed_tools",
           all(n in opts.allowed_tools for n in graph_tools.GRAPH_TOOL_NAMES))
    # OSINT tools must still be there (additive, not a replacement).
    _check("existing osint tools preserved",
           any("kipi-osint" in t for t in opts.allowed_tools))


def main():
    test_names_and_convention()
    test_is_graph_tool()
    test_handlers_mutate_deterministically()
    test_factory_wires_graph_server_and_allowlist()
    print("\nALL PASS: test_graph_tools")


if __name__ == "__main__":
    main()
