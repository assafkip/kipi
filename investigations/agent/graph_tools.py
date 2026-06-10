"""In-process SDK MCP tools that let the warm agent act on the graph.

The chat-led agent already runs OSINT via kipi-osint; these tools give it the
graph operations too, so "investigate X and add what you find" completes in one
conversational turn (prd-chat-graph-tools).

Every tool is a THIN wrapper over the existing, tested `graph_chat.execute` —
the agent decides WHEN to call; the WRITE stays deterministic + structured (and
reversible/additive exactly as on the 9-intent router). `graph_chat` is unchanged.

Each tool closes over the warm session's `case_slug`. Resolution is case-scoped
(`graph_chat._resolve`); mutation semantics on shared entities match the router
(global), which is the existing model — not new cross-case exposure.

Tool names follow the live `mcp__<server>__<tool>` convention (verified against
the kipi-osint allowlist), so GRAPH_TOOL_NAMES are what go in `allowed_tools` and
what appear in a run's `tools` list.
"""
from __future__ import annotations

SERVER_NAME = "kipi-graph"

# short name -> (graph_chat intent, JSON-schema for the tool's args, description)
_TOOLS = {
    "graph_detail": (
        "detail",
        {"type": "object", "properties": {"target": {"type": "string"}},
         "required": ["target"]},
        "Facts about one node in the active case: what it is, where it came from, "
        "who it appears with, confirmed links.",
    ),
    "graph_connections": (
        "connections",
        {"type": "object", "properties": {"target": {"type": "string"}},
         "required": ["target"]},
        "List the typed connections of one node in the active case.",
    ),
    "graph_find": (
        "find",
        {"type": "object", "properties": {"query": {"type": "string"}},
         "required": ["query"]},
        "Search the active case's graph for nodes whose name matches a query.",
    ),
    "graph_add_node": (
        "add_node",
        {"type": "object", "properties": {
            "name": {"type": "string"},
            "node_type": {"type": "string"},
            "link_to": {"type": "string"},
            "rel_type": {"type": "string"},
        }, "required": ["name"]},
        "Add a node to the active case's graph (optionally linked to an existing "
        "node). Use for an entity you discovered. name is a handle/domain/IP/wallet.",
    ),
    "graph_add_edge": (
        "add_edge",
        {"type": "object", "properties": {
            "src": {"type": "string"},
            "dst": {"type": "string"},
            "rel_type": {"type": "string"},
        }, "required": ["src", "dst"]},
        "Connect two existing nodes in the active case with a typed relationship.",
    ),
    "graph_hide": (
        "hide",
        {"type": "object", "properties": {"target": {"type": "string"}},
         "required": ["target"]},
        "Remove a node from the graph (reversible soft-hide; the row stays).",
    ),
    "graph_unhide": (
        "unhide",
        {"type": "object", "properties": {"target": {"type": "string"}},
         "required": ["target"]},
        "Restore a previously hidden node.",
    ),
}

# Fully-qualified names for the allowlist + run["tools"] matching.
GRAPH_TOOL_NAMES = [f"mcp__{SERVER_NAME}__{short}" for short in _TOOLS]


def is_graph_tool(name: str) -> bool:
    """True if a tool name (as it appears in a run's tools list) is a graph tool.
    Used by /api/chat to bump the case when the agent changed the graph."""
    return isinstance(name, str) and name.startswith(f"mcp__{SERVER_NAME}__")


def _make_handler(intent: str, case_slug: str):
    """Build one tool handler bound to (intent, case). Opens its own connection
    (the warm tools run on the warm loop thread; a fresh connection per call is
    sqlite-safe), runs the deterministic op, returns the prose reply as content."""
    async def handler(args: dict) -> dict:
        from investigations.storage import db
        from investigations.webapp import graph_chat
        try:
            clean = args if isinstance(args, dict) else {}
            with db.connect() as conn:
                result = graph_chat.execute(conn, intent, clean, case_slug, None)
            return {"content": [{"type": "text",
                                 "text": result.get("reply", "(no result)")}]}
        except Exception as exc:
            # A bad arg or transient DB error must surface as a tool error, never
            # abort the warm turn (the agent can retry or move on).
            return {"content": [{"type": "text",
                                 "text": f"graph tool error: {str(exc)[:200]}"}],
                    "is_error": True}
    return handler


def build_graph_server(case_slug: str):
    """Build the in-process kipi-graph MCP server for one warm case session."""
    from claude_agent_sdk import create_sdk_mcp_server, tool

    sdk_tools = []
    for short, (intent, schema, desc) in _TOOLS.items():
        decorated = tool(short, desc, schema)(_make_handler(intent, case_slug))
        sdk_tools.append(decorated)
    return create_sdk_mcp_server(SERVER_NAME, tools=sdk_tools)
