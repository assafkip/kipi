"""Shortest-path mode (issue graph-pathfinding, PRD graph-analyst-craft).

Template-level guards for the deterministic parts: the toggle exists, taps
route through path mode, dijkstra runs undirected over visible elements, the
no-path case messages instead of silently doing nothing, and Esc/background
click clears. The visual behavior is proven by a browser screenshot on the
live server (issue acceptance).

Run: .venv/bin/python3 -m pytest investigations/tests/test_graph_pathfinding.py -q
"""
from pathlib import Path

GRAPH = (Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html").read_text()


def test_path_mode_toggle_renders():
    assert 'data-testid="path-mode-toggle"' in GRAPH
    assert "togglePathMode()" in GRAPH
    assert 'x-text="pathMsg"' in GRAPH


def test_node_taps_route_through_path_mode_first():
    # onNodeTap must check pathMode BEFORE the normal selection flow.
    body = GRAPH.split("async onNodeTap(node) {", 1)[1]
    first_lines = "\n".join(body.splitlines()[:3])
    assert "pathMode" in first_lines and "_pathTap" in first_lines


def test_dijkstra_is_undirected_over_visible_elements():
    assert ".dijkstra({ root: src, directed: false })" in GRAPH
    assert "elements(':visible')" in GRAPH


def test_no_path_case_shows_a_message():
    assert "no path between those two nodes" in GRAPH
    assert "distanceTo(node) === Infinity" in GRAPH


def test_escape_and_background_click_clear():
    assert "e.key === 'Escape'" in GRAPH
    assert "clearPath" in GRAPH
    # The background-tap handler clears path state too.
    bg = GRAPH.split("if (evt.target === this.cy)", 1)[1].split("});", 1)[0]
    assert "clearPath" in bg


def test_path_styles_defined_after_provisional():
    for sel in ("'.path-dim'", "'node.path-highlight'", "'edge.path-highlight'",
                "'node.path-endpoint'"):
        assert sel in GRAPH, sel
    # Cytoscape applies later matching selectors over earlier ones — the path
    # styles must come AFTER edge.provisional or a provisional edge on the
    # found path keeps its provisional look.
    assert GRAPH.index("'edge.provisional'") < GRAPH.index("'edge.path-highlight'")


def test_rebuild_clears_path_state():
    rebuild = GRAPH.split("this.cy.elements().remove();", 1)[0]
    assert "clearPath" in rebuild.splitlines()[-6:][0] or "clearPath()" in "\n".join(rebuild.splitlines()[-8:])


def test_edge_taps_inert_in_path_mode():
    body = GRAPH.split("async onEdgeTap(edge) {", 1)[1]
    first = "\n".join(body.splitlines()[:5])
    assert "pathMode" in first and "return" in first
