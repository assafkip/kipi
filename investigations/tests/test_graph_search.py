"""Search spotlight has an escape (graph UI). A search dims every non-match;
without a clear path the graph stayed greyed-out with no way back (the
"nodes went opaque and stayed that way" dead-end). clearSearch() must be
reachable from: empty box, Esc, the Clear button, and a background click.

Run: .venv/bin/python3 -m pytest investigations/tests/test_graph_search.py -q
"""
from pathlib import Path

GRAPH = (Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html").read_text()


def test_clear_search_method_exists():
    assert "clearSearch()" in GRAPH
    # It removes BOTH the dim and the match highlight.
    body = GRAPH.split("clearSearch() {", 1)[1].split("},", 1)[0]
    assert "removeClass('dimmed facet-match')" in body


def test_empty_box_clears_the_spotlight():
    # searchNode on an empty query must clear, not no-op (the old `return` left
    # the graph dimmed).
    body = GRAPH.split("searchNode() {", 1)[1].split("},", 1)[0]
    assert "if (!q) { this.clearSearch(); return; }" in body


def test_escape_clears_search():
    assert "this.cy.elements('.facet-match').length" in GRAPH
    assert "this.clearSearch()" in GRAPH


def test_clear_button_rendered_when_search_active():
    assert 'clearSearch()' in GRAPH
    assert "title=\"Clear search (Esc)\"" in GRAPH


def test_background_click_lifts_search():
    tap = GRAPH.split("if (evt.target === this.cy)", 1)[1].split("});", 1)[0]
    assert "facet-match" in tap   # background click also clears the spotlight
