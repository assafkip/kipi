"""Structural guard for issue node-spotlight (PRD prd-node-spotlight).

An OPT-IN "focus this node's web" (dim-to-focus) from the right-click menu — NEVER
automatic on tap (the founder rejected auto-dim: "I want to see all the nodes").
Reuses the existing `dimmed` classes; clears on canvas tap / Escape. Behavioral
confirmation is a live /graph render-smoke at verify time.
"""
import re
from pathlib import Path

GRAPH = Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html"


def _src() -> str:
    return GRAPH.read_text(encoding="utf-8")


def _method_body(src: str, header_regex: str) -> str:
    m = re.search(header_regex, src)
    assert m, f"method header not found: {header_regex}"
    end = src.find("\n    },", m.end())
    assert end != -1, f"method end not found for: {header_regex}"
    return src[m.start():end]


def test_spotlight_method_exists_and_dims_only_the_web():
    body = _method_body(_src(), r"\n    spotlightNode\(id\)")
    assert "addClass('dimmed')" in body, "spotlight must dim the graph"
    assert "closedNeighborhood()" in body, "spotlight must un-dim the node's neighborhood"
    assert "removeClass('facet-match')" in body, "spotlight must clear stale facet/search highlight"


def test_spotlight_is_in_the_context_menu():
    assert "spotlightNode(selected.id)" in _src(), "the right-click menu must offer the focus action"


def test_tap_does_not_auto_dim():
    """A plain node tap must NOT dim the graph (founder's see-all rule)."""
    body = _method_body(_src(), r"\n    async onNodeTap\(")
    assert "addClass('dimmed')" not in body, "onNodeTap must not auto-dim the graph"


def test_escape_clears_and_reconciles_the_spotlight():
    src = _src()
    i = src.find("this.cy.elements('node.dimmed').length")
    assert i != -1, "Escape must detect an active spotlight"
    branch = src[i:i + 140]
    assert "this.highlightFacets()" in branch, \
        "Escape spotlight-clear must reconcile to active facet state via highlightFacets()"
