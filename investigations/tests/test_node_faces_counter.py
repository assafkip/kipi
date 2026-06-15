"""Structural guard for issue node-faces-counter (PRD prd-node-faces-counter).

A live 'faces: N' header counter — N = on-canvas nodes that carry a thumbnail
(favicon/avatar) — updated at every node-count site. Collection shells (no
thumbnail) are excluded by the node[thumbnail] selector.
"""
from pathlib import Path

GRAPH = Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html"


def _src() -> str:
    return GRAPH.read_text(encoding="utf-8")


def test_face_count_state_and_header():
    s = _src()
    assert "faceCount: 0," in s, "faceCount state field missing"
    assert 'x-text="faceCount"' in s, "header must bind the faces count"
    assert "faces:" in s, "header must label the faces count"


def test_face_count_updates_at_every_count_site():
    """reload + growGraph + applyDeltas + addNodeToCanvas — 4 update sites."""
    assert _src().count("this.faceCount = this.cy.nodes('[thumbnail]').length") >= 4, \
        "faceCount must update wherever node counts update"


def test_face_count_excludes_collection_shells():
    """The node[thumbnail] selector only matches real faces — shells have no thumbnail."""
    s = _src()
    assert "this.cy.nodes('[thumbnail]')" in s, "must count via the thumbnail selector"
    assert "this.cy.nodes('[isCollection]').length" not in s, "must not count collection shells as faces"
