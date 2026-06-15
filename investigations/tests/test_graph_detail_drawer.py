"""Graph detail panel = right slide-in overlay drawer (issue graph-detail-overlay-drawer).

Structural assertions over graph.html: the node + edge detail panels are absolute
right-edge overlays (not shrink-0 columns) so the canvas stays full-width; filters
default collapsed; cy.resize() fires on the filters toggle. Behavioural acceptance
(drawer slides in over a full-width graph) is screenshot-verified live.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GRAPH = REPO / "investigations" / "webapp" / "templates" / "graph.html"


def src():
    return GRAPH.read_text()


def test_detail_panels_are_absolute_overlays_not_columns():
    s = src()
    assert "w-96 shrink-0 bg-bg-card border-l" not in s, \
        "a detail panel is still a shrink-0 column (squishes the graph)"
    assert s.count("absolute top-0 right-0 bottom-0 w-96") >= 2, \
        "node + edge drawers should both be absolute right-edge overlays"


def test_filters_collapsed_by_default():
    assert re.search(r"showControls:\s*false", src()), \
        "filters (showControls) should default collapsed so the graph is full-width"


def test_graph_row_is_positioning_context():
    assert "flex-[1] min-h-0 flex relative" in src(), \
        "the graph sub-area row needs `relative` to anchor the overlay drawer"


def test_cy_resizes_on_filter_toggle():
    assert re.search(r"showControls = !showControls;.*cy.*resize", src()), \
        "the filters toggle must cy.resize() so Cytoscape reflows to the new width"
