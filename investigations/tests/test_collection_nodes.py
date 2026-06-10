"""Collection nodes for high-fanout neighborhoods (issue graph-collection-nodes,
PRD graph-analyst-craft).

Template-level guards for the deterministic parts: the extension is pinned on
the CDN and feature-checked; >=15 same-type degree-1 children of one hub fold
into a compound parent labeled "N <type>s"; the parent collapses by default
with edge aggregation ON (the finding-10 contract); a collapsed node expands
on click; the grouping pass runs before layout. The visual behavior is proven
by a browser screenshot on the live server with a high-fanout fixture.

Run: .venv/bin/python3 -m pytest investigations/tests/test_collection_nodes.py -q
"""
from pathlib import Path

_TPL = Path(__file__).resolve().parents[1] / "webapp" / "templates"
GRAPH = (_TPL / "graph.html").read_text()
LAYOUT = (_TPL / "_layout.html").read_text()


def test_extension_pinned_and_feature_checked():
    assert "cytoscape-expand-collapse@4.1.1" in LAYOUT
    assert "collectionsOk" in GRAPH
    assert "typeof this.cy.expandCollapse === 'function'" in GRAPH


def test_grouping_threshold_and_label():
    assert "COLLECTION_MIN: 15" in GRAPH
    assert "${kids.length} ${type}s" in GRAPH
    # Only LEAF children fold (degree 1) — connected structure stays visible.
    assert "n.degree(false) !== 1" in GRAPH


def test_collapsed_by_default_with_edge_aggregation():
    # The grouping pass collapses the new parents immediately...
    assert "this._ec.collapse(" in GRAPH
    # ...with the extension's meta-edge aggregation ON, so edges into hidden
    # children re-attach to the collapsed parent (finding-10).
    assert "groupEdgesOfSameTypeOnCollapse: true" in GRAPH


def test_click_expands_and_group_shell_is_not_an_entity():
    assert "cy-expand-collapse-collapsed-node" in GRAPH
    assert "this._ec.expand(node)" in GRAPH
    assert "node.data('isCollection')" in GRAPH


def test_grouping_runs_before_layout():
    rebuild = GRAPH.split("this.cy.add(data.edges);", 1)[1]
    build_pos = rebuild.index("_buildCollections()")
    layout_pos = rebuild.index("cy.layout(")
    assert build_pos < layout_pos


def test_bucket_carries_children_type_for_facets_and_rules():
    # The collapsed bucket must match node[type=...] style rules + facet
    # highlighting — it carries the children's shared type/origin.
    assert "type, surface_type: type, origin: kids[0].data('origin')" in GRAPH


def test_path_mode_wins_over_expand_on_tap():
    body = GRAPH.split("async onNodeTap(node) {", 1)[1]
    first = "\n".join(body.splitlines()[:6])
    assert "pathMode" in first and "_pathTap" in first
    # The expand branch comes AFTER the path-mode branch.
    assert body.index("this._pathTap(node)") < body.index("this._ec.expand(node)")


def test_incremental_deltas_fold_new_bursts_and_counts_exclude_shells():
    assert GRAPH.count("this._buildCollections()") >= 2   # reload + applyDeltas
    assert "this.cy.nodes('[!isCollection]').length" in GRAPH


def test_failed_cdn_load_only_disables_grouping():
    # _buildCollections is a no-op without the extension; nothing else gates on it.
    assert "if (!this.collectionsOk || !this.groupCollections) return;" in GRAPH
