"""Layout switcher (issue graph-layouts, PRD graph-analyst-craft).

Template-level guards for the deterministic parts: the switcher exists, cose
stays the default, every layout call site routes through _layoutOpts, the CDN
scripts are version-pinned, and dagre is feature-checked (a failed CDN load
hides the option instead of blanking the graph). The visual behavior itself is
proven by browser screenshots on the live server (issue acceptance).

Run: .venv/bin/python3 -m pytest investigations/tests/test_graph_layouts.py -q
"""
from pathlib import Path

_TPL = Path(__file__).resolve().parents[1] / "webapp" / "templates"
GRAPH = (_TPL / "graph.html").read_text()
LAYOUT = (_TPL / "_layout.html").read_text()


def test_switcher_renders_with_cose_default():
    assert 'data-testid="layout-switcher"' in GRAPH
    assert "layoutName: 'cose'" in GRAPH          # cose stays the default
    for opt in ('value="cose"', 'value="dagre"', 'value="concentric"', 'value="circle"'):
        assert opt in GRAPH, opt


def test_all_layout_call_sites_route_through_layout_opts():
    import re
    assert "_layoutOpts()" in GRAPH
    # Every cy.layout(...) call must either derive from _layoutOpts (single
    # source) or be one of the two documented exceptions: the dagre feature
    # check (constructs, never runs) and the cose physics relaxation in
    # _spreadAndFit (guarded by an explicit layoutName !== 'cose' early-exit).
    lines = GRAPH.splitlines()
    offenders = []
    for i, line in enumerate(lines):
        if not re.search(r"\bcy\.layout\(", line):
            continue
        ctx = "\n".join(lines[max(0, i - 14):i + 1])
        if "_layoutOpts" in ctx:   # derived from the single source nearby
            continue
        is_feature_check = "dagreOk" in ctx
        is_spread_exception = "_spreadBusy" in ctx and "layoutName !== 'cose'" in ctx
        if not (is_feature_check or is_spread_exception):
            offenders.append(f"line {i + 1}: {line.strip()}")
    assert offenders == [], "cy.layout call(s) bypass _layoutOpts:\n" + "\n".join(offenders)


def test_cdn_scripts_are_version_pinned():
    assert "dagre@0.8.5" in LAYOUT
    assert "cytoscape-dagre@2.5.0" in LAYOUT


def test_dagre_is_feature_checked():
    # The option is offered only when the scripts actually loaded + registered.
    assert "dagreOk" in GRAPH
    assert "typeof window.dagre !== 'undefined'" in GRAPH
    assert 'x-if="dagreOk"' in GRAPH


def test_concentric_centers_on_selected_node_with_fallback():
    assert "_egoNode()" in GRAPH
    assert "_hopDepths(" in GRAPH
    assert "max((n) => n.degree(false))" in GRAPH   # highest-degree fallback
