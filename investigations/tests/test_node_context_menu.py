"""Structural guard for issue node-right-click-menu (PRD prd-node-context-menu).

Right-clicking a graph node must open a context menu at the cursor that wires the
EXISTING per-node actions (no new backend), and close cleanly. These assertions
lock that wiring over graph.html. Behavioral confirmation is a live /graph
render-smoke (Alpine inits, no console errors) at verify time.
"""
from pathlib import Path

GRAPH = Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html"


def _src() -> str:
    return GRAPH.read_text(encoding="utf-8")


def test_node_menu_state_exists():
    assert "nodeMenu: {" in _src(), "nodeMenu state missing"


def test_cxttap_handler_and_native_menu_suppressed():
    s = _src()
    assert "this.cy.on('cxttap', 'node'" in s, "cxttap (right-click) handler missing"
    assert "addEventListener('contextmenu'" in s, "native context menu must be suppressed"


def test_open_node_menu_method():
    s = _src()
    assert "openNodeMenu(evt)" in s, "openNodeMenu method missing"
    # selects the node so the existing actions target it
    assert "this.onNodeTap(node)" in s


def test_menu_wires_existing_actions():
    s = _src()
    assert 'x-show="nodeMenu.open && selected"' in s, "menu template missing"
    for action in ("openDig(selected)", "investigateThisNode()", "expandNode()",
                   "openNodeNewGraph(selected.id)"):
        assert action in s, f"menu must wire existing action: {action}"


def test_menu_close_paths():
    s = _src()
    assert "@click.outside=\"nodeMenu.open = false\"" in s, "outside-click close missing"
    assert "@keydown.escape.window=\"nodeMenu.open = false\"" in s, "escape close missing"
    assert "this.nodeMenu.open = false" in s, "tap-to-close missing"


def test_menu_clamped_to_viewport():
    """The menu must clamp x/y so it never renders off the right/bottom edge."""
    assert "window.innerWidth" in _src(), "menu position must be clamped to the viewport"


def test_menu_gated_on_selected():
    """A null `selected` (cleared by live deltas) must hide the menu, not deref null."""
    assert 'x-show="nodeMenu.open && selected"' in _src(), "menu must be gated on selected"
