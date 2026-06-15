"""Graph multi-select + Stop (issue graph-multiselect-and-stop, finding-6).

Structural assertions over graph.html: visible persistent multi-select
(shift/⌘-click toggle into an .in-set ring), directional in/out edge tint, the
window.open -> in-app kipiNav.openGraph swap, and a Stop control on the
Expand/Deep-investigate runs. Issue required_check.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GRAPH = REPO / "investigations" / "webapp" / "templates" / "graph.html"


def src():
    return GRAPH.read_text()


def test_new_graph_is_in_app_not_window_open():
    s = src()
    assert "window.open(" not in s, "graph.html still opens a browser tab (window.open)"
    assert "kipiNav.openGraph(" in s, "new-graph actions not routed through kipiNav.openGraph"


def test_shift_click_toggles_into_the_set():
    s = src()
    # the node tap handler branches on a modifier key into toggleInSet
    assert re.search(r"shiftKey\s*\|\|\s*.*metaKey", s), "shift/⌘-click toggle not wired"
    assert "toggleInSet(" in s, "toggleInSet handler missing"


def test_selection_is_persistently_visible():
    s = src()
    # set members carry the persistent .in-set class (not the transient .selected)
    assert "node.in-set" in s, ".in-set selection style missing"
    assert "addClass('in-set')" in s, "set members not given the persistent ring"
    assert "removeClass('in-set')" in s, "clearSelection does not drop the ring"
    # boxselect must mark the box-selected nodes too
    assert s.count("addClass('in-set')") >= 2, "box-select / connections not marked in-set"


def test_in_out_edge_tint():
    s = src()
    assert "edge.edge-in" in s and "edge.edge-out" in s, "directional edge tint styles missing"
    assert "outgoers('edge').addClass('edge-out')" in s, "outgoing tint not applied on select"
    assert "incomers('edge').addClass('edge-in')" in s, "incoming tint not applied on select"


def test_stop_control_on_graph_runs():
    s = src()
    assert "stopInvestigate(" in s, "stopInvestigate method missing"
    assert "/api/investigate/stop" in s, "Stop does not call the investigate-stop endpoint"
    # a Stop button bound to it, shown while a run is in progress
    assert re.search(r'@click="stopInvestigate\(\)"', s), "Stop button not wired"
    assert s.count('@click="stopInvestigate()"') >= 2, "Stop missing on a run panel (single + set)"
