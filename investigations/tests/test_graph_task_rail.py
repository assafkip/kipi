"""Task/dig cards decoupled into a left Runs rail (issue graph-task-rail-decouple, finding-3).

Structural assertions over graph.html: the dig-card rail is a SEPARATE left aside
(not inside the right node-detail drawer), the right drawer is selection-only, the
reopen tab is decoupled, and cy.resize() is wired to digOrder changes. Behaviour
(task boxes persist across node switches) is screenshot-verified live.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GRAPH = REPO / "investigations" / "webapp" / "templates" / "graph.html"


def src():
    return GRAPH.read_text()


def test_dig_rail_lives_in_a_left_aside_not_the_node_drawer():
    s = src()
    i_rail = s.find("LEFT TASK RAIL")
    i_loop = s.find('x-for="did in digOrder"')
    i_drawer = s.find("Selected node panel")
    assert i_rail != -1 and i_loop != -1 and i_drawer != -1, "markers missing"
    assert i_rail < i_loop < i_drawer, \
        "the digOrder loop must render in the left rail, before the right node drawer"


def test_right_drawer_is_selection_only():
    s = src()
    assert 'x-show="(selected || digOrder.length) && panelOpen && !selectedEdge"' not in s, \
        "right drawer is still keyed on digOrder"
    assert 'x-show="selected && panelOpen && !selectedEdge"' in s, \
        "right drawer x-show is not selection-only"


def test_left_rail_gated_on_digorder_with_runs_header():
    s = src()
    assert 'x-show="digOrder.length"' in s, "left rail not gated on digOrder.length"
    assert "Runs" in s, "Runs header missing from the rail"


def test_reopen_tab_decoupled_from_digorder():
    s = src()
    assert "(selected || selectedEdge || digOrder.length)" not in s, \
        "reopen tab still references digOrder"
    assert 'x-show="(selected || selectedEdge) && !panelOpen"' in s


def test_cy_resizes_on_digorder_change():
    assert re.search(r"\$watch\('digOrder\.length'", src()), \
        "cy.resize() is not wired to digOrder changes"
