"""Collapsible chat dock (issue graph-chat-dock-collapse, finding-4).

Structural assertions over graph.html: the docked Investigator chat has a
collapse/expand toggle, is collapsed by a thin bar (not a fixed 50/50 split) so
the graph grows, the chat body renders only when open, and the state persists.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GRAPH = REPO / "investigations" / "webapp" / "templates" / "graph.html"


def src():
    return GRAPH.read_text()


def test_dock_has_collapse_toggle():
    s = src()
    assert "dockOpen" in s, "dock open/collapsed state missing"
    assert re.search(r"dockOpen = !dockOpen", s), "no dock toggle"


def test_dock_not_hard_split_when_collapsed():
    s = src()
    assert "flex-[1] min-h-0 border-t border-bg-border bg-bg-card" not in s, \
        "chat dock is still a fixed flex-[1] 50/50 split"
    assert re.search(r"dockOpen \? 'flex-\[1\] min-h-0' : ''", s), \
        "dock sizing should be conditional on dockOpen (grows when collapsed)"


def test_chat_body_shown_only_when_dock_open():
    assert re.search(r'x-show="dockOpen"', src()), "the chat body is not gated on dockOpen"


def test_dock_state_persisted_for_the_session():
    s = src()
    assert "sessionStorage.setItem('kipiDockOpen'" in s and "getItem('kipiDockOpen')" in s, \
        "dock state is not session-persisted"
