"""Graph detail card cleanup (issue graph-detail-card, finding-3).

Structural assertions over graph.html: the drawer is a clean sectioned card, the
three overlapping neighbor-add control blocks are collapsed to ONE Neighbors
block, the dossier is a link (not a full-width teal block), and the 'what we
found' wall is height-capped. Behavioural look is screenshot-verified live.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GRAPH = REPO / "investigations" / "webapp" / "templates" / "graph.html"


def src():
    return GRAPH.read_text()


def test_no_duplicate_neighbor_control_blocks():
    s = src()
    assert ">Focus this node</div>" not in s, "the 'Focus this node' section header should be merged into Neighbors"
    assert "Connections (incoming / outgoing)" not in s, "the separate Connections block should be merged into Neighbors"
    assert ">Neighbors<" in s, "consolidated Neighbors block missing"


def test_actions_grouped_not_a_stacked_wall_of_teal_buttons():
    s = src()
    # the dossier is a small inline link now, not a full-width teal block
    assert "Open full dossier →" in s
    assert "block text-center bg-accent text-white" not in s, "dossier is still a full-width teal block"
    # Expand + Investigate still reachable from the panel
    assert "expandNode()" in s and "investigateThisNode()" in s


def test_what_we_found_is_height_capped():
    assert "markdown max-h-56 overflow-y-auto" in src(), "the 'what we found' wall is not height-capped"


def test_card_keeps_its_clean_sections():
    s = src()
    for marker in ("in / out (typed)", "Origin", "Connected — and how", "Neighbors"):
        assert marker in s, f"card section/stat '{marker}' missing"
