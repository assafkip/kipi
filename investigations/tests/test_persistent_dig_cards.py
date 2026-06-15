"""Structural guard for issue persistent-dig-cards (PRD prd-persistent-node-investigation).

Per-node investigation (transforms / results / past lookups) must live in a `digs`
map keyed by node id and render in a persistent dig rail, so switching nodes never
destroys a node's results. These assertions lock the keyed-state shape over
graph.html so a future edit can't silently re-flatten it back to the single-panel
state that lost results on every node switch.

Behavioral acceptance (open A, transform, switch to B, back to A — A persists) is
confirmed by a live /graph render-smoke at verify time; source inspection can't
prove reactive behavior.
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


def test_digs_state_exists():
    s = _src()
    assert "digs: {}" in s, "digs map state missing"
    assert "digOrder: []" in s, "digOrder rail-order state missing"


def test_dig_helpers_exist():
    s = _src()
    for fn in ("openDig(", "closeDig(", "loadProvidersForDig(", "transformConfigured("):
        assert fn in s, f"dig helper missing: {fn}"


def test_no_flat_per_node_state():
    """The per-node investigation fields must be keyed by dig, never flat top-level state."""
    s = _src()
    for bad in ("this.enrichResults", "this.pastRuns", "this.activeRunId",
                "this.enrichProvider", "this.enrichBusy", "this.enrichError",
                "this.providers", "selectedTransformConfigured", "loadProvidersForType("):
        assert bad not in s, f"flat per-node reference still present: {bad}"


def test_onnodetap_does_not_clear_dig_state():
    body = _method_body(_src(), r"\n    async onNodeTap\(")
    for bad in ("enrichResults", "pastRuns", "loadHistory("):
        assert bad not in body, f"onNodeTap still touches per-dig state: {bad}"


def test_runenrich_is_per_dig():
    s = _src()
    assert "async runEnrich(id)" in s, "runEnrich must take a dig id"
    body = _method_body(s, r"\n    async runEnrich\(id\)")
    assert "this.digs[id]" in body, "runEnrich must operate on digs[id]"
    assert "this.enrichResults" not in body, "runEnrich must not write flat state"


def test_dig_rail_template():
    s = _src()
    assert 'x-for="did in digOrder"' in s, "dig rail x-for missing"
    assert 'x-model="digs[did].enrichProvider"' in s, "per-dig transform select missing"
    assert "runEnrich(did)" in s, "per-dig Run transform missing"
    assert "closeDig(did)" in s, "per-dig close missing"


def test_panel_stays_open_for_digs():
    # Digs now live in the LEFT task rail, decoupled from the node-detail drawer
    # (issue graph-task-rail-decouple). The rail — not the node panel — persists
    # while digs exist; this preserves the original "digs stay visible" intent.
    assert 'x-show="digOrder.length"' in _src(), \
        "the left task rail must stay open while digs exist"


def test_growgraph_closes_removed_dig():
    body = _method_body(_src(), r"\n    async growGraph\(\)")
    assert "closeDig(" in body, "growGraph must drop the dig of a removed node"


def test_applydeltas_closes_hidden_dig():
    """A chat delta hiding a node must also drop that node's dig (no stale digOrder)."""
    body = _method_body(_src(), r"\n    applyDeltas\(")
    assert "closeDig(" in body, "applyDeltas hide_ids must drop the hidden node's dig"


def test_node_panel_excludes_edge_selection():
    """The node aside must not co-render with the edge-detail aside."""
    assert "selected && panelOpen && !selectedEdge" in _src(), \
        "node aside must be hidden while an edge is selected"
