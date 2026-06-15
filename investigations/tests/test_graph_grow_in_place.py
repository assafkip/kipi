"""Structural guard for issue graph-grow-in-place (PRD prd-incremental-graph-growth).

The graph viewer must grow / reconcile IN PLACE: new nodes land at a free slot
near their discovery anchor, existing nodes update without moving, gone nodes are
removed, and NO live path relayouts or refits the viewport. These assertions read
graph.html's source and lock the shape of the live-update paths (growGraph,
applyDeltas, watchRunThenRefresh, onCaseChanged) so a future edit can't silently
re-introduce the force-relaxation / refit that caused the "graph pops around"
friction. reload() — the explicit-view-change path — must still relayout + fit.

Pure source inspection — no browser, no agents, no network.
"""
import re
from pathlib import Path

GRAPH = Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html"


def _src() -> str:
    return GRAPH.read_text(encoding="utf-8")


def _method_body(src: str, header_regex: str) -> str:
    """Slice an Alpine object method body: from its header to the first
    4-space-indented `},` (the method's own close; nested closes are deeper)."""
    m = re.search(header_regex, src)
    assert m, f"method header not found: {header_regex}"
    end = src.find("\n    },", m.end())
    assert end != -1, f"method end not found for: {header_regex}"
    return src[m.start():end]


def test_freespot_helper_is_deterministic():
    src = _src()
    assert "freeSpot(" in src, "freeSpot placement helper missing"
    body = _method_body(src, r"\n    freeSpot\(")
    assert "Math.random" not in body, "freeSpot must place deterministically, not at a random angle"


def test_placement_helpers_exist():
    src = _src()
    assert "_anchorFor(" in src, "_anchorFor (neighbour anchor) helper missing"
    assert "_placeAndReveal(" in src, "_placeAndReveal helper missing"
    assert "_visibleObstacles(" in src, "_visibleObstacles (freeSpot perf cache) helper missing"


def test_growgraph_reconciles_in_place():
    body = _method_body(_src(), r"\n    async growGraph\(\)")
    # places via freeSpot, never relayouts / refits
    assert "this.freeSpot(" in body, "growGraph must place new nodes via freeSpot"
    assert "_spreadAndFit" not in body, "growGraph must not force-relax the layout"
    assert "_frame(" not in body, "growGraph must not refit the viewport"
    assert "cy.fit(" not in body, "growGraph must not call cy.fit"
    assert "cy.layout(" not in body, "growGraph must not run a layout"
    # full reconcile: removes gone elements (not add-only)
    assert "this.cy.remove(" in body, "growGraph must remove nodes/edges gone from the data"


def test_oncasechanged_always_grows_in_place():
    body = _method_body(_src(), r"\n    async onCaseChanged\(\)")
    assert "this.growGraph(" in body, "onCaseChanged must grow the graph"
    assert "this.reload(" not in body, "onCaseChanged must not branch to a full reload"


def test_applydeltas_grows_in_place():
    body = _method_body(_src(), r"\n    applyDeltas\(")
    assert "this.freeSpot(" in body, "applyDeltas must place nodes via freeSpot"
    assert "this.cy.layout(" not in body, "applyDeltas must not run an incremental relayout"


def test_run_completion_grows_in_place():
    """watchRunThenRefresh fires when a dig finishes — it must grow in place, not reload."""
    body = _method_body(_src(), r"\n    watchRunThenRefresh\(\)")
    assert "this.growGraph(" in body, "run completion must grow the graph in place"
    assert "this.reload(" not in body, "run completion must not full-reload (wipe+relayout+fit)"


def test_reload_still_relayouts_and_fits():
    """The full reload path is the CORRECT place to relayout+fit (explicit view changes)."""
    body = _method_body(_src(), r"\n    async reload\(\)")
    assert "cy.layout(" in body, "reload must still run a layout"
    assert "cy.fit(" in body, "reload must still fit the viewport"
