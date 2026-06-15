"""Single launch-surface-per-verb gate (issue graph-single-action-surface).

Founder direction "de-dupe verbs, keep rail": the persistent dig rail (3-surfaces
PRDs, "don't re-couple") is KEPT; each primary node-action verb (Expand /
Investigate / open-dig) has exactly ONE launch surface — the right detail drawer.
The right-click context menu keeps only the spatial-nav shortcuts the drawer does
NOT offer (Focus this node's web / Open in new graph / Open entity page).

This gate drives REAL interaction (select + right-click a node) and asserts on
VISIBLE text, and it also pins the codex-adversarial fix: a node tap must
supersede an open edge drawer, or the node drawer (and its verbs) stay hidden.

Skips when playwright/chromium is unavailable (see prd-graph-outcome-gate).
"""
import pytest

pytest.importorskip("playwright.sync_api", reason="playwright not installed (pip install playwright)")
from playwright.sync_api import sync_playwright  # noqa: E402

from investigations.tests import browser_smoke as bs  # noqa: E402

# Screen-space center of the first rendered node (cy renderedPosition is relative
# to the #cy container; add the container's viewport offset).
_NODE_POS_JS = """
() => {
  const el = document.getElementById('cy');
  const data = window.Alpine.$data(el);
  const n = data.cy.nodes('[!isCollection]')[0] || data.cy.nodes()[0];
  const rp = n.renderedPosition();
  const r = el.getBoundingClientRect();
  return { x: r.left + rp.x, y: r.top + rp.y };
}
"""


def _launch(p):
    try:
        return p.chromium.launch(headless=True)
    except Exception as exc:
        pytest.skip(f"chromium unavailable (run: playwright install chromium): {exc}")


def test_one_launch_surface_per_verb_rail_kept(tmp_path):
    db_path = tmp_path / "surface.db"
    bs.seed_graph(db_path)
    with bs.serve(db_path) as base_url, sync_playwright() as p:
        browser = _launch(p)
        try:
            page = browser.new_page(viewport={"width": 1430, "height": 940})
            page.goto(base_url + "/graph", wait_until="load")
            bs.wait_for_rendered_nodes(page, timeout_ms=8000)  # layout settled

            # 1) the persistent-digs rail element still EXISTS (kept, not deleted).
            assert page.locator("[data-testid='dig-rail']").count() == 1, (
                "dig rail element is gone — the persistent-digs rail must be KEPT"
            )

            pos = page.evaluate(_NODE_POS_JS)

            # 2) selecting a node opens the drawer (visible) with the canonical verbs.
            page.mouse.click(pos["x"], pos["y"])
            drawer = page.locator("[data-testid='node-drawer']")
            drawer.wait_for(state="visible", timeout=5000)
            drawer_text = drawer.inner_text()
            assert "Expand" in drawer_text and "Investigate" in drawer_text, (
                f"drawer does not launch the canonical action verbs: {drawer_text!r}"
            )

            # 3) the context menu, when OPEN (its cxttap trigger is covered by
            #    test_node_context_menu.py), shows NO duplicate action verbs while
            #    VISIBLE — only the spatial-nav shortcuts the drawer lacks.
            page.evaluate("() => { window.Alpine.$data(document.getElementById('cy')).nodeMenu.open = true; }")
            menu = page.locator("[data-testid='node-context-menu']")
            menu.wait_for(state="visible", timeout=5000)
            menu_text = menu.inner_text()
            for verb in ("Expand", "Deep investigate", "open dig"):
                assert verb not in menu_text, (
                    f"right-click menu still duplicates the action verb {verb!r}: {menu_text!r}"
                )
            assert "Open in new graph" in menu_text and "Open entity page" in menu_text, (
                f"right-click menu lost its unique spatial-nav shortcuts: {menu_text!r}"
            )

            # 4) codex-adversarial fix: a node tap must supersede an OPEN edge drawer,
            #    or the node drawer (now the only home for the verbs) stays hidden.
            #    Calls the real tap handler (what a canvas tap invokes) with an open
            #    edge-drawer state, so it deterministically exercises onNodeTap.
            page.evaluate(
                "async () => { const d = window.Alpine.$data(document.getElementById('cy'));"
                " d.nodeMenu.open = false;"
                " d.selectedEdge = { id: 'e-stub', source: 'a', target: 'b' }; d.edgeDetail = {};"
                " d.panelOpen = true;"
                " const n = d.cy.nodes('[!isCollection]')[0] || d.cy.nodes()[0];"
                " await d.onNodeTap(n); }"
            )
            drawer.wait_for(state="visible", timeout=5000)  # hidden unless selectedEdge cleared
            assert page.evaluate(
                "() => !window.Alpine.$data(document.getElementById('cy')).selectedEdge"
            ), "onNodeTap must clear selectedEdge so the node drawer (and its verbs) are reachable"
        finally:
            browser.close()
