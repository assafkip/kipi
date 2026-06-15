"""Focus deep-link render gate (issue graph-focus-renders).

The reported symptom: /graph?focus=<id> looked blank in a long-lived browser tab.
Grounding it (fable: confirm the error reproduces) showed current code renders a
focus neighborhood correctly — the blank tab was stale in-browser JS, not a code
defect. So this issue ships the REGRESSION GATE that proves it and would catch a
real future blank-focus, with the enforceable invariant:

  the painted Cytoscape node count == the /api/graph?focus count, AND that count
  is a STRICT SUBSET of the full graph (so a page that ignored ?focus would fail),
  AND a blank canvas FAILS (no fallback to the in-memory model count).

Skips when playwright/chromium is unavailable (see prd-graph-outcome-gate).
"""
import pytest

pytest.importorskip("playwright.sync_api", reason="playwright not installed (pip install playwright)")
from playwright.sync_api import sync_playwright  # noqa: E402

from investigations.storage import db  # noqa: E402
from investigations.tests import browser_smoke as bs  # noqa: E402

# Count nodes the renderer actually PAINTED (non-zero rendered box), not the
# model count — a blank/zero-size canvas with a loaded model returns 0 here.
_PAINTED_COUNT_JS = """
() => {
  const el = document.getElementById('cy');
  if (!el || !window.Alpine) return -1;
  const data = window.Alpine.$data(el);
  if (!data || !data.cy) return -1;
  let painted = 0;
  data.cy.nodes().forEach(n => {
    const b = n.renderedBoundingBox();
    if (b && (b.w > 0 || b.h > 0)) painted++;
  });
  return painted;
}
"""


def _launch(p):
    try:
        return p.chromium.launch(headless=True)
    except Exception as exc:
        pytest.skip(f"chromium unavailable (run: playwright install chromium): {exc}")


def _add_offshoot(db_path, case):
    """Two extra nodes OUTSIDE the focus neighborhood, so the full graph is
    strictly larger than the focus view (lets the test prove focus filters)."""
    with db.connect(db_path) as conn:
        rep = conn.execute(
            "SELECT id FROM reports WHERE investigation = ? LIMIT 1", (case,)
        ).fetchone()[0]
        x = db.upsert_entity(conn, "offshoot-a.com", "domain", rep, provenance="ingest:report")
        y = db.upsert_entity(conn, "offshoot-b.com", "domain", rep, provenance="ingest:report")
        db.add_mention(conn, x, rep, "offshoot-a.com", "")
        db.add_mention(conn, y, rep, "offshoot-b.com", "")
        conn.execute(
            "INSERT INTO typed_relationships "
            "(src_entity_id, dst_entity_id, rel_type, status, provenance) "
            "VALUES (?, ?, 'linked_to', 'active', 'smoke')",
            (x, y),
        )
        conn.commit()


def test_focus_deeplink_renders_only_its_neighborhood(tmp_path):
    db_path = tmp_path / "focus.db"
    info = bs.seed_graph(db_path)            # 3-node focus neighborhood
    _add_offshoot(db_path, info["case"])     # +2 disconnected -> full graph = 5
    focus_id = info["focus_id"]
    with bs.serve(db_path) as base_url, sync_playwright() as p:
        browser = _launch(p)
        try:
            page = browser.new_page(viewport={"width": 1430, "height": 940})
            console: list[str] = []
            page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
            page.on("pageerror", lambda e: console.append(f"pageerror: {e}"))

            focus_api = len(page.request.get(f"{base_url}/api/graph?focus={focus_id}").json().get("nodes", []))
            full_api = len(page.request.get(f"{base_url}/api/graph").json().get("nodes", []))
            assert focus_api >= 1, f"seed/API broken: focus API returned {focus_api} nodes"
            assert focus_api < full_api, (
                f"focus neighborhood ({focus_api}) is not a strict subset of the full graph "
                f"({full_api}); a focus-ignoring page could pass — strengthen the seed"
            )

            page.goto(f"{base_url}/graph?focus={focus_id}", wait_until="load")
            try:
                # RAISES on a blank canvas (no fallback to the model count), so a
                # real blank-focus regression FAILS this gate instead of passing.
                bs.wait_for_rendered_nodes(page, timeout_ms=8000)
            except AssertionError as exc:
                raise AssertionError(f"{exc}\nconsole:\n" + "\n".join(console[-40:])) from exc

            painted = page.evaluate(_PAINTED_COUNT_JS)
            assert painted == focus_api, (
                f"focus deep-link painted {painted} nodes, expected {focus_api} (the "
                f"neighborhood; full graph has {full_api}). A blank canvas, a partial "
                f"paint, or an ignored ?focus all fail here.\nconsole:\n"
                + "\n".join(console[-40:])
            )
        finally:
            browser.close()
