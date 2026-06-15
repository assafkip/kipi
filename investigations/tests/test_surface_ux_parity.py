"""Cross-surface UX-parity gate (issue graph-drawer-ux-parity).

The entity page is the UX benchmark; the graph drawer drifted below it. This is
the standing CONTRACT that keeps them at parity: every node-detail surface (the
entity page AND the graph drawer) must expose the same bounded core set, so a
future surface can't quietly ship without them (the structural fix for "no shared
acceptance contract across surfaces").

Bounded core set (small on purpose — not a full mirror, per the PRD):
  1. plain-language empty state  ("No … yet")               — copy
  2. the analyst your-call / override action                 — a real control
  3. an OSINT-enrich path  (Expand / Investigate / Enrich)   — a real control

Action affordances are checked as INTERACTIVE CONTROLS (<a>/<button> text), not
loose words, so passive copy or an empty-state sentence cannot satisfy them
(codex). The entity-page benchmark also pins HTTP 200 + the entity's own name, so
a wrong-id render can't pass (codex adversarial).

Skips when playwright/chromium is unavailable (see prd-graph-outcome-gate).
"""
import re

import pytest

pytest.importorskip("playwright.sync_api", reason="playwright not installed (pip install playwright)")
from playwright.sync_api import sync_playwright  # noqa: E402

from investigations.tests import browser_smoke as bs  # noqa: E402

_ACTION = {
    "your-call / override": re.compile(r"assert|disagree|override|your call", re.I),
    "OSINT-enrich path": re.compile(r"expand|investigate|enrich", re.I),
}
_EMPTY = re.compile(r"no .{0,40} yet", re.I)
_FOCUS_NAME = "smoke-actor.com"   # bs.seed_graph()'s focus node canonical_name


def _launch(p):
    try:
        return p.chromium.launch(headless=True)
    except Exception as exc:
        pytest.skip(f"chromium unavailable (run: playwright install chromium): {exc}")


def _control_texts(page, scope):
    """Visible text of the interactive controls (<a>/<button>) within scope."""
    return page.eval_on_selector_all(
        f"{scope} a, {scope} button",
        "els => els.map(e => (e.textContent || '').trim()).filter(Boolean)",
    )


def _has_control(texts, rx):
    return any(rx.search(t) for t in texts)


def test_node_detail_surfaces_have_core_affordance_parity(tmp_path):
    db_path = tmp_path / "parity.db"
    info = bs.seed_graph(db_path)
    eid = info["focus_id"]
    with bs.serve(db_path) as base_url, sync_playwright() as p:
        browser = _launch(p)
        try:
            page = browser.new_page(viewport={"width": 1430, "height": 940})

            # --- Surface A: the entity page (benchmark). Pin status + identity. ---
            resp = page.goto(f"{base_url}/entity/{eid}", wait_until="load")
            assert resp and resp.ok, f"entity page failed to load (status {resp.status if resp else 'none'})"
            body_text = page.eval_on_selector("body", "el => el.textContent") or ""
            assert _FOCUS_NAME in body_text, (
                f"entity page is not entity {eid} — its name {_FOCUS_NAME!r} is absent"
            )
            # the your-call control text is Alpine x-text; wait for it to populate.
            page.wait_for_function(
                "() => [...document.querySelectorAll('a,button')]"
                ".some(b => /assert|disagree|override|your call/i.test(b.textContent || ''))",
                timeout=6000,
            )
            ent_controls = _control_texts(page, "body")
            for name, rx in _ACTION.items():
                assert _has_control(ent_controls, rx), f"entity page lacks a real control for: {name}"
            assert _EMPTY.search(body_text), "entity page lacks a plain-language empty state"

            # --- Surface B: the graph node drawer. Must match the bounded set. ---
            page.goto(base_url + "/graph", wait_until="load")
            bs.wait_for_rendered_nodes(page, timeout_ms=8000)
            page.evaluate(
                "(id) => { const d = window.Alpine.$data(document.getElementById('cy'));"
                " const n = d.cy.getElementById(String(id)); d.onNodeTap(n); }",
                eid,
            )
            page.wait_for_selector("[data-testid='node-drawer']", state="attached", timeout=8000)
            scope = "[data-testid='node-drawer']"
            drawer_controls = _control_texts(page, scope)
            for name, rx in _ACTION.items():
                assert _has_control(drawer_controls, rx), (
                    f"graph drawer is below the entity-page UX bar — no real control for: {name}"
                )
            drawer_text = page.eval_on_selector(scope, "el => el.textContent") or ""
            assert _EMPTY.search(drawer_text), "graph drawer lacks a plain-language empty state"
        finally:
            browser.close()
