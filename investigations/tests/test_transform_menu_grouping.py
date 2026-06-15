"""OSINT transform-menu grouping + run-state gate (issue graph-osint-dropdown-grouping).

The dropdown was a flat ~39-row wall of jargon with cryptic tags and no sense of
what had already run. This gate proves the menu is now grouped by intent and
flagged with already-run state:
  - API: /api/transforms?type=&entity_id= returns each provider with `group` and
    `ran`, plus a `groups` list (intent buckets in a stable order); a seeded run
    flips that provider's `ran` to true while others stay false.
  - Browser: the rendered <select> shows <optgroup> intent headers.

Skips when playwright/chromium is unavailable (see prd-graph-outcome-gate).
"""
import pytest

pytest.importorskip("playwright.sync_api", reason="playwright not installed (pip install playwright)")
from playwright.sync_api import sync_playwright  # noqa: E402

from investigations.storage import db  # noqa: E402
from investigations.tests import browser_smoke as bs  # noqa: E402

_INTENT_GROUPS = {"Infrastructure", "Threat intel", "On-chain", "Identity",
                  "Web search", "Social", "Other"}


def _launch(p):
    try:
        return p.chromium.launch(headless=True)
    except Exception as exc:
        pytest.skip(f"chromium unavailable (run: playwright install chromium): {exc}")


def test_transform_menu_grouped_with_run_state(tmp_path):
    db_path = tmp_path / "menu.db"
    info = bs.seed_graph(db_path)
    domain_id = info["focus_id"]  # the seeded domain node
    # Seed a SUCCESSFUL run (crtsh) and a FAILED run (whoisxml) on the domain node:
    # `ran` must reflect the success and NOT the error (codex adversarial).
    with db.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO enrichment_runs (entity_id, provider_slug, query, status, investigation) "
            "VALUES (?, 'crtsh', 'q', 'success', ?)",
            (domain_id, info["case"]),
        )
        conn.execute(
            "INSERT INTO enrichment_runs (entity_id, provider_slug, query, status, investigation) "
            "VALUES (?, 'whoisxml', 'q', 'error', ?)",
            (domain_id, info["case"]),
        )
        conn.commit()

    with bs.serve(db_path) as base_url, sync_playwright() as p:
        browser = _launch(p)
        try:
            page = browser.new_page(viewport={"width": 1430, "height": 940})

            # --- API: grouped + run-state ---
            data = page.request.get(
                f"{base_url}/api/transforms?type=domain&entity_id={domain_id}"
            ).json()
            transforms = data.get("transforms", [])
            assert transforms, "no domain transforms returned"
            for t in transforms:
                assert "group" in t and "ran" in t, f"transform missing group/ran: {t}"
                assert t["group"] in _INTENT_GROUPS, f"unknown intent group: {t['group']}"
            assert any(t["slug"] == "crtsh" and t["ran"] for t in transforms), \
                "seeded crtsh success run is not flagged ran=true"
            assert not any(t["slug"] == "whoisxml" and t["ran"] for t in transforms), \
                "a failed (status='error') run must NOT be marked ran=true"
            assert any(not t["ran"] for t in transforms), \
                "every provider flagged ran — run-state is not discriminating"
            groups = data.get("groups", [])
            assert groups, "no `groups` bucket list returned"
            for g in groups:
                assert g["group"] in _INTENT_GROUPS and g["items"], f"bad group bucket: {g}"
            # groups must hold every transform (no provider dropped by grouping)
            assert sum(len(g["items"]) for g in groups) == len(transforms), \
                "grouped items do not cover every transform"

            # --- Browser: the rendered dropdown shows intent <optgroup> headers ---
            page.goto(base_url + "/graph", wait_until="load")
            bs.wait_for_rendered_nodes(page, timeout_ms=8000)
            page.evaluate(
                "(id) => { const d = window.Alpine.$data(document.getElementById('cy'));"
                " const n = d.cy.getElementById(String(id)); d.openDig(n.data()); }",
                domain_id,
            )
            # optgroup has no layout box of its own, so wait for ATTACHED, not visible.
            page.wait_for_selector("optgroup", state="attached", timeout=8000)
            labels = page.eval_on_selector_all("optgroup", "els => els.map(e => e.label)")
            assert any(l in _INTENT_GROUPS for l in labels), \
                f"no intent optgroups rendered in the dropdown: {labels}"
        finally:
            browser.close()
