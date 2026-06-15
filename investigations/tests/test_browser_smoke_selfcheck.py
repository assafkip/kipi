"""Self-check for the browser-smoke harness (issue graph-browser-smoke-harness).

Proves the harness asserts RENDER OUTCOMES, not just HTTP payloads:
  - positive: a seeded non-empty graph renders >=1 laid-out/painted node;
  - negative self-test: a seeded EMPTY graph is READY (Cytoscape initialized)
    with exactly 0 nodes — NOT merely "non-positive", so a never-loaded page
    fails instead of passing. A green positive is trusted only because the
    negative proves the counter does not false-positive.

Skips (does NOT fail) when playwright or the chromium browser is unavailable, so
a non-browser CI run stays green; the gate is enforced wherever the cached
chromium (build 1223) is present. Enable elsewhere with `playwright install
chromium`. See prd-graph-outcome-gate.
"""
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="playwright not installed (pip install playwright)")
from playwright.sync_api import sync_playwright  # noqa: E402

from investigations.tests import browser_smoke as bs  # noqa: E402


def _launch(p):
    try:
        return p.chromium.launch(headless=True)
    except Exception as exc:  # browser binary missing / launch blocked
        pytest.skip(f"chromium unavailable (run: playwright install chromium): {exc}")


def _open_graph(db_path: Path, want: str, *, timeout_ms: int) -> int:
    """Serve the seeded DB, open /graph headless, return the node count.
    want='nodes' waits for >=1 painted node; want='ready' waits for Cytoscape
    to exist (count may be 0)."""
    with bs.serve(db_path) as base_url, sync_playwright() as p:
        browser = _launch(p)
        try:
            page = browser.new_page(viewport={"width": 1430, "height": 940})
            page.goto(base_url + "/graph", wait_until="load")
            if want == "nodes":
                return bs.wait_for_rendered_nodes(page, timeout_ms=timeout_ms)
            return bs.wait_until_graph_ready(page, timeout_ms=timeout_ms)
        finally:
            browser.close()


def test_seeded_graph_renders_nodes(tmp_path):
    db_path = tmp_path / "smoke.db"
    info = bs.seed_graph(db_path)
    count = _open_graph(db_path, "nodes", timeout_ms=8000)
    assert count >= 1, (
        f"seeded graph ({info['expected_nodes']} entities) rendered {count} nodes; "
        "the harness cannot see a render the API populated"
    )


def test_empty_graph_renders_zero_nodes_negative_selftest(tmp_path):
    db_path = tmp_path / "smoke_empty.db"
    bs.seed_graph(db_path, empty=True)
    # wait_until_graph_ready RAISES if Cytoscape never initialized, so a
    # never-loaded page fails here instead of masquerading as an empty graph.
    count = _open_graph(db_path, "ready", timeout_ms=8000)
    assert count == 0, (
        f"empty graph should be ready with 0 nodes, got {count} — the counter "
        "false-positives and cannot be trusted as a gate"
    )
