"""Whole-case assessment overlay (issue ad-1, assessment-dossier-promotion).

Backend: GET /api/assessment surfaces the existing synthesis brief markdown for the
active case, with every edge case (no active case / no brief / unreadable) returning
200 has_brief:false rather than a 500 — so the overlay shows its empty state, never a
broken panel. Test isolation: VAULT_DIR (where the brief file lives) is monkeypatched to
a temp dir and restored; never the live vault.

Frontend (structural over graph.html): the assessment is a SEPARATE right overlay keyed
on assessmentOpen (not `selected`), opened by a header toggle that hides the node drawer
(one right overlay at a time), with Open-full routing through kipiNav and NO in-overlay
synthesis trigger. Live behaviour is screenshot-verified.

Run: .venv/bin/python3 -m pytest investigations/tests/test_assessment_dossier.py -q
"""
import pathlib
import tempfile

from starlette.testclient import TestClient

from investigations.webapp import app as app_module

GRAPH = pathlib.Path(app_module.__file__).resolve().parent / "templates" / "graph.html"


# --- backend: GET /api/assessment -------------------------------------------------

def _client_with_vault(tmp):
    """A TestClient with VAULT_DIR pointed at an isolated temp dir. Returns (client, restore)."""
    orig = app_module.VAULT_DIR
    app_module.VAULT_DIR = pathlib.Path(tmp)
    return TestClient(app_module.app), (lambda: setattr(app_module, "VAULT_DIR", orig))


def test_no_active_case_is_empty_not_error():
    with tempfile.TemporaryDirectory() as tmp:
        client, restore = _client_with_vault(tmp)
        try:
            # No case cookie → 'all cases' → _active_case None → empty, never a 500.
            r = client.get("/api/assessment")
            assert r.status_code == 200
            d = r.json()
            assert d["has_brief"] is False and d["case"] is None
        finally:
            restore()


def test_active_case_no_brief_is_empty():
    with tempfile.TemporaryDirectory() as tmp:
        client, restore = _client_with_vault(tmp)
        try:
            client.cookies.set(app_module.CASE_COOKIE, "case-x")
            r = client.get("/api/assessment")
            assert r.status_code == 200
            d = r.json()
            assert d["has_brief"] is False and d["case"] == "case-x"
        finally:
            restore()


def test_brief_is_surfaced_with_frontmatter_stripped():
    with tempfile.TemporaryDirectory() as tmp:
        (pathlib.Path(tmp) / "synthesis-case-x.md").write_text(
            "---\nreport_count: 3\n---\n# Bottom line\nPhaaS operation, live threat active.\n",
            encoding="utf-8")
        client, restore = _client_with_vault(tmp)
        try:
            client.cookies.set(app_module.CASE_COOKIE, "case-x")
            r = client.get("/api/assessment")
            assert r.status_code == 200
            d = r.json()
            assert d["has_brief"] is True and d["case"] == "case-x"
            assert "Bottom line" in d["markdown"]
            assert "report_count" not in d["markdown"], "YAML frontmatter must be stripped"
        finally:
            restore()


# --- frontend structural assertions over graph.html -------------------------------

def src():
    return GRAPH.read_text()


def test_assessment_is_a_separate_overlay_keyed_on_its_own_state():
    s = src()
    i_marker = s.find("ASSESSMENT overlay")
    assert i_marker != -1, "assessment overlay missing"
    assert 'x-show="assessmentOpen"' in s, "assessment overlay not keyed on its own state"
    # It is NOT the node drawer (which is keyed on selected && panelOpen).
    block = s[i_marker:i_marker + 1400]
    assert 'x-show="selected && panelOpen' not in block, \
        "assessment overlay must not reuse the node-drawer condition"


def test_toggle_button_exists_and_opens_overlay():
    s = src()
    assert "openAssessment()" in s, "no assessment toggle handler"
    assert "⚖ Assessment" in s, "no assessment toggle button label"


def test_one_right_overlay_at_a_time():
    # Opening the assessment hides the node drawer (keeps selected) so the right edge is singular.
    s = src()
    i = s.find("async openAssessment()")
    assert i != -1, "openAssessment method missing"
    body = s[i:i + 400]
    assert "setPanel(false)" in body, "openAssessment must hide the node drawer (one overlay at a time)"


def test_node_and_edge_taps_close_the_assessment():
    # codex: the one-right-overlay invariant must hold at ALL times, not just at open. Tapping
    # a node/edge opens the drawer (panelOpen=true), so it must also close the assessment.
    s = src()
    for handler in ("async onNodeTap(node) {", "onEdgeTap(edge) {"):
        i = s.find(handler)
        assert i != -1, f"{handler} missing"
        body = s[i:i + 1400]
        assert "this.assessmentOpen = false" in body, \
            f"{handler} must close the assessment so the right edge stays singular"


def test_open_full_uses_kipinav_no_browser_nav_and_no_inline_synthesis():
    s = src()
    i = s.find("ASSESSMENT overlay")
    end = s.find("</aside>", i)
    assert end != -1, "assessment overlay aside not closed"
    block = s[i:end]
    assert "kipiNav.go('/synthesis')" in block, "Open-full must route through kipiNav"
    for bad in ("window.open", "location.href", "location.assign", "_blank"):
        assert bad not in block, f"assessment overlay must not use {bad}"
    # No in-overlay regeneration (finding-3): regen lives on /synthesis.
    assert "/api/synthesize" not in block, "overlay must not trigger synthesis inline"


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\nPASS: {len(fns)} tests")
    sys.exit(0)
