"""Guard for issue node-favicons (PRD prd-node-favicons).

Domain / URL nodes get a favicon face. Founder OPSEC decision: Google as the source,
served through a SAME-ORIGIN /api/favicon proxy (cytoscape forces CORS and Google sends
none, so a direct URL is blocked — verified). The browser must hit kipi's origin, never
Google directly. Structural assertions lock the helper + call sites; a TestClient checks
the proxy route's sanitization/404 behavior (no network).
"""
from pathlib import Path

GRAPH = Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html"


def _src() -> str:
    return GRAPH.read_text(encoding="utf-8")


def test_favicon_helper_uses_same_origin_proxy():
    s = _src()
    assert "_faviconFor(d)" in s, "_faviconFor helper missing"
    assert "/api/favicon?domain=" in s, "favicon must go through the same-origin proxy"
    assert "google.com/s2/favicons" not in s, "the browser must not request Google directly (CORS + OPSEC)"


def test_favicon_checks_type_and_surface_type():
    s = _src()
    assert "st !== 'domain' && st !== 'url'" in s, "favicon gate must also check surface_type"
    assert "[^\\x00-\\x7F]" in s, "non-ASCII / IDN hosts must be skipped, not mangled"


def test_favicon_proxy_security_app_py():
    """The proxy must allowlist inert image types (no SVG) and send nosniff (Codex security)."""
    app_src = (Path(__file__).resolve().parents[1] / "webapp" / "app.py").read_text(encoding="utf-8")
    assert "_FAVICON_OK_TYPES" in app_src, "proxy must allowlist content-types"
    assert "image/svg" not in app_src, "SVG must never be in the favicon allowlist"
    assert "X-Content-Type-Options" in app_src, "proxy must send nosniff"
    assert "ctype not in _FAVICON_OK_TYPES" in app_src, "proxy must reject non-allowlisted types"


def test_favicon_host_extraction_robust():
    s = _src()
    body = s[s.index("_faviconFor(d)"):s.index("_faviconFor(d)") + 1500]
    assert "split('@')" in body, "must strip userinfo"
    assert "split(':')" in body, "must strip port"
    assert "replace(/^www\\./" in body, "must strip leading www"
    assert "indexOf('.') === -1" in body, "must require a dot in the host"


def test_favicon_applied_in_all_insertion_paths():
    assert _src().count("this._faviconFor(") >= 4, \
        "_faviconFor must be wired into every node-insertion path"


def test_thumbnail_style_present():
    assert "node[thumbnail]" in _src(), "the node[thumbnail] render style must remain"


def test_favicon_proxy_route_sanitizes():
    """The /api/favicon proxy 404s on empty/dotless hosts before any fetch (no SSRF, no network).

    Skips when the webapp/fastapi stack isn't importable (e.g. a bare system python without
    the project venv) so the required_check passes under either interpreter; the structural
    assertions above always run.
    """
    import pytest
    app = pytest.importorskip("investigations.webapp.app").app
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    client = TestClient(app)
    assert client.get("/api/favicon?domain=").status_code == 404
    assert client.get("/api/favicon?domain=nodot").status_code == 404
