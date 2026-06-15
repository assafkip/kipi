"""Frontend connection-wiring ratchet (prd-frontend-wiring-ratchet-2026-06-15).

Deterministic structural gate. It forbids the class the built-not-wired RCA
(2026-06-14) named: a feature works on its own surface, but the connection to
the next surface is delegated to the browser (tabs, Back, full-page reload), so
it breaks in the native pywebview app where that chrome does not exist. Third
instance of "convention not choke-point" — the cure is a choke-point, not more
discipline.

Three ratchets over investigations/webapp/templates/*.html:
  (a) no same-origin browser-delegated navigation
      (window.open('/...'), location.reload(), location.href='/...') — route
      these through the in-app nav shim (window.kipiNav.*) instead.
  (b) every internal href/fetch('/...') resolves to a registered FastAPI route
      (catches dead seams like an href to an unbuilt route).
  (c) a content-rendered href="#" (e.g. the [[entity]] replace) must bind a
      click handler, else the link goes nowhere.

Per-line escape hatch: put the token `wiring-allow` in a comment on the
offending line. One documented exception at a time — never a blanket skip.

This test IS the bypass_check on its issue spec, so dsse closeout registers it
into .prd-os/gates.jsonl as a standing, grows-only gate (like spine_gates.py).
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TEMPLATES_DIR = REPO / "investigations" / "webapp" / "templates"
APP_PY = REPO / "investigations" / "webapp" / "app.py"

# Static mounts are registered route prefixes too (app.mount).
STATIC_MOUNTS = ("/static", "/vault-assets", "/raw-assets")

ALLOW_TOKEN = "wiring-allow"


def _template_files():
    return sorted(TEMPLATES_DIR.glob("*.html"))


def _iter_lines():
    for path in _template_files():
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            yield path, lineno, line


def _allowed(line):
    return ALLOW_TOKEN in line


def _fmt(hits):
    return "\n".join(f"  {p.name}:{n}: {line.strip()[:120]}" for p, n, line in hits)


# ---------------------------------------------------------------------------
# (a) no same-origin browser-delegated navigation
# ---------------------------------------------------------------------------

# window.open('/...') / window.open("/...") / window.open(`/...`)  -> new tab,
#   no tabs in the native app.
# location.reload() / window.location.reload()  -> full-page reload crutch.
# location.href = '/...' (also .assign/.replace, same-origin)  -> full-page nav.
_NAV_BANS = (
    ("window.open(same-origin)", re.compile(r"""window\.open\(\s*['"`]/""")),
    ("location.reload()", re.compile(r"""\blocation\.reload\s*\(""")),
    ("location.href=/ (same-origin)",
     re.compile(r"""\blocation\.(href\s*=|assign\(|replace\()\s*['"`]/""")),
    # bare (window.)location = '/…' assignment — same full-page nav, the form the
    # first cut missed (cases/report-detail/reports/schema). Not preceded by a
    # dot, so a foo.location = … property assign on another object is not flagged.
    ("location = '/' (same-origin assignment)",
     re.compile(r"""(?:^|[;{(\s])(?:window\.)?location\s*=\s*['"`]/""")),
)


def test_no_browser_delegated_navigation():
    hits = []
    for path, lineno, line in _iter_lines():
        if _allowed(line):
            continue
        for _label, rx in _NAV_BANS:
            if rx.search(line):
                hits.append((path, lineno, line))
                break
    assert not hits, (
        "Same-origin browser-delegated navigation in templates — breaks in the "
        "native app. Route through window.kipiNav.* (go/back/refresh/openGraph) "
        f"or mark a necessary external line with `{ALLOW_TOKEN}`:\n" + _fmt(hits)
    )


# ---------------------------------------------------------------------------
# (b) every internal href/fetch('/...') resolves to a registered route
# ---------------------------------------------------------------------------

_ROUTE_RE = re.compile(r"""@app\.(?:get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""")


def _registered_route_regexes():
    """Compile each FastAPI route + static mount into a path regex.

    `{param}` -> one path segment; trailing template/concat wildcards in a
    caller path are matched by prefix below, not here.
    """
    text = APP_PY.read_text()
    regexes = []
    raw_paths = set(_ROUTE_RE.findall(text)) | set(STATIC_MOUNTS)
    for route in raw_paths:
        pat = re.sub(r"\{[^}]+\}", r"[^/]+", route)
        regexes.append((route, re.compile("^" + pat + "$")))
    return sorted(raw_paths), regexes


# href="/..."  /  fetch('/...')  /  kipiNav.go('/...')  -- internal path literals.
_HREF_RE = re.compile(r"""href=["'](/[^"'#?][^"']*)["']""")
_FETCH_RE = re.compile(r"""(?:fetch|kipiNav\.go|kipiNav\.openGraph)\(\s*['"`](/[^'"`]*)""")


def _normalize_caller_path(raw):
    """Strip query/fragment, collapse template/JS expressions to a wildcard."""
    path = raw.split("?", 1)[0].split("#", 1)[0]
    path = re.sub(r"\{\{.*?\}\}", "_", path)   # Jinja {{ x }}
    path = re.sub(r"\$\{.*?\}", "_", path)     # template literal ${x}
    return path


def _caller_paths():
    seen = {}
    for path, lineno, line in _iter_lines():
        if _allowed(line):
            continue
        for rx in (_HREF_RE, _FETCH_RE):
            for raw in rx.findall(line):
                norm = _normalize_caller_path(raw)
                seen.setdefault(norm, (path, lineno, line))
    return seen


def _resolves(norm, route_paths, route_regexes):
    # exact / param match
    for _route, rx in route_regexes:
        if rx.match(norm):
            return True
    # concatenated dynamic path: caller captured only the static prefix
    # (e.g. '/api/entity/' + id + '/flag'); OK if any route starts with it.
    for route in route_paths:
        if route.startswith(norm):
            return True
    # static asset under a mount
    if any(norm == m or norm.startswith(m + "/") for m in STATIC_MOUNTS):
        return True
    return False


def test_internal_links_resolve_to_registered_routes():
    route_paths, route_regexes = _registered_route_regexes()
    unresolved = []
    for norm, (path, lineno, line) in sorted(_caller_paths().items()):
        if "_" in norm and norm.rstrip("/_").count("/") == 0:
            continue  # fully-dynamic root-level path, nothing to resolve
        if not _resolves(norm, route_paths, route_regexes):
            unresolved.append((path, lineno, line))
    assert not unresolved, (
        "Internal href/fetch path does not resolve to any registered FastAPI "
        "route (dead seam). Register the route or fix the path:\n"
        + _fmt(unresolved)
    )


# ---------------------------------------------------------------------------
# (c) content-rendered href="#" must bind a click handler
# ---------------------------------------------------------------------------

# Any anchor with a bare href="#" (raw or backslash-escaped) and NO handler
# token on the same line is a dead link — clicking it does nothing. Scanned on
# every line (not only `.replace(`), so a dead anchor built via innerHTML, a
# template literal, or static HTML is caught too — not just the [[entity]]
# replace idiom (synthesis.html, entity.html). `href="#section"` in-page anchors
# are NOT matched (the regex requires the quote right after `#`).
_DEAD_ANCHOR_RE = re.compile(r"""href=\\*["']#\\*["']""")
_HANDLER_TOKENS = ("onclick", "@click", "addEventListener",
                   "kipiNav.", "data-entity", "data-nav")


def test_content_rendered_anchors_bind_a_handler():
    hits = []
    for path, lineno, line in _iter_lines():
        if _allowed(line):
            continue
        if not _DEAD_ANCHOR_RE.search(line):
            continue
        if any(tok in line for tok in _HANDLER_TOKENS):
            continue
        hits.append((path, lineno, line))
    assert not hits, (
        'Content-rendered href="#" with no click handler — the rendered link '
        "goes nowhere. Bind a handler (kipiNav.entity / onclick) or use a data "
        "attribute + delegated listener:\n" + _fmt(hits)
    )
