"""All-surfaces render smoke (issue all-surfaces-render-smoke).

The graph blank-render bug was invisible because no test executed JS on that
surface — and ~20 OTHER Alpine surfaces had the same blind spot. This is the
generalized guard: every HTML GET route, DISCOVERED from the FastAPI app (not a
hardcoded list, so a new page is auto-covered), loaded headless against a seeded
DB, must:
  - return status < 400,
  - raise zero uncaught JS errors (pageerror),
  - have zero FAILED same-origin data fetch/xhr (a 4xx/5xx data call blanks an
    Alpine page; asset 404s are ignored by resource-type),
  - leave no element stuck under x-cloak (Alpine actually booted), and
  - render non-trivial content in its <main> region (excludes shared chrome).

Param routes are filled from seeded fixtures; any discovered route that is
neither fillable nor in _EXCLUDED FAILS the ratchet, so coverage can't silently
shrink. Skips when chromium is unavailable (enforced where the cached browser is
present). See prd-render-smoke-sweep.
"""
import re

import pytest

pytest.importorskip("playwright.sync_api", reason="playwright not installed (pip install playwright)")
from playwright.sync_api import sync_playwright  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402

from investigations.storage import db  # noqa: E402
from investigations.tests import browser_smoke as bs  # noqa: E402

# Discovered HTML routes we cannot fixture yet -> excluded WITH a reason. The
# ratchet fails if a discovered route is neither fillable nor listed here.
_EXCLUDED = {
    "/briefs/{group_idx}": "no seeded brief-group fixture (briefs require a synthesized brief)",
}


def _html_routes(app):
    out = set()
    for r in app.routes:
        if "GET" not in (getattr(r, "methods", None) or set()):
            continue
        rc = getattr(r, "response_class", None)
        rc = getattr(rc, "value", rc)  # unwrap FastAPI Default(...)
        if rc is HTMLResponse:
            out.add(r.path)
    return sorted(out)


def _seed(db_path):
    info = bs.seed_graph(db_path)
    with db.connect(db_path) as c:
        rid = c.execute(
            "SELECT id FROM reports WHERE investigation = ? ORDER BY id LIMIT 1",
            (info["case"],),
        ).fetchone()[0]
    return {"entity_id": info["focus_id"], "report_id": rid, "case": info["case"]}


def _fill(path, params):
    """Fill {param} path segments from the fixture map; None if any is unfillable."""
    sentinel = "\x00"
    filled = re.sub(r"\{([^}]+)\}", lambda m: str(params.get(m.group(1), sentinel)), path)
    return None if sentinel in filled else filled


def _launch(p):
    try:
        return p.chromium.launch(headless=True)
    except Exception as exc:
        pytest.skip(f"chromium unavailable (run: playwright install chromium): {exc}")


def test_all_html_surfaces_render(tmp_path):
    from investigations.webapp.app import app

    db_path = tmp_path / "sweep.db"
    fx = _seed(db_path)
    params = {"entity_id": fx["entity_id"], "report_id": fx["report_id"]}
    routes = _html_routes(app)

    # Ratchet: every discovered param route is fixturable or explicitly excluded.
    uncovered = [r for r in routes
                 if "{" in r and r not in _EXCLUDED and _fill(r, params) is None]
    assert not uncovered, (
        f"discovered HTML route(s) with unfilled params and not in _EXCLUDED: {uncovered}. "
        "Add a fixture param or add to _EXCLUDED with a reason — coverage must not silently shrink."
    )

    targets = [u for r in routes if r not in _EXCLUDED for u in [_fill(r, params)] if u is not None]
    assert targets, "no HTML routes discovered — discovery is broken"

    failures = []
    with bs.serve(db_path) as base, sync_playwright() as p:
        browser = _launch(p)
        try:
            # Run as an analyst with a case selected (realistic) — also lets
            # case-scoped pages like the print-export /report/render render.
            ctx = browser.new_context(viewport={"width": 1430, "height": 940})
            ctx.add_cookies([{"name": "case", "value": fx["case"], "url": base}])
            for route in targets:
                page = ctx.new_page()
                errs, bad_fetch = [], []
                page.on("pageerror", lambda e, _e=errs: _e.append(str(e)))

                def _on_response(resp, _base=base, _bad=bad_fetch):
                    try:
                        if (resp.url.startswith(_base)
                                and resp.request.resource_type in ("fetch", "xhr")
                                and resp.status >= 400):
                            _bad.append(f"{resp.status} {resp.url}")
                    except Exception:
                        pass

                page.on("response", _on_response)
                page.on("requestfailed", lambda req, _bad=bad_fetch: (
                    _bad.append(f"failed {req.url}")
                    if req.url.startswith(base) and req.resource_type in ("fetch", "xhr") else None
                ))
                try:
                    resp = page.goto(base + route, wait_until="load", timeout=20000)
                    page.wait_for_timeout(800)  # let Alpine + initial fetches settle
                    status = resp.status if resp else 0
                    stuck = page.eval_on_selector_all(
                        "[x-cloak]", "els => els.filter(e => getComputedStyle(e).display === 'none').length")
                    main_text = page.evaluate(
                        "() => { const m = document.querySelector('main');"
                        " return ((m || document.body).innerText || '').trim(); }")
                    probs = []
                    if status >= 400:
                        probs.append(f"status {status}")
                    if errs:
                        probs.append(f"pageerror: {errs[0][:120]}")
                    if bad_fetch:
                        probs.append(f"failed data call: {bad_fetch[0][:120]}")
                    if stuck:
                        probs.append(f"{stuck} element(s) stuck under x-cloak (Alpine did not boot)")
                    if len(main_text) < 20:
                        probs.append(f"main region blank ({len(main_text)} chars)")
                    if probs:
                        failures.append(f"{route}: " + "; ".join(probs))
                except Exception as exc:
                    failures.append(f"{route}: EXC {str(exc)[:140]}")
                finally:
                    page.close()
        finally:
            browser.close()

    assert not failures, (
        f"render smoke failed on {len(failures)}/{len(targets)} surface(s):\n  "
        + "\n  ".join(failures)
    )
