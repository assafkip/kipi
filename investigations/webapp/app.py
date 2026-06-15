"""FastAPI webapp for kipi-investigations."""
import asyncio
import json
import logging
import os
from pathlib import Path

import re
import time
import urllib.parse
import urllib.request

from fastapi import FastAPI, Request, UploadFile, File, Form, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from investigations.storage import db
from investigations import store
from investigations.enrich import get_adapter
from investigations.enrich import runner as enrich_runner
from investigations.enrich import base as enrich_base
from investigations import alerts as alerts_mod
from investigations import claims as claims_mod
from investigations import annotations as annotations_mod
from investigations import activity as activity_mod
from investigations import client_report as client_report_mod
from investigations import seen as seen_mod
from investigations import ask as ask_mod
from investigations import hypotheses as hypotheses_mod

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
APP_DIR = Path(__file__).parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"
VAULT_DIR = ROOT / "investigations" / "vault"
ASSETS_DIR = ROOT / "investigations" / "assets"

app = FastAPI(title="kipi-investigations")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _cluster_style(cid) -> str:
    """Deterministic per-cluster CSS for a colored chip. Matches the JS
    clusterColor() helper in _layout.html so colors line up across views."""
    if cid is None or cid == "":
        return "color: #475569; background: rgba(71,85,105,0.10); border: 1px solid #D6D3CC;"
    try:
        cid = int(cid)
    except (TypeError, ValueError):
        return ""
    h = (cid * 137.5) % 360
    # Light variant: legible dark hue text on a soft tint (matches window.clusterColor).
    return (
        f"color: hsl({h:.1f} 70% 32%); "
        f"background: hsl({h:.1f} 60% 94%); "
        f"border: 1px solid hsl({h:.1f} 45% 78%);"
    )


templates.env.filters["cluster_style"] = _cluster_style


def _md_to_html(text: str | None) -> str:
    """Render a SAFE subset of markdown to HTML for agent/report text shown in tabs
    (so '**Source:**' renders bold, not literal). Escapes HTML first, so untrusted
    report/agent text can't inject markup. Mirrors the client-side renderMd(). Use as
    `{{ text | md | safe }}` — the |safe is sound because we escaped before transforming."""
    import re as _r
    if not text:
        return ""
    h = (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    # headers (#, ##, ###) → bold lines; **bold**; *italic*; `code`; [t](url)
    h = _r.sub(r"(?m)^#{1,6}\s*(.+)$", r"<strong>\1</strong>", h)
    h = _r.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", h)
    h = _r.sub(r"(?<!\*)\*(?!\s)([^*\n]+?)\*(?!\*)", r"<em>\1</em>", h)
    h = _r.sub(r"`([^`]+?)`", r"<code>\1</code>", h)
    h = _r.sub(r"\[([^\]]+?)\]\((https?://[^)\s]+?)\)",
               r'<a href="\2" target="_blank" class="text-accent hover:underline">\1</a>', h)
    # bullet blocks → <ul>
    def _ul(m):
        items = [ln.strip()[2:] for ln in m.group(0).strip().split("\n")]
        return "<ul class='list-disc ml-4'>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"
    h = _r.sub(r"(?m)(?:^[-*] .+(?:\n|$))+", _ul, h)
    # paragraphs / line breaks
    out = []
    for block in _r.split(r"\n{2,}", h):
        b = block.strip()
        if not b:
            continue
        out.append(b if _r.match(r"^<(ul|ol|h\d|blockquote|strong)", b)
                   else "<p>" + b.replace("\n", "<br>") + "</p>")
    return "".join(out)


templates.env.filters["md"] = _md_to_html

# Ensure the static-mounted dirs exist so a FRESH instance (no data yet) boots —
# they're otherwise only created once reports are ingested / the vault exported.
for _d in (STATIC_DIR, VAULT_DIR / "assets", ASSETS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.mount("/vault-assets", StaticFiles(directory=str(VAULT_DIR / "assets")), name="vault-assets")
app.mount("/raw-assets", StaticFiles(directory=str(ASSETS_DIR)), name="raw-assets")


def _role(notes):
    if not notes:
        return ""
    return (notes or "").split(" — ")[0].replace("role:", "").strip()


CASE_COOKIE = "case"
ALL_CASES = "__all__"


import re as _re
_SLUG_RE = _re.compile(r"^[a-z0-9][a-z0-9_-]*$")


def _valid_slug(slug: str | None) -> bool:
    return bool(slug) and bool(_SLUG_RE.match(slug))


def _slugify(s: str | None) -> str | None:
    """Turn a free-typed case name into a valid slug ('John Doe' -> 'john-doe')."""
    s = _re.sub(r"[^a-z0-9]+", "-", (s or "").strip().lower()).strip("-")
    return s[:60] or None


ANALYST_COOKIE = "analyst"


def _clean_analyst(name: str | None) -> str:
    """Printable, slash-free, length-bounded — safe for cookies + display."""
    name = "".join(ch for ch in (name or "") if ch.isprintable() and ch != "/").strip()[:40]
    return name or "anonymous"


def _active_analyst(request: Request) -> str:
    """The name the analyst set for this session (attribution only, no auth).

    Sanitized on read too, so a hand-crafted cookie can't smuggle junk into the
    activity feed / attribution labels.
    """
    return _clean_analyst(request.cookies.get(ANALYST_COOKIE))


def _active_cases(request: Request) -> list[str]:
    """All case slugs the analyst has selected (multi-select). The cookie holds a
    comma-joined set; '__all__' / missing / malformed → [] meaning 'all cases'.
    Each slug is validated (path-traversal guard) so junk can't reach a query."""
    c = request.cookies.get(CASE_COOKIE)
    if not c or c == ALL_CASES:
        return []
    out, seen = [], set()
    for s in c.split(","):
        s = s.strip()
        if _valid_slug(s) and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _active_case(request: Request) -> str | None:
    """The SINGLE case for per-case operations (brief filename, client report,
    activity stamp). Returns the slug only when exactly one case is selected;
    None for 'all cases' OR a multi-case selection (those ops then run unscoped
    or ask the analyst to narrow)."""
    cases = _active_cases(request)
    return cases[0] if len(cases) == 1 else None


# --- PRD-11: one "data changed → refresh" signal --------------------------------
import threading as _change_threading

# Every mutation routes through store.apply_mutation, which bumps the case's
# DB-backed version (investigations.version) inside the SAME transaction as the
# write — so CLI/pipeline mutations refresh open views too (the old in-memory
# dict could not, and a forgotten bump went silent: gap 2). These wrappers serve
# (a) route sites whose underlying helper isn't store-migrated yet and (b) the
# /api/changed reader. Pass conn= to join an open transaction — NEVER open a
# second connection while holding an uncommitted write (SQLite single-writer).


def bump_case(case, conn=None) -> int:
    """Signal that `case` data changed. Open views re-fetch on their next poll."""
    if not case:
        return 0
    if conn is not None:
        return store.bump_case(conn, case)
    with db.connect() as fresh:
        return store.bump_case(fresh, case)


def case_version(case, conn=None) -> int:
    """Current change version for `case` (0 if never bumped)."""
    if not case:
        return 0
    if conn is not None:
        return store.case_version(conn, case)
    with db.connect() as fresh:
        return store.case_version(fresh, case)


@app.get("/api/changed")
async def api_changed(case: str = "", since: int = 0):
    """Cheap poll: has `case` data changed since version `since`? The shared client
    subscriber (in _layout.html) hits this and re-fetches the open view on a bump."""
    version = case_version(case)
    return JSONResponse({"case": case, "version": version, "changed": version > since})


# Same-origin favicon proxy (issue node-favicons; founder decision 2026-06-12). cytoscape
# forces CORS on node background-images and Google's s2/favicons sends no CORS header, so a
# direct favicon URL is blocked. This route fetches it server-side and serves it from the
# kipi origin, which the browser renders cleanly. Privacy is identical to the founder's
# Google choice (Google still sees the domains, just server-side). Read-only; the `domain`
# is sanitized and only ever passed to Google's fixed URL as a query param (no SSRF).
_FAVICON_CACHE: dict = {}          # host -> (bytes, content_type, fetched_at)
_FAVICON_TTL = 7 * 24 * 3600       # a week
_FAVICON_MAX = 2000                # bound the in-memory cache
# Allowlist inert raster/icon types only — never relay SVG (a script vector) or a spoofed
# Content-Type from the (analyst-choosable) favicon source on our own origin (Codex).
_FAVICON_OK_TYPES = frozenset({
    "image/png", "image/x-icon", "image/vnd.microsoft.icon",
    "image/jpeg", "image/gif", "image/webp",
})
_FAVICON_HEADERS = {"Cache-Control": "max-age=604800", "X-Content-Type-Options": "nosniff"}


@app.get("/api/favicon")
async def api_favicon(domain: str = ""):
    host = re.sub(r"[^a-z0-9.\-]", "", (domain or "").strip().lower())
    if not host or "." not in host:
        return Response(status_code=404)
    now = time.time()
    hit = _FAVICON_CACHE.get(host)
    if hit and now - hit[2] < _FAVICON_TTL:
        return Response(content=hit[0], media_type=hit[1], headers=_FAVICON_HEADERS)
    url = "https://www.google.com/s2/favicons?sz=64&domain=" + urllib.parse.quote(host)

    def _fetch():
        req = urllib.request.Request(url, headers={"User-Agent": "kipi-favicon-proxy"})
        with urllib.request.urlopen(req, timeout=6) as r:   # nosec: fixed Google host
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            return r.read(), ct

    try:
        data, ctype = await run_in_threadpool(_fetch)
    except Exception:
        return Response(status_code=404)
    if not data or ctype not in _FAVICON_OK_TYPES:   # reject SVG + spoofed/empty types
        return Response(status_code=404)
    if len(_FAVICON_CACHE) >= _FAVICON_MAX:
        _FAVICON_CACHE.clear()
    _FAVICON_CACHE[host] = (data, ctype, now)
    return Response(content=data, media_type=ctype, headers=_FAVICON_HEADERS)


def _case_in(cases, col: str = "r.investigation"):
    """(sql_fragment, params) for an IN-filter on a case-set. Accepts a list, a
    single slug, or None/[] (→ empty fragment = all cases)."""
    if isinstance(cases, str):
        cases = [cases]
    cases = [c for c in (cases or []) if c]
    if not cases:
        return "", []
    return f"{col} IN ({','.join('?' for _ in cases)})", list(cases)


def _all_cases(conn) -> list[dict]:
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT i.slug, i.client, i.case_name, i.status, "
            "i.investigation_type, i.type_status, "
            "(SELECT COUNT(*) FROM reports r WHERE r.investigation = i.slug) AS report_count, "
            "(SELECT MAX(r.ingested_at) FROM reports r WHERE r.investigation = i.slug) AS last_activity "
            "FROM investigations i "
            "ORDER BY last_activity DESC NULLS LAST, i.slug"
        ).fetchall()]
    except Exception:
        # Pre-migration DB (no type columns) — fall back to the base columns.
        rows = [dict(r) for r in conn.execute(
            "SELECT i.slug, i.client, i.case_name, i.status, "
            "(SELECT COUNT(*) FROM reports r WHERE r.investigation = i.slug) AS report_count, "
            "(SELECT MAX(r.ingested_at) FROM reports r WHERE r.investigation = i.slug) AS last_activity "
            "FROM investigations i ORDER BY last_activity DESC NULLS LAST, i.slug").fetchall()]
        for c in rows:
            c["investigation_type"], c["type_status"] = None, None
    # The schema 'domain' (fine description) is the fallback label when no coarse
    # type was detected yet. One small read, tolerant of pre-migration DBs.
    try:
        srows = {r["case_slug"]: (r["schema_json"], r["status"]) for r in conn.execute(
            "SELECT case_slug, schema_json, status FROM case_schemas")}
    except Exception:
        srows = {}
    import json as _json
    for c in rows:
        raw = srows.get(c["slug"])
        c["schema_status"] = raw[1] if raw else None
        c["domain"] = None
        if raw:
            try:
                c["domain"] = (_json.loads(raw[0]) or {}).get("domain") or None
            except (TypeError, _json.JSONDecodeError):
                pass
        # Coarse detected type wins for the badge; schema domain is the fallback.
        if not c.get("investigation_type"):
            c["investigation_type"] = c["domain"]
    return rows


def _scope(cases, alias: str = "e"):
    """Entity-scope predicate for the active case-SET (global pool, case-scoped
    views). Accepts a list of slugs, a single slug, or None/[] (→ all cases).

    Returns (sql_fragment, params). Empty when no case is active so callers can
    drop it straight into a WHERE chain. Restricts to entities that have a
    mention in a report belonging to ANY of the selected cases.
    """
    if isinstance(cases, str):
        cases = [cases]
    cases = [c for c in (cases or []) if c]
    if not cases:
        return "", []
    ph = ",".join("?" for _ in cases)
    return (
        f"AND {alias}.id IN (SELECT m.entity_id FROM mentions m "
        f"JOIN reports r ON r.id = m.report_id WHERE r.investigation IN ({ph}))",
        list(cases),
    )


def _log(request, conn, action, **kw):
    """Stamp an activity entry with the current analyst AND active case, so the
    case-scoped feed isn't empty."""
    kw.setdefault("investigation", _active_case(request))
    activity_mod.log(conn, _active_analyst(request), action, **kw)


def _synth_path(case: str | None) -> Path:
    """Where the synthesis brief for a case (or the global brief) lives."""
    return VAULT_DIR / (f"synthesis-{case}.md" if case else "synthesis.md")


def _brief_freshness(conn, case: str | None) -> tuple[str, dict | None]:
    """('none'|'fresh'|'stale', stale_detail). The brief bakes in the report count
    at generation time; compare to the live count so an out-of-date brief can't
    read as current. Shared by the synthesis page and the lifecycle rail."""
    path = _synth_path(case)
    if not path.exists():
        return "none", None
    content = path.read_text(encoding="utf-8")
    m = _re.search(r"^reports:\s*(\d+)", content, _re.MULTILINE)
    gen = int(m.group(1)) if m else None
    if case:
        live = conn.execute("SELECT COUNT(*) AS n FROM reports WHERE investigation = ?",
                            (case,)).fetchone()["n"]
    else:
        live = conn.execute("SELECT COUNT(*) AS n FROM reports").fetchone()["n"]
    if gen is not None and gen != live:
        return "stale", {"generated_for": gen, "live": live}
    return "fresh", None


def _lifecycle_state(conn, case: str | None) -> list[dict] | None:
    """The six investigation stages for a single active case, each with a done
    flag + a short detail. Drives the sidebar stage badges and the progress rail.
    None for 'all cases' / multi-select (the rail is per-case)."""
    if not case:
        return None

    def _count(sql, *params):
        try:
            return conn.execute(sql, params).fetchone()[0]
        except Exception:
            return 0

    reports = _count("SELECT COUNT(*) FROM reports WHERE investigation = ?", case)
    runs = _count("SELECT COUNT(*) FROM enrichment_runs "
                  "WHERE provider_slug = 'agent' AND investigation = ?", case)
    findings = _count(
        "SELECT COUNT(*) FROM enrichment_results er "
        "JOIN enrichment_runs r ON r.id = er.run_id "
        "WHERE r.provider_slug = 'agent' AND r.investigation = ? "
        "AND er.result_type = 'finding'", case)
    fresh, _detail = _brief_freshness(conn, case)
    crosscase = _count(
        "SELECT COUNT(*) FROM (SELECT m.entity_id FROM mentions m "
        "JOIN reports r ON r.id = m.report_id WHERE m.entity_id IN "
        "(SELECT m2.entity_id FROM mentions m2 JOIN reports r2 ON r2.id = m2.report_id "
        "WHERE r2.investigation = ?) GROUP BY m.entity_id "
        "HAVING COUNT(DISTINCT r.investigation) >= 2)", case)

    def _plural(n, word):
        return f"{n} {word}" + ("" if n == 1 else "s")

    # The schema/Understand stage is GONE from the lifecycle: the tool auto-models
    # the case schema during Process, so there's nothing for the analyst to do or
    # see here (founder decision 2026-06-10). Stages: Intake → Investigate →
    # Deliver → Portfolio.
    return [
        {"key": "intake", "num": 1, "label": "Intake", "href": "/reports",
         "done": reports > 0, "count": reports, "detail": _plural(reports, "report")},
        # Investigate + Findings are ONE stage: same data (agent runs and what they
        # found), one page with a Trail/Findings toggle. The detail shows both.
        {"key": "investigate", "num": 2, "label": "Investigate", "href": "/runs",
         "done": runs > 0, "count": runs,
         "detail": _plural(runs, "run") + (f" · {_plural(findings, 'finding')}" if findings else "")},
        {"key": "deliver", "num": 3, "label": "Deliver", "href": "/synthesis",
         "done": fresh == "fresh",
         "detail": {"none": "no brief", "fresh": "brief fresh", "stale": "brief stale"}[fresh]},
        {"key": "portfolio", "num": 4, "label": "Portfolio", "href": "/cross-case",
         "done": crosscase > 0, "count": crosscase, "detail": _plural(crosscase, "shared entity")},
    ]


# Per-stage primary action. The design rule (ui-ux-pro-max `primary-action`): every
# screen has exactly ONE primary CTA. The active case's single next move is the first
# lifecycle stage that isn't done — surfaced as a persistent "Next step" strip + as
# the primary button in every empty state. label, href, one-line hint.
_STAGE_ACTIONS = {
    "intake":      ("Add reports",             "/reports",    "Drop files or paste text to start the case."),
    "investigate": ("Run the investigator",    "/runs?run=1", "Send the agent to dig the case end-to-end (it picks its own targets), then review + promote what it finds."),
    "deliver":     ("Write the brief",         "/synthesis",  "Generate the deliverable from the findings."),
    "portfolio":   ("Compare across cases",    "/cross-case", "See what this case shares with your others."),
}


def _next_action(stages) -> dict | None:
    """The single primary next move for the active case: the first stage not yet
    done. None for all/multi-case (no stages). When every stage is done, point at
    the deliverable. Also carries `ready`: done stages that have content to view
    now (so a page can say 'your work is over here')."""
    if not stages:
        return None
    ready = [{"label": s["label"], "href": s["href"], "count": s.get("count")}
             for s in stages if s.get("done") and (s.get("count") or s["key"] == "deliver")]
    for s in stages:
        if not s.get("done"):
            label, href, hint = _STAGE_ACTIONS[s["key"]]
            return {"key": s["key"], "num": s["num"], "label": label,
                    "href": href, "hint": hint, "ready": ready}
    return {"key": "done", "num": 6, "label": "Open the brief", "href": "/synthesis",
            "hint": "Every stage is complete — read or export the deliverable.", "ready": ready}


def _tpl(request, name, ctx):
    # Read-only render path — skip the schema migration (runs at startup/ingest).
    with db.connect(migrate=False) as conn:
        nav = ctx.get("nav") or {
            "active_case": _active_case(request),
            "cases": _all_cases(conn),
        }
        if "cases" not in nav:
            nav["cases"] = _all_cases(conn)
        # Prune the selected case-SET to slugs that still exist. A DB reset or a
        # deleted/renamed case otherwise leaves a stale cookie that renders a ghost
        # chip in the selector (and scopes every query to a case with no rows).
        known = {c["slug"] for c in nav["cases"]}
        raw_selected = _active_cases(request)
        selected = [s for s in raw_selected if s in known]
        nav["active_cases"] = selected
        # Keep the single-active-case (drives brief filename, lifecycle rail) in
        # sync with the pruned set: a slug only when exactly one real case is chosen.
        nav["active_case"] = selected[0] if len(selected) == 1 else None
        nav["open_alerts"] = alerts_mod.open_count(conn)
        try:
            nav["open_corrections"] = claims_mod.count_contradictions(conn)
        except Exception:
            nav["open_corrections"] = 0
        # Lifecycle stage state for the sidebar badges + progress rail (per single
        # active case; None when viewing all/multiple cases).
        nav["stages"] = _lifecycle_state(conn, nav["active_case"])
        # Single source of truth for "what do I do next" — drives the persistent
        # Next-step strip and every empty state's primary button.
        nav["next_action"] = _next_action(nav["stages"])
    nav["analyst"] = _active_analyst(request)
    resp = templates.TemplateResponse(request, name, {**ctx, "nav": nav})
    # Self-heal the cookie when the selection drifted from what still exists.
    if selected != raw_selected:
        if selected:
            resp.set_cookie(CASE_COOKIE, ",".join(selected))
        else:
            resp.delete_cookie(CASE_COOKIE)
    return resp


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    selected = _active_cases(request)        # the chosen case-SET ([] = all)
    with db.connect() as conn:
        cases = _all_cases(conn)
        known = {c["slug"] for c in cases}
        # Separation-first: with no case chosen yet (no cookie at all), send the
        # analyst to the picker to click into a case rather than landing on a
        # mixed all-cases view. An explicit 'All cases' choice (cookie=__all__)
        # is respected and shows the full view.
        if request.cookies.get(CASE_COOKIE) is None and cases:
            return RedirectResponse(url="/cases", status_code=302)
        # Any stale/unknown slug in the selection (DB reset, renamed/deleted case)
        # → don't trap the analyst on an all-zeros view; clear it, send to picker.
        if selected and not set(selected) <= known:
            resp = RedirectResponse(url="/cases", status_code=302)
            resp.delete_cookie(CASE_COOKIE)
            return resp
        # Focus is the home/command-center; the Focus ranking is per single case
        # (union when multiple/all are selected).
        focus = _load_focus(selected[0] if len(selected) == 1 else None, conn)
        # A single, unprocessed case has no graph yet — don't dead-end on an empty
        # canvas. Send the analyst to Reports, where Process runs (schema is
        # auto-modeled, no approval step). The graph home returns once it's processed.
        if len(selected) == 1 and not focus.get("items"):
            return RedirectResponse(url="/reports", status_code=302)
    # Home IS "a chat with a graph": land the analyst directly in the docked
    # chat+graph view (graph.html renders the investigator chat beside a live
    # canvas), not the lifecycle dashboard. The redirects above still guard the
    # no-case (pick one) and unprocessed (run Process) states.
    return _tpl(request, "graph.html", {})


def _scoped_stats(conn, cases) -> dict:
    """Dashboard counters, scoped to the active case-SET (list/slug). Empty → all."""
    inq, inp = _case_in(cases)
    if not inq:
        return db.db_stats(conn)
    rinq, _ = _case_in(cases)                       # alias 'r.investigation'
    p = tuple(inp)
    one = lambda sql: conn.execute(sql, p).fetchone()["n"]
    return {
        "reports": one(f"SELECT COUNT(*) AS n FROM reports r WHERE {rinq}"),
        "entities": one(
            "SELECT COUNT(DISTINCT m.entity_id) AS n FROM mentions m "
            f"JOIN reports r ON r.id = m.report_id WHERE {rinq}"),
        "mentions": one(
            "SELECT COUNT(*) AS n FROM mentions m "
            f"JOIN reports r ON r.id = m.report_id WHERE {rinq}"),
        "relationships": one(
            "SELECT COUNT(*) AS n FROM relationships rel "
            f"JOIN reports r ON r.id = rel.report_id WHERE {rinq}"),
        "assets": one(
            "SELECT COUNT(*) AS n FROM assets a "
            f"JOIN reports r ON r.id = a.report_id WHERE {rinq}"),
        "top_entities": conn.execute(
            "SELECT e.canonical_name, e.entity_type, COUNT(m.id) AS mention_count "
            "FROM entities e JOIN mentions m ON m.entity_id = e.id "
            f"JOIN reports r ON r.id = m.report_id WHERE {rinq} "
            "GROUP BY e.id ORDER BY mention_count DESC LIMIT 10", p).fetchall(),
    }


@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request):
    with db.connect() as conn:
        cases = _all_cases(conn)
        nav = {"active_case": _active_case(request), "cases": cases}
    return _tpl(request, "cases.html", {"cases": cases, "nav": nav})


# Single source of truth lives in investigations.alerts (cross-case panel and
# alert detection must agree on what counts as generic infrastructure noise).
GENERIC_INFRA = alerts_mod.GENERIC_INFRA


@app.get("/cross-case", response_class=HTMLResponse)
async def cross_case_page(request: Request):
    """Actors/indicators that appear in 2+ cases — the pivot intel.

    With a case active, narrows to entities that touch THIS case and at least
    one other. With 'All cases', shows every overlap.
    """
    cases = _active_cases(request)
    placeholders = ",".join("?" for _ in GENERIC_INFRA)
    scope_sql, scope_params = _scope(cases)
    with db.connect() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT e.id, e.canonical_name, e.entity_type, e.notes, e.sub_role, "
            "COALESCE(s.threat_score, 0) AS threat_score, "
            "COUNT(DISTINCT r.investigation) AS case_count, "
            "GROUP_CONCAT(DISTINCT r.investigation) AS cases "
            "FROM entities e "
            "JOIN mentions m ON m.entity_id = e.id "
            "JOIN reports r ON r.id = m.report_id "
            "LEFT JOIN entity_scores s ON s.entity_id = e.id "
            "WHERE r.investigation IS NOT NULL "
            "AND (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
            "AND e.entity_type != 'person_candidate' "
            f"AND e.canonical_name NOT IN ({placeholders}) "
            f"{scope_sql} "
            "GROUP BY e.id "
            "HAVING case_count >= 2 "
            "ORDER BY case_count DESC, threat_score DESC",
            (*GENERIC_INFRA, *scope_params),
        ).fetchall()]
        # Drop date-shaped / low-confidence noise (shared rule with alerts).
        rows = [r for r in rows
                if alerts_mod.is_pivotable(r["canonical_name"], r["entity_type"])]
        for r in rows:
            r["role"] = _role(r.get("notes"))
            r["case_list"] = [c for c in (r["cases"] or "").split(",") if c]
        nav = {"active_case": _active_case(request), "cases": _all_cases(conn)}
    return _tpl(request, "cross-case.html", {"entities": rows, "nav": nav})


@app.get("/corrections", response_class=HTMLResponse)
async def corrections_page(request: Request):
    return _tpl(request, "corrections.html", {"signals_delta": _signals_delta(request)})


@app.get("/api/corrections")
async def api_corrections(request: Request):
    # Read-only: claims are backfilled on ingest + by `./invctl corrections`.
    with db.connect() as conn:
        cons = claims_mod.detect_contradictions(conn, _active_cases(request))
    return JSONResponse({"contradictions": cons, "count": len(cons)})


@app.post("/api/claims/{claim_id}/resolve")
async def api_claim_resolve(request: Request, claim_id: int):
    with db.connect() as conn:
        result = claims_mod.resolve(conn, claim_id)
        if not result.get("error"):
            _log(request, conn,"resolved a contradiction",
                             detail=f"claim {claim_id} authoritative")
        status = 400 if result.get("error") else 200
    if not result.get("error"):
        bump_case(_active_case(request))
    return JSONResponse(result, status_code=status)


@app.post("/api/claims/{claim_id}/reject")
async def api_claim_reject(request: Request, claim_id: int):
    with db.connect() as conn:
        result = claims_mod.reject(conn, claim_id)
        if not result.get("error"):
            _log(request, conn,"rejected a claim",
                             detail=f"claim {claim_id}")
    if not result.get("error"):
        bump_case(_active_case(request))
    return JSONResponse(result)


def _signals_delta(request: Request) -> dict:
    """Compute 'since you last looked' for the active analyst+case, then stamp the
    view forward. Called by every Signals inbox tab so the delta strip is the same
    across Alerts / Changes / Activity, and opening any tab marks the inbox seen."""
    analyst = _active_analyst(request)
    case = _active_case(request)
    with db.connect() as conn:
        since = seen_mod.get_last_seen(conn, analyst, case)
        delta = seen_mod.compute_delta(conn, analyst, case, since)
        seen_mod.mark_seen(conn, analyst, case)
    return delta


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    return _tpl(request, "alerts.html", {"signals_delta": _signals_delta(request)})


@app.get("/api/alerts")
async def api_alerts(include_ack: bool = False):
    with db.connect() as conn:
        return JSONResponse({"alerts": alerts_mod.list_alerts(conn, include_ack=include_ack),
                             "open_count": alerts_mod.open_count(conn)})


@app.post("/api/alerts/{alert_id}/ack")
async def api_alert_ack(request: Request, alert_id: int):
    with db.connect() as conn:
        alerts_mod.acknowledge(conn, alert_id)
        _log(request, conn,"acknowledged alert",
                         detail=f"alert {alert_id}")
        return JSONResponse({"ok": True, "open_count": alerts_mod.open_count(conn)})


@app.post("/api/alerts/ack-all")
async def api_alert_ack_all(request: Request):
    with db.connect() as conn:
        n = alerts_mod.acknowledge_all(conn)
        _log(request, conn,"acknowledged all alerts",
                         detail=f"{n} alerts")
        return JSONResponse({"ok": True, "acknowledged": n, "open_count": 0})


@app.post("/api/entity/{entity_id}/notes")
async def api_entity_notes(request: Request, entity_id: int, payload: dict):
    analyst = _active_analyst(request)
    with db.connect() as conn:
        if not conn.execute("SELECT 1 FROM entities WHERE id=?", (entity_id,)).fetchone():
            return JSONResponse({"error": "unknown entity"}, status_code=404)
        annotations_mod.set_notes(conn, entity_id, payload.get("notes") or None, author=analyst)
        _log(request, conn,"edited notes", entity_id=entity_id)
    return JSONResponse({"ok": True})


@app.post("/api/entity/{entity_id}/dossier")
async def api_entity_dossier(request: Request, entity_id: int, payload: dict):
    """Save an analyst dossier override (regen-safe). Empty body reverts to AI."""
    analyst = _active_analyst(request)
    with db.connect() as conn:
        if not conn.execute("SELECT 1 FROM entities WHERE id=?", (entity_id,)).fetchone():
            return JSONResponse({"error": "unknown entity"}, status_code=404)
        body = (payload.get("body") or "").strip()
        if body:
            annotations_mod.set_dossier_override(conn, entity_id, body, author=analyst)
            _log(request, conn,"edited dossier", entity_id=entity_id)
            return JSONResponse({"ok": True, "override": True})
        annotations_mod.clear_dossier_override(conn, entity_id)
        _log(request, conn,"reverted dossier to AI", entity_id=entity_id)
    return JSONResponse({"ok": True, "override": False})


@app.post("/api/entity/{entity_id}/dossier/revert")
async def api_entity_dossier_revert(request: Request, entity_id: int):
    with db.connect() as conn:
        if not conn.execute("SELECT 1 FROM entities WHERE id=?", (entity_id,)).fetchone():
            return JSONResponse({"error": "unknown entity"}, status_code=404)
        annotations_mod.clear_dossier_override(conn, entity_id)
        _log(request, conn,"reverted dossier to AI", entity_id=entity_id)
    return JSONResponse({"ok": True, "override": False})


@app.post("/api/entity/{entity_id}/flag")
async def api_entity_flag(request: Request, entity_id: int, payload: dict):
    flagged = bool(payload.get("flagged"))
    with db.connect() as conn:
        row = conn.execute("SELECT id FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "unknown entity"}, status_code=404)
        # Only touch the note when the caller actually sent one — a bare toggle
        # must not wipe an analyst's existing note.
        if "note" in payload:
            new_alerts = alerts_mod.set_flag(conn, entity_id, flagged,
                                             note=(payload.get("note") or None))
        else:
            new_alerts = alerts_mod.set_flag(conn, entity_id, flagged)
        _log(request, conn,"flagged actor" if flagged else "unflagged actor",
                         entity_id=entity_id)
    return JSONResponse({"ok": True, "flagged": flagged, "new_alerts": new_alerts})


@app.post("/api/entity/{entity_id}/assert")
async def api_entity_assert(request: Request, entity_id: int, payload: dict):
    """Analyst override — the analyst is the top authority. Asserts a fact that
    supersedes the report/AI claim and reprojects into role/graph/scores/brief."""
    analyst = _active_analyst(request)
    claim_type = (payload.get("claim_type") or "attribute").strip()
    predicate = (payload.get("predicate") or "").strip()
    value = (payload.get("value") or "").strip()
    rationale = (payload.get("rationale") or "").strip() or None
    if not predicate or not value:
        return JSONResponse({"error": "field and value are required"}, status_code=400)
    with db.connect() as conn:
        if not conn.execute("SELECT 1 FROM entities WHERE id=?", (entity_id,)).fetchone():
            return JSONResponse({"error": "unknown entity"}, status_code=404)
        result = claims_mod.assert_claim(
            conn, entity_id, claim_type=claim_type, predicate=predicate,
            value=value, analyst=analyst, rationale=rationale)
        if not result.get("error"):
            _log(request, conn, "overrode (analyst call)", entity_id=entity_id,
                 detail=f"{predicate} = {value}")
        status = 200 if not result.get("error") else 400
    return JSONResponse(result, status_code=status)


@app.get("/set-analyst/{name}")
async def set_analyst(name: str):
    # Sanitize: printable, slash-free, bounded — a raw control char would make
    # set_cookie raise (500). _clean_analyst handles all of it.
    clean = _clean_analyst(name)
    resp = RedirectResponse(url="/activity", status_code=302)
    resp.set_cookie(ANALYST_COOKIE, clean, max_age=60 * 60 * 24 * 365, samesite="lax")
    return resp


@app.get("/activity", response_class=HTMLResponse)
async def activity_page(request: Request):
    delta = _signals_delta(request)
    with db.connect() as conn:
        items = activity_mod.recent(conn, case=_active_cases(request), limit=200)
    return _tpl(request, "activity.html", {"activity": items, "signals_delta": delta})


@app.get("/api/activity")
async def api_activity(request: Request, limit: int = 100):
    with db.connect() as conn:
        return JSONResponse({"activity": activity_mod.recent(conn, case=_active_cases(request), limit=limit)})


@app.get("/select-case/{slug}")
async def select_case(slug: str):
    """Set the active case SELECTION. `slug` is '__all__', a single slug, or a
    comma-joined set (e.g. 'case-a,case-b'). Unknown slugs are dropped;
    an empty/all-unknown selection bounces back to the picker."""
    year = 60 * 60 * 24 * 365
    if slug == ALL_CASES:
        resp = RedirectResponse(url="/", status_code=302)
        resp.set_cookie(CASE_COOKIE, ALL_CASES, max_age=year, samesite="lax")
        return resp
    wanted = [s.strip() for s in slug.split(",") if s.strip() and _valid_slug(s.strip())]
    if not wanted:
        return RedirectResponse(url="/cases", status_code=302)
    with db.connect() as conn:
        known = {r["slug"] for r in conn.execute("SELECT slug FROM investigations")}
    chosen, seen = [], set()
    for s in wanted:
        if s in known and s not in seen:
            seen.add(s)
            chosen.append(s)
    if not chosen:
        return RedirectResponse(url="/cases", status_code=302)
    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie(CASE_COOKIE, ",".join(chosen), max_age=year, samesite="lax")
    return resp


def _create_case(name: str, client: str | None = None) -> tuple[str, bool]:
    """Insert a case (idempotent) and return (slug, existed_before). Shared by the
    New Case UI route and chat-driven case creation. Raises ValueError on an
    unsluggable name so callers can return a clean 400."""
    slug = _slugify(name)
    if not slug:
        raise ValueError("Name the case (letters or numbers).")
    with db.connect() as conn:
        existed = conn.execute(
            "SELECT 1 FROM investigations WHERE slug = ?", (slug,)).fetchone() is not None
        conn.execute(
            "INSERT OR IGNORE INTO investigations (slug, case_name, client) VALUES (?, ?, ?)",
            (slug, name.strip(), (client or "").strip() or None))
        conn.commit()
    return slug, existed


@app.post("/api/cases")
async def api_new_case(request: Request, name: str = Form(...), client: str = Form("")):
    """Create an empty case from the UI (no evidence yet) and make it the active
    case. The investigation TYPE + schema get identified later, once docs land."""
    try:
        slug, existed = _create_case(name, client)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    year = 60 * 60 * 24 * 365
    resp = JSONResponse({"ok": True, "slug": slug, "existed": existed})
    resp.set_cookie(CASE_COOKIE, slug, max_age=year, samesite="lax")
    return resp


def _load_focus(case: str | None = None, conn=None) -> dict:
    """Focus payload for the banner / Focus page.

    No case → the generated all-cases focus.json (with deltas + LLM summary).
    A case → a live, scoped ranking computed from entity_scores within the case
    (no cross-run delta; always current for that case).
    Both carry a live `gaps` list — what's missing + what to look for next.
    """
    from investigations import focus as focus_mod

    # Live gap analysis (deterministic) for whatever scope is active.
    gaps = []
    if conn is not None:
        try:
            gaps = focus_mod.compute_gaps(conn, case)
        except Exception:
            import traceback
            traceback.print_exc()

    if case:
        empty = {"items": [], "elevated": [], "cooling": [], "generated_at": None,
                 "summary": "", "scoped_to": case, "gaps": gaps}
        # A case is set but we have no connection, or analysis hasn't run — never
        # fall through to the GLOBAL focus.json (that would mislabel all-cases
        # data as this case).
        if conn is None:
            return {**empty, "gaps": []}
        if not _table_exists(conn, "entity_scores"):
            return {**empty, "summary": f"No analysis yet for {case} — run analyze."}
        try:
            items = focus_mod._gather_top(conn, 8, case=case)
            for it in items:
                it["status"] = ""  # no cross-run delta in the live scoped view
            names = ", ".join(x["name"] for x in items[:3])
            summary = (f"Top targets in {case}: {names}." if items
                       else f"No scored entities in {case} yet.")
            return {**empty, "items": items, "summary": summary}
        except Exception:
            import traceback
            traceback.print_exc()  # surface real query errors in the console
            return empty

    focus_json_path = VAULT_DIR / "focus.json"
    if focus_json_path.exists():
        import json as _json
        try:
            data = _json.loads(focus_json_path.read_text(encoding="utf-8"))
            return {
                "items": data.get("items", []),
                "elevated": data.get("elevated", []),
                "cooling": data.get("cooling", []),
                "generated_at": data.get("generated_at"),
                "summary": data.get("summary", ""),
                "gaps": gaps,
            }
        except Exception:
            pass
    return {"items": [], "elevated": [], "cooling": [],
            "generated_at": None, "summary": "", "gaps": gaps}


@app.get("/graph", response_class=HTMLResponse)
async def graph_page(request: Request):
    return _tpl(request, "graph.html", {})


@app.get("/entities", response_class=HTMLResponse)
async def entities_page(request: Request):
    return _tpl(request, "entities.html", {})


@app.get("/entity/{entity_id}", response_class=HTMLResponse)
async def entity_detail(request: Request, entity_id: int):
    with db.connect() as conn:
        e = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if not e:
            return HTMLResponse("Not found", status_code=404)
        entity = dict(e)
        entity["role"] = _role(entity.get("notes"))
        aliases = [r["alias"] for r in conn.execute(
            "SELECT alias FROM aliases WHERE entity_id = ?", (entity_id,)
        ).fetchall()]
        mentions = []
        for r in conn.execute(
            "SELECT m.surface_form, m.context, r.id AS report_id, "
            "r.title AS report_title, a.page_number, a.file_path, a.report_id AS asset_report_id "
            "FROM mentions m JOIN reports r ON r.id = m.report_id "
            "LEFT JOIN assets a ON a.id = m.asset_id "
            "WHERE m.entity_id = ? ORDER BY r.id, a.page_number",
            (entity_id,),
        ).fetchall():
            d = dict(r)
            if d.get("file_path") and d.get("asset_report_id"):
                d["vault_image"] = f"r{d['asset_report_id']:04d}_{Path(d['file_path']).name}"
            mentions.append(d)

        score_row = conn.execute("SELECT * FROM entity_scores WHERE entity_id = ?",
                                 (entity_id,)).fetchone()
        score = dict(score_row) if score_row else {"threat_score": 0, "degree": 0, "report_count": 0}

        # Score breakdown — reconstruct the components so the analyst can see
        # WHY this entity has this score (matches the formula in analyze.compute_threat_scores)
        from investigations.analyze import ROLE_WEIGHTS
        role = entity.get("role") or ""
        role_w = ROLE_WEIGHTS.get(role, 0)
        role_pts = role_w * 10
        reports_pts = (score.get("report_count") or 0) * 5
        degree_pts = score.get("degree") or 0
        seed_row = conn.execute(
            "SELECT MAX(weight) AS w FROM seeds WHERE entity_id = ?",
            (entity_id,),
        ).fetchone() if _table_exists(conn, "seeds") else None
        seed_w = (seed_row["w"] if seed_row and seed_row["w"] is not None else 0) or 0
        prior_pts = seed_w * 30
        # Propagation: count seeds at depth 1 + depth 2
        d1_pts = d2_pts = 0
        if _table_exists(conn, "seeds"):
            d1_neighbors = {row["other"] for row in conn.execute(
                "SELECT CASE WHEN src_entity_id = ? THEN dst_entity_id ELSE src_entity_id END AS other "
                "FROM typed_relationships WHERE (src_entity_id = ? OR dst_entity_id = ?) "
                "AND COALESCE(status,'active') = 'active'",
                (entity_id, entity_id, entity_id),
            ).fetchall()}
            for n in d1_neighbors:
                w = conn.execute("SELECT MAX(weight) AS w FROM seeds WHERE entity_id = ?", (n,)).fetchone()
                if w and w["w"]:
                    d1_pts += float(w["w"]) * 10
            # depth 2 — neighbors of neighbors (skip if entity is itself a direct neighbor of the seed)
            for n in d1_neighbors:
                d2 = {row["other"] for row in conn.execute(
                    "SELECT CASE WHEN src_entity_id = ? THEN dst_entity_id ELSE src_entity_id END AS other "
                    "FROM typed_relationships WHERE src_entity_id = ? OR dst_entity_id = ?",
                    (n, n, n),
                ).fetchall()} - d1_neighbors - {entity_id}
                for nn in d2:
                    w = conn.execute("SELECT MAX(weight) AS w FROM seeds WHERE entity_id = ?", (nn,)).fetchone()
                    if w and w["w"]:
                        d2_pts += float(w["w"]) * 4
        total = role_pts + reports_pts + degree_pts + prior_pts + d1_pts + d2_pts
        score_breakdown = {
            "role": role, "role_weight": role_w, "role_pts": role_pts,
            "reports": score.get("report_count") or 0, "reports_pts": reports_pts,
            "degree": score.get("degree") or 0, "degree_pts": degree_pts,
            "seed_weight": seed_w, "prior_pts": prior_pts,
            "propagation_d1_pts": d1_pts,
            "propagation_d2_pts": d2_pts,
            "computed_total": total,
            "stored_total": float(score.get("threat_score") or 0),
        }

        typed_in = [dict(r) for r in conn.execute(
            "SELECT t.rel_type, t.confidence, t.evidence, "
            "e2.id AS other_id, e2.canonical_name AS other_name, e2.entity_type AS other_type "
            "FROM typed_relationships t JOIN entities e2 ON e2.id = t.src_entity_id "
            "WHERE t.dst_entity_id = ? AND t.status = 'active'", (entity_id,),
        ).fetchall()]
        typed_out = [dict(r) for r in conn.execute(
            "SELECT t.rel_type, t.confidence, t.evidence, "
            "e2.id AS other_id, e2.canonical_name AS other_name, e2.entity_type AS other_type "
            "FROM typed_relationships t JOIN entities e2 ON e2.id = t.dst_entity_id "
            "WHERE t.src_entity_id = ? AND t.status = 'active'", (entity_id,),
        ).fetchall()]

        pivot_links = [dict(r) for r in conn.execute(
            "SELECT label, url FROM enrichment_links WHERE entity_id = ?",
            (entity_id,),
        ).fetchall()]

        clusters = [dict(r) for r in conn.execute(
            "SELECT c.id, c.name, c.kind, c.description "
            "FROM clusters c JOIN cluster_members cm ON cm.cluster_id = c.id "
            "WHERE cm.entity_id = ?", (entity_id,),
        ).fetchall()]

        seed = conn.execute(
            "SELECT * FROM seeds WHERE entity_id = ?", (entity_id,)
        ).fetchone() if _table_exists(conn, "seeds") else None

        dossier_md = ""
        profiles_dir = VAULT_DIR / "profiles"
        if profiles_dir.exists():
            for candidate in profiles_dir.glob("*.md"):
                content = candidate.read_text(encoding="utf-8")
                # Anchored to the frontmatter line so '@al' can't match '@alice'.
                if any(ln.strip() == f"name: {entity['canonical_name']}"
                       for ln in content.splitlines()[:8]):
                    # Strip YAML frontmatter so it doesn't render as body text.
                    if content.startswith("---"):
                        parts = content.split("---", 2)
                        if len(parts) == 3:
                            content = parts[2].lstrip("\n")
                    dossier_md = content
                    break

        # Which cases this actor/indicator appears in (cross-case visibility).
        also_in_cases = [row["investigation"] for row in conn.execute(
            "SELECT r.investigation, COUNT(*) AS n FROM mentions m "
            "JOIN reports r ON r.id = m.report_id "
            "WHERE m.entity_id = ? AND r.investigation IS NOT NULL "
            "GROUP BY r.investigation ORDER BY n DESC",
            (entity_id,),
        ).fetchall()]

        # Provenance / corrections: every claim about this entity + its status.
        try:
            entity_claims = claims_mod.entity_claims(conn, entity_id)
        except Exception:
            entity_claims = []

        # Where the analyst has overridden the report/AI: predicate -> author. Drives
        # the 'analyst override · by X' badges so the authority is visible at a glance.
        analyst_overrides = {
            c["predicate"]: (c.get("author") or "analyst")
            for c in entity_claims
            if c.get("status") == "active" and c.get("source") == "manual"
        }

        # Analyst layer (notes + optional dossier override), separate from the AI dossier.
        ann = annotations_mod.get(conn, entity_id)

    return _tpl(request, "entity.html", {
        "entity": entity, "aliases": aliases, "mentions": mentions,
        "score": score, "score_breakdown": score_breakdown,
        "typed_in": typed_in, "typed_out": typed_out,
        "pivot_links": pivot_links, "clusters": clusters, "dossier_md": dossier_md,
        "seed": dict(seed) if seed else None,
        "also_in_cases": also_in_cases,
        "entity_claims": entity_claims,
        "analyst_overrides": analyst_overrides,
        "analyst_notes": ann["notes"] or "",
        "dossier_override": ann["dossier_override"],
        "dossier_updated_at": ann["dossier_updated_at"],
        "notes_updated_at": ann["notes_updated_at"],
        "notes_author": ann.get("notes_author"),
        "dossier_author": ann.get("dossier_author"),
    })


def _table_exists(conn, name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (name,),
    ).fetchone()
    return bool(row)


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    inq, inp = _case_in(_active_cases(request), col="investigation")
    with db.connect() as conn:
        reports = []
        for r in conn.execute(
            "SELECT id, title, source_type, investigation, ingested_at, source_path "
            "FROM reports "
            + (f"WHERE {inq} " if inq else "")
            + "ORDER BY ingested_at DESC",
            inp,
        ).fetchall():
            ent_count = conn.execute(
                "SELECT COUNT(DISTINCT entity_id) AS n FROM mentions WHERE report_id = ?",
                (r["id"],),
            ).fetchone()["n"]
            asset_count = conn.execute(
                "SELECT COUNT(*) AS n FROM assets WHERE report_id = ?",
                (r["id"],),
            ).fetchone()["n"]
            d = dict(r)
            d["entity_count"] = ent_count
            d["asset_count"] = asset_count
            reports.append(d)
        objective = db.get_objective(conn, _active_case(request))
    return _tpl(request, "reports.html", {"reports": reports, "objective": objective})


# --- Linked-image capture (gated per-link). Image URLs found in report text become
# 'pending' candidates; the analyst Scans (fetch+OCR→asset) or Skips each one. Nothing
# fetches automatically — discover() is text-only, scan_one() runs one approved link. ---
@app.get("/links", response_class=HTMLResponse)
async def links_page(request: Request):
    from investigations.ingest import linked_images as li
    case = _active_case(request)
    cands = []
    if case:
        with db.connect() as conn:
            cands = li.candidates(conn, case)
    return _tpl(request, "links.html", {"candidates": cands, "links_case": case})


@app.post("/api/links/discover")
async def api_links_discover(request: Request):
    from investigations.ingest import linked_images as li
    case = _active_case(request)
    if not case:
        return JSONResponse({"error": "select a single case first"}, status_code=400)
    with db.connect() as conn:
        added = li.discover(conn, case)
        cands = li.candidates(conn, case)
    return JSONResponse({"added": added, "candidates": cands})


@app.post("/api/links/{cand_id}/scan")
def api_links_scan(request: Request, cand_id: int):
    """GATED fetch: download + OCR + store ONE approved candidate image. Sync `def`
    (not async) so the blocking network fetch runs in FastAPI's threadpool and doesn't
    freeze the event loop for the up-to-20s download."""
    from investigations.ingest import linked_images as li
    with db.connect() as conn:
        res = li.scan_one(conn, cand_id)
    return JSONResponse(res)


@app.post("/api/links/{cand_id}/skip")
async def api_links_skip(request: Request, cand_id: int):
    from investigations.ingest import linked_images as li
    with db.connect() as conn:
        res = li.skip_one(conn, cand_id)
    return JSONResponse(res)


@app.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: int):
    """Report workspace: the report's entities + analyst notes + the analyst
    overrides that contradict this report (the analyst is the top authority)."""
    with db.connect() as conn:
        rep = conn.execute(
            "SELECT id, title, source_type, investigation, ingested_at, source_path "
            "FROM reports WHERE id = ?", (report_id,)).fetchone()
        if not rep:
            return HTMLResponse("Report not found", status_code=404)
        report = dict(rep)
        entities = [dict(r) for r in conn.execute(
            "SELECT DISTINCT e.id, e.canonical_name, e.entity_type, e.notes, e.sub_role, "
            "s.threat_score "
            "FROM mentions m JOIN entities e ON e.id = m.entity_id "
            "LEFT JOIN entity_scores s ON s.entity_id = e.id "
            "WHERE m.report_id = ? AND (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
            "ORDER BY s.threat_score DESC NULLS LAST LIMIT 200", (report_id,)).fetchall()]
        for e in entities:
            e["role"] = _role(e.get("notes"))
        # Analyst overrides touching this report's entities — what the analyst has
        # contradicted, shown back on the report.
        overrides = []
        if _table_exists(conn, "claims"):
            overrides = [dict(r) for r in conn.execute(
                "SELECT c.entity_id, c.predicate, c.value, c.author, c.evidence, "
                "e.canonical_name "
                "FROM claims c JOIN entities e ON e.id = c.entity_id "
                "WHERE c.source = 'manual' AND c.status = 'active' "
                "AND c.entity_id IN (SELECT entity_id FROM mentions WHERE report_id = ?) "
                "ORDER BY c.id DESC", (report_id,)).fetchall()]
        asset_count = conn.execute(
            "SELECT COUNT(*) AS n FROM assets WHERE report_id = ?", (report_id,)).fetchone()["n"]
        ann = annotations_mod.get_report(conn, report_id)
        # Other cases this report could be moved into (the analyst may have filed
        # it under the wrong one). Exclude the case it's already in.
        cases = [r["slug"] for r in conn.execute(
            "SELECT slug FROM investigations WHERE slug != ? ORDER BY slug",
            (report.get("investigation") or "",)).fetchall()]
    return _tpl(request, "report-detail.html", {
        "report": report, "entities": entities, "overrides": overrides,
        "asset_count": asset_count, "cases": cases,
        "report_notes": ann["notes"] or "", "notes_author": ann.get("notes_author"),
    })


@app.post("/api/report/{report_id}/notes")
async def api_report_notes(request: Request, report_id: int, payload: dict):
    analyst = _active_analyst(request)
    with db.connect() as conn:
        if not conn.execute("SELECT 1 FROM reports WHERE id = ?", (report_id,)).fetchone():
            return JSONResponse({"error": "unknown report"}, status_code=404)
        annotations_mod.set_report_notes(conn, report_id, payload.get("notes") or None, author=analyst)
        _log(request, conn, "edited report notes", report_id=report_id)
    return JSONResponse({"ok": True})


@app.post("/api/report/{report_id}/delete")
async def api_report_delete(request: Request, report_id: int):
    """Remove a report completely — DB rows (purging entities exclusive to it) and
    the on-disk archive / asset / inbox files."""
    reports_dir = ROOT / "investigations" / "reports"
    with db.connect() as conn:
        rep = conn.execute("SELECT source_path FROM reports WHERE id = ?", (report_id,)).fetchone()
        if not rep:
            return JSONResponse({"error": "report not found"}, status_code=404)
        source_path = rep["source_path"]
        asset_files = [r["file_path"] for r in conn.execute(
            "SELECT file_path FROM assets WHERE report_id = ?", (report_id,)).fetchall()]
        result = db.delete_report(conn, report_id)
        if not result.get("error"):
            _log(request, conn, "deleted a report", detail=f"report {report_id}")
    # Physical files (best-effort).
    try:
        for f in reports_dir.glob(f"{report_id:04d}_*"):
            f.unlink(missing_ok=True)
        for ap in asset_files:
            p = Path(ap) if Path(ap).is_absolute() else (ROOT / ap)
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        if source_path:
            sp = Path(source_path)
            if sp.is_file() and "inbox" in str(sp):
                sp.unlink(missing_ok=True)
    except Exception:
        pass
    return JSONResponse(result, status_code=200 if not result.get("error") else 404)


@app.post("/api/report/{report_id}/move")
async def api_report_move(request: Request, report_id: int, payload: dict):
    """Move a report into a different case (the analyst filed it under the wrong
    one). Updates the case tag + re-detects the target case's investigation type,
    same as a fresh upload does."""
    target = (payload.get("case") or "").strip()
    if not target:
        return JSONResponse({"error": "target case required"}, status_code=400)
    with db.connect() as conn:
        result = db.move_report(conn, report_id, target)
        if not result.get("error"):
            _log(request, conn, f"moved a report to {target}", report_id=report_id)
            try:
                from investigations.intake import types as types_mod
                types_mod.detect(conn, target)
            except Exception:
                pass
    return JSONResponse(result, status_code=200 if not result.get("error") else 400)


@app.post("/api/investigation/delete")
async def api_investigation_delete(request: Request, investigation: str = Form("")):
    """Delete an ENTIRE investigation + everything scoped to it. Irreversible —
    the UI gates this behind an 'are you sure' confirm. Also drops the case's
    synthesis brief from the vault and clears it from the active-case cookie."""
    case = (investigation or "").strip()
    if not case:
        return JSONResponse({"error": "investigation required"}, status_code=400)
    with db.connect() as conn:
        result = db.delete_investigation(conn, case)
        if not result.get("error"):
            _log(request, conn, f"deleted investigation {case}")
    if result.get("error"):
        return JSONResponse(result, status_code=404)

    # Signal any in-flight investigation on this case to wrap up — its write-back
    # is already guarded (land_findings discards on a deleted case), but stopping
    # the run early avoids wasted OSINT spend on a case that's gone.
    with _INVESTIGATE_LOCK:
        cancel = _INVESTIGATE_CANCEL.get(_investigate_key(case))
    if cancel is not None:
        cancel.set()

    # Best-effort: remove the case's synthesis brief file from the vault.
    try:
        _synth_path(case).unlink(missing_ok=True)
    except Exception:
        pass

    resp = JSONResponse(result)
    # Drop the deleted case from the active-case cookie so no view points at it.
    remaining = [s for s in _active_cases(request) if s != case]
    if remaining:
        resp.set_cookie(CASE_COOKIE, ",".join(remaining),
                        max_age=60 * 60 * 24 * 365, samesite="lax")
    elif request.cookies.get(CASE_COOKIE):
        resp.delete_cookie(CASE_COOKIE)
    return resp


def _skip_reason(conn, path: Path) -> str:
    """Why did _ingest_one decline this file? The pipeline returns a bare None for
    several distinct cases; recover the real reason so the UI stops calling every
    skip 'unsupported type'. A matching hash means it's already in a case (often a
    different one) — name it so the analyst can move it instead of guessing."""
    import hashlib
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        existing = conn.execute(
            "SELECT investigation FROM reports WHERE source_hash = ?",
            (h.hexdigest(),)).fetchone()
    except Exception:
        existing = None
    if existing:
        other = existing["investigation"] or "another case"
        return f"already uploaded in another case: {other} — open that report to move it here"
    return "skipped — empty or unreadable file"


def _ingest_saved(paths: list, case: str, analyst: str, objective: str = "") -> dict:
    """Run the full ingest pipeline on already-saved files (sync — called in a
    threadpool). Mirrors `./invctl ingest`: per-file OCR + entity extraction +
    alerts, then recalibrate scores + backfill + LLM correction-extraction."""
    from investigations.cli import invctl
    from investigations import analyze as analyze_mod
    invctl.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    invctl.ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    new_ids, reports = [], []
    with db.connect() as conn:
        for p in paths:
            try:
                rid = invctl._ingest_one(conn, p, case)
            except Exception as exc:
                reports.append({"file": p.name, "error": str(exc)[:200]})
                continue
            if rid:
                new_ids.append(rid)
                ec = conn.execute("SELECT COUNT(DISTINCT entity_id) AS n FROM mentions "
                                  "WHERE report_id = ?", (rid,)).fetchone()["n"]
                t = conn.execute("SELECT title FROM reports WHERE id = ?", (rid,)).fetchone()
                reports.append({"report_id": rid, "title": (t["title"] if t else p.name),
                                "entities": ec, "file": p.name})
            else:
                reports.append({"file": p.name, "note": _skip_reason(conn, p)})
        extracted = 0
        if new_ids:
            try:
                scored_n = analyze_mod.compute_threat_scores(conn)
                log.info("upload: rescored %d entities", scored_n)
            except Exception as exc:
                log.warning("upload: threat-score recompute failed: %s: %s",
                            type(exc).__name__, exc)
            try:
                claims_mod.backfill(conn)
                extracted = sum(claims_mod.extract_claims_for_report(conn, rid) for rid in new_ids)
            except Exception:
                pass
            for rid in new_ids:
                activity_mod.log(conn, analyst, "uploaded a report", report_id=rid, investigation=case)
            # Register the case NOW (don't wait for the next connect's backfill) so
            # the post-upload redirect into it works immediately.
            conn.execute("INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?, ?)",
                         (case, case))
            # Identify the investigation TYPE from the evidence just landed
            # (deterministic-first; advisory + gated, never auto-approved).
            try:
                from investigations.intake import types as types_mod
                types_mod.detect(conn, case)
            except Exception:
                pass
        # Store the analyst's objective on the case (the scope anchor). Set even
        # when nothing ingested, so a fileless objective still anchors the case.
        if objective and objective.strip():
            db.set_objective(conn, case, objective)
        try:
            contradictions = len(claims_mod.detect_contradictions(conn, case))
        except Exception:
            contradictions = 0
    skipped = [r for r in reports if not r.get("report_id")]
    return {"ok": True, "case": case, "ingested": len(new_ids), "reports": reports,
            "skipped": skipped, "extracted_claims": extracted,
            "open_contradictions": contradictions}


@app.post("/api/upload")
async def api_upload(request: Request, files: list[UploadFile] = File(...),
                     investigation: str = Form(""), objective: str = Form("")):
    """Web upload: save files to the inbox + run the full ingest pipeline into the
    chosen case. `investigation` (free-typed) wins, else the active case.
    `objective` (free-typed) is the case's scope anchor — stored on the case."""
    case = (_slugify(investigation) if investigation.strip() else None) or _active_case(request)
    if not case:
        return JSONResponse(
            {"error": "Pick a single case (top-right) or name one to file these under."},
            status_code=400)
    analyst = _active_analyst(request)
    inbox = ROOT / "investigations" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    saved = []
    for f in files:
        if not f.filename:
            continue
        safe = _re.sub(r"[^A-Za-z0-9._ -]", "_", Path(f.filename).name)[:120] or "upload"
        dest = inbox / safe
        dest.write_bytes(await f.read())
        saved.append(dest)
    if not saved:
        return JSONResponse({"error": "no files received"}, status_code=400)
    # Heavy (OCR + LLM) — run off the event loop so the app stays responsive.
    result = await run_in_threadpool(_ingest_saved, saved, case, analyst, objective)
    return JSONResponse(result)


@app.post("/api/paste")
async def api_paste(request: Request, text: str = Form(...),
                    title: str = Form(""), investigation: str = Form(""),
                    objective: str = Form("")):
    """Paste investigative notes straight in (no file). The text becomes a report
    in the chosen case, then runs the same extraction pipeline as an upload."""
    case = (_slugify(investigation) if investigation.strip() else None) or _active_case(request)
    if not case:
        return JSONResponse(
            {"error": "Pick a single case (top-right) or name one to file these notes under."},
            status_code=400)
    if not text.strip():
        return JSONResponse({"error": "Paste some text first."}, status_code=400)
    analyst = _active_analyst(request)
    inbox = ROOT / "investigations" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    slug = _slugify(title) if title.strip() else "notes"
    # Unique-ish filename without a clock dependency: short content hash.
    import hashlib
    tag = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    dest = inbox / f"{slug}-{tag}.md"
    header = f"# {title.strip()}\n\n" if title.strip() else ""
    dest.write_text(header + text, encoding="utf-8")
    result = await run_in_threadpool(_ingest_saved, [dest], case, analyst, objective)
    return JSONResponse(result)


@app.post("/api/objective")
async def api_objective(request: Request, objective: str = Form(""),
                        investigation: str = Form("")):
    """Set / update the case's objective (the scope anchor) after intake. Used by
    the Understand (schema) page so the analyst can refine the goal any time."""
    case = (_slugify(investigation) if investigation.strip() else None) or _active_case(request)
    if not case:
        return JSONResponse({"error": "Pick or name a case first."}, status_code=400)
    with db.connect() as conn:
        db.set_objective(conn, case, objective)
        _log(request, conn, "set the case objective")
    return JSONResponse({"ok": True, "case": case, "objective": objective.strip()})


# The Process pipeline's steps, in run order, with human labels. Drives the live
# progress bar + step log on the Reports panel (so the analyst sees what's running,
# not a blind spinner). Keys MUST match the _step() names below.
PROCESS_STEPS = [
    ("reextract", "Re-extract fingerprints"),
    ("retro_clean", "Clean stale extractions"),
    ("consolidate", "Consolidate + de-dupe entities"),
    ("typing", "Type entities to the schema"),
    ("correlate", "Correlate across reports"),
    ("cross_domain", "Find cross-domain links"),
    ("analyze", "Score + cluster"),
    ("score", "Recompute threat scores"),
    ("graph_metrics", "Graph analytics (centrality + communities)"),
    ("synthesize", "Write the brief"),
    ("dossiers", "Build actor dossiers"),
]


def _schema_gate(case: str, analyst: str) -> dict | None:
    """Ensure an APPROVED per-case schema exists, proposing AND auto-approving one
    when there's none — then return None so Process runs straight through.

    The schema step is no longer a human gate: the agent-proposed ontology has
    proven sharp enough that the approval prompt was friction, not safety
    (founder decision 2026-06-10, reversing the original propose-then-approve
    gate). The /schema page stays reachable by URL for correcting a bad
    auto-schema, but it is never a required step and not shown in nav. Returns
    None always (no needs_approval) unless discovery itself errors (raised)."""
    from investigations import understand as understand_mod
    with db.connect() as conn:
        if understand_mod.approved_schema(conn, case) is not None:
            return None
        existing = understand_mod.get_schema(conn, case)
        proposed = existing if existing else understand_mod.discover_schema(conn, case)
        understand_mod.save_schema(conn, case, proposed, status="approved", analyst=analyst)
        activity_mod.log(conn, analyst,
                         "auto-modeled the case schema (no approval needed)",
                         investigation=case)
    return None


def _process_case(case: str, analyst: str, on_step=None, on_progress=None) -> dict:
    """Run the analysis pipeline so an uploaded case becomes a real investigation:
    role-tag + de-dup entities (drops noise), correlate, cluster + score, then write
    the synthesis brief + actor dossiers. Heavy (LLM passes) — runs in a threadpool.

    `on_step(name, status)` (optional) is called as each step starts ('running')
    and finishes ('ok'/'skipped') so the caller can surface live progress.

    Schema: classification uses a per-case ontology that _schema_gate now
    auto-proposes AND auto-approves inline (no human approval step) — Process
    runs straight through (founder decision 2026-06-10)."""
    from investigations import consolidate as consolidate_mod, analyze as analyze_mod
    from investigations import synthesize as synthesize_mod, profile as profile_mod
    from investigations import understand as understand_mod, typing as typing_mod
    from investigations import reextract as reextract_mod, fingerprints as fp_mod
    from investigations import graph_metrics as graph_metrics_mod
    from investigations.correlate import engine as correlate_engine
    from investigations.maintenance import retro_clean as retro_clean_mod

    try:
        _schema_gate(case, analyst)   # auto-proposes + auto-approves; no stop
    except Exception as exc:
        return {"error": f"Schema modeling failed: {str(exc)[:160]}", "case": case}
    with db.connect() as conn:
        schema = understand_mod.approved_schema(conn, case)

    steps = {}

    def _step(name, fn):
        if on_step:
            on_step(name, "running")
        try:
            fn(); steps[name] = "ok"
            if on_step:
                on_step(name, "ok")
        except Exception as exc:
            steps[name] = f"skipped: {str(exc)[:120]}"
            if on_step:
                on_step(name, "skipped")

    # Dossiers cover the actor roles this case actually uses + the generic ones.
    dossier_roles = {"operator", "channel", "ioc"} | understand_mod.actor_roles(schema)

    with db.connect() as conn:
        # Backfill fingerprint entities (tracking tags, WalletConnect ids, service
        # accounts, nameservers) the original ingest's older extractor missed.
        _step("reextract", lambda: reextract_mod.run(conn, case))
        # Retroactive cleanup: junk phone nodes, wallet case-twins, and ungated
        # same_operator edges left by pre-fix extractions (reextract is additive
        # by contract, so the deletions live in their own pass).
        _step("retro_clean", lambda: retro_clean_mod.run(conn, case))
        _step("consolidate", lambda: consolidate_mod.run(
            conn, dry_run=False, only_new=False, schema=schema, case=case,
            on_progress=on_progress))
        # Typing pass: fit existing entities to the case's types + recover the
        # ones the regex missed (wallets, orgs, infra IDs).
        _step("typing", lambda: typing_mod.run(conn, case, schema))
        _step("correlate", lambda: (correlate_engine.cross_report_overlap(conn),
                                    correlate_engine.auto_link_aliases(conn)))
        # Cross-domain links: shared tracking tag / WalletConnect id / nameserver.
        _step("cross_domain", lambda: fp_mod.correlate(conn, case))
        _step("analyze", lambda: analyze_mod.run(conn, VAULT_DIR, schema=schema, case=case))

        # Dedicated score step (gma-1): analyze scores internally, but analyze is
        # the step with timeout history — when it's skipped, scores must still
        # compute or the graph's min_score filter silently dies (the gate2 bug).
        # The count is surfaced three ways: the job log (print -> _JobLogWriter),
        # an extra on_step emission, and the step status itself.
        def _score_step():
            n = analyze_mod.compute_threat_scores(conn)
            print(f"scored {n} entities")
            if on_step:
                on_step(f"scored {n}", "ok")

        _step("score", _score_step)
        # Deterministic graph analytics (centrality + Louvain) over the case
        # subgraph -> node_properties; feeds the style rules (community color,
        # betweenness size). No LLM.
        _step("graph_metrics", lambda: graph_metrics_mod.run(conn, case))
        _step("synthesize", lambda: synthesize_mod.run(conn, VAULT_DIR, case=case))
        _step("dossiers", lambda: profile_mod.run(conn, VAULT_DIR, roles=dossier_roles, case=case))
        activity_mod.log(conn, analyst, "processed the case", investigation=case)
        roled = conn.execute("SELECT COUNT(*) FROM entities WHERE notes LIKE 'role:%' "
                             "AND notes NOT LIKE 'role:noise%'").fetchone()[0]
        clusters = conn.execute("SELECT COUNT(*) FROM clusters").fetchone()[0]
    return {"ok": True, "case": case, "steps": steps,
            "roled_entities": roled, "clusters": clusters}


# Per-case processing jobs run SERVER-SIDE in a daemon thread, not tied to the
# HTTP request — so the pipeline survives a tab switch / navigation (the old
# version held the request open for minutes and died when you left the page).
import threading as _threading
_PROCESS_JOBS: dict[str, dict] = {}
_PROCESS_LOCK = _threading.Lock()

# Cap the live log tail so the status payload stays small and old noise scrolls off.
_PROCESS_LOG_MAX = 200


class _JobLogWriter:
    """Tee the pipeline thread's stdout/stderr into the job's live log buffer so the
    Process panel can show a scrolling 'what's the agent doing right now' window —
    while still forwarding every line to the real terminal. Line-buffered: the
    batch prints (`  batch 3/12 (40 entities)… ` then `7 clusters returned`) land as
    one combined line per batch, which is exactly what you want to watch tick by."""

    def __init__(self, case: str, real):
        self.case = case
        self.real = real
        self._partial = ""

    def write(self, text: str) -> int:
        self.real.write(text)
        self._partial += text
        while "\n" in self._partial:
            line, self._partial = self._partial.split("\n", 1)
            self._append(line)
        return len(text)

    def _append(self, line: str) -> None:
        line = line.rstrip()
        if not line:
            return
        with _PROCESS_LOCK:
            job = _PROCESS_JOBS.get(self.case)
            if job is None:
                return
            log = job.setdefault("log", [])
            log.append(line)
            if len(log) > _PROCESS_LOG_MAX:
                del log[: len(log) - _PROCESS_LOG_MAX]

    def flush(self) -> None:
        self.real.flush()


def _process_case_job(case: str, analyst: str) -> None:
    # Seed a per-step progress checklist (all pending) so the panel can render the
    # plan immediately, then flip each step running -> ok/skipped as it executes.
    progress = {"total": len(PROCESS_STEPS), "current": None,
                "steps": [{"key": k, "label": lbl, "status": "pending"}
                          for k, lbl in PROCESS_STEPS]}
    with _PROCESS_LOCK:
        _PROCESS_JOBS[case] = {"status": "running", "case": case, "progress": progress}

    def on_step(name: str, status: str) -> None:
        with _PROCESS_LOCK:
            job = _PROCESS_JOBS.get(case) or {"status": "running", "case": case,
                                              "progress": progress}
            prog = job.get("progress") or progress
            for s in prog["steps"]:
                if s["key"] == name:
                    s["status"] = status
            if status == "running":
                prog["current"] = name
                # Clear any sub-step bar left over from the previous step.
                prog.pop("substep", None)
            job["progress"] = prog
            _PROCESS_JOBS[case] = job

    def on_progress(done: int, total: int, label: str = "") -> None:
        # Sub-step progress WITHIN the current step (e.g. consolidate batches), so the
        # bar crawls instead of freezing for the whole slow step.
        with _PROCESS_LOCK:
            job = _PROCESS_JOBS.get(case)
            if not job:
                return
            prog = job.get("progress") or progress
            prog["substep"] = {"done": done, "total": total, "label": label}
            job["progress"] = prog
            _PROCESS_JOBS[case] = job

    import contextlib as _contextlib
    import sys as _sys
    writer = _JobLogWriter(case, _sys.stdout)
    try:
        # Tee stdout+stderr so every pipeline print (batch counters, cluster results,
        # recovered entities) streams to the panel's live log window in real time.
        with _contextlib.redirect_stdout(writer), _contextlib.redirect_stderr(writer):
            result = _process_case(case, analyst, on_step=on_step, on_progress=on_progress)
        status = "error" if result.get("error") else "done"
        with _PROCESS_LOCK:
            prev = _PROCESS_JOBS.get(case, {})
            _PROCESS_JOBS[case] = {"status": status, "result": result, "case": case,
                                   "progress": prev.get("progress"), "log": prev.get("log")}
        # Process reclassified/typed the case's entities → tell open views to refresh.
        bump_case(case)
    except Exception as exc:
        with _PROCESS_LOCK:
            prev = _PROCESS_JOBS.get(case, {})
            _PROCESS_JOBS[case] = {"status": "error", "result": {"error": str(exc)[:200]},
                                   "case": case, "progress": prev.get("progress"),
                                   "log": prev.get("log")}


@app.post("/api/process")
async def api_process(request: Request):
    """Start the analysis pipeline for the active case as a BACKGROUND job and
    return immediately. Poll /api/process/status. Survives tab switches."""
    case = _active_case(request)
    if not case:
        return JSONResponse({"error": "Pick a single case to process."}, status_code=400)
    analyst = _active_analyst(request)
    # Auto-model the case schema OFF the event loop — for a brand-new case
    # _schema_gate runs the LLM discover_schema; it auto-approves inline (no
    # analyst step) and returns None, so we proceed straight to the job.
    try:
        await run_in_threadpool(_schema_gate, case, analyst)
    except Exception as exc:
        return JSONResponse(
            {"error": f"Schema modeling failed: {str(exc)[:160]}", "case": case},
            status_code=500)
    with _PROCESS_LOCK:
        cur = _PROCESS_JOBS.get(case)
        if cur and cur.get("status") == "running":
            return JSONResponse({"status": "running", "case": case})
        _PROCESS_JOBS[case] = {"status": "running", "case": case}
    t = _threading.Thread(target=_process_case_job, args=(case, analyst), daemon=True)
    t.start()
    return JSONResponse({"status": "started", "case": case})


@app.get("/api/process/status")
async def api_process_status(request: Request):
    """Current processing state for the active case. 'idle' if never run."""
    case = _active_case(request)
    if not case:
        return JSONResponse({"status": "idle"})
    with _PROCESS_LOCK:
        job = _PROCESS_JOBS.get(case)
    return JSONResponse(job or {"status": "idle", "case": case})


def _find_links(case: str | None, analyst: str) -> dict:
    """Backfill the fingerprint entities (re-extract) then correlate cross-domain
    links (shared tracking tag / WalletConnect id / nameserver / service account)."""
    from investigations import reextract as reextract_mod, fingerprints as fp_mod
    with db.connect() as conn:
        re = reextract_mod.run(conn, case)
        corr = fp_mod.correlate(conn, case)
        try:
            from investigations import analyze as analyze_mod
            scored_n = analyze_mod.compute_threat_scores(conn)
            log.info("link-finder: rescored %d entities", scored_n)
        except Exception as exc:
            log.warning("link-finder: threat-score recompute failed: %s: %s",
                        type(exc).__name__, exc)
        activity_mod.log(conn, analyst, "ran cross-domain link finder",
                         investigation=case)
    return {"ok": True, "case": case, "reextract": re, "correlate": corr}


def _investigate_entity(entity: str, case: str | None, on_event=None,
                        question: str | None = None, cancel=None,
                        expand: bool = False) -> dict:
    from investigations.agent import investigator
    with db.connect() as conn:
        # Maltego EXPAND: pure deterministic one-hop (infra belt + promote, NO LLM brief).
        # Fast — "pull this node's connections," the founder's click-a-node-to-expand.
        if expand:
            return investigator.investigate_entity_quick(conn, entity, case=case,
                                                         on_event=on_event, cancel=cancel,
                                                         with_read=False, suggest=True)
        # Default "Investigate this node" = a fast ONE-HOP read (deterministic infra belt +
        # a single short LLM summary), NOT the 28-turn end-to-end agent. The founder's "one
        # node investigation should not go crazy and run 10 minutes — I just want info about
        # that node." A SPECIFIC analyst question still gets the deep agent — they asked for
        # depth. Plan: q-system/output/plans/deterministic-enumeration-split-2026-06-08.md
        if question and question.strip():
            return investigator.investigate_entity(conn, entity, case=case, on_event=on_event,
                                                   question=question, cancel=cancel)
        # `cancel` makes the Stop button actually stop the quick run (the belt checks it
        # between lookups). Without it, Stop was a no-op on a node investigation.
        return investigator.investigate_entity_quick(conn, entity, case=case, on_event=on_event,
                                                      cancel=cancel)


def _investigate_edge(src_id: int, dst_id: int, case: str | None, on_event=None,
                      cancel=None) -> dict:
    from investigations.agent import investigator
    with db.connect() as conn:
        return investigator.investigate_edge(conn, src_id, dst_id, case=case,
                                             on_event=on_event, cancel=cancel)


# Investigator runs as a BACKGROUND job (like Process) so the page can stream the
# agent's live step trail and the run survives a tab switch. Keyed by active case
# (one investigation at a time per case — the expected analyst flow).
_INVESTIGATE_JOBS: dict[str, dict] = {}
_INVESTIGATE_LOCK = _threading.Lock()
_INVESTIGATE_LOG_MAX = 200
# Per-case Stop signal: POST /api/investigate/stop sets the case's Event; the
# persona-driven run watches it, kills the agent, and keeps whatever already landed.
_INVESTIGATE_CANCEL: dict[str, "_threading.Event"] = {}
# Max nodes a single "investigate selected" run will dispatch the full agent on
# (PRD-07). Bounds cost/concurrency; excess is reported, not silently dropped.
_SELECT_CAP = 12


def _investigate_key(case: str | None) -> str:
    return case or "__noscope__"


def _start_investigate_job(case: str | None, entity: str | None, analyst: str,
                           deep: bool = False) -> bool:
    """Start a single-target investigator run as a background job. Returns False if a
    run is already live for this case. Shared by the /api/investigate route's logic and
    chat-driven create+run, so both register the same job/cancel state + progress."""
    key = _investigate_key(case)
    label = entity or "whole case"
    with _INVESTIGATE_LOCK:
        cur = _INVESTIGATE_JOBS.get(key)
        if cur and cur.get("status") == "running":
            return False
        _INVESTIGATE_JOBS[key] = {"status": "running", "case": case,
                                  "entity": label, "log": [], "progress": _new_progress()}
    t = _threading.Thread(
        target=_investigate_job,
        args=(entity or None, case, analyst, False, None, False, None, bool(deep)),
        daemon=True)
    t.start()
    record_ui_event(case, f"launched an investigation on {label}")
    return True


def _investigate_swarm(case: str, shallow: bool, on_event=None, cancel=None,
                       deep: bool = False) -> dict:
    """A whole-case run is driven by ONE agent (no fan-out) in both modes (founder
    decision 2026-06-05, revises 2026-06-03). The old default fanned out twice —
    `volley` (one agent per entity) then `investigate_entity_crew` (per-dimension
    sub-agents) — which wasted spawns AND lost the cross-entity pivots that are the
    highest-value findings (replay D4). Both modes now use the 4_points one-agent model:
      - default → `investigate_case_agentic(max_passes=1)` — ONE bounded pass, NO
        fan-out. The agent drives its own paths within the pass, then STOPS; the
        analyst expands further via deep or per-node. Bounded (1 pass) < deep.
      - `deep=True` → `investigate_case_agentic(max_passes=CASE_MAX_PASSES)` — the same
        one agent, re-seeding the uninvestigated inventory pass after pass until dry."""
    from investigations.agent import swarm, investigator  # noqa: F401 (swarm used by callers/tests)
    with db.connect() as conn:
        if deep:
            return investigator.investigate_case_agentic(
                conn, case, on_event=on_event, cancel=cancel,
                max_passes=investigator.CASE_MAX_PASSES, deep=True)
        # DEFAULT (k4p-01 un-cage + k4p-02 completeness): ONE agent over the whole case,
        # NO fan-out, UN-CAGED — it pivots freely to every seed + the assets it surfaces
        # (the 4_points shape) and runs to COMPLETENESS (covered/dry), not a single hop
        # and not a budget cut. CASE_MAX_PASSES is only a hard backstop; the completeness
        # stop concludes earlier. `shallow=True` opts back into RULE-112 leads-first.
        return investigator.investigate_case_agentic(
            conn, case, on_event=on_event, cancel=cancel,
            max_passes=investigator.CASE_MAX_PASSES, deep=False, caged=bool(shallow))


def _new_progress() -> dict:
    # The 4 aggregate keys are the stable base shape (an existing test pins it by equality).
    # The run-card per-node fields — `targets` (queued|running|done state machine),
    # `started_at` (epoch, live elapsed), `secs_per_target` + `eta_s` (historical ETA) — are
    # layered on by `_investigate_job` at launch and by `_update_progress` lazily, so they are
    # absent-safe here (run-progress-semantics).
    return {"phase": "starting", "targets_total": 0, "targets_done": 0, "findings": 0}


def _progress_target(prog: dict, name: str, create: bool = True):
    """Find the per-target record by name. With create=True (start signals), lazily add it so
    deep/whole-case runs — which have no `picked` pre-seed — still show each target as it
    appears. With create=False (completion lines), return None for an unknown name so a
    non-target summary like "✓ case mapped (...)" cannot fabricate a per-target node
    (codex finding-2)."""
    name = (name or "").strip()
    for t in prog.setdefault("targets", []):
        if t["name"] == name:
            return t
    if not create:
        return None
    rec = {"name": name, "state": "queued", "findings": 0}
    prog["targets"].append(rec)
    # Keep the total honest on lazy paths (deep/whole-case have no "picked N" seed): the
    # per-target list is the floor for targets_total, so the card never shows "1/0"
    # (codex finding-4). Seeded paths already match (picked sets total == len).
    prog["targets_total"] = max(prog.get("targets_total", 0), len(prog["targets"]))
    return rec


def _recompute_eta(prog: dict) -> None:
    """eta_s = (targets not yet done) × historical secs/target. Null when there's no history
    (cold-start) or no per-target list — never a fabricated number."""
    secs = prog.get("secs_per_target")
    targets = prog.get("targets") or []
    if not secs or not targets:
        prog["eta_s"] = None
        return
    remaining = sum(1 for t in targets if t.get("state") != "done")
    prog["eta_s"] = int(round(remaining * secs)) if remaining else 0


def _update_progress(prog: dict, line: str) -> None:
    """Derive a live progress snapshot from the swarm's own event lines (the same
    ones shown in the trail). The markers below are emitted UNTAGGED by
    volley/investigate_selected/_expand_selected; per-target sub-steps are prefixed
    'entity · …' so they don't match. Deterministic parse of strings we own — guarded by a
    unit test.

    Besides the aggregate counters, this assembles a per-target state machine
    (queued → running → done) in `prog["targets"]` so the run card can show node-by-node
    progress instead of a single "0/N · 0 findings" line that reads as a false negative
    mid-run (run-progress-semantics). `_recompute_eta` runs after each target-state change."""
    if line == "planning targets…":
        prog["phase"] = "planning"
        return
    if line.startswith("no pivotable entities"):
        prog["phase"] = "done"
        return
    # "picked N target(s): a, b, c" (investigate_selected + _expand_selected): set the total
    # AND seed each named target as queued so the card shows the whole belt up front.
    m = _re.match(r"^picked (\d+) target\(s\)(?::\s*(.*))?$", line)
    if m:
        prog["targets_total"] = int(m.group(1))
        prog["phase"] = "investigating"
        names = m.group(2)
        if names:
            for nm in (n.strip() for n in names.split(",")):
                if nm:
                    _progress_target(prog, nm)
        _recompute_eta(prog)
        return
    # Per-target START (untagged): "→ start {ent}" (volley worker) or "expanding {ent}…"
    # (one-hop set-expand). Flips THAT target to running. startswith guards keep tagged
    # sub-steps ("{ent} · …") from matching.
    sm = _re.match(r"^→ start (.+)$", line)
    if sm:
        _progress_target(prog, sm.group(1))["state"] = "running"
        prog["phase"] = "investigating"
        _recompute_eta(prog)
        return
    em = _re.match(r"^expanding (.+?)…$", line)
    if em:
        _progress_target(prog, em.group(1))["state"] = "running"
        prog["phase"] = "investigating"
        _recompute_eta(prog)
        return
    # Crew path inner rollup: "{ent} · crew merged: N finding(s)" is emitted (tagged) by
    # investigate_entity_crew. It is intentionally NOT counted here: volley ALWAYS wraps each
    # result with an UNTAGGED "✓ {ent}: N" (the authoritative per-target completion, fired for
    # the single-agent AND crew paths alike). Counting the rollup too double-counted
    # targets_done/findings on every crew target (codex finding-1). The tagged line falls
    # through inert — it doesn't start with "✓ "/"✗ " so the block below ignores it.
    if line.startswith("✓ ") or line.startswith("✗ "):
        prog["targets_done"] += 1
        fm = _re.search(r": (\d+) finding\(s\)", line)
        found = int(fm.group(1)) if fm else 0
        if fm:
            prog["findings"] += found
        # Named per-target completion: "✓ {ent}: K finding(s)" / "✗ {ent}: error". Mark THAT
        # target done with its count — but only if it is a KNOWN target (create=False), so a
        # whole-case summary like "✓ case mapped (...)" cannot fabricate a node (finding-2).
        # A known target with K=0 reads `done · none` (neutral), never a mid-run "0 findings"
        # verdict — the false-negative this whole feature fixes.
        dm = _re.match(r"^[✓✗] (.+?)(?::|$)", line)
        if dm:
            rec = _progress_target(prog, dm.group(1), create=False)
            if rec is not None:
                rec["state"] = "done"
                rec["findings"] = found
        _recompute_eta(prog)


def _prep_extract(case: str, on_event=None) -> None:
    """The 'brush' before a whole-case pass: turn the OSINT a prior run left as report
    TEXT into typed entities, so the next pass investigates the new artifacts — not just
    the handful the last run auto-promoted. Re-extract (deterministic) + typing (fit to
    the approved schema, recover missed wallets/orgs/infra). Best-effort; a failure here
    never blocks the investigation."""
    from investigations import reextract as reextract_mod, typing as typing_mod
    from investigations import understand as understand_mod
    if on_event:
        on_event("re-extracting new artifacts from this case…")
    with db.connect() as conn:
        try:
            rx = reextract_mod.run(conn, case)
            if on_event:
                on_event(f"extracted {rx.get('new_entities', 0)} new entity(ies) from report text")
        except Exception as exc:
            if on_event:
                on_event(f"re-extract skipped: {str(exc)[:120]}")
        schema = understand_mod.approved_schema(conn, case)
        if not schema:
            if on_event:
                on_event("no approved schema — skipped typing")
            return
        try:
            if on_event:
                on_event("typing new artifacts to the case schema…")
            typing_mod.run(conn, case, schema)
            if on_event:
                on_event("typing complete — new artifacts are now investigable")
        except Exception as exc:
            if on_event:
                on_event(f"typing skipped: {str(exc)[:120]}")


def _investigate_selected(case: str | None, targets: list, on_event=None) -> dict:
    from investigations.agent import swarm
    with db.connect() as conn:
        return swarm.investigate_selected(conn, case, targets, on_event=on_event)


def _expand_selected(case: str | None, targets: list, on_event=None, cancel=None) -> dict:
    """One-hop EXPAND of a selected SET (Maltego): run the deterministic infra belt on EACH
    target and promote its direct connections — ONE hop beyond the set, no LLM, no multi-hop
    chasing. The analyst drives the next hop by expanding the new nodes (founder: 'one set of
    nodes opens just one additional set of nodes hop beyond it, not multiple hops')."""
    from investigations.agent import investigator
    added = 0
    done = 0
    all_result_ids: list = []
    # Seed the per-target progress list up front so the 7-node set shows queued→running→done
    # node-by-node instead of a frozen "0 findings" (run-progress-semantics). The expand belt
    # has no LLM "picked" line of its own, so emit the same marker the parser already reads.
    clean_targets = [str(t) for t in targets if str(t).strip()]
    if on_event and clean_targets:
        on_event(f"picked {len(clean_targets)} target(s): {', '.join(clean_targets)}")
    with db.connect() as conn:
        for t in clean_targets:
            if cancel is not None and cancel.is_set():
                break
            if on_event:
                on_event(f"expanding {t}…")
            r = investigator.investigate_entity_quick(conn, t, case=case, on_event=on_event,
                                                      cancel=cancel, with_read=False)
            n_added = int(r.get("nodes_added") or 0)
            added += n_added
            all_result_ids += list(r.get("result_ids") or [])
            done += 1
            # Named per-target completion: for a one-hop expand, "found" = new connections
            # promoted. K=0 reads `done · none`, never a standing "0 findings" mid-run.
            if on_event:
                on_event(f"✓ {t}: {n_added} finding(s)")
        # ONE next-hop suggestion for the whole set (the agent advises; the analyst drives).
        next_hop = ""
        if all_result_ids and not (cancel is not None and cancel.is_set()):
            if on_event:
                on_event("thinking about the next hop…")
            label = ", ".join(str(t) for t in targets[:5]) + ("…" if len(targets) > 5 else "")
            next_hop = investigator._suggest_next_hop(
                f"the selected set ({label})", "mixed",
                investigator._infra_digest(conn, all_result_ids))
    return {"ok": True, "case": case, "expanded": done, "nodes_added": added,
            "next_hop": next_hop, "worked": added > 0 or done > 0}


def _investigate_job(entity: str | None, case: str | None, analyst: str,
                     shallow: bool = False, question: str | None = None,
                     prep: bool = False, entities: list | None = None,
                     deep: bool = False, edge: tuple | None = None,
                     expand: bool = False) -> None:
    """Background investigator run — an explicit selected set (`entities`), a single
    entity, or (no entity) a whole-case swarm where the agent plans its own targets.
    Streams every move to the job log. `prep` brushes new OSINT artifacts into typed
    entities first (whole-case only)."""
    key = _investigate_key(case)
    label = (f"{len(entities)} selected node(s)" if entities else entity) or "whole case"
    cancel = _threading.Event()
    # Seed the run clock + ETA basis once at launch: started_at drives the live elapsed
    # display; secs_per_target is the historical avg used for the ETA (None on cold-start).
    start_progress = _new_progress()
    start_progress["started_at"] = time.time()
    try:
        from investigations.agent import swarm as _swarm_eta
        with db.connect() as _eta_conn:
            start_progress["secs_per_target"] = _swarm_eta._historical_seconds_per_target(_eta_conn)[0]
    except Exception:
        pass
    with _INVESTIGATE_LOCK:
        _INVESTIGATE_CANCEL[key] = cancel
        _INVESTIGATE_JOBS[key] = {"status": "running", "case": case, "entity": label,
                                  "log": [], "progress": start_progress}

    def on_event(line: str) -> None:
        with _INVESTIGATE_LOCK:
            job = _INVESTIGATE_JOBS.get(key)
            if job is None:
                return
            log = job.setdefault("log", [])
            log.append(line)
            if len(log) > _INVESTIGATE_LOG_MAX:
                del log[: len(log) - _INVESTIGATE_LOG_MAX]
            _update_progress(job.setdefault("progress", _new_progress()), line)

    def _set_phase(phase: str) -> None:
        with _INVESTIGATE_LOCK:
            job = _INVESTIGATE_JOBS.get(key)
            if job is not None:
                job.setdefault("progress", _new_progress())["phase"] = phase

    try:
        # Brush new artifacts into typed entities before the agent plans (whole-case
        # only — single-entity runs are already targeted).
        if prep and case and not entity and not entities:
            _set_phase("extracting")
            _prep_extract(case, on_event=on_event)
        if edge:
            result = _investigate_edge(edge[0], edge[1], case, on_event=on_event,
                                       cancel=cancel)
        elif entities and expand:
            result = _expand_selected(case, entities, on_event=on_event, cancel=cancel)
        elif entities:
            result = _investigate_selected(case, entities, on_event=on_event)
        elif entity:
            result = _investigate_entity(entity, case, on_event=on_event, question=question,
                                         cancel=cancel, expand=expand)
        else:
            result = _investigate_swarm(case, shallow, on_event=on_event, cancel=cancel,
                                        deep=deep)
        # Analyst Stop wins the status label: a stopped run is not an error, it kept
        # whatever already landed.
        if cancel.is_set() or result.get("stopped"):
            status = "stopped"
        elif not result.get("ok"):
            status = "error"
        elif result.get("worked") is False:
            # Ran but collected nothing (no tools, no findings). Not an error, but NOT a
            # silent success either — surface it so the analyst knows the agent did no work.
            status = "no_work"
        else:
            status = "done"
        # Auto-write the brief BEFORE marking the job done, so the deliverable is fresh the
        # moment a run finishes (the founder shouldn't have to click Regenerate). Best-effort:
        # a brief failure never fails the investigation whose findings already landed.
        # SKIP on EXPAND and any SINGLE-NODE run: a one-hop expand or a "just info about this
        # node" dig should NOT re-synthesize the whole-case brief (an LLM pass) — that was the
        # hidden cost/slowness on every node click. The whole-case + selected-set runs still
        # auto-refresh the deliverable; single-node uses the on-demand Regenerate brief button.
        if status == "done" and case and not expand and not entity:
            try:
                _set_phase("writing brief")
                on_event("writing the brief…")
                from investigations import synthesize as synthesize_mod
                with db.connect() as bconn:
                    synthesize_mod.run(bconn, VAULT_DIR, case=case)
                on_event("brief written")
            except Exception as brief_exc:
                on_event(f"brief auto-write skipped: {str(brief_exc)[:120]}")
        with _INVESTIGATE_LOCK:
            prev = _INVESTIGATE_JOBS.get(key, {})
            prog = prev.get("progress") or _new_progress()
            prog["phase"] = ("stopped" if status == "stopped"
                             else "no findings — agent ran no tools (check setup)"
                             if status == "no_work" else "done")
            _INVESTIGATE_JOBS[key] = {"status": status, "result": result, "case": case,
                                      "entity": label, "log": prev.get("log"), "progress": prog}
            _INVESTIGATE_CANCEL.pop(key, None)
        # The agent promoted findings → nodes/edges. Tell open views to refresh.
        bump_case(case)
    except Exception as exc:
        with _INVESTIGATE_LOCK:
            prev = _INVESTIGATE_JOBS.get(key, {})
            prog = prev.get("progress") or _new_progress()
            prog["phase"] = "error"
            _INVESTIGATE_JOBS[key] = {"status": "error", "result": {"error": str(exc)[:200]},
                                      "case": case, "entity": label, "log": prev.get("log"),
                                      "progress": prog}
            _INVESTIGATE_CANCEL.pop(key, None)


@app.get("/api/investigate/preflight")
async def api_investigate_preflight():
    """Which OSINT tools are live vs need a key — so the analyst sees, BEFORE
    spending a run, that a no-key investigation would be shallow (not a silent
    surprise from thin findings)."""
    from investigations.agent import swarm
    return JSONResponse(swarm.tool_status())


@app.get("/api/investigate/estimate")
async def api_investigate_estimate(request: Request):
    """Pre-run cost estimate so the analyst sees the bill BEFORE committing a run (kills the
    'expensive black box' sin). ?deep=1 estimates a whole-case deep run; default is a one-hop
    expand. Returns the POINT estimate (est_typical_usd) + the cap ceiling + the basis. NEVER
    blocks a run — informational only (cost-model-budget-the-scope)."""
    from investigations.agent import swarm
    case = _active_case(request)
    deep = str(request.query_params.get("deep", "")).strip() in ("1", "true", "True", "yes")
    with db.connect() as conn:
        est = swarm.estimate_run(conn, case, deep=deep)
    return JSONResponse(est)


@app.post("/api/investigate")
async def api_investigate(request: Request):
    """Run the investigator agent. Body: {entities:[..]} for an analyst-chosen set
    (PRD-07), {entity} for one target, else a whole-case swarm (optionally {deep:true}).
    The agent auto-builds the graph from validated findings; unvalidated stay gated."""
    body = await request.json()
    case = _active_case(request)
    entity = (body.get("entity") or "").strip()
    # Explicit selected set: run the full agent on exactly these (no planner). Dedup +
    # cap; analyst's pick overrides the planner's skip-covered.
    raw_entities = body.get("entities") or []
    entities = [e.strip() for e in raw_entities if isinstance(e, str) and e.strip()] \
        if isinstance(raw_entities, list) else []
    capped = entities[:_SELECT_CAP]
    over_cap = len(entities) > _SELECT_CAP
    # A selected-set or whole-case swarm needs a case; single-entity can run unscoped.
    if not entity and not capped and not case:
        return JSONResponse({"error": "Pick a single case for a swarm investigation."},
                            status_code=400)
    # All paths run as a streaming background job → /api/investigate/status.
    key = _investigate_key(case)
    analyst = _active_analyst(request)
    label = (f"{len(capped)} selected node(s)" if capped else entity) or "whole case"
    with _INVESTIGATE_LOCK:
        cur = _INVESTIGATE_JOBS.get(key)
        if cur and cur.get("status") == "running":
            return JSONResponse({"status": "running", "case": case,
                                 "entity": cur.get("entity")})
        _INVESTIGATE_JOBS[key] = {"status": "running", "case": case,
                                  "entity": label, "log": [], "progress": _new_progress()}
    question = (body.get("question") or "").strip() or None
    t = _threading.Thread(target=_investigate_job,
                          args=(entity or None, case, analyst, bool(body.get("shallow")),
                                question, bool(body.get("prep")), capped or None,
                                bool(body.get("deep"))),
                          kwargs={"expand": bool(body.get("expand"))},
                          daemon=True)
    t.start()
    record_ui_event(case, f"launched an investigation on {label}")
    resp = {"status": "started", "case": case, "entity": label}
    if over_cap:
        resp["note"] = f"Selected more than {_SELECT_CAP}; running the first {_SELECT_CAP}."
    return JSONResponse(resp)


@app.post("/api/investigate/edge")
async def api_investigate_edge(request: Request):
    """Investigate a graph EDGE (the relationship), not just read it. Body: {src, dst}
    entity ids. Runs investigator.investigate_edge as a background job keyed by case —
    the analyst expands an edge on demand (4pp-15)."""
    body = await request.json()
    case = _active_case(request)
    try:
        src = int(body.get("src")); dst = int(body.get("dst"))
    except (TypeError, ValueError):
        return JSONResponse({"error": "src + dst entity ids required"}, status_code=400)
    analyst = _active_analyst(request)
    key = _investigate_key(case)
    with _INVESTIGATE_LOCK:
        cur = _INVESTIGATE_JOBS.get(key)
        if cur and cur.get("status") == "running":
            return JSONResponse({"status": "running", "case": case,
                                 "entity": cur.get("entity")})
    t = _threading.Thread(target=_investigate_job,
                          kwargs={"entity": None, "case": case, "analyst": analyst,
                                  "edge": (src, dst)},
                          daemon=True)
    t.start()
    return JSONResponse({"status": "started", "case": case, "edge": [src, dst]})


@app.get("/api/investigate/status")
async def api_investigate_status(request: Request):
    """Live state of the active case's investigator run: status + streaming step
    log + final result. 'idle' if none has run."""
    case = _active_case(request)
    with _INVESTIGATE_LOCK:
        job = _INVESTIGATE_JOBS.get(_investigate_key(case))
    return JSONResponse(job or {"status": "idle", "case": case})


@app.post("/api/investigate/stop")
async def api_investigate_stop(request: Request):
    """Stop the active case's running investigation. Signals the run to wrap up — the
    agent is killed and whatever it already found is salvaged + kept (not discarded)."""
    case = _active_case(request)
    key = _investigate_key(case)
    with _INVESTIGATE_LOCK:
        cancel = _INVESTIGATE_CANCEL.get(key)
        job = _INVESTIGATE_JOBS.get(key)
        running = bool(job and job.get("status") == "running")
        if cancel is not None:
            cancel.set()
    if not running or cancel is None:
        return JSONResponse({"ok": False, "error": "no run in progress"}, status_code=400)
    return JSONResponse({"ok": True, "stopping": True, "case": case})


@app.get("/simple", response_class=HTMLResponse)
async def simple_page(request: Request):
    """PRD-03 Simple Mode: one seed in, watch the agent build it out. No intake, no
    schema, no setup — the front door / demo path."""
    return _tpl(request, "simple.html", {})


@app.post("/api/quick-look")
async def api_quick_look(request: Request, payload: dict):
    """PRD-03: take a single seed (username / domain / wallet / handle), spin up a case
    behind the scenes, and run the full investigator on it immediately. No schema gate.
    Returns the case slug; the page then streams the live run via /api/investigate/status."""
    seed = (payload.get("seed") or "").strip()
    if not seed:
        return JSONResponse({"error": "Enter a username, domain, wallet, or handle."},
                            status_code=400)
    slug = _slugify(seed) or "quick-look"
    analyst = _active_analyst(request)
    with db.connect() as conn:
        conn.execute("INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?, ?)",
                     (slug, f"Quick look: {seed[:60]}"))
        conn.commit()
    key = _investigate_key(slug)
    with _INVESTIGATE_LOCK:
        cur = _INVESTIGATE_JOBS.get(key)
        if cur and cur.get("status") == "running":
            return _with_case_cookie({"status": "running", "case": slug, "seed": seed}, slug)
        _INVESTIGATE_JOBS[key] = {"status": "running", "case": slug, "entity": seed,
                                  "log": [], "progress": _new_progress()}
    t = _threading.Thread(target=_investigate_job, args=(seed, slug, analyst),
                          daemon=True)
    t.start()
    # Make the quick-look case active so the live status + graph scope to it.
    return _with_case_cookie({"status": "started", "case": slug, "seed": seed}, slug)


def _with_case_cookie(body: dict, slug: str) -> JSONResponse:
    resp = JSONResponse(body)
    resp.set_cookie(CASE_COOKIE, slug, max_age=60 * 60 * 24 * 365, samesite="lax")
    return resp


@app.post("/api/find-links")
async def api_find_links(request: Request):
    """Re-extract fingerprints + correlate cross-domain links for the active case
    (or all cases if none selected)."""
    case = _active_case(request)
    analyst = _active_analyst(request)
    result = await run_in_threadpool(_find_links, case, analyst)
    return JSONResponse(result)


@app.get("/cross-domain", response_class=HTMLResponse)
async def cross_domain_page(request: Request):
    """Shared-fingerprint hubs: the domains/handles/wallets linked because they
    share a tracking tag, WalletConnect id, nameserver, or service-account id."""
    from investigations import fingerprints as fp_mod
    cases = _active_cases(request)
    case = _active_case(request)
    with db.connect() as conn:
        hubs = fp_mod.shared(conn, case)
        # Count fingerprint entities in scope so the empty state can explain why.
        scope_sql, scope_params = _scope(cases)
        fp_count = conn.execute(
            "SELECT COUNT(*) FROM entities e WHERE e.entity_type IN "
            "('tracking_tag','walletconnect_id','saas_service_account','nameserver','registrar','registrant_email') "
            f"{scope_sql}", scope_params).fetchone()[0]
    return _tpl(request, "cross-domain.html", {"hubs": hubs, "fp_count": fp_count})


def _asset_rollup(results: list[dict]) -> list[dict]:
    """Group a run's findings by the asset they're about, and for each compute: how it
    was first found (provenance + step), which tools checked it, whether it's live
    (parsed from dns/whois results), and whether it was actively pivoted (>=2 checks or
    a liveness check) vs merely surfaced once. Makes "the agent found these URLs" legible:
    where each came from, if it was chased, if it resolves."""
    import re as _re2
    PROV_TOOL = _re2.compile(
        r"(dns_lookup|reverse_dns|whois|crtsh|virustotal|abusech|web_search|perplexity|"
        r"tavily|exa|jina|social_scrape|apify|webfetch|dns)", _re2.I)
    DEAD = _re2.compile(r"no dns|not found|does not resolve|nxdomain|servfail|no a record|"
                        r"no records|unregistered|no whois|is down|currently down", _re2.I)
    LIVE = _re2.compile(r"\bA record|resolves|http 200|name ?server|\bns\d|registrar|"
                        r"\bactive\b|MX record|hosted", _re2.I)
    LIVE_TOOLS = {"dns", "reverse_dns", "whois", "virustotal", "webfetch"}
    # "Chased" = the agent actively PROBED the asset (infra/reputation/fetch/scrape),
    # not merely named it in a web search. A search mention is "surfaced", not pivoted.
    INVESTIGATE_TOOLS = LIVE_TOOLS | {"crtsh", "crtsh_subdomains", "abusech",
                                      "social_scrape", "jina"}
    INFRA_TYPES = {"domain", "subdomain", "url", "ip"}
    # The agent runs tools two ways: an MCP tool (step_tool = 'dns_lookup') or the Bash
    # belt (step_tool = 'bash', the REAL provider only in the provenance). So collect the
    # tool from step_tool AND from every provider named in the provenance — union — or a
    # belt-run whois/dns gets mislabeled 'bash' and the asset wrongly reads "not chased".
    GENERIC = {"", "bash", "task", "read", "toolsearch", "tasksearch"}
    by: dict[str, dict] = {}
    for r in results:
        ent = (r.get("title") or "").strip()
        if not ent:
            continue
        a = by.setdefault(ent, {"asset": ent, "type": r.get("entity_type") or "?",
                                "checks": set(), "found_via": None, "found_step": None,
                                "promoted": False, "_blob": ""})
        st = (r.get("step_tool") or "").strip().lower()
        if st and st not in GENERIC:
            a["checks"].add(st.replace("_lookup", ""))
        for m in PROV_TOOL.finditer(r.get("provenance") or ""):
            a["checks"].add(m.group(1).lower().replace("_lookup", ""))
        if a["found_via"] is None:
            a["found_via"] = r.get("provenance") or st or "?"
            a["found_step"] = r.get("step_ref")
        if r.get("extracted_entity_id"):
            a["promoted"] = True
        a["_blob"] += " " + (r.get("summary") or "") + " " + (r.get("provenance") or "")
    out = []
    for a in by.values():
        checks = a["checks"]
        has_live = bool(checks & LIVE_TOOLS)
        blob = a.pop("_blob")
        if a["type"] not in INFRA_TYPES:
            live = "n/a"            # liveness is meaningless for an org/person/wallet
        elif not has_live:
            live = "not checked"
        elif DEAD.search(blob):
            live = "dead"
        elif LIVE.search(blob):
            live = "live"
        else:
            live = "checked"
        out.append({"asset": a["asset"], "type": a["type"], "found_via": a["found_via"],
                    "found_step": a["found_step"], "checks": sorted(checks), "live": live,
                    "pivoted": bool(checks & INVESTIGATE_TOOLS), "promoted": a["promoted"]})
    order = {"domain": 0, "subdomain": 0, "url": 0, "ip": 1, "wallet": 2}
    out.sort(key=lambda x: (order.get(x["type"], 5), x["asset"]))
    return out


def _agent_findings(conn, cases) -> list[dict]:
    """Every investigator-agent run in the case-set, with the entity it targeted,
    its findings, and the process trail. Powers the Findings page (one place for
    all agent output, instead of hopping entity to entity)."""
    import json as _json
    clause, cparams = _case_in(cases, col="r.investigation")
    where = "WHERE r.provider_slug = 'agent'" + (f" AND {clause}" if clause else "")
    runs = conn.execute(
        f"SELECT r.id, r.entity_id, r.query, r.started_at, r.investigation, r.agent_process, "
        f"e.canonical_name AS entity_name, e.notes AS entity_notes, e.sub_role AS entity_sub_role "
        f"FROM enrichment_runs r LEFT JOIN entities e ON e.id = r.entity_id "
        f"{where} ORDER BY r.id DESC", cparams).fetchall()
    out = []
    for r in runs:
        d = {"run_id": r["id"], "entity_id": r["entity_id"],
             "entity_name": r["entity_name"] or "(target not in DB)",
             "entity_role": _role(r["entity_notes"]), "entity_sub_role": r["entity_sub_role"],
             "query": r["query"], "started_at": r["started_at"], "case": r["investigation"]}
        try:
            d["process"] = _json.loads(r["agent_process"]) if r["agent_process"] else None
        except (TypeError, ValueError):
            d["process"] = None
        results = []
        for x in conn.execute(
            "SELECT id, title, summary, url, confidence, extracted_entity_id, raw_json "
            "FROM enrichment_results WHERE run_id = ? AND result_type = 'finding'", (r["id"],)):
            rec = dict(x)
            try:
                rj = _json.loads(rec.pop("raw_json")) if rec.get("raw_json") else {}
            except (TypeError, ValueError):
                rj = {}
            # Step attribution rides in the finding's raw_json (set by the agent's
            # _attribute_findings); surface it for the Run trail "from step N".
            rec["step_ref"] = rj.get("step_ref")
            rec["step_tool"] = rj.get("step_tool")
            rec["provenance"] = rj.get("provenance")
            rec["entity_type"] = rj.get("entity_type")
            results.append(rec)
        d["results"] = results
        d["promoted"] = sum(1 for x in d["results"] if x["extracted_entity_id"])
        # Per-discovered-asset rollup: how each URL/domain/wallet was found, what checks
        # ran on it, whether it's live, and whether it was actively pivoted vs just
        # mentioned. Answers "where did this come from / did we chase it / is it live".
        d["assets"] = _asset_rollup(results)
        # PRD-04: split the agent's recommended pivots into 'investigate now' vs
        # 'needs external' so the doable ones become one-click runs, not chores.
        from investigations.agent import pivots as pivots_mod, swarm as swarm_mod
        configured = {n.lower() for n in swarm_mod.tool_status().get("live", [])}
        recs = (d.get("process") or {}).get("recommended_pivots") or []
        classified = pivots_mod.classify_all(recs, configured)
        d["pivots_now"] = [p for p in classified if p.get("actionable_now")]
        d["pivots_blocked"] = [p for p in classified if not p.get("actionable_now")]
        out.append(d)
    return out


@app.get("/api/findings")
async def api_findings(request: Request):
    """All investigator-agent findings for the active case-set."""
    with db.connect() as conn:
        runs = _agent_findings(conn, _active_cases(request))
    total = sum(len(r["results"]) for r in runs)
    return JSONResponse({"runs": runs, "run_count": len(runs), "finding_count": total})


@app.get("/findings")
async def findings_page(request: Request):
    """Findings merged into the single Investigate page (/runs) — same agent-run
    data, now one stage with a Trail/Findings toggle. Kept as a redirect so old
    links + bookmarks land on the Findings view."""
    return RedirectResponse(url="/runs?view=findings", status_code=302)


@app.get("/runs", response_class=HTMLResponse)
async def runs_page(request: Request):
    """The single Investigate page. Same agent-run data, two views via a toggle:
    'trail' = the narrative of what the AI actually did; 'findings' = the flat,
    promotable list of what it turned up. `?view=findings` opens the latter."""
    view = "findings" if request.query_params.get("view") == "findings" else "trail"
    with db.connect() as conn:
        runs = _agent_findings(conn, _active_cases(request))
    total = sum(len(r["results"]) for r in runs)
    promoted = sum(r["promoted"] for r in runs)
    return _tpl(request, "runs.html",
                {"runs": runs, "finding_count": total, "promoted_count": promoted,
                 "default_view": view})


def _synthesize_case(case: str, analyst: str) -> dict:
    """Regenerate the case synthesis brief in-process (same call the Process
    pipeline makes), so the analyst can refresh it without a terminal."""
    from investigations import synthesize as synthesize_mod, tradecraft
    with db.connect() as conn:
        synthesize_mod.run(conn, VAULT_DIR, case=case)
        activity_mod.log(conn, analyst, "regenerated the synthesis brief",
                         investigation=case)
        # SOFT nudge (founder: never block): if a tradecraft gate hasn't run, surface it
        # on the brief so the analyst sees what was skipped — they decide whether to go back.
        unmet = tradecraft.unmet_gates(conn, case)
    out = {"ok": True, "case": case}
    if unmet:
        names = ", ".join(s["label"] for s in unmet)
        out["tradecraft_warning"] = (
            f"Brief generated, but {len(unmet)} tradecraft gate(s) haven't run: {names}. "
            "Consider running them before you deliver.")
        out["unmet_gates"] = [s["key"] for s in unmet]
    return out


_SYNTH_JOBS: dict = {}
_SYNTH_LOCK = _threading.Lock()


def _synthesize_job(case: str, analyst: str) -> None:
    """Run the brief on the SERVER in a background thread, so switching windows or
    reloading the page can't kill it (the old blocking fetch died when the tab backgrounded
    mid-LLM-pass). The UI polls /api/synthesize/status and reconnects on load."""
    try:
        # Project FIRST: a brief never renders pre-override state (sp3).
        from investigations import projection
        with db.connect() as conn:
            projection.project(conn, case)
            conn.commit()
        result = _synthesize_case(case, analyst)
        # The brief regenerated: ONE event that logs the act + bumps the case
        # version in the same transaction (gap 2 closed structurally).
        with db.connect() as conn:
            store.apply_mutation(conn, store.brief_generated(
                case, actor=f"analyst:{analyst}",
                detail={"trigger": "synthesize-job"}))
        with _SYNTH_LOCK:
            _SYNTH_JOBS[case] = {**result, "status": "done"}
    except Exception as exc:
        with _SYNTH_LOCK:
            _SYNTH_JOBS[case] = {"status": "error", "error": str(exc)[:200], "case": case}


@app.post("/api/synthesize")
async def api_synthesize(request: Request):
    """Start a brief regeneration as a background JOB (closes the input → findings →
    deliverable loop without the CLI). Returns immediately; poll /api/synthesize/status.
    The server does the LLM pass, so the brief completes even if the analyst switches
    windows or reloads (the old blocking fetch dropped the work when the tab backgrounded)."""
    case = _active_case(request)
    if not case:
        return JSONResponse({"error": "Pick a single case to regenerate its brief."},
                            status_code=400)
    analyst = _active_analyst(request)
    with _SYNTH_LOCK:
        cur = _SYNTH_JOBS.get(case)
        if cur and cur.get("status") == "running":
            return JSONResponse({"status": "running", "case": case})
        _SYNTH_JOBS[case] = {"status": "running", "case": case}
    _threading.Thread(target=_synthesize_job, args=(case, analyst), daemon=True).start()
    return JSONResponse({"status": "started", "case": case})


@app.get("/api/synthesize/status")
async def api_synthesize_status(request: Request):
    """Poll the brief job for the active case: idle | running | done | error."""
    case = _active_case(request)
    with _SYNTH_LOCK:
        job = dict(_SYNTH_JOBS.get(case) or {"status": "idle"})
    return JSONResponse(job)


def _explain_cluster(case: str | None, names: list[str]) -> dict:
    """Plain-English read of a selected cluster: gather the nodes + how they interconnect
    + a claim or two each, then one bounded LLM pass answers 'what is this?'."""
    from investigations.llm import client as llm
    with db.connect() as conn:
        ents = []
        for n in [x for x in names if x][:40]:
            row = conn.execute(
                "SELECT id, canonical_name, entity_type FROM entities "
                "WHERE canonical_name = ? COLLATE NOCASE LIMIT 1", (n,)).fetchone()
            if row:
                ents.append(row)
        if not ents:
            return {"ok": False, "error": "Could not resolve the selected nodes."}
        idset = {e["id"] for e in ents}
        lines = []
        for e in ents:
            edges = conn.execute(
                "SELECT t.rel_type, t.dst_entity_id, e2.canonical_name AS other "
                "FROM typed_relationships t JOIN entities e2 ON e2.id = t.dst_entity_id "
                "WHERE t.src_entity_id = ? AND COALESCE(t.status,'active') = 'active' LIMIT 20",
                (e["id"],)).fetchall()
            within = [f"{r['rel_type']} → {r['other']}" for r in edges if r["dst_entity_id"] in idset]
            out_links = [f"{r['rel_type']} → {r['other']}" for r in edges if r["dst_entity_id"] not in idset]
            claim = conn.execute(
                "SELECT value FROM claims WHERE entity_id = ? AND value IS NOT NULL "
                "AND length(value) > 0 LIMIT 1", (e["id"],)).fetchone()
            part = f"- {e['canonical_name']} ({e['entity_type'] or 'entity'})"
            org = _node_origin(conn, e["id"])
            if org and org.get("trail"):
                part += f"; origin: {org['trail']}"
            if within:
                part += "; in-cluster: " + "; ".join(within[:6])
            if out_links:
                part += "; also: " + "; ".join(out_links[:4])
            if claim and claim["value"]:
                part += f"; note: {str(claim['value'])[:120]}"
            lines.append(part)
    body = "\n".join(lines)
    system = (
        "You are an OSINT analyst. Given a CLUSTER of graph nodes (each with its ORIGIN — "
        "how it entered the investigation), answer in plain English and tight: (1) WHERE this "
        "cluster came from — what seed or pivot brought it in (use the origins; if it looks "
        "disconnected, say what tied it to the case); (2) what it IS (one actor's "
        "infrastructure, a payment chain, a content network, a coincidence); (3) the bottom "
        "line + the single best next pivot. Lead with the origin. No preamble, no restating "
        "the node list.")
    prompt = f"Case: {case or '(unscoped)'}\n\nCluster ({len(lines)} nodes):\n{body}\n\nWhat is this cluster?"
    try:
        ans = llm.ask(prompt, system=system, tools=False, max_tokens=700).strip()
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}
    return {"ok": True, "answer": ans or "(no read returned)", "node_count": len(lines)}


@app.post("/api/cluster/explain")
async def api_cluster_explain(request: Request):
    """'What is this?' for a selected cluster (the node ledger / a box-selection). Body:
    {names:[...]}. Returns a plain-English read of what the cluster represents + the next pivot."""
    body = await request.json()
    raw = body.get("names") or []
    names = [s.strip() for s in raw if isinstance(s, str) and s.strip()] if isinstance(raw, list) else []
    if not names:
        return JSONResponse({"error": "Select some nodes first, then ask."}, status_code=400)
    case = _active_case(request)
    try:
        result = await run_in_threadpool(_explain_cluster, case, names)
    except Exception as exc:
        return JSONResponse({"error": f"Cluster read failed: {str(exc)[:200]}"}, status_code=500)
    if not result.get("ok"):
        return JSONResponse(result, status_code=500)
    return JSONResponse(result)


@app.get("/api/tradecraft")
async def api_tradecraft_state(request: Request):
    """The per-case tradecraft checklist (Scope/Challenge/Premortem gates + helper steps),
    for the chat's step bar. None/empty for no single case."""
    from investigations import tradecraft
    case = _active_case(request)
    with db.connect() as conn:
        st = tradecraft.state(conn, case)
    return JSONResponse({"case": case, "steps": st or []})


@app.post("/api/tradecraft/scope")
async def api_tradecraft_scope(request: Request):
    """Capture the case framing (the analyst feeds it): the question, the hypotheses, and
    what counts as proof. Stored as the 'scope' gate artifact."""
    from investigations import tradecraft
    case = _active_case(request)
    if not case:
        return JSONResponse({"error": "Pick a single case to scope."}, status_code=400)
    body = await request.json()
    question = (body.get("question") or "").strip()
    hypotheses = (body.get("hypotheses") or "").strip()
    proof = (body.get("proof") or "").strip()
    if not question:
        return JSONResponse({"error": "A core question is required to scope the case."},
                            status_code=400)
    content = (f"## Core question\n{question}\n\n## Hypotheses\n{hypotheses or '(none stated)'}"
               f"\n\n## What counts as proof\n{proof or '(not specified)'}")
    analyst = _active_analyst(request)
    with db.connect() as conn:
        tradecraft.record(conn, case, "scope", content, analyst=analyst)
        activity_mod.log(conn, analyst, "scoped the investigation", investigation=case)
        st = tradecraft.state(conn, case)
    bump_case(case)
    return JSONResponse({"ok": True, "step": "scope", "content": content, "steps": st})


@app.post("/api/tradecraft/run")
async def api_tradecraft_run(request: Request):
    """Run an analytical gate (challenge | premortem) over the case's current findings,
    store the result, and return it for display in the chat."""
    from investigations import tradecraft
    case = _active_case(request)
    if not case:
        return JSONResponse({"error": "Pick a single case to run this step."}, status_code=400)
    body = await request.json()
    step = (body.get("step") or "").strip()
    if step not in ("challenge", "premortem"):
        return JSONResponse({"error": "step must be 'challenge' or 'premortem'."},
                            status_code=400)
    analyst = _active_analyst(request)

    def _go():
        with db.connect() as conn:
            out = tradecraft.run_analysis(conn, case, step, analyst=analyst)
            if out.get("ok"):
                activity_mod.log(conn, analyst, f"ran the {step} analysis", investigation=case)
                out["steps"] = tradecraft.state(conn, case)
            return out

    try:
        result = await run_in_threadpool(_go)
    except Exception as exc:
        return JSONResponse({"error": f"{step} failed: {str(exc)[:200]}"}, status_code=500)
    if not result.get("ok"):
        return JSONResponse(result, status_code=500)
    bump_case(case)
    return JSONResponse(result)


def _run_understand(case: str, analyst: str) -> dict:
    from investigations import understand as understand_mod
    with db.connect() as conn:
        schema = understand_mod.discover_schema(conn, case)
        activity_mod.log(conn, analyst, "ran Understand (proposed an entity schema)",
                         investigation=case)
    return {"ok": True, "case": case, "schema": schema, "status": "proposed"}


@app.post("/api/understand")
async def api_understand(request: Request):
    """Run the Understand step: read the case, PROPOSE an entity/role schema fit
    to its domain. Stores it as 'proposed' — the analyst approves on /schema."""
    case = _active_case(request)
    if not case:
        return JSONResponse({"error": "Pick a single case to understand."}, status_code=400)
    analyst = _active_analyst(request)
    try:
        result = await run_in_threadpool(_run_understand, case, analyst)
    except Exception as exc:
        return JSONResponse({"error": f"Understand failed: {str(exc)[:200]}"}, status_code=500)
    return JSONResponse(result)


@app.post("/api/schema/approve")
async def api_schema_approve(request: Request):
    """Save the analyst-edited schema and mark it APPROVED. Only an approved
    schema drives classification (Process)."""
    from investigations import understand as understand_mod
    case = _active_case(request)
    if not case:
        return JSONResponse({"error": "Pick a single case."}, status_code=400)
    body = await request.json()
    schema = body.get("schema")
    if not isinstance(schema, dict) or not schema.get("roles"):
        return JSONResponse({"error": "schema with at least one role required"}, status_code=400)
    inv_type = (body.get("investigation_type") or "").strip()
    analyst = _active_analyst(request)
    with db.connect() as conn:
        understand_mod.save_schema(conn, case, schema, status="approved", analyst=analyst)
        if inv_type:
            from investigations.intake import types as types_mod
            types_mod.set_type(conn, case, inv_type, status="approved")
        activity_mod.log(conn, analyst, "approved the entity schema", investigation=case)
    return JSONResponse({"ok": True, "case": case, "status": "approved"})


@app.get("/schema", response_class=HTMLResponse)
async def schema_page(request: Request):
    """Review / edit / approve the case's entity-role schema (the Understand
    step's output). The analyst is the top authority — Process won't classify
    until the schema here is approved."""
    from investigations import understand as understand_mod
    from investigations.intake import types as types_mod
    case = _active_case(request)
    row = None
    inv_type = None
    objective = ""
    if case:
        with db.connect(migrate=False) as conn:
            row = understand_mod.get_schema(conn, case)
            inv_type = types_mod.get_type(conn, case)
            objective = db.get_objective(conn, case)
    if row:
        schema, status = row["schema"], row["status"]
        approved_by, approved_at = row.get("approved_by"), row.get("approved_at")
    else:
        schema, status = understand_mod.DEFAULT_SCHEMA, "default"
        approved_by = approved_at = None
    return _tpl(request, "schema.html", {
        "schema": schema, "schema_status": status, "case": case,
        "approved_by": approved_by, "approved_at": approved_at,
        "inv_type": inv_type, "type_options": list(types_mod.TAXONOMY.keys()),
        "objective": objective,
    })


@app.get("/sources", response_class=HTMLResponse)
async def sources_page(request: Request):
    return _tpl(request, "sources.html", {})


@app.get("/focus", response_class=HTMLResponse)
async def focus_page(request: Request):
    case = _active_case(request)
    with db.connect() as conn:
        focus = _load_focus(case, conn)
        stats = _scoped_stats(conn, _active_cases(request))
    return _tpl(request, "focus.html", {"focus": focus, "stats": stats})


@app.get("/bridges", response_class=HTMLResponse)
async def bridges_page(request: Request):
    return _tpl(request, "bridges.html", {})


@app.get("/synthesis", response_class=HTMLResponse)
async def synthesis_page(request: Request):
    case = _active_case(request)
    synth_path = _synth_path(case)
    regen_cmd = f"./invctl synthesize --case {case}" if case else "./invctl synthesize"
    if synth_path.exists():
        content = synth_path.read_text(encoding="utf-8")
    else:
        scope_label = f" for {case}" if case else ""
        content = f"_No synthesis brief{scope_label} yet — Regenerate it below._"
    # Staleness check (shared helper): the brief bakes in the report count at
    # generation time; compare to the live count so it can't read as current.
    stale = None
    if synth_path.exists():
        with db.connect(migrate=False) as conn:
            _state, stale = _brief_freshness(conn, case)
        # Strip the YAML frontmatter for display — it was parsed in the helper, it
        # should not render as body text in the brief.
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) == 3:
                content = parts[2].lstrip("\n")
    return _tpl(request, "synthesis.html",
                {"content": content, "stale": stale, "regen_cmd": regen_cmd,
                 "has_brief": synth_path.exists(), "can_regen": bool(case)})


@app.get("/api/assessment")
async def api_assessment(request: Request):
    """The whole-case assessment (the synthesis brief markdown) for the on-graph overlay —
    a read-only peek at the same brief `/synthesis` renders, so the analyst sees the verdict
    without leaving the graph (assessment-dossier-promotion). Mirrors synthesis_page's read.

    Every edge case returns 200 with has_brief:false rather than an error, so the overlay
    shows its empty state and never a broken panel: no active case, missing/unreadable/empty
    brief, or a freshness-check that raises (stale:null, best-effort)."""
    case = _active_case(request)
    if not case:
        return JSONResponse({"has_brief": False, "case": None, "markdown": "", "stale": None})
    synth_path = _synth_path(case)
    try:
        content = synth_path.read_text(encoding="utf-8") if synth_path.exists() else ""
    except OSError:
        content = ""
    if not content.strip():
        return JSONResponse({"has_brief": False, "case": case, "markdown": "", "stale": None})
    stale = None
    try:
        with db.connect(migrate=False) as conn:
            _state, stale = _brief_freshness(conn, case)
    except Exception:
        stale = None  # best-effort: a freshness failure must not blank the assessment
    # Strip YAML frontmatter so it doesn't render as body text (same as synthesis_page).
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) == 3:
            content = parts[2].lstrip("\n")
    return JSONResponse({"has_brief": True, "case": case, "markdown": content, "stale": stale})


@app.get("/exports", response_class=HTMLResponse)
async def exports_page(request: Request):
    return _tpl(request, "exports.html", {})


@app.get("/report", response_class=HTMLResponse)
async def report_builder(request: Request):
    return _tpl(request, "report-builder.html", {})


@app.get("/report/render", response_class=HTMLResponse)
async def report_render(request: Request, client: str = "", title: str = "",
                        prepared_by: str = "", accent: str = "#1e3a5f", logo: str = "",
                        sections: str = "summary,actors,dossiers,iocs,crosscase,methodology"):
    """The branded, print-ready client report for the active case."""
    case = _active_case(request)
    if not case:
        return HTMLResponse(
            "<p style='font-family:sans-serif;padding:2rem'>Pick a case first "
            "(top-right switcher), then build the report.</p>", status_code=400)
    import datetime as _dt
    sel = {s.strip() for s in sections.split(",") if s.strip()}
    # Sanitize the accent to a hex colour (it goes straight into a CSS var).
    if not _re.match(r"^#[0-9a-fA-F]{3,8}$", accent or ""):
        accent = "#1e3a5f"
    with db.connect() as conn:
        data = client_report_mod.gather(conn, VAULT_DIR, case)
        activity_mod.log(conn, _active_analyst(request), "generated client report",
                         investigation=case)
    case_name = data["case"].get("case_name") or case
    branding = {
        "client": (client.strip()[:80] or (data["case"].get("client") or "")),
        "title": (title.strip()[:120] or f"Intelligence Report — {case_name}"),
        "prepared_by": (prepared_by.strip()[:80] or _active_analyst(request)),
        "accent": accent,
        "logo": (logo.strip()[:1000] if logo.strip().startswith(("http://", "https://", "data:image/")) else ""),
        "generated_at": _dt.date.today().isoformat(),
    }
    return templates.TemplateResponse(request, "report.html",
                                      {"d": data, "b": branding, "sel": sel})


@app.get("/api/search")
async def api_search(request: Request, q: str = "", limit: int = 20):
    if not q.strip():
        return JSONResponse({"results": []})
    pat = f"%{q.strip()}%"
    scope_sql, scope_params = _scope(_active_cases(request))
    with db.connect() as conn:
        results = []
        for r in conn.execute(
            "SELECT DISTINCT e.id, e.canonical_name, e.entity_type, e.notes, "
            "e.sub_role, s.threat_score "
            "FROM entities e LEFT JOIN entity_scores s ON s.entity_id = e.id "
            "LEFT JOIN aliases a ON a.entity_id = e.id "
            f"WHERE (e.canonical_name LIKE ? OR a.alias LIKE ?) {scope_sql} "
            "ORDER BY s.threat_score DESC NULLS LAST LIMIT ?",
            (pat, pat, *scope_params, limit),
        ).fetchall():
            d = dict(r)
            d["role"] = _role(d.get("notes"))
            results.append(d)
    return JSONResponse({"results": results})


# Shipped style-rule defaults (issue graph-style-rules). The community→color set
# ships DISABLED so it never fights the analyst cluster colors out of the box
# (PRD finding-7 mitigation) — the analyst opts in from the rule editor.
_STYLE_RULE_DEFAULTS = [
    {"label": "Betweenness → size", "selector": "node[betweenness]",
     "style": {"width": "mapData(betweenness, 0, 0.3, 24, 64)",
               "height": "mapData(betweenness, 0, 0.3, 24, 64)"}, "enabled": 1},
    {"label": "Analyst-added → solid amber border", "selector": "node[origin = 'manual']",
     "style": {"border-width": 3, "border-color": "#B45309", "border-style": "solid"},
     "enabled": 1},
    {"label": "AI/OSINT-discovered → dashed teal border", "selector": "node[origin = 'osint']",
     "style": {"border-width": 2, "border-color": "#0F766E", "border-style": "dashed"},
     "enabled": 1},
] + [
    {"label": f"Community {c} → color", "selector": f"node[community = '{c}']",
     "style": {"background-color": color}, "enabled": 0}
    for c, color in (("c0", "#7C3AED"), ("c1", "#0E7490"), ("c2", "#B45309"),
                     ("c3", "#BE185D"), ("c4", "#15803D"), ("c5", "#4338CA"))
]


# A hidden marker row (position -1, never returned) records that a case's rule
# set was seeded once — so an analyst's intentionally-empty set stays empty on
# the next GET instead of resurrecting the defaults.
_SEED_MARKER = "__seeded__"


def _seed_style_rules(conn, case: str | None, force: bool = False) -> None:
    """Seed the shipped defaults once per case. The marker INSERT is guarded by
    NOT EXISTS in a single statement, so two racing first-touch GETs cannot
    double-seed (SQLite serializes writers; only one marker insert wins)."""
    if not force:
        cur = conn.execute(
            "INSERT INTO style_rules (investigation, label, selector, style_json, enabled, position) "
            "SELECT ?, ?, '', '{}', 0, -1 "
            "WHERE NOT EXISTS (SELECT 1 FROM style_rules WHERE investigation IS ? AND label = ?)",
            (case, _SEED_MARKER, case, _SEED_MARKER))
        if not cur.rowcount:
            conn.commit()
            return   # already seeded once (even if the analyst emptied the set since)
    for pos, r in enumerate(_STYLE_RULE_DEFAULTS):
        conn.execute(
            "INSERT INTO style_rules (investigation, label, selector, style_json, enabled, position) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (case, r["label"], r["selector"], json.dumps(r["style"]), r["enabled"], pos))
    conn.commit()


@app.get("/api/graph/style-rules")
async def api_style_rules(request: Request, case: str | None = None, seed: bool = True):
    case = (case or "").strip() or None
    with db.connect() as conn:
        if seed:
            _seed_style_rules(conn, case)
        rows = conn.execute(
            "SELECT id, label, selector, style_json, enabled, position FROM style_rules "
            "WHERE investigation IS ? AND position >= 0 ORDER BY position, id", (case,)).fetchall()
        return {"case": case, "rules": [
            {"id": r["id"], "label": r["label"], "selector": r["selector"],
             "style": json.loads(r["style_json"]), "enabled": bool(r["enabled"]),
             "position": r["position"]} for r in rows]}


@app.put("/api/graph/style-rules")
async def api_style_rules_put(request: Request):
    """Replace the case's full rule list (the editor saves the whole set)."""
    body = await request.json()
    # Accept the case from the body OR the ?case= query param — the GET/PUT pair
    # advertises the same ?case= contract, so a query-param-only caller must not
    # silently write the global NULL bucket.
    case = (body.get("case") or request.query_params.get("case") or "").strip() or None
    if body.get("reset"):
        # Explicit restore-defaults: wipe the analyst rules and force-reseed.
        with db.connect() as conn:
            conn.execute("DELETE FROM style_rules WHERE investigation IS ? AND position >= 0", (case,))
            _seed_style_rules(conn, case, force=True)
        return {"ok": True, "reset": True}
    rules = body.get("rules")
    if not isinstance(rules, list):
        return JSONResponse({"error": "rules must be a list"}, status_code=400)
    cleaned = []
    for i, r in enumerate(rules):
        err = _validate_style_rule(r)
        if err:
            return JSONResponse({"error": f"rule #{i + 1}: {err}"}, status_code=400)
        cleaned.append(r)
    with db.connect() as conn:
        # The seed marker (position -1) survives a replace — an intentionally
        # emptied set must stay empty on the next GET.
        conn.execute("DELETE FROM style_rules WHERE investigation IS ? AND position >= 0", (case,))
        for pos, r in enumerate(cleaned):
            conn.execute(
                "INSERT INTO style_rules (investigation, label, selector, style_json, enabled, position) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (case, (r.get("label") or "rule").strip()[:80], r["selector"].strip(),
                 json.dumps(r["style"]), 1 if r.get("enabled", True) else 0, pos))
        conn.commit()
    return {"ok": True, "count": len(cleaned)}


# Known-safe cytoscape style properties a rule may set (issue
# graph-style-validation). Visual-only: no content/label injection surface,
# no event hooks. Unknown properties are rejected by name.
_SAFE_STYLE_PROPS = {
    "background-color", "background-opacity", "border-width", "border-color",
    "border-style", "border-opacity", "width", "height", "shape", "opacity",
    "color", "font-size", "font-weight", "text-outline-color",
    "text-outline-width", "line-color", "line-style", "line-opacity",
    "target-arrow-color", "target-arrow-shape", "source-arrow-color",
    "source-arrow-shape", "arrow-scale", "curve-style", "z-index",
    "text-opacity", "underlay-color", "underlay-opacity", "underlay-padding",
}

# Coarse selector sanity (full parsing is cytoscape's job, isolated client-side
# per rule): the cytoscape selector charset (incl. '?' for boolean data attrs
# like node[?is_bridge]) + ordered bracket balance + paired quotes.
_SELECTOR_RE = _re.compile(r"^[A-Za-z0-9\s\[\]'\"=^$*!?<>.,:#_()-]+$")


def _brackets_balanced(s: str) -> bool:
    depth = 0
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth < 0:    # ']' before '[' — reversed brackets
                return False
    return depth == 0


def _validate_style_rule(r) -> str | None:
    """Reject a malformed rule with a NAMED reason; None = valid. Server-side
    checks are deterministic (charset/balance/allowlist); cytoscape-level
    selector semantics are isolated client-side (each rule applies in its own
    try/catch — a rejected rule is skipped + flagged, never blanks the canvas)."""
    if not isinstance(r, dict):
        return "must be an object"
    sel = r.get("selector")
    if not isinstance(sel, str) or not sel.strip():
        return "selector is required"
    if len(sel) > 300:
        return "selector too long"
    if not _SELECTOR_RE.match(sel):
        return "selector contains characters outside the cytoscape selector syntax"
    if not _brackets_balanced(sel):
        return "selector has unbalanced brackets"
    if sel.count("'") % 2 or sel.count('"') % 2:
        return "selector has unbalanced quotes"
    style = r.get("style")
    if not isinstance(style, dict) or not style:
        return "style must be a non-empty object"
    for k, v in style.items():
        if not isinstance(k, str) or not isinstance(v, (str, int, float)):
            return f"style property {k!r} must map to a string or number (flat dict only)"
        if k not in _SAFE_STYLE_PROPS:
            return f"unknown style property {k!r} (allowed: visual properties only)"
        if isinstance(v, str) and len(v) > 200:
            return f"style value for {k!r} too long"
    return None


@app.get("/api/graph")
async def api_graph(request: Request, min_score: float = 30.0, cluster_id: int | None = None,
                    role: str | None = None, sub_role: str | None = None,
                    etype: str | None = None, in_cluster_only: bool = True,
                    show_all: bool = False, origin: str | None = None,
                    co_occurrence: bool = True, meaningful_only: bool = True,
                    focus: int | None = None):
    scope_sql, scope_params = _scope(_active_cases(request))
    with db.connect() as conn:
        cluster_filter = ""
        params: list = []
        if cluster_id:
            cluster_filter = ("AND e.id IN (SELECT entity_id FROM cluster_members "
                              "WHERE cluster_id = ?)")
            params.append(cluster_id)
        role_filter = ""
        if role:
            role_filter = f"AND e.notes LIKE 'role:{role}%'"
        sub_role_filter = ""
        if sub_role:
            sub_role_filter = "AND e.sub_role = ?"
            params.append(sub_role)
        # Filter by entity TYPE (domain / ip / url / hash / telegram_channel / …) —
        # the granular axis under the coarse 'ioc' role.
        type_filter = ""
        if etype:
            # Match either the regex surface type or the case schema type.
            type_filter = "AND (e.entity_type = ? OR e.case_type = ?)"
            params.append(etype)
            params.append(etype)
        # Enrichment-derived nodes are exempt from the score + in-cluster gates so
        # what an analyst promotes off an enrichment always shows on the graph
        # (they start with a low score and may not be in a cluster yet).
        ENRICH_NODE = ("e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
                       "ON r.id = m.report_id WHERE r.source_type IN ('enrichment','manual'))")
        # "Show all" drops the score + in-cluster gates so every real entity shows
        # (singleton fingerprints, low-score nodes, the long tail). The hard noise
        # filters stay — role:noise + raw person_candidate are extraction garbage,
        # not "everything". Limit bumps so the tail actually appears.
        if show_all:
            score_pred, score_params = "1=1", []
            in_cluster_filter, limit = "", 1200
        else:
            score_pred, score_params = (
                f"(s.threat_score IS NULL OR s.threat_score >= ? OR {ENRICH_NODE})", [min_score])
            in_cluster_filter = (
                f"AND (e.id IN (SELECT entity_id FROM cluster_members) OR {ENRICH_NODE})"
                if in_cluster_only else "")
            limit = 400
        # origin = where the entity FIRST appeared: an ingested report (intake) vs an
        # enrichment/manual report (the detective/OSINT added it). Lets the graph show
        # at a glance what came from the source vs what the investigation discovered.
        # Meaningful-only: a node earns a place on the graph if it's CONNECTED (has a
        # typed edge) or CLASSIFIED (has a role). Drops the raw phone numbers, truncated
        # handles, and OCR fragments that carry no analytic meaning. On by default;
        # toggle off to see the full extraction tail.
        meaning_filter = ""
        if meaningful_only:
            # A node earns a place if it's CONNECTED (typed edge), CLASSIFIED (role),
            # CLUSTERED (an analyst/LLM grouped it), or ANALYST-PROMOTED (enrichment /
            # manual — these must always show, same carve-out as the score gate). Only
            # the truly orphaned tail (bare phones, OCR fragments) is dropped.
            # A node earns a graph spot only if it's CONNECTED (typed edge), CLASSIFIED
            # (role), or CLUSTERED. The old `OR ENRICH_NODE` exemption let ORPHAN
            # enrichment leftovers (a bare phone with no edges + no data) clutter the
            # graph — dropped. Connected enrich nodes still show via the edge clause; the
            # orphan tail lives in the entity/findings views, not the network map.
            meaning_filter = (
                "AND (e.notes LIKE 'role:%' "
                "OR e.id IN (SELECT src_entity_id FROM typed_relationships WHERE status='active' "
                "            UNION SELECT dst_entity_id FROM typed_relationships WHERE status='active') "
                "OR e.id IN (SELECT entity_id FROM cluster_members)) "
                # Drop free-text deception assets (scam slogans / lure copy / impersonated
                # brand strings) from the graph — they're findings, not network nodes, and
                # they bury the real domain→wallet→infra structure. Toggle 'meaningful only'
                # off to see them; they still live in the entity + findings views.
                "AND (e.notes IS NULL OR e.notes NOT LIKE 'role:deception_asset%') ")
        # "osint" = the detective TOUCHED this entity: it discovered it (first_seen via
        # enrichment) OR investigated it (has an agent run). That's what the analyst wants
        # to see — what the detective worked on — not just the handful it created fresh.
        _TOUCHED = ("(rp0.source_type IN ('enrichment','manual') "
                    "OR e.id IN (SELECT entity_id FROM enrichment_runs "
                    "WHERE provider_slug='agent' AND entity_id IS NOT NULL))")
        origin_filter = ""
        if origin == "intake":
            origin_filter = f"AND NOT {_TOUCHED} "
        elif origin == "osint":
            origin_filter = f"AND {_TOUCHED} "
        # FOCUS mode (opening one node "on a new graph"): restrict to that node + its
        # neighborhood (typed + co-occurrence neighbors) and drop the score/cluster/
        # meaning gates — the neighborhood IS the filter. Without this, ?focus only
        # panned to the node while still loading the entire graph.
        if focus:
            nbr = {focus}
            for r in conn.execute(
                "SELECT src_entity_id, dst_entity_id FROM typed_relationships "
                "WHERE (src_entity_id=? OR dst_entity_id=?) AND status='active'",
                (focus, focus)).fetchall():
                nbr.add(r["src_entity_id"]); nbr.add(r["dst_entity_id"])
            for r in conn.execute(
                "SELECT src_entity_id, dst_entity_id FROM relationships "
                "WHERE rel_type='co_mentioned' AND (src_entity_id=? OR dst_entity_id=?) LIMIT 250",
                (focus, focus)).fetchall():
                nbr.add(r["src_entity_id"]); nbr.add(r["dst_entity_id"])
            fph = ",".join("?" * len(nbr))
            score_pred, score_params = f"e.id IN ({fph})", list(nbr)
            params = []
            cluster_filter = role_filter = sub_role_filter = type_filter = ""
            in_cluster_filter = meaning_filter = origin_filter = ""
            limit = 600
        entities = conn.execute(
            f"SELECT e.id, e.canonical_name, e.entity_type, e.case_type, e.notes, "
            f"e.sub_role, e.thumbnail, rp0.source_type AS origin_src, "
            f"(SELECT 1 FROM enrichment_runs er WHERE er.entity_id = e.id "
            f" AND er.provider_slug = 'agent' LIMIT 1) AS investigated, "
            f"s.threat_score, s.degree, s.report_count "
            f"FROM entities e LEFT JOIN entity_scores s ON s.entity_id = e.id "
            f"LEFT JOIN reports rp0 ON rp0.id = e.first_seen_report_id "
            f"WHERE {score_pred} "
            f"AND (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
            f"AND (e.entity_type != 'person_candidate' OR e.notes IS NOT NULL) "
            f"AND (e.hidden IS NULL OR e.hidden = 0) "
            f"{meaning_filter}{origin_filter}"
            f"{cluster_filter} {role_filter} {sub_role_filter} {type_filter} {in_cluster_filter} {scope_sql} "
            f"ORDER BY s.threat_score DESC NULLS LAST LIMIT {limit}",
            (*score_params, *params, *scope_params),
        ).fetchall()
        node_ids = set()
        # entity_id -> set of cluster_ids it belongs to
        node_cluster_map: dict[int, set[int]] = {}
        for cm in conn.execute(
            "SELECT entity_id, cluster_id FROM cluster_members"
        ).fetchall():
            node_cluster_map.setdefault(cm["entity_id"], set()).add(cm["cluster_id"])
        # Graph-metric properties ride on the node payload as cytoscape data attrs
        # so style rules can select on them (node[betweenness], node[community='c0']
        # — issue graph-style-rules, the finding-4 API contract). Numbers parse so
        # mapData works; community stays a string label. Scoped to the VISIBLE
        # entities (not a global node_properties scan) — a small case must not pay
        # O(all properties). metrics_provenance names the case that computed the
        # score (last-write-wins on shared entities is the documented model).
        # path_confidence (graph-trust-layer gtl-1): the strength of a node's
        # WEAKEST link back to a case seed, so the front-end can de-weight a strong
        # sub-chain that hangs off one weak bridge. Carried as a numeric data attr
        # alongside the centrality metrics. A node with NO path_confidence row is
        # unreachable from a seed (not weak — unanchored); left absent, not 0-faked.
        _METRIC_KEYS = ("degree_centrality", "betweenness", "eigenvector", "community",
                        "path_confidence")
        visible_ids = [e["id"] for e in entities]
        node_metrics: dict[int, dict] = {}
        if visible_ids:
            for np_row in conn.execute(
                f"SELECT entity_id, key, value, provenance FROM node_properties "
                f"WHERE key IN ({','.join('?' * len(_METRIC_KEYS))}) "
                f"AND entity_id IN ({','.join('?' * len(visible_ids))})",
                (*_METRIC_KEYS, *visible_ids)):
                m = node_metrics.setdefault(np_row["entity_id"], {})
                if np_row["key"] == "community":
                    m["community"] = np_row["value"]
                else:
                    try:
                        m[np_row["key"]] = float(np_row["value"])
                    except (TypeError, ValueError):
                        continue
                m["metrics_provenance"] = np_row["provenance"] or ""
        nodes = []
        for e in entities:
            node_ids.add(e["id"])
            r = _role(e["notes"])
            ent_clusters = sorted(node_cluster_map.get(e["id"], set()))
            nodes.append({"data": {
                "id": str(e["id"]),
                "label": e["canonical_name"][:40],
                "full_name": e["canonical_name"],
                "type": e["case_type"] or e["entity_type"],
                "surface_type": e["entity_type"],
                "case_type": e["case_type"] or "",
                "role": r,
                "sub_role": e["sub_role"] or "",
                "score": e["threat_score"] or 0,
                "degree": e["degree"] or 0,
                "report_count": e["report_count"] or 0,
                "cluster_ids": ent_clusters,
                "is_bridge": len(ent_clusters) >= 2,
                "thumbnail": e["thumbnail"] or "",
                "origin": ("manual" if e["origin_src"] == "manual"
                           else "osint" if (e["origin_src"] == "enrichment" or e["investigated"])
                           else "intake"),
                **node_metrics.get(e["id"], {}),
            }})
        # t.id (the integer PK) is selected so the client can address the real edge
        # for hypothesis tagging (ea-2) — the cytoscape `id` below is a fabricated
        # display string, not addressable.
        edge_rows = conn.execute(
            "SELECT id, src_entity_id, dst_entity_id, rel_type, confidence, evidence "
            "FROM typed_relationships WHERE status = 'active'"
        ).fetchall()
        visible_edge_ids = [r["id"] for r in edge_rows
                            if r["src_entity_id"] in node_ids and r["dst_entity_id"] in node_ids]
        edge_hyp = hypotheses_mod.tags_for_edges(conn, visible_edge_ids)
        edges = []
        for r in edge_rows:
            if r["src_entity_id"] in node_ids and r["dst_entity_id"] in node_ids:
                src_cl = node_cluster_map.get(r["src_entity_id"], set())
                dst_cl = node_cluster_map.get(r["dst_entity_id"], set())
                # Two definitions surfaced together:
                #   strict_cross = endpoints share NO cluster (rare in practice)
                #   bridge_edge  = at least one endpoint is in 2+ clusters (analyst-useful)
                strict_cross = bool(src_cl and dst_cl and not (src_cl & dst_cl))
                bridge_edge = (len(src_cl) >= 2) or (len(dst_cl) >= 2)
                edges.append({"data": {
                    "id": f"e{r['src_entity_id']}-{r['dst_entity_id']}-{r['rel_type']}",
                    "edge_id": r["id"],
                    "source": str(r["src_entity_id"]),
                    "target": str(r["dst_entity_id"]),
                    "rel_type": r["rel_type"],
                    "confidence": r["confidence"],
                    "evidence": (r["evidence"] or "")[:200],
                    "cross_cluster": strict_cross,
                    "bridge_edge": bridge_edge,
                    "hypotheses": edge_hyp.get(r["id"], []),
                }})
        # Co-occurrence ("same pic") edges: entities that appeared together in a report.
        # These live in `relationships` (rel_type='co_mentioned'), which the graph never
        # drew before — so two entities from the same screenshot looked unrelated. Drawn
        # faint + capped, only when toggled on. The query is:
        #   - SCOPED to the visible nodes (IN the node id set) so it doesn't scan the
        #     whole table, and to the active case-set so the report count is case-accurate;
        #   - DIRECTION-NORMALIZED (lo/hi) so reciprocal (a,b)/(b,a) rows merge into one
        #     pair with the correct shared-report count (was double-counted/undercounted);
        #   - ORDERED by shared DESC + LIMITed, so the cap keeps the STRONGEST pairs
        #     deterministically instead of dropping random ones.
        co_truncated = False
        if co_occurrence and node_ids:
            typed_pairs = {(e["data"]["source"], e["data"]["target"]) for e in edges}
            typed_pairs |= {(t, s) for s, t in typed_pairs}
            CO_CAP = 1500
            id_list = list(node_ids)
            ph = ",".join("?" * len(id_list))
            co_case_sql, co_case_params = _case_in(_active_cases(request), "rp.investigation")
            co_join = "JOIN reports rp ON rp.id = rel.report_id" if co_case_sql else ""
            co_where = f"AND {co_case_sql} " if co_case_sql else ""
            co_rows = conn.execute(
                f"SELECT MIN(rel.src_entity_id, rel.dst_entity_id) AS lo, "
                f"  MAX(rel.src_entity_id, rel.dst_entity_id) AS hi, "
                f"  COUNT(DISTINCT rel.report_id) AS shared "
                f"FROM relationships rel {co_join} "
                f"WHERE rel.rel_type = 'co_mentioned' "
                f"AND rel.src_entity_id IN ({ph}) AND rel.dst_entity_id IN ({ph}) {co_where}"
                f"GROUP BY lo, hi ORDER BY shared DESC LIMIT ?",
                (*id_list, *id_list, *co_case_params, CO_CAP + 1)).fetchall()
            n_co = 0
            for r in co_rows:
                a, b = r["lo"], r["hi"]
                key = (str(a), str(b))
                # Skip if a TYPED edge already connects them (the real relationship wins).
                if key in typed_pairs or (str(b), str(a)) in typed_pairs:
                    continue
                if n_co >= CO_CAP:
                    co_truncated = True
                    break
                n_co += 1
                edges.append({"data": {
                    "id": f"co{a}-{b}",
                    "source": str(a), "target": str(b),
                    "rel_type": "co-occurs", "confidence": "low",
                    "evidence": f"appeared together in {r['shared']} report(s)",
                    "co_occurrence": True,
                }})
        clusters_data = [dict(r) for r in conn.execute(
            "SELECT c.id, c.name, c.kind, "
            "GROUP_CONCAT(cm.entity_id) AS member_ids "
            "FROM clusters c LEFT JOIN cluster_members cm ON cm.cluster_id = c.id "
            "GROUP BY c.id"
        ).fetchall()]
    return JSONResponse({"nodes": nodes, "edges": edges, "clusters": clusters_data,
                         "co_truncated": co_truncated})


@app.post("/api/edge/{edge_id}/hypothesis")
async def api_edge_hypothesis(request: Request, edge_id: int):
    """Set or clear a hypothesis stance on a typed edge (ea-2). Body:
    {hypothesis, stance ∈ supports/contradicts/consistent_with} to set, or
    {hypothesis, clear: true} to remove. Never mutates the edge itself."""
    analyst = _active_analyst(request)
    case = _active_case(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    hyp = (payload.get("hypothesis") or "").strip()
    if not hyp:
        return JSONResponse({"error": "hypothesis is required"}, status_code=400)
    with db.connect() as conn:
        if payload.get("clear"):
            result = hypotheses_mod.clear_tag(conn, edge_id, hyp, author=analyst)
        else:
            try:
                result = hypotheses_mod.set_tag(conn, edge_id, hyp,
                                                payload.get("stance"), author=analyst)
            except hypotheses_mod.BadStance as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
        if result.get("error"):
            return JSONResponse(result, status_code=400)
        _log(request, conn, "tagged edge hypothesis", detail=f"edge {edge_id}: {hyp}")
        bump_case(case, conn=conn)
    return JSONResponse(result, status_code=200)


@app.get("/api/entity/{entity_id}/artifacts")
async def api_entity_artifacts(entity_id: int):
    """The captured point-in-time evidence artifacts for an entity (ea-1) — the raw
    provider/finding responses that ground this node, newest-first, so an analyst
    can pull the proof even after the live source changed or died."""
    from investigations import evidence as evidence_mod
    with db.connect() as conn:
        artifacts = evidence_mod.artifacts_for_entity(conn, entity_id)
    return JSONResponse({"entity_id": entity_id, "artifacts": artifacts})


@app.get("/api/entity/{entity_id}/neighborhood")
async def api_neighborhood(entity_id: int):
    with db.connect() as conn:
        center = conn.execute(
            "SELECT e.id, e.canonical_name, e.entity_type, e.notes, e.sub_role, "
            "s.threat_score "
            "FROM entities e LEFT JOIN entity_scores s ON s.entity_id = e.id "
            "WHERE e.id = ?", (entity_id,),
        ).fetchone()
        if not center:
            return JSONResponse({"nodes": [], "edges": []})
        nodes = {center["id"]: dict(center)}
        edges = []
        for r in conn.execute(
            "SELECT * FROM typed_relationships "
            "WHERE (src_entity_id = ? OR dst_entity_id = ?) AND status = 'active'",
            (entity_id, entity_id),
        ).fetchall():
            other_id = (r["dst_entity_id"] if r["src_entity_id"] == entity_id
                        else r["src_entity_id"])
            other = conn.execute(
                "SELECT e.id, e.canonical_name, e.entity_type, e.notes, e.sub_role, "
                "s.threat_score "
                "FROM entities e LEFT JOIN entity_scores s ON s.entity_id = e.id "
                "WHERE e.id = ?", (other_id,),
            ).fetchone()
            if other:
                nodes[other_id] = dict(other)
            edges.append(dict(r))
        cy_nodes = []
        for nid, n in nodes.items():
            cy_nodes.append({"data": {
                "id": str(nid),
                "label": n["canonical_name"][:40],
                "full_name": n["canonical_name"],
                "type": n["entity_type"],
                "role": _role(n.get("notes")),
                "sub_role": n.get("sub_role") or "",
                "score": n.get("threat_score") or 0,
            }})
        cy_edges = []
        for e in edges:
            cy_edges.append({"data": {
                "id": f"e{e['src_entity_id']}-{e['dst_entity_id']}-{e['rel_type']}",
                "source": str(e["src_entity_id"]),
                "target": str(e["dst_entity_id"]),
                "rel_type": e["rel_type"],
                "confidence": e["confidence"],
            }})
    return JSONResponse({"nodes": cy_nodes, "edges": cy_edges})


def _rel_gloss(rel_type: str) -> str:
    """Human-readable label for a controlled-vocab edge type (panel/edge legend)."""
    try:
        from investigations.enrich.rel_vocab import gloss
        return gloss(rel_type or "")
    except Exception:
        return rel_type or ""


def _providers_for_type(entity_type: str | None) -> set[str] | None:
    """The provider slugs that apply to a node's type, for the type-filtered transform
    menu (Maltego-style: right action on the right node). Uses the agent's existing
    _infra_belt_for_type mapping. Returns None when the type has no specific recipe
    (actor/handle/org/wallet) so the caller falls back to the full provider list (those
    nodes are enriched by search providers, not an infra belt)."""
    try:
        from investigations.agent.investigator import _infra_belt_for_type
    except Exception:
        return None
    belt = _infra_belt_for_type(entity_type)
    if not belt:
        return None
    return {slug for slug, _mode in belt}


def _origin_target(query: str) -> str:
    """The clean target a run was investigating, from its (possibly messy / tab-joined)
    query string — the host the analyst would recognise."""
    import re as _re
    q = (query or "").strip()
    m = _re.search(r"https?://([^/\s]+)", q)
    host = m.group(1) if m else (q.split()[0] if q.split() else q)
    return _re.sub(r"^www\.", "", host.strip().lower()).rstrip("/")[:60] or "the case"


def _node_origin(conn, entity_id: int) -> dict | None:
    """Where this node came from — so it never looks 'out of nowhere' (founder 2026-06-11).
    A found node traces to the run that surfaced it, and that run's query is the target the
    investigator was digging (its pivot source). An ingested node traces to its report."""
    e = conn.execute("SELECT canonical_name, provenance, first_seen_at FROM entities "
                     "WHERE id = ?", (entity_id,)).fetchone()
    if not e:
        return None
    prov = (e["provenance"] or "").strip().lower()
    when = (e["first_seen_at"] or "")[:10]
    run = conn.execute(
        "SELECT er.query FROM enrichment_results res JOIN enrichment_runs er ON er.id = res.run_id "
        "WHERE res.extracted_entity_id = ? ORDER BY er.started_at LIMIT 1", (entity_id,)).fetchone()
    if run and run["query"]:
        tgt = _origin_target(run["query"])
        if tgt and tgt not in (e["canonical_name"] or "").lower():
            return {"trail": f"found by the investigator while digging {tgt}",
                    "when": when, "kind": "pivot", "from": tgt}
        return {"trail": "found by the investigator agent", "when": when, "kind": "agent"}
    rep = conn.execute(
        "SELECT r.title, r.source_type FROM mentions m JOIN reports r ON r.id = m.report_id "
        "WHERE m.entity_id = ? AND COALESCE(r.source_type,'') != 'enrichment' "
        "ORDER BY r.id LIMIT 1", (entity_id,)).fetchone()
    if prov.startswith("ingest") or rep:
        src = (rep["title"] if rep else None) or "an uploaded report"
        return {"trail": f"extracted from {src}", "when": when, "kind": "intake"}
    if prov == "analyst":
        return {"trail": "you added this manually", "when": when, "kind": "analyst"}
    if prov in ("agent", "osint"):
        return {"trail": "found by the investigator agent", "when": when, "kind": "agent"}
    if prov.startswith("enrich"):
        return {"trail": "materialized from an infrastructure lookup", "when": when, "kind": "enrich"}
    return {"trail": prov or "origin unknown", "when": when, "kind": "other"}


@app.get("/api/entity/{entity_id}/detail")
async def api_entity_detail(entity_id: int, request: Request):
    """Everything the graph panel needs to make a node MEAN something: what it is,
    WHERE it came from (the source report + the screenshot context = its meaning), and
    what it's connected to AND HOW (typed rel + direction), plus its clusters."""
    # Source context is scoped to the active case-set so a single-case view never shows
    # another case's screenshots for a shared entity (entities are a global pool).
    src_case_sql, src_case_params = _case_in(_active_cases(request), "r.investigation")
    with db.connect(migrate=False) as conn:
        e = conn.execute(
            "SELECT e.id, e.canonical_name, e.entity_type, e.case_type, e.notes, "
            "e.sub_role, e.provenance, rp.source_type AS origin_src, "
            "(SELECT COUNT(*) FROM typed_relationships t "
            " WHERE (t.src_entity_id=e.id OR t.dst_entity_id=e.id) AND t.status='active') AS deg "
            "FROM entities e LEFT JOIN reports rp ON rp.id = e.first_seen_report_id "
            "WHERE e.id = ?", (entity_id,)).fetchone()
        if not e:
            return JSONResponse({"error": "not found"}, status_code=404)
        # Typed property sheet (registrar, A-record, ASN, dates…) — real fields, not prose.
        properties = [dict(r) for r in conn.execute(
            "SELECT key, value, value_type, provenance, confidence FROM node_properties "
            "WHERE entity_id = ? ORDER BY key", (entity_id,)).fetchall()]
        role = _role(e["notes"])
        investigated = conn.execute(
            "SELECT 1 FROM enrichment_runs WHERE entity_id=? AND provider_slug='agent' LIMIT 1",
            (entity_id,)).fetchone() is not None
        origin = ("manual" if e["origin_src"] == "manual"
                  else "osint" if (e["origin_src"] == "enrichment" or investigated)
                  else "intake")
        dossier = (annotations_mod.get(conn, entity_id) or {}).get("dossier_override") or ""
        # WHERE IT CAME FROM — the source reports + the mention context (its meaning).
        sources = []
        src_where = f"AND {src_case_sql} " if src_case_sql else ""
        for r in conn.execute(
            "SELECT r.title, r.source_type, m.context FROM mentions m "
            "JOIN reports r ON r.id = m.report_id WHERE m.entity_id = ? " + src_where +
            "ORDER BY (m.context IS NULL), m.id LIMIT 4",
            (entity_id, *src_case_params)).fetchall():
            sources.append({"report": r["title"] or "report", "kind": r["source_type"],
                            "context": " ".join((r["context"] or "").split())[:280]})
        # CONNECTED + HOW — typed edges with direction + the analyst-readable rel.
        # Scoped to the active case (the OTHER endpoint must appear in this case) so a
        # single-case view doesn't surface another case's relationships. in/out counts
        # come from the full scoped set (not the rendered slice), so they're accurate.
        mem_sql, mem_params = _case_in(_active_cases(request), "rc.investigation")
        in_case = (f"AND other_id IN (SELECT mc.entity_id FROM mentions mc "
                   f"JOIN reports rc ON rc.id = mc.report_id WHERE {mem_sql}) "
                   if mem_sql else "")
        rows = conn.execute(
            "SELECT rel_type, confidence, evidence, dir, other_id FROM ("
            "  SELECT tr.rel_type, tr.confidence, tr.evidence, "
            "    CASE WHEN tr.src_entity_id=? THEN 'out' ELSE 'in' END AS dir, "
            "    CASE WHEN tr.src_entity_id=? THEN tr.dst_entity_id ELSE tr.src_entity_id END AS other_id "
            "  FROM typed_relationships tr "
            "  WHERE (tr.src_entity_id=? OR tr.dst_entity_id=?) AND tr.status='active') "
            f"WHERE 1=1 {in_case} ORDER BY (dir='out') DESC LIMIT 300",
            (entity_id, entity_id, entity_id, entity_id, *mem_params)).fetchall()
        in_degree = sum(1 for r in rows if r["dir"] == "in")
        out_degree = sum(1 for r in rows if r["dir"] == "out")
        has_claims = claims_mod._has(conn, "claims")
        conns = []
        for r in rows[:80]:
            o = conn.execute("SELECT canonical_name FROM entities WHERE id=? "
                             "AND (hidden IS NULL OR hidden=0)", (r["other_id"],)).fetchone()
            # PRD-05: find the claim behind this edge so the analyst can reject it in
            # place (reject → cascade/reproject). Edges not backed by a claim have none.
            claim_id = None
            if has_claims:
                s_e, d_e = ((entity_id, r["other_id"]) if r["dir"] == "out"
                            else (r["other_id"], entity_id))
                cl = conn.execute(
                    "SELECT id FROM claims WHERE entity_id=? AND predicate=? "
                    "AND IFNULL(value,'')=IFNULL(?,'') AND status='active' LIMIT 1",
                    (s_e, f"rel:{d_e}", r["rel_type"])).fetchone()
                claim_id = cl["id"] if cl else None
            conns.append({"other_id": r["other_id"], "other": o["canonical_name"] if o else "?",
                          "rel_type": r["rel_type"], "rel_gloss": _rel_gloss(r["rel_type"]),
                          "dir": r["dir"], "claim_id": claim_id,
                          "confidence": r["confidence"], "evidence": (r["evidence"] or "")[:160]})
        # Clusters this node belongs to, scoped to the active case.
        cl_mem_sql, cl_mem_params = _case_in(_active_cases(request), "rk.investigation")
        cl_where = (f"AND c.id IN (SELECT cm2.cluster_id FROM cluster_members cm2 "
                    f"JOIN mentions mk ON mk.entity_id = cm2.entity_id "
                    f"JOIN reports rk ON rk.id = mk.report_id WHERE {cl_mem_sql}) "
                    if cl_mem_sql else "")
        clusters = [dict(r) for r in conn.execute(
            "SELECT c.id, c.name FROM clusters c JOIN cluster_members cm ON cm.cluster_id=c.id "
            "WHERE cm.entity_id = ? " + cl_where, (entity_id, *cl_mem_params)).fetchall()]
        # CO-OCCURRENCE ("appears with") — entities it shared a report with. These are
        # the faint "same pic" edges on the graph; the panel must reflect them too, else
        # a node whose only links are co-occurrence shows in/out=0 and looks unconnected.
        co_sql, co_p = _case_in(_active_cases(request), "rco.investigation")
        co_join = "JOIN reports rco ON rco.id = rel.report_id" if co_sql else ""
        co_where = f"AND {co_sql} " if co_sql else ""
        co_occurs = []
        for r in conn.execute(
            "SELECT other_id, COUNT(DISTINCT report_id) AS shared FROM ("
            "  SELECT CASE WHEN rel.src_entity_id=? THEN rel.dst_entity_id ELSE rel.src_entity_id END AS other_id, "
            "    rel.report_id "
            f"  FROM relationships rel {co_join} "
            "  WHERE rel.rel_type='co_mentioned' AND (rel.src_entity_id=? OR rel.dst_entity_id=?) "
            f"  {co_where}) GROUP BY other_id ORDER BY shared DESC LIMIT 40",
            (entity_id, entity_id, entity_id, *co_p)).fetchall():
            o = conn.execute("SELECT canonical_name FROM entities WHERE id=? "
                             "AND (hidden IS NULL OR hidden=0)", (r["other_id"],)).fetchone()
            if o:
                co_occurs.append({"other_id": r["other_id"], "other": o["canonical_name"],
                                  "shared": r["shared"]})
        # Compute the origin trail INSIDE the `with` block — it queries `conn`, so it must
        # run before the connection closes. (Bug: it used to run in the return dict below,
        # after the block exited → "Cannot operate on a closed database" → the endpoint
        # 500'd on every node, and the panel's swallowed-error path left in/out at 0.)
        origin_trail = _node_origin(conn, entity_id)
    return JSONResponse({
        "id": entity_id, "name": e["canonical_name"],
        "type": e["case_type"] or e["entity_type"], "surface_type": e["entity_type"],
        "role": role, "sub_role": e["sub_role"] or "", "origin": origin, "degree": e["deg"],
        "origin_trail": origin_trail,   # WHERE it came from (never "out of nowhere")
        "provenance": e["provenance"] or "", "properties": properties,
        "in_degree": in_degree, "out_degree": out_degree, "dossier": dossier,
        "sources": sources, "connections": conns, "clusters": clusters,
        "co_occurs": co_occurs,
    })


def _graph_chat(message: str, case: str | None, selected_name: str | None) -> dict:
    from investigations.webapp import graph_chat
    try:
        parsed = graph_chat.interpret(message, selected_name)
        with db.connect() as conn:
            return graph_chat.execute(conn, parsed["intent"], parsed["args"], case, selected_name)
    except Exception as exc:
        return {"reply": f"I hit an error handling that: {str(exc)[:120]}", "deltas": {}}


@app.post("/api/graph/chat")
async def api_graph_chat(request: Request):
    """Natural-language graph control: detail / connections / find / add / hide-unhide.
    The LLM only parses intent; the backend executes deterministically. Hides are a
    reversible soft-hide (the row stays), so the analyst can always restore."""
    body = await request.json()
    message = (body.get("message") or "").strip()
    if not message:
        return JSONResponse({"reply": "Ask me to show, add, hide, or detail a node.", "deltas": {}})
    case = _active_case(request)
    selected_name = (body.get("selected_name") or "").strip() or None
    result = await run_in_threadpool(_graph_chat, message, case, selected_name)
    # A hide/add/unhide changed the data → tell OTHER open views to refresh (the graph
    # itself already applied the returned deltas in-place).
    if result.get("deltas"):
        bump_case(case)
    return JSONResponse(result)


# --- Chat-led investigator: the chat IS the agent ------------------------------
# A human message becomes ONE warm-agent turn; both sides land in the transcript
# (prd-chat-led-endpoint). Warm path = the live investigator (real OSINT bursts
# via the warm session's MCP tools). Fallback = the deterministic graph_chat
# router when the warm session isn't available, so the endpoint always works.
CHAT_TIMEOUT = int(os.environ.get("KIPI_CHAT_TIMEOUT", "240"))

# Transcript turn roles (the DB stores role as free-form TEXT; these are the
# canonical values everything that scans the transcript depends on).
ROLE_ANALYST = "analyst"
ROLE_AGENT = "agent"
ROLE_UI_EVENT = "ui_event"
ROLE_SYSTEM = "system"

# UI -> chat memory bridge (prd-chat-ui-memory-bridge): per-case high-water mark
# of the last ui_event id already shown to the agent. In-memory; resets on
# restart (correct — the warm SDK session is also fresh then).
_UI_SEEN: dict = {}
_UI_SEEN_GUARD = _change_threading.Lock()


def record_ui_event(case, text: str) -> None:
    """Record an analyst UI action as a ui_event turn in the case transcript so the
    chat agent learns of it on its next turn. Best-effort + case-guarded: a no-op
    when there's no single active case, and never raises (a transcript write must
    not break the mutation endpoint that called it)."""
    case = (case or "").strip() if isinstance(case, str) else case
    if not case:
        return
    try:
        with db.connect() as conn:
            db.add_chat_turn(conn, case, ROLE_UI_EVENT, text)
    except Exception:
        pass


_UI_PREFIX_CAP = 20  # most-recent UI events to show in one turn's prefix (safety bound)


def _peek_ui_events(conn, case: str) -> list:
    """Un-consumed UI-event turns for a case (id past the per-case high-water mark),
    WITHOUT advancing the mark. Side-effect-free so the caller only marks them seen
    after the agent actually received them (a successful warm turn). Returns Rows."""
    with _UI_SEEN_GUARD:
        seen = _UI_SEEN.get(case, 0)
    return [t for t in db.get_chat_turns(conn, case)
            if t["role"] == ROLE_UI_EVENT and t["id"] > seen]


def _advance_ui_mark(case: str, last_id: int) -> None:
    """Mark every UI event up to last_id as seen (so it's injected exactly once).
    Called only after a successful warm turn carried the prefix — never on the
    fallback path or a failed turn, so unshown events are never silently dropped."""
    with _UI_SEEN_GUARD:
        if last_id > _UI_SEEN.get(case, 0):
            _UI_SEEN[case] = last_id


def _ui_prefix(ui_rows: list) -> str:
    """The task prefix for a turn's un-consumed UI events, capped to the most
    recent _UI_PREFIX_CAP and each text bounded, so a backlog can't oversize the
    task."""
    shown = ui_rows[-_UI_PREFIX_CAP:]
    texts = [(r["text"] or "")[:200] for r in shown]
    return "[Since your last reply, the analyst did this in the UI: " + "; ".join(texts) + "]"

# Per-case chat lock: serializes a case's persist->run->persist so concurrent
# same-case requests can't interleave the transcript. Different cases never block
# each other. The guard protects lazy creation of each case's asyncio.Lock.
_CHAT_LOCKS: dict = {}
_CHAT_LOCKS_GUARD = _change_threading.Lock()


def _chat_lock(case: str) -> asyncio.Lock:
    with _CHAT_LOCKS_GUARD:
        lock = _CHAT_LOCKS.get(case)
        if lock is None:
            lock = asyncio.Lock()
            _CHAT_LOCKS[case] = lock
        return lock


# One-hop chat routing (prd: chat-one-hop-routing). DETERMINISTIC, no LLM classify:
# a one-hop verb + a node the message names that resolves to a KNOWN case entity, and NO
# "deep" qualifier → expand that node ONE hop (matches the graph + the canonical one-hop
# model). "deep …"/whole-case/questions/unknown targets fall through to the warm agent.
_ONE_HOP_VERB_RE = _re.compile(r"\b(investigate|expand|look into|dig into|look up|pull|enrich)\b", _re.I)
_DEEP_RE = _re.compile(r"\b(deep|whole[ -]?case|end[ -]?to[ -]?end|full sweep|map (the|out)|recursiv|everything)\b", _re.I)


def _one_hop_target(message: str, case: str | None, selected: str | None) -> str | None:
    """The KNOWN case node a one-hop chat command names, or None to fall through to the
    warm agent. None when: no one-hop verb, a 'deep' qualifier is present, or no entity in
    the message resolves to a node in this case (a new/fuzzy target → the agent handles it)."""
    if not message or not _ONE_HOP_VERB_RE.search(message) or _DEEP_RE.search(message):
        return None
    from investigations.ingest.extractor import extract_all
    from investigations.webapp.graph_chat import _resolve
    candidates = []
    if selected:
        candidates.append(selected)
    candidates += [e.canonical for e in extract_all(message)]
    seen = set()
    with db.connect() as conn:
        for c in candidates:
            if not c or c in seen:
                continue
            seen.add(c)
            eid, name = _resolve(conn, c, case)
            if eid:
                return name
    return None


def _activity_context(case: str | None) -> str:
    """The note() bridge (gap 3): the case's recent event-log tail, prepended
    to every warm turn so analyst actions (hide / add / reject) are in the
    agent's working context next turn. One shared source —
    store.format_recent_activity — also feeds /ask (never two readers)."""
    if not case:
        return ""
    try:
        # migrate=False: a hot read-only probe at the top of EVERY warm turn —
        # never re-run the schema migration (and its commit) here.
        with db.connect(migrate=False) as conn:
            tail = store.format_recent_activity(conn, case)
    except Exception:
        return ""
    if not tail:
        return ""
    return ("RECENT CASE ACTIVITY (the analyst sees this graph; their actions "
            "are authoritative):\n" + tail + "\n\n")


def _run_chat_turn(case: str, message: str, selected: str | None,
                   on_step=None, cancel=None, redirect=None) -> dict:
    """Sync worker (off the event loop): persist the analyst turn, run the warm
    agent turn (or the router fallback), persist the agent turn. Returns the
    payload for the client. `on_step`/`cancel` stream + stop the warm turn (the
    background job path); both None on the synchronous router fallback path.
    `redirect` (RedirectBox) injects a new instruction into the live warm turn."""
    from investigations.agent.investigator import warm_run_available

    with db.connect() as conn:
        db.add_chat_turn(conn, case, ROLE_ANALYST, message)
        # UI actions the analyst took since the agent last replied — peek (don't
        # consume yet) so they're only marked seen once the agent actually gets
        # them, never on the fallback/failure path (prd-chat-ui-memory-bridge).
        ui_rows = _peek_ui_events(conn, case)

    action = None
    graph_touched = False
    stopped = False
    redirected = False
    cost_usd = None      # real $ spend of the warm turn (from the SDK ResultMessage)
    cost_estimated = False  # true when cost_usd is a price-table estimate (stopped turn)
    elapsed_s = None     # wall-clock seconds for the turn

    # ONE-HOP DEFAULT (prd: chat-one-hop-routing): "investigate/expand <known node>" with no
    # "deep" qualifier expands ONE hop + suggests the next hop — the canonical analyst-driven
    # model — instead of the multi-hop autonomous agent. "deep …"/whole-case/questions/unknown
    # targets fall through to the warm agent below. Runs inside this job so steps still stream.
    one_hop = _one_hop_target(message, case, selected)
    if one_hop:
        # The infra belt emits STRING events; the chat job's on_step expects step DICTS —
        # adapt so the live trail renders (tool line for "infra: …", reasoning otherwise).
        def _belt_step(line):
            if on_step:
                txt = str(line)
                is_tool = txt.startswith("infra:")
                on_step({"type": "tool" if is_tool else "reasoning",
                         "tool": (txt.replace("infra:", "").split("\u2192")[0].strip() if is_tool else None),
                         "text": txt[:200]})
        _belt_step(f"one-hop expand of {one_hop}")
        result = _investigate_entity(one_hop, case, on_event=_belt_step, expand=True, cancel=cancel)
        n = result.get("nodes_added", 0) if isinstance(result, dict) else 0
        nh = (result or {}).get("next_hop") or ""
        reply = f"Expanded **{one_hop}** — added {n} connected node(s) one hop out."
        if nh:
            reply += f"\n\n**Suggested next hop:** {nh}"
        elif not n:
            reply += (" Nothing new surfaced one hop out — try another node, or say "
                      "\"deep investigate " + one_hop + "\" for the full agent.")
        if ui_rows:
            _advance_ui_mark(case, ui_rows[-1]["id"])
        with db.connect() as conn:
            aid = db.add_chat_turn(conn, case, ROLE_AGENT, reply)
        return {"reply": reply, "steps": [], "capped": False, "deltas": {},
                "action": None, "agent_turn_id": aid, "graph_touched": True,
                "stopped": bool(cancel is not None and cancel.is_set()), "redirected": False,
                "cost_usd": None, "cost_estimated": False, "elapsed_s": None, "step_count": 0}

    if warm_run_available():
        from investigations.agent.warm_session import run_turn_on_warm_loop
        from investigations.agent import graph_tools
        from investigations.agent import investigator as inv
        # Append the findings contract so the turn both TALKS and emits landable findings —
        # talking to the investigator BUILDS the graph (issue warm-lands-findings).
        base = (_ui_prefix(ui_rows) + "\n\n" + message) if ui_rows else message
        task = _activity_context(case) + base + inv.CHAT_FINDINGS_CONTRACT
        try:
            # NO wall-clock deadline: an investigation runs to its OWN completion (the
            # agent's recursive-completeness doctrine + its max-turns backstop decide when
            # it's done) — never killed mid-dig (founder: "no more deadlines"; a 240s cap
            # truncated a real dig to 7 findings + no summary). Stop stays cooperative.
            run = run_turn_on_warm_loop(case, task, timeout=None,
                                        cancel=cancel, on_step=on_step, redirect=redirect)
        except Exception as exc:  # never let a wedged turn 500 the chat
            run = {"ok": False, "error": str(exc)[:200]}
        stopped = bool(run.get("stopped")) or bool(cancel is not None and cancel.is_set())
        landed_intel = False
        deltas = {}  # canvas refreshes via bump_case when a graph tool was used
        if run.get("ok"):
            # Land the turn's findings into the graph + strip the JSON from the reply, via
            # the SAME cold land path (parse → attribute → land_findings). The narration is
            # the conversational reply the analyst sees.
            with db.connect() as conn:
                landed = inv.land_warm_chat(conn, case, message, run)
            reply = landed.get("reply") or (
                "(stopped before the investigator replied)" if stopped
                else "(the investigator returned no text)")
            # Any landed intel (findings OR relationships OR same_as) is a graph change.
            landed_intel = bool(landed.get("landed_any"))
            steps = run.get("steps") or []
            capped = bool(run.get("capped"))
            # The 80-step safety backstop fired (very large network, or a stuck loop) —
            # say so in the chat, never a silent truncation (founder directive).
            if run.get("cap_reason") == "turn_limit":
                nf = landed.get("findings") or 0
                reply = (f"⚠️ I hit the safety step-limit (80 actions) before fully "
                         f"wrapping up — this is a very large network or I got stuck in a "
                         f"loop. I've kept the {nf} finding(s) so far. Say 'continue' to "
                         f"keep digging from here.\n\n" + reply)
            if ui_rows:  # the agent received the prefix → mark those events seen
                _advance_ui_mark(case, ui_rows[-1]["id"])
        elif stopped:
            reply = run.get("result_text") or "Stopped."
            steps, capped = run.get("steps") or [], True
        else:
            # Warm turn FAILED (not a Stop). Fall back to the deterministic router so the
            # analyst still gets a usable response — never a dead "try again" (Codex
            # finding-2: guaranteed graceful fallback, never a 500). The router answers the
            # question / classifies the intent deterministically.
            fb = _graph_chat(message, case, selected)
            reply = fb.get("reply") or "The investigator turn is unavailable right now."
            deltas = fb.get("deltas") or {}
            action = fb.get("action")
            steps, capped = [], True
        # The graph may have changed via: warm kipi-graph tools, landed findings parsed
        # from the reply, OR a router-fallback that returned deltas (add/hide/unhide) —
        # any of these must refresh open views (Codex: fallback deltas were missed).
        graph_touched = landed_intel or bool(deltas) or any(
            graph_tools.is_graph_tool(t) for t in (run.get("tools") or []))
        redirected = bool(run.get("redirected"))
        cost_usd = run.get("cost_usd")
        cost_estimated = bool(run.get("cost_estimated"))
        elapsed_s = run.get("elapsed_s")
    else:
        r = _graph_chat(message, case, selected)  # deterministic router fallback
        reply = r.get("reply", "")
        deltas = r.get("deltas") or {}
        action = r.get("action")  # preserve investigate-from-chat launch
        steps, capped = [], False

    with db.connect() as conn:
        aid = db.add_chat_turn(conn, case, ROLE_AGENT, reply,
                               deltas=deltas or None, steps=steps or None, capped=capped)
    return {"reply": reply, "steps": steps, "capped": capped, "deltas": deltas,
            "action": action, "agent_turn_id": aid, "graph_touched": graph_touched,
            "stopped": stopped, "redirected": redirected,
            "cost_usd": cost_usd, "cost_estimated": cost_estimated,
            "elapsed_s": elapsed_s, "step_count": len(steps or [])}


# Live chat jobs: the warm path runs as a background job so steps stream + Stop
# works (prd-chat-stream-control). Mirrors the investigate job machinery.
_CHAT_JOBS: dict = {}
_CHAT_CANCEL: dict = {}
_CHAT_REDIRECT: dict = {}  # case → RedirectBox for the running turn (mid-burst steer)
_CHAT_LOCK = _change_threading.Lock()
_CHAT_STEP_MAX = 200  # cap the live step list a job holds


# Guess-only types the GRAPH already excludes from display (4 SQL filters on
# `entity_type != 'person_candidate'`). The live dig runs over TOOL NARRATION, where
# the proper-name regex matches UI/HTTP boilerplate ("Ran Playwright", "Page Title",
# "Not Found") as person_candidate. Minting them draws phantom edges to nodes the graph
# never shows — so the writer applies the SAME exclusion the display does. A real person
# enters the graph as `person` (hint-backed) or via the typing pass, not as a raw guess
# off browser narration (trump-demo, 2026-06-11).
_LIVE_DIG_EXCLUDED_TYPES = {"person_candidate"}


def _entities_from(text: str) -> list:
    """Deduped {type,value} entities in a blob, via extract_all — the SAME deterministic
    regex extractor the ingest path uses, so the overlay's vocabulary matches what lands.
    Drops guess-only types the graph itself excludes (person_candidate), so the live dig
    never draws an edge to a node the display would hide."""
    if not text or not text.strip():
        return []
    from investigations.ingest.extractor import extract_all
    out, seen = [], set()
    for e in extract_all(text):
        if e.entity_type in _LIVE_DIG_EXCLUDED_TYPES:
            continue
        key = (e.entity_type, e.canonical)
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": e.entity_type, "value": e.canonical})
    return out


def _step_discovery(step: dict) -> dict:
    """Split a TOOL step into the entity it looked UP (anchor, from the input) and the
    entities that lookup SURFACED (found, from the result). The overlay draws anchor→found
    edges from this so the discovered nodes form a graph, not disconnected dots. Tool
    steps only (reasoning narration is too noisy). found excludes the anchor + is capped."""
    if (step.get("type") or "") != "tool":
        return {"anchor": None, "found": []}
    in_ents = _entities_from(step.get("input") or "")
    res_ents = _entities_from(step.get("result") or "")
    anchor = in_ents[0] if in_ents else None
    anchor_val = anchor["value"] if anchor else None
    found, seen = [], set()
    for e in res_ents:
        if e["value"] == anchor_val or e["value"] in seen:
            continue
        seen.add(e["value"])
        found.append(e)
        if len(found) >= 25:
            break
    return {"anchor": anchor, "found": found}


def _step_entities(step: dict) -> list:
    """Flat entity list for a step (anchor + found), for the trail's entity chips."""
    d = _step_discovery(step)
    return ([d["anchor"]] if d["anchor"] else []) + d["found"]


def _decorate_step(step: dict) -> dict:
    """JSON-safe copy of a step with its discovered entities attached: `entities` (flat,
    for the trail chips) + `discovery` ({anchor, found}, for the provisional-node edges)."""
    disc = _step_discovery(step)
    flat = ([disc["anchor"]] if disc["anchor"] else []) + disc["found"]
    return {**step, "entities": flat, "discovery": disc}


# Tool → the relationship a discovery from that tool implies (anchor → found). Passed
# through normalize_rel (the one-vocab edge gate) before writing; unknown tools fall back
# to a generic link.
_REL_FOR_TOOL = {
    "crtsh": "tls_cert", "crt.sh": "tls_cert", "cert": "tls_cert",
    "dns": "resolves_to", "reverse-dns": "resolves_to", "infra": "resolves_to",
    "whois": "registered_via", "rdap": "registered_via",
    "reverse-whois": "shares_registrant", "reverse_whois": "shares_registrant",
    "virustotal": "related_to", "perplexity": "mentions",
}


def _rel_for_tool(tool: str) -> str:
    t = (tool or "").lower()
    for key, rel in _REL_FOR_TOOL.items():
        if key in t:
            return rel
    return "linked_to"


def _persist_step_discovery(case: str, step: dict) -> int:
    """Write a tool step's discovery (anchor → found) into the case graph as REAL
    entities + a typed edge, live as the dig runs — so the graph the analyst watches
    building IS the one that persists (provenance 'osint', the relationship derived from
    the tool + passed through normalize_rel). Returns the number of found entities
    written. Anchor-less or found-less steps write nothing (a lone unconnected dot is
    noise; the end-of-run land path still captures the agent's curated findings)."""
    disc = _step_discovery(step)
    anchor = disc.get("anchor")
    found = disc.get("found") or []
    if not anchor or not found:
        return 0
    from investigations.enrich.promote import _enrichment_report
    from investigations.enrich.rel_vocab import normalize_rel
    from investigations.admission import is_admissible
    # The live dig is a graph-CREATION path, so it must clear the SAME admission gate as
    # every other creation path (RCA rca-recurring-graph-noise). A junk anchor (a bare
    # tracking id, a reference domain) roots nothing worth keeping — skip the whole step;
    # a junk FOUND entity is dropped individually so the rest of the step still lands.
    if not is_admissible(anchor.get("type"), anchor.get("value"))[0]:
        return 0
    found = [f for f in found if is_admissible(f.get("type"), f.get("value"))[0]]
    if not found:
        return 0
    tool = step.get("raw_tool") or step.get("tool") or ""
    # The osint command (crtsh/whois/dns) is usually in the INPUT (the bash invocation),
    # not the tool name ("Bash") — derive the relationship from both so edges are labeled
    # meaningfully (tls_cert / resolves_to / registered_via …), not a flat 'linked_to'.
    rel = normalize_rel(_rel_for_tool(f"{tool} {step.get('input') or ''}"),
                        evidence=tool, allow_novel=True) or "linked_to"
    written = 0
    with db.connect() as conn:
        if case and not conn.execute(
                "SELECT 1 FROM investigations WHERE slug = ?", (case,)).fetchone():
            return 0   # case deleted mid-run — don't resurrect it
        rep_id = _enrichment_report(conn, case)
        anchor_res = store.apply_mutation(conn, store.entity_upserted(
            case, anchor["value"], anchor["type"], rep_id, actor="agent",
            provenance="osint"))
        if not anchor_res["applied"]:
            return 0
        anchor_id = anchor_res["entity_id"]
        # Mentions scope an entity into a case (case views join mentions →
        # reports.investigation, see promote._primary_case). Without these rows the
        # live-dig nodes are invisible to every case-scoped surface (issue
        # live-dig-mentions). Guarded SELECT keeps the 1.2s re-sweep idempotent —
        # mentions has no UNIQUE constraint.
        def _mention_once(eid: int, value: str) -> None:
            exists = conn.execute(
                "SELECT 1 FROM mentions WHERE entity_id = ? AND report_id = ?",
                (eid, rep_id)).fetchone()
            if not exists:
                db.add_mention(conn, eid, rep_id, value,
                               f"discovered via {tool} (live dig)".strip())

        _mention_once(anchor_id, anchor["value"])
        for f in found:
            found_res = store.apply_mutation(conn, store.entity_upserted(
                case, f["value"], f["type"], rep_id, actor="agent",
                provenance="osint"))
            if not found_res["applied"]:
                continue
            fid = found_res["entity_id"]
            _mention_once(fid, f["value"])
            if fid != anchor_id:
                ev = f"discovered via {tool}".strip()
                db.add_relationship(conn, anchor_id, fid, rel, rep_id,
                                    evidence=ev, confidence=0.5)
                # The graph draws edges AND judges "meaningful" nodes from
                # typed_relationships, NOT the legacy `relationships` table. Write the typed
                # edge too (mirrors enrich/promote + investigator.land_findings) so the graph
                # the analyst watches build live IS the one that persists. Without this the
                # live dig lands only in `relationships`, which the graph never reads, and the
                # canvas stays empty.
                store.apply_mutation(conn, store.edge_upserted(
                    case, anchor_id, fid, rel, actor="agent",
                    evidence=ev, provenance="osint"))
                written += 1
    return written


def _chat_job(case: str, message: str, selected: str | None, cancel, redirect=None) -> None:
    """Background warm chat turn: run _run_chat_turn with a step streamer + the
    cancel Event + the redirect box, then write the final result to the per-case job
    dict. A watcher thread lands each tool step's discovery into the graph live (the
    analyst watches the REAL graph build). Status becomes done | stopped | error; a
    stopped/failed turn still persists its partial (handled inside _run_chat_turn)."""
    def on_step(step: dict) -> None:
        with _CHAT_LOCK:
            job = _CHAT_JOBS.get(case)
            if job is None:
                return
            steps = job.setdefault("steps", [])
            # Monotonic seq per step so the SSE stream tracks progress by seq, not list
            # index — the front-trim below (cap) shifts indices and would otherwise make
            # the stream silently skip/stall after _CHAT_STEP_MAX steps (Codex P2).
            seq = job.get("_seq", 0) + 1
            job["_seq"] = seq
            # Store the live step dict BY REFERENCE (just stamp seq on it), keeping its
            # full shape (type/tool/input/result/text). warm_session fills `result` in
            # place after the tool returns and never re-emits the step, so a stored
            # reference is what lets the trail + provisional overlay pick up the result on
            # the next status/stream read.
            step["seq"] = seq
            steps.append(step)
            if len(steps) > _CHAT_STEP_MAX:
                del steps[: len(steps) - _CHAT_STEP_MAX]

    # Live graph build: a watcher lands each tool step's discovery (anchor → found) into
    # the case graph as REAL nodes/edges the moment its result fills, then bumps the case
    # so the open canvas grows. Decoupled from warm_session's stream loop (which we don't
    # touch) — it reads the same by-reference step dicts on_step stores.
    _landed_seqs: set = set()
    # Serializes the watcher tick against the finally-block's final pass: without it the
    # two can land the same step concurrently and double its mentions rows (the dedupe
    # SELECT inside _persist_step_discovery is not atomic; mentions has no UNIQUE).
    _sweep_lock = _threading.Lock()

    def _sweep_discoveries() -> None:
        with _CHAT_LOCK:
            snapshot = list(_CHAT_JOBS.get(case, {}).get("steps") or [])
        wrote = 0
        with _sweep_lock:
            for s in snapshot:
                seq = s.get("seq")
                if seq is None or seq in _landed_seqs:
                    continue
                if s.get("type") != "tool" or s.get("result") is None:
                    continue
                try:
                    wrote += _persist_step_discovery(case, s)
                    _landed_seqs.add(seq)    # mark done only on success → transient locks retry
                except Exception:
                    pass
        if wrote:
            bump_case(case)

    _watch_stop = _change_threading.Event()

    def _watch() -> None:
        while not _watch_stop.wait(1.2):
            _sweep_discoveries()

    _watcher = _threading.Thread(target=_watch, daemon=True)
    _watcher.start()

    try:
        result = _run_chat_turn(case, message, selected, on_step=on_step,
                                cancel=cancel, redirect=redirect)
        status = "stopped" if result.get("stopped") else "done"
        with _CHAT_LOCK:
            live = _CHAT_JOBS.get(case, {}).get("steps", [])
            # `steps` AFTER **result so the live streamed trail isn't clobbered by
            # result["steps"]; fall back to result's trail if nothing streamed.
            _CHAT_JOBS[case] = {**result, "status": status,
                                "steps": live or result.get("steps") or []}
            _CHAT_CANCEL.pop(case, None)
            _CHAT_REDIRECT.pop(case, None)
        if result.get("graph_touched"):
            bump_case(case)
    except Exception as exc:
        with _CHAT_LOCK:
            live = _CHAT_JOBS.get(case, {}).get("steps", [])
            _CHAT_JOBS[case] = {"status": "error", "error": str(exc)[:200],
                                "reply": "The investigator turn failed; try again.",
                                "steps": live}
            _CHAT_CANCEL.pop(case, None)
            _CHAT_REDIRECT.pop(case, None)
    finally:
        _watch_stop.set()
        try:
            _sweep_discoveries()   # final pass: land discoveries that filled after the last tick
        except Exception:
            pass


def _launch_warm_chat_job(case: str, message: str, selected: str | None = None) -> str:
    """Start the warm chat investigator as a background job for `case` — the live-trail +
    provisional-overlay path. Returns 'running' if one is already live, 'started' on
    launch, 'error' if the thread couldn't start. Shared by /api/chat AND chat-driven
    create+run, so a NEW case digs through the SAME path as an in-case turn (one unified
    investigator — not the separate run-panel job). _chat_job → _run_chat_turn persists
    the analyst + agent turns itself, so callers must not double-persist them."""
    from investigations.agent.warm_session import RedirectBox
    with _CHAT_LOCK:
        if _CHAT_JOBS.get(case, {}).get("status") == "running":
            return "running"
        cancel = _change_threading.Event()
        redirect = RedirectBox()
        _CHAT_CANCEL[case] = cancel
        _CHAT_REDIRECT[case] = redirect
        _CHAT_JOBS[case] = {"status": "running", "steps": []}
    try:
        _threading.Thread(target=_chat_job, args=(case, message, selected, cancel, redirect),
                          daemon=True).start()
    except Exception as exc:  # thread-start failure must not leave a forever-running job
        with _CHAT_LOCK:
            _CHAT_JOBS[case] = {"status": "error", "error": str(exc)[:200],
                                "reply": "Could not start the turn.", "steps": []}
            _CHAT_CANCEL.pop(case, None)
            _CHAT_REDIRECT.pop(case, None)
        return "error"
    return "started"


# Phrasings that mean "spin up a NEW investigation". Gates the up-front classify so a
# normal in-case turn pays no extra LLM call — only no-case turns or explicit new-case
# phrasings get classified before the regular chat path.
_NEW_CASE_RE = _re.compile(
    r"\bnew (case|investigation)\b"
    r"|\bstart(ing)? (a |an |the )?(new )?(case|investigation)\b"
    r"|\bopen (a |an |the )?(new )?(case|investigation)\b"
    r"|\bcreate (a |an )?(new )?(case|investigation)\b",
    _re.I)

# A question the analyst wants ANSWERED from the case (grounded Q&A), vs a command to
# DO something (investigate/add/connect). Ends with '?' or opens with a question word.
# Modal command-questions ('can you investigate…?') are excluded by the action guard.
_QUESTION_RE = _re.compile(
    r"\?\s*$"
    r"|^\s*(who|what|whose|whom|why|how|when|where|which|is|are|was|were|does|do|did|"
    r"has|have|had)\b",
    _re.I)
# Action phrasings that must reach the investigator/router, never the grounded Q&A —
# they need live tools or mutate the graph, which the report-grounded answerer can't do.
_CHAT_ACTION_RE = _re.compile(
    r"\b(investigate|dig into|look up|look into|run the|enrich|pivot|"
    r"add (a |an )?(node|edge)|connect|link|hide|unhide)\b",
    _re.I)


def _materialize_new_case_from_chat(request: Request, name: str, target: str | None,
                                    deep: bool, message: str) -> JSONResponse:
    """Create the case, switch to it (cookie), persist the chat turns to its transcript,
    and fire the investigator when a target is named. Returns the response the chat client
    uses to reload into the fresh case (+ watch the live run). Founder pick: create + run
    fused."""
    try:
        slug, _existed = _create_case(name)
    except ValueError as exc:
        return JSONResponse({"mode": "sync", "reply": str(exc), "deltas": {}},
                            status_code=400)
    from investigations.agent.investigator import warm_run_available
    ran, warm = False, False
    if target and warm_run_available():
        # Dig through the SAME warm chat path an in-case turn uses → the live step trail +
        # cinematic graph overlay, not the separate run-panel job (one unified investigator).
        # _chat_job persists the analyst + agent turns itself, so DON'T double-persist here.
        warm = True
        ran = _launch_warm_chat_job(slug, f"investigate {target}") in ("started", "running")
    elif target:
        ran = _start_investigate_job(slug, target, _active_analyst(request), deep=deep)
    article = "a deep" if deep else "an"
    if ran:
        where = "in the chat" if warm else "in the run panel"
        reply = (f"Created case '{slug}' and started {article} investigation on "
                 f"{target}. Watch the live steps {where}, and Stop anytime.")
    else:
        reply = (f"Created case '{slug}' and switched to it. Drop evidence, or say "
                 f"'investigate <target>' to start collecting.")
    with db.connect() as conn:
        # The warm path records the analyst 'investigate …' + the dig reply itself; only
        # the non-warm/switched-only replies need persisting here (avoid a doubled turn).
        if not warm:
            db.add_chat_turn(conn, slug, ROLE_ANALYST, message)
            db.add_chat_turn(conn, slug, ROLE_AGENT, reply)
    resp = JSONResponse({"mode": "sync", "reply": reply, "deltas": {},
                         "action": {"type": "new_case", "slug": slug, "ran": ran, "warm": warm}})
    year = 60 * 60 * 24 * 365
    resp.set_cookie(CASE_COOKIE, slug, max_age=year, samesite="lax")
    return resp


@app.post("/api/chat")
async def api_chat(request: Request):
    """Conversational turn with the investigator. Warm path → a background job that
    streams steps (poll /api/chat/status, Stop via /api/chat/stop). Fallback (no
    warm session) → a synchronous deterministic graph_chat command. Both persist
    analyst + agent turns to the case transcript."""
    from investigations.agent.investigator import warm_run_available
    body = await request.json()
    message = (body.get("message") or "").strip()
    if not message:
        return JSONResponse({"mode": "sync", "reply": "Type a message to the investigator.",
                             "deltas": {}})
    case = (body.get("case") or "").strip() or _active_case(request)
    # Chat can START a brand-new investigation (founder pick: create + run fused). Classify
    # up front ONLY when no case is open OR the analyst used a new-case phrasing — so a
    # normal in-case turn pays no extra LLM. A start-shaped intent creates the case,
    # switches to it, and fires the investigator when a target is named.
    has_case = bool(case and _valid_slug(case))
    if not has_case or _NEW_CASE_RE.search(message):
        from investigations.webapp import graph_chat
        parsed = graph_chat.interpret(message, None)
        intent = parsed.get("intent")
        args = parsed.get("args") or {}
        # No case yet → any start-shaped intent opens one. Case already open → only an
        # explicit new_case forks a second (so "start the investigation" stays in-case).
        make_new = (not has_case and intent in ("new_case", "investigate")) \
            or (has_case and intent == "new_case")
        if make_new:
            target = (args.get("target") or "").strip() or None
            name = (args.get("name") or "").strip() or target or message
            return _materialize_new_case_from_chat(
                request, name, target, bool(args.get("deep")), message)
        if not has_case:
            return JSONResponse(
                {"mode": "sync", "reply": "No case open yet. Say 'new case on <subject>' "
                 "(or upload evidence) to start one.", "deltas": {}}, status_code=400)

    # One chat, every capability: a plain QUESTION is answered from the case (grounded
    # Q&A with sources) — the same answerer the retired "Ask the case" box used — UNLESS
    # the warm investigator is live, in which case the agent handles questions too (it
    # has the session/graph context a report-only answerer lacks, e.g. "what did I just
    # add?"). Action phrasings (investigate/add/connect) always fall through to the
    # investigator/router below. has_case is guaranteed True here.
    if (_QUESTION_RE.search(message) and not _CHAT_ACTION_RE.search(message)
            and not warm_run_available()):
        with db.connect() as conn:
            db.add_chat_turn(conn, case, ROLE_ANALYST, message)
            result = ask_mod.answer(conn, case, message)
            reply = result.get("answer") or result.get("error") or "(no answer)"
            aid = db.add_chat_turn(conn, case, ROLE_AGENT, reply)
            _log(request, conn, "asked the case (chat)", detail=message[:120])
        return JSONResponse({"mode": "sync", "reply": reply, "deltas": {},
                             "sources": result.get("sources") or [],
                             "grounded": bool(result.get("grounded")),
                             "coverage": result.get("coverage"), "agent_turn_id": aid})

    selected = (body.get("selected_name") or "").strip() or None
    # Client-batched node-selections since the last message (prd-chat-ui-selections):
    # the analyst clicked through these nodes; fold them into the SAME ui-event memory
    # bridge so the turn's prefix carries "viewed node X" context. Batched on the
    # client → no per-click round-trip. Bounded so a long browse can't oversize it.
    selections = body.get("selections") or []
    if isinstance(selections, list):
        seen_sel = set()
        for name in selections[-8:]:
            name = (str(name) if name is not None else "").strip()[:120]
            if name and name not in seen_sel:
                seen_sel.add(name)
                record_ui_event(case, f"viewed node {name}")

    if not warm_run_available():
        # Synchronous router fallback — instant, no job needed (today's path).
        async with _chat_lock(case):
            result = await run_in_threadpool(_run_chat_turn, case, message, selected)
        if result.get("deltas") or result.get("graph_touched"):
            bump_case(case)
        return JSONResponse({"mode": "sync", **result})

    # Warm path → background job (one running turn per case).
    status = _launch_warm_chat_job(case, message, selected)
    if status == "error":
        return JSONResponse({"mode": "job", "status": "error",
                             "reply": "Could not start the turn."})
    return JSONResponse({"mode": "job", "status": status})


@app.get("/api/chat/status")
async def api_chat_status(request: Request, case: str = ""):
    """Live state of the active case's warm chat turn: status + streaming step
    trail + final reply. 'idle' if none has run."""
    case = (case or "").strip() or _active_case(request)
    if not case:
        return JSONResponse({"status": "idle"})
    with _CHAT_LOCK:
        job = dict(_CHAT_JOBS.get(case) or {"status": "idle"})
        # Snapshot the steps list under the lock — on_step mutates it from the warm
        # loop thread, so JSON serialization must not share the live list.
        steps_snapshot = list(job.get("steps") or [])
    # Decorate outside the lock (extract_all is pure CPU): each step carries the entities
    # it touched, so the poll-fallback path drives the same provisional overlay as SSE.
    job["steps"] = [_decorate_step(s) for s in steps_snapshot]
    return JSONResponse(job)


@app.get("/api/chat/stream")
async def api_chat_stream(request: Request, case: str = ""):
    """Server-Sent-Events stream of the active case's warm turn: pushes each new step
    as a `step` event and a final `done` event (status + reply) when the turn ends —
    so the client opens ONE connection instead of polling /api/chat/status each second
    (prd-chat-sse). The generator reads the in-memory job under the lock and emits only
    the new steps since the last tick; it ends on a terminal status or client
    disconnect. /api/chat/status stays as the poll fallback."""
    case = (case or "").strip() or _active_case(request)

    async def gen():
        if not case:
            yield f"event: done\ndata: {json.dumps({'status': 'idle'})}\n\n"
            return
        emitted: dict = {}   # seq -> bool(result already streamed)
        while True:
            if await request.is_disconnected():
                break
            with _CHAT_LOCK:
                job = dict(_CHAT_JOBS.get(case) or {"status": "idle"})
                steps = list(job.get("steps") or [])
            # Stream by monotonic seq, not list index — the live steps list is
            # front-trimmed at a cap, so index-based slicing would skip/stall. Each step
            # is emitted once when it appears, then ONCE MORE when its result fills in
            # (warm_session fills by reference and never re-emits), so the trail's results
            # and the discovered-entities overlay update live. `emitted` is per-connection,
            # so a reconnect replays the full trail from seq 0.
            for step in steps:
                seq = step.get("seq", 0)
                if not seq:
                    continue
                has_result = step.get("result") is not None
                if seq not in emitted:
                    yield f"event: step\ndata: {json.dumps(_decorate_step(step))}\n\n"
                    emitted[seq] = has_result
                elif has_result and not emitted[seq]:
                    yield f"event: step\ndata: {json.dumps(_decorate_step(step))}\n\n"
                    emitted[seq] = True
            status = job.get("status")
            if status in ("done", "stopped", "error", "idle"):
                payload = {"status": status, "reply": job.get("reply"),
                           "graph_touched": bool(job.get("graph_touched")),
                           "redirected": bool(job.get("redirected")),
                           "cost_usd": job.get("cost_usd"),
                           "cost_estimated": bool(job.get("cost_estimated")),
                           "elapsed_s": job.get("elapsed_s"),
                           "step_count": job.get("step_count")}
                yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                break
            await asyncio.sleep(0.25)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.post("/api/chat/stop")
async def api_chat_stop(request: Request, case: str = ""):
    """Stop the active case's running warm chat turn. Sets its cancel Event — the
    turn wraps up and salvages whatever the agent already produced."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    case = (body.get("case") or case or "").strip() or _active_case(request)
    with _CHAT_LOCK:
        cancel = _CHAT_CANCEL.get(case)
        running = bool(_CHAT_JOBS.get(case, {}).get("status") == "running")
        if cancel is not None:
            cancel.set()
    return JSONResponse({"ok": bool(running and cancel is not None)})


@app.post("/api/chat/redirect")
async def api_chat_redirect(request: Request, case: str = ""):
    """Steer the active case's running warm turn mid-burst: drop a NEW instruction into
    the live turn. The warm loop interrupts the current burst, salvages it, then
    re-queries the instruction on the same session — one continuous turn. No-op (ok:
    false) when no turn is running or no message is given."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    case = (body.get("case") or case or "").strip() or _active_case(request)
    message = (body.get("message") or "").strip()
    if not message:
        return JSONResponse({"ok": False, "error": "empty instruction"})
    with _CHAT_LOCK:
        box = _CHAT_REDIRECT.get(case)
        running = bool(_CHAT_JOBS.get(case, {}).get("status") == "running")
        if box is not None and running:
            box.set(message)
    return JSONResponse({"ok": bool(running and box is not None)})


@app.get("/api/chat/transcript")
async def api_chat_transcript(request: Request, case: str = ""):
    """The persisted transcript for a case so the chat renders its history on
    load (closes the vanishes-on-reload gap). JSON columns are parsed here.
    `case` may be passed explicitly or resolved from the active-case cookie."""
    case = (case or "").strip() or _active_case(request)
    if not case or not _valid_slug(case):
        return JSONResponse([])

    def _load():
        with db.connect() as conn:
            out = []
            for r in db.get_chat_turns(conn, case):
                out.append({
                    "id": r["id"], "role": r["role"], "text": r["text"],
                    "deltas": json.loads(r["deltas_json"]) if r["deltas_json"] else None,
                    "steps": json.loads(r["step_trail_json"]) if r["step_trail_json"] else None,
                    "capped": bool(r["capped"]), "created_at": r["created_at"],
                })
            return out

    return JSONResponse(await run_in_threadpool(_load))


@app.post("/api/run/start")
async def api_run_start(request: Request):
    """Start a phased warm run for the active case (4pa-03 production start path).
    Phased runs need the warm session; cold runs stay fire-and-forget. Runs the
    first phase off the event loop, returns the first checkpoint (paused state)."""
    from investigations.agent import phase_gates
    from investigations.agent.investigator import warm_run_available
    body = await request.json()
    case = _active_case(request) or (body.get("case") or "").strip()
    if not case:
        return JSONResponse({"error": "no active case"}, status_code=400)
    if not warm_run_available():
        return JSONResponse(
            {"error": "phased runs require KIPI_WARM_SESSION"}, status_code=400)
    status = await run_in_threadpool(phase_gates.start_phased_run, case)
    return JSONResponse(status)


@app.post("/api/run/control")
async def api_run_control(request: Request):
    """Mid-run analyst steering (4pa-03): continue / redirect / stop a phased warm
    run between phases. The chat surface routes 'continue' / 'stop' / 'go after X'
    here; the run pauses after each phase until the analyst drives the next move.
    Runs off the event loop — a warm phase can block up to its timeout."""
    from investigations.agent import phase_gates
    body = await request.json()
    case = _active_case(request) or (body.get("case") or "").strip()
    command = (body.get("command") or "").strip()
    redirect = (body.get("redirect") or "").strip() or None
    if not case:
        return JSONResponse({"error": "no active case"}, status_code=400)
    try:
        status = await run_in_threadpool(
            phase_gates.registry().control, case, command, redirect)
    except (KeyError, RuntimeError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(status)


@app.post("/api/node/{entity_id}/unhide")
async def api_node_unhide(request: Request, entity_id: int):
    """Restore a soft-hidden node (the Undo for a chat 'hide')."""
    case = _active_case(request)
    analyst = _active_analyst(request)
    with db.connect() as conn:
        result = store.apply_mutation(conn, store.entity_unhidden(
            case, entity_id, actor=f"analyst:{analyst}"))
        if not result["applied"]:
            return JSONResponse({"error": result["reason"]}, status_code=404)
        conn.commit()
        row = conn.execute(
            "SELECT canonical_name FROM entities WHERE id = ?", (entity_id,)).fetchone()
    record_ui_event(case, f"restored node {row['canonical_name'] if row else entity_id}")
    return JSONResponse({"ok": True, "id": entity_id})


@app.get("/api/edge")
async def api_edge(request: Request, src: int, dst: int):
    """Why an edge exists + what it means. Returns the typed relationship(s) between
    two nodes (rel_type + direction + evidence/provenance = why it was created) AND,
    for co-occurrence, the reports they share + the screenshot context where both
    appear (what the 'same pic' link actually means). Case-scoped."""
    mem_sql, mem_p = _case_in(_active_cases(request), "r.investigation")
    with db.connect(migrate=False) as conn:
        def nm(i):
            r = conn.execute("SELECT canonical_name FROM entities WHERE id=?", (i,)).fetchone()
            return r["canonical_name"] if r else "?"
        src_name, dst_name = nm(src), nm(dst)
        typed = []
        for r in conn.execute(
            "SELECT rel_type, confidence, evidence, "
            "  CASE WHEN src_entity_id=? THEN 'forward' ELSE 'reverse' END AS dir "
            "FROM typed_relationships WHERE status='active' "
            "AND ((src_entity_id=? AND dst_entity_id=?) OR (src_entity_id=? AND dst_entity_id=?))",
            (src, src, dst, dst, src)).fetchall():
            typed.append({"rel_type": r["rel_type"], "confidence": r["confidence"],
                          "evidence": r["evidence"] or "", "dir": r["dir"]})
        # Co-occurrence: reports where BOTH appear + the source context (the meaning).
        where = f"AND {mem_sql} " if mem_sql else ""
        shared = []
        for r in conn.execute(
            "SELECT r.title, r.source_type, ms.context FROM mentions ms "
            "JOIN reports r ON r.id = ms.report_id "
            "WHERE ms.entity_id = ? AND ms.report_id IN "
            "  (SELECT report_id FROM mentions WHERE entity_id = ?) " + where +
            "AND ms.context IS NOT NULL ORDER BY ms.id LIMIT 5",
            (src, dst, *mem_p)).fetchall():
            shared.append({"report": r["title"] or "report", "kind": r["source_type"],
                           "context": " ".join((r["context"] or "").split())[:300]})
    return JSONResponse({"src": src, "dst": dst, "src_name": src_name, "dst_name": dst_name,
                         "typed": typed, "shared_reports": shared,
                         "co_occurrence": len(shared) > 0 and not typed})


@app.get("/api/clusters")
async def api_clusters(request: Request):
    inq, inp = _case_in(_active_cases(request))
    cl_sql = (
        "WHERE c.id IN (SELECT cm2.cluster_id FROM cluster_members cm2 "
        "JOIN mentions m ON m.entity_id = cm2.entity_id "
        f"JOIN reports r ON r.id = m.report_id WHERE {inq}) "
    ) if inq else ""
    with db.connect() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT c.id, c.name, c.kind, c.description, "
            "COUNT(cm.entity_id) AS n "
            "FROM clusters c LEFT JOIN cluster_members cm ON cm.cluster_id = c.id "
            f"{cl_sql}"
            "GROUP BY c.id ORDER BY n DESC",
            inp,
        ).fetchall()]
    return JSONResponse({"clusters": rows})


def _gated_leads(conn, cases, exclude_names=None, limit: int = 200) -> list[dict]:
    """k4p-04: findings the promotion gate held back (NOT promoted to entity nodes) are
    surfaced as LEAD rows for the entity list — VISIBLE but badged unconfirmed, instead
    of buried in /enrich. The gate stops auto-FACT, not auto-VISIBILITY.

    Codex hardening: dedup is against the CASE-SCOPED confirmed names passed in
    (`exclude_names`), not a global name match; each lead gets a unique non-null id
    (`lead:<name>`) so the frontend never collides on null keys; one row per title is
    chosen DETERMINISTICALLY (highest confidence, then newest); the count is capped to
    `limit` so appending leads can't blow past the page size."""
    import json as _json
    if limit <= 0:
        return []
    inq, inp = _case_in(cases, col="run.investigation")
    where = "WHERE er.result_type='finding' AND er.extracted_entity_id IS NULL"
    if inq:
        where += f" AND {inq}"
    rank = ("CASE er.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 "
            "WHEN 'low' THEN 2 ELSE 3 END")
    rows = conn.execute(
        f"SELECT er.title, er.confidence, er.raw_json FROM enrichment_results er "
        f"JOIN enrichment_runs run ON run.id = er.run_id {where} "
        f"ORDER BY {rank} ASC, er.id DESC", inp).fetchall()
    exclude = {(n or "").strip().lower() for n in (exclude_names or [])}
    out, seen = [], set()
    for r in rows:
        name = (r["title"] or "").strip()
        key = name.lower()
        if not name or key in seen or key in exclude:
            continue
        seen.add(key)  # first row per title = highest confidence (ordered above)
        etype = "indicator"
        try:
            etype = (_json.loads(r["raw_json"]) or {}).get("entity_type") or "indicator"
        except Exception:
            pass
        out.append({"id": f"lead:{name}", "canonical_name": name, "entity_type": etype,
                    "notes": None, "sub_role": None, "sub_role_reason": None,
                    "threat_score": None, "degree": 0, "report_count": 0,
                    "clusters": None, "role": "lead", "lead": True,
                    "confidence": (r["confidence"] or "unconfirmed")})
        if len(out) >= limit:
            break
    return out


@app.get("/api/entities")
async def api_entities(request: Request, role: str | None = None, sub_role: str | None = None,
                       min_score: float = 0, limit: int = 200):
    scope_sql, scope_params = _scope(_active_cases(request))
    with db.connect() as conn:
        role_filter = f"AND e.notes LIKE 'role:{role}%'" if role else ""
        params: list = [min_score]
        sub_role_filter = ""
        if sub_role:
            sub_role_filter = "AND e.sub_role = ?"
            params.append(sub_role)
        params.extend(scope_params)
        params.append(limit)
        rows = [dict(r) for r in conn.execute(
            f"SELECT e.id, e.canonical_name, e.entity_type, e.notes, "
            f"e.sub_role, e.sub_role_reason, "
            f"s.threat_score, s.degree, s.report_count, "
            f"GROUP_CONCAT(DISTINCT c.name) AS clusters "
            f"FROM entities e "
            f"LEFT JOIN entity_scores s ON s.entity_id = e.id "
            f"LEFT JOIN cluster_members cm ON cm.entity_id = e.id "
            f"LEFT JOIN clusters c ON c.id = cm.cluster_id "
            f"WHERE (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
            f"AND (e.entity_type != 'person_candidate' OR e.notes IS NOT NULL) "
            f"AND (s.threat_score IS NULL OR s.threat_score >= ?) "
            f"{role_filter} {sub_role_filter} {scope_sql} "
            f"GROUP BY e.id "
            f"ORDER BY s.threat_score DESC NULLS LAST LIMIT ?",
            tuple(params),
        ).fetchall()]
        for r in rows:
            r["role"] = _role(r.get("notes"))
            r["lead"] = False
        # k4p-04: append the gated findings as badged LEAD rows so the entity list shows
        # everything the agent found, not only what cleared the gate. Skipped when the
        # analyst filters by a specific role/sub_role (a lead has neither). Dedup is
        # against the IN-SCOPE confirmed names (Codex), and leads fill only the remaining
        # page budget so the `limit` is honored. Leads carry no score by design (badged
        # unconfirmed, not score-0) and are independent of the min_score slider.
        if not role and not sub_role:
            confirmed_names = [r.get("canonical_name") for r in rows]
            remaining = max(0, limit - len(rows))
            rows += _gated_leads(conn, _active_cases(request),
                                 exclude_names=confirmed_names, limit=remaining)
    return JSONResponse({"entities": rows})


@app.get("/api/sub-roles")
async def api_sub_roles(request: Request):
    scope_sql, scope_params = _scope(_active_cases(request))
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT e.sub_role AS sub_role, COUNT(*) AS n FROM entities e "
            "WHERE e.sub_role IS NOT NULL AND e.sub_role != '' "
            f"{scope_sql} "
            "GROUP BY e.sub_role ORDER BY n DESC",
            scope_params,
        ).fetchall()
    return JSONResponse({"sub_roles": [dict(r) for r in rows]})


@app.get("/api/entity-types")
async def api_entity_types(request: Request):
    """Distinct types in scope + counts — populates the graph's Type filter.
    Prefers the case schema type (case_type: wallet_address / scam_domain) when
    the typing pass set one, falling back to the regex surface type. Mirrors the
    graph's own noise / person_candidate exclusions."""
    scope_sql, scope_params = _scope(_active_cases(request))
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT COALESCE(NULLIF(e.case_type,''), e.entity_type) AS etype, "
            "COUNT(*) AS n FROM entities e "
            "WHERE COALESCE(NULLIF(e.case_type,''), e.entity_type) IS NOT NULL "
            "AND COALESCE(NULLIF(e.case_type,''), e.entity_type) != '' "
            "AND (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
            "AND (e.entity_type != 'person_candidate' OR e.notes IS NOT NULL) "
            f"{scope_sql} "
            "GROUP BY etype ORDER BY n DESC",
            scope_params,
        ).fetchall()
    return JSONResponse({"types": [dict(r) for r in rows]})


@app.get("/api/sources")
async def api_sources(request: Request, report_id: int | None = None,
                      entity_id: int | None = None,
                      date: str | None = None, q: str | None = None,
                      limit: int = 500):
    """Filterable sources feed.
       - report_id: only sources from this report
       - entity_id: only sources where this entity was mentioned
       - date: 'YYYY-MM-DD' — only sources from this ingest date
       - q: free text against OCR + report title
    """
    cases = _active_cases(request)
    where = []
    params: list = []
    _cinq, _cinp = _case_in(cases)
    if _cinq:
        where.append(_cinq)
        params.extend(_cinp)
    if report_id:
        where.append("a.report_id = ?")
        params.append(report_id)
    if entity_id:
        where.append("a.id IN (SELECT asset_id FROM mentions WHERE entity_id = ? AND asset_id IS NOT NULL)")
        params.append(entity_id)
    if date:
        where.append("substr(r.ingested_at, 1, 10) = ?")
        params.append(date)
    if q:
        where.append("(a.ocr_text LIKE ? OR r.title LIKE ?)")
        pat = f"%{q.strip()}%"
        params.extend([pat, pat])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    with db.connect() as conn:
        rows = conn.execute(
            f"SELECT a.id, a.file_path, a.page_number, a.ocr_text, "
            f"a.report_id, r.title AS report_title, r.ingested_at, "
            f"substr(r.ingested_at, 1, 10) AS ingest_date "
            f"FROM assets a JOIN reports r ON r.id = a.report_id "
            f"{where_sql} "
            f"ORDER BY a.report_id, a.page_number LIMIT ?",
            tuple(params),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["vault_image"] = f"r{d['report_id']:04d}_{Path(d['file_path']).name}"
            # collect linked entities (for filter chips + display)
            ents = conn.execute(
                "SELECT DISTINCT e.id, e.canonical_name, e.entity_type, e.sub_role "
                "FROM mentions m JOIN entities e ON e.id = m.entity_id "
                "WHERE m.asset_id = ? LIMIT 12",
                (d["id"],),
            ).fetchall()
            d["entities"] = [dict(x) for x in ents]
            out.append(d)
        # facets for the filter UI (scoped to the active case-set)
        fq, fp = _case_in(cases, col="investigation")
        facet_where = f"WHERE {fq} " if fq else ""
        reports = [dict(x) for x in conn.execute(
            "SELECT id, title, substr(ingested_at, 1, 10) AS d "
            f"FROM reports {facet_where}ORDER BY ingested_at DESC",
            fp,
        ).fetchall()]
        dates = [x["d"] for x in conn.execute(
            "SELECT DISTINCT substr(ingested_at, 1, 10) AS d FROM reports "
            + (facet_where + "AND d IS NOT NULL " if fq else "WHERE d IS NOT NULL ")
            + "ORDER BY d DESC",
            fp,
        ).fetchall()]
    return JSONResponse({"sources": out, "facets": {"reports": reports, "dates": dates}})


# The standalone /ask page + /api/ask route were retired 2026-06-08 — grounded Q&A is
# now one capability of the single unified chat (/api/chat → ask_mod when the warm agent
# isn't live). ask_mod itself stays; only the dead second surface is gone.


@app.get("/enrich", response_class=HTMLResponse)
async def enrich_page(request: Request):
    return _tpl(request, "enrich.html", {})


@app.get("/briefs", response_class=HTMLResponse)
async def briefs_index(request: Request):
    return _tpl(request, "briefs.html", {})


@app.get("/briefs/{group_idx}", response_class=HTMLResponse)
async def brief_detail(request: Request, group_idx: str):
    briefs_dir = VAULT_DIR / "briefs"
    # support both "group-1" and "1" and "standalone"
    if group_idx == "standalone":
        target = briefs_dir / "standalone.md"
    elif group_idx.startswith("group-"):
        target = briefs_dir / f"{group_idx}.md"
    else:
        target = briefs_dir / f"group-{group_idx}.md"
    if not target.exists():
        return HTMLResponse(f"Brief not found: {target.name}", status_code=404)
    content = target.read_text(encoding="utf-8")
    return _tpl(request, "brief.html", {"content": content, "name": target.name})


@app.get("/api/enrich/providers")
async def api_enrich_providers(type: str | None = None):
    # NOTE: api_key is deliberately NOT selected — keys never leave the server.
    # `type` (the selected node's entity_type) filters the list to the transforms valid
    # for that node — Maltego-style. None/empty type or an actor type returns the full list.
    type_slugs = _providers_for_type(type) if type else None
    with db.connect() as conn:
        # 'agent' is the autonomous investigator, NOT a single-tool enrich adapter — it
        # only lives in osint_providers so past agent RUNS show in history. Don't offer
        # it as a runnable enrichment provider (running it errored 'unknown adapter
        # slug: agent'). Investigating a node is the dedicated "Investigate this node"
        # action instead.
        rows = [dict(r) for r in conn.execute(
            "SELECT slug, display_name, description, category, env_var, "
            "cost_estimate_usd, docs_url "
            "FROM osint_providers WHERE slug != 'agent' ORDER BY slug"
        ).fetchall()]
    # Type-scope: when the node's type has an infra recipe, show only those transforms.
    if type_slugs is not None:
        rows = [r for r in rows if r["slug"] in type_slugs]
    # Annotate with adapter modes + configured status + where the key lives
    for r in rows:
        try:
            a = get_adapter(r["slug"])
            r["configured"] = a.is_configured()
            r["modes"] = a.modes()
        except KeyError:
            r["configured"] = False
            r["modes"] = []
        r["key_source"] = enrich_base.key_source(r["slug"], r["env_var"])
    return JSONResponse({"providers": rows})


@app.post("/api/enrich/providers/{slug}/key")
async def api_enrich_set_key(slug: str, payload: dict):
    """Save (or clear) a provider's API key in the local gitignored DB.

    Empty/missing api_key clears the stored key (falls back to env var).
    The key is never echoed back — only configured status + source.
    """
    api_key = (payload.get("api_key") or "").strip()
    with db.connect() as conn:
        row = conn.execute(
            "SELECT slug, env_var FROM osint_providers WHERE slug = ?", (slug,)
        ).fetchone()
        if not row:
            return JSONResponse({"error": f"unknown provider: {slug}"}, status_code=404)
        env_var = row["env_var"]
        conn.execute(
            "UPDATE osint_providers SET api_key = ? WHERE slug = ?",
            (api_key or None, slug),
        )
        conn.commit()
    try:
        configured = get_adapter(slug).is_configured()
    except KeyError:
        # No adapter for this provider row — reflect persisted state + env
        # fallback the same way key_source does, not the raw submitted value.
        configured = enrich_base.key_source(slug, env_var) != "none"
    return JSONResponse({
        "slug": slug,
        "configured": configured,
        "has_key": bool(api_key),
        "key_source": enrich_base.key_source(slug, env_var),
        "cleared": not bool(api_key),
    })


# Intent groups for the OSINT transform menu (issue graph-osint-dropdown-grouping).
# The analyst reads by intent, not a flat 39-row wall of jargon. Unknown/new slugs
# fall through to "Other" so the menu never HIDES a provider; "Other" is the safety
# net, not a target. Keep roughly in sync with the adapter registry.
_TRANSFORM_GROUP = {
    # Infrastructure — DNS / whois / certs / hosting / IP geo / lookalikes
    "asn": "Infrastructure", "crtsh": "Infrastructure", "infra": "Infrastructure",
    "ipgeo": "Infrastructure", "whoisxml": "Infrastructure", "censys": "Infrastructure",
    "shodan": "Infrastructure", "typosquat": "Infrastructure",
    # Threat intel — reputation / abuse / blocklists / sanctions / dark web
    "abusech": "Threat intel", "abuseipdb": "Threat intel", "otx": "Threat intel",
    "virustotal": "Threat intel", "greynoise": "Threat intel", "urlscan": "Threat intel",
    "crypto_abuse": "Threat intel", "ofac": "Threat intel", "darkweb": "Threat intel",
    # On-chain — wallet / chain explorers / labels
    "blockchair": "On-chain", "ens": "On-chain", "solana": "On-chain", "tron": "On-chain",
    "wallet": "On-chain", "wallet_labels": "On-chain", "wallet_ton": "On-chain",
    "walletexplorer": "On-chain",
    # Identity — email / breach / people / orgs / handles / phone
    "email": "Identity", "gravatar": "Identity", "hibp": "Identity", "breach": "Identity",
    "opencorporates": "Identity", "username": "Identity", "phone": "Identity",
    # Web search — general web recon
    "tavily": "Web search", "perplexity": "Web search", "jina": "Web search",
    "exa": "Web search", "git_osint": "Web search",
    # Social — social-platform scrapers
    "apify": "Social",
    # Other — media/forensics with no larger bucket
    "exif": "Other",
}
_TRANSFORM_GROUP_ORDER = ["Infrastructure", "Threat intel", "On-chain", "Identity",
                          "Web search", "Social", "Other"]


@app.get("/api/transforms")
async def api_transforms(type: str = "", entity_id: int | None = None):
    """The Maltego-style type-filtered transform menu (sp2-transform-menu-api),
    GROUPED by intent + flagged with already-run state (issue
    graph-osint-dropdown-grouping). What can run on a node of this type, in the
    registry recipe map's order. Unknown/missing type -> an empty list (an untyped
    node has no menu, never a refusal). Unconfigured transforms are INCLUDED with
    configured=false (discoverability over hiding). With entity_id, each provider
    carries `ran` = whether it has already run on that entity, so the analyst sees
    what is left to do, not just a flat wall."""
    from investigations.enrich.registry import transforms_for_type
    # Threadpool: is_configured() does sync SQLite reads — keep them off the
    # event loop (codex adversarial).
    transforms = await run_in_threadpool(transforms_for_type, type)

    ran: set = set()
    if entity_id:
        def _ran_slugs():
            with db.connect() as conn:
                # status='success' only: a queued/running/error run must NOT show the
                # ✓ "already ran" marker (codex adversarial) — that would hide work left to do.
                return {r[0] for r in conn.execute(
                    "SELECT DISTINCT provider_slug FROM enrichment_runs "
                    "WHERE entity_id = ? AND status = 'success'",
                    (entity_id,))}
        ran = await run_in_threadpool(_ran_slugs)

    for t in transforms:
        t["group"] = _TRANSFORM_GROUP.get(t["slug"], "Other")
        t["ran"] = t["slug"] in ran

    by_group: dict = {}
    for t in transforms:
        by_group.setdefault(t["group"], []).append(t)
    groups = [{"group": g, "items": by_group[g]}
              for g in _TRANSFORM_GROUP_ORDER if g in by_group]
    return JSONResponse({"type": type, "transforms": transforms, "groups": groups})


@app.post("/api/enrich/run")
async def api_enrich_run(payload: dict):
    provider = payload.get("provider")
    query = payload.get("query")
    if not provider or not query:
        return JSONResponse({"error": "provider + query required"}, status_code=400)
    entity_id = payload.get("entity_id")
    mode = payload.get("mode")
    investigation = payload.get("investigation")
    timeout = int(payload.get("timeout") or 90)
    with db.connect() as conn:
        result = enrich_runner.run_and_persist(
            conn, provider, query,
            entity_id=entity_id, mode=mode, investigation=investigation,
            timeout=timeout,
        )
    return JSONResponse(result)


@app.post("/api/node/manual")
async def api_node_manual(request: Request, payload: dict):
    """Analyst-created node: name + type + optional thumbnail, optionally linked
    to an existing node. Joins the global pool + the active case."""
    from investigations.enrich import promote as promote_mod
    name = (payload.get("name") or "").strip()
    etype = (payload.get("entity_type") or "indicator").strip() or "indicator"
    thumb = (payload.get("thumbnail") or "").strip() or None
    # Same safety guard as the client-report logo: only http(s) or data:image.
    if thumb and not thumb.startswith(("http://", "https://", "data:image/")):
        thumb = None
    if not name:
        return JSONResponse({"error": "name is required"}, status_code=400)
    link_to = payload.get("link_to")
    case = _active_case(request)
    analyst = _active_analyst(request)
    with db.connect() as conn:
        if link_to is not None:
            try:
                link_to = int(link_to)
            except (TypeError, ValueError):
                link_to = None
            if link_to and not conn.execute(
                    "SELECT 1 FROM entities WHERE id = ?", (link_to,)).fetchone():
                link_to = None
        result = promote_mod.add_manual_node(
            conn, name, etype, analyst=analyst, thumbnail=thumb,
            link_to=link_to, case=case)
        if not result.get("error"):
            _log(request, conn, "added a node", entity_id=result.get("entity_id"),
                 detail=f"{etype}: {name}")
    if not result.get("error"):
        bump_case(case)
        record_ui_event(result.get("case") or case, f"added node {name}")
    return JSONResponse(result, status_code=200 if not result.get("error") else 400)


@app.post("/api/enrich/result/{result_id}/promote")
async def api_enrich_promote(request: Request, result_id: int):
    """Promote an enrichment result into a graph node linked to the source actor
    (and, via the global entity pool, possibly bridging into other cases)."""
    from investigations.enrich import promote as promote_mod
    from investigations import annotations as annotations_mod
    analyst = _active_analyst(request)
    case = _active_case(request)
    with db.connect() as conn:
        result = promote_mod.promote_result(conn, result_id, analyst=analyst)
        if not result.get("error"):
            _log(request, conn, "promoted enrichment to node",
                 entity_id=result.get("entity_id"), detail=result.get("name"))
            bump_case(case, conn=conn)
            record_ui_event(result.get("case") or case,
                            f"promoted finding {result.get('name') or result.get('entity_id')}")
            return JSONResponse(result, status_code=200)
        # Not a promotable indicator (it's a handle/summary about the actor). Don't error
        # — attach it to the TARGET actor's dossier as a note. So "Promote" always does
        # something useful instead of bouncing.
        row = conn.execute(
            "SELECT er.summary, er.title, run.entity_id FROM enrichment_results er "
            "JOIN enrichment_runs run ON run.id = er.run_id WHERE er.id = ?",
            (result_id,)).fetchone()
        if row and row["entity_id"]:
            note = (row["summary"] or row["title"] or "").strip()
            ann = annotations_mod.get(conn, row["entity_id"]) or {}
            existing = (ann.get("dossier_override") or "").strip()
            block = f"**Investigator note:** {note}"
            if note and note not in existing:
                merged = (existing + "\n\n" + block).strip() if existing else block
                annotations_mod.set_dossier_override(conn, row["entity_id"], merged,
                                                     author="analyst (from finding)")
            conn.execute("UPDATE enrichment_results SET extracted_entity_id = ? WHERE id = ?",
                         (row["entity_id"], result_id))
            conn.commit()
            _log(request, conn, "added finding to actor dossier", entity_id=row["entity_id"])
            bump_case(case, conn=conn)
            return JSONResponse({"ok": True, "added_to_dossier": True,
                                 "entity_id": row["entity_id"]}, status_code=200)
    return JSONResponse(result, status_code=400)


@app.post("/api/enrich/result/{result_id}/reject")
async def api_enrich_reject(request: Request, result_id: int):
    """Analyst rejects an enrichment finding (gtl-2): records decision='rejected'
    + a rejection claim on the source actor, no node built. The accept side is
    handled inside /promote (promote_result writes decision='accepted')."""
    from investigations.enrich import promote as promote_mod
    analyst = _active_analyst(request)
    case = _active_case(request)
    payload = {}
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    reason = (payload.get("reason") or "").strip() or None
    with db.connect() as conn:
        result = promote_mod.reject_result(conn, result_id, analyst=analyst, reason=reason)
        if not result.get("error"):
            _log(request, conn, "rejected enrichment finding",
                 detail=f"result #{result_id}")
            bump_case(case, conn=conn)
            record_ui_event(case, f"rejected finding #{result_id}")
            return JSONResponse(result, status_code=200)
    return JSONResponse(result, status_code=400)


@app.post("/api/enrich/result/{result_id}/decide")
async def api_enrich_decide(request: Request, result_id: int, payload: dict):
    """Analyst's decision on a LARGE result (needs_decision). We never cap evidence —
    the full set is in raw_json; this chooses what to materialize:
      revert  — discard the result (nothing was built)
      cluster — open the full set as a new collapsible cluster in the case
      subset  — materialize the first N items into a new cluster
      reason  — keep the set as evidence, materialize nothing
    """
    from investigations.enrich import promote as promote_mod
    action = (payload.get("action") or "").strip()
    case = _active_case(request)
    analyst = _active_analyst(request)
    with db.connect() as conn:
        if action == "revert":
            result = promote_mod.revert_result(conn, result_id)
        elif action == "cluster":
            result = promote_mod.materialize_to_cluster(conn, result_id, analyst=analyst)
        elif action == "subset":
            try:
                n = int(payload.get("subset"))
            except (TypeError, ValueError):
                return JSONResponse({"error": "subset must be a count (int)"}, status_code=400)
            result = promote_mod.materialize_to_cluster(conn, result_id, subset=n, analyst=analyst)
        elif action == "reason":
            result = promote_mod.mark_reasoned(conn, result_id)
        else:
            return JSONResponse({"error": f"unknown action: {action!r}"}, status_code=400)
        if not result.get("error"):
            _log(request, conn, f"enrich volume decision: {action}",
                 detail=str(result.get("cluster_name") or result.get("added") or action))
            bump_case(case, conn=conn)
            record_ui_event(case, f"enrich decision {action} on result #{result_id}")
    return JSONResponse(result, status_code=200 if not result.get("error") else 400)


@app.get("/api/enrich/history")
async def api_enrich_history(entity_id: int | None = None,
                              provider: str | None = None,
                              limit: int = 50):
    where = []
    params: list = []
    if entity_id is not None:
        where.append("entity_id = ?")
        params.append(entity_id)
    if provider:
        where.append("provider_slug = ?")
        params.append(provider)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    with db.connect() as conn:
        runs = [dict(r) for r in conn.execute(
            f"SELECT id, entity_id, provider_slug, query, mode, status, "
            f"started_at, finished_at, cost_usd, error_message, investigation, agent_process "
            f"FROM enrichment_runs {where_sql} "
            f"ORDER BY id DESC LIMIT ?",
            tuple(params),
        ).fetchall()]
        for r in runs:
            r["results"] = [dict(x) for x in conn.execute(
                "SELECT id, result_type, title, summary, url, confidence, "
                "extracted_entity_id, raw_json "
                "FROM enrichment_results WHERE run_id = ? LIMIT 25",
                (r["id"],),
            ).fetchall()]
    return JSONResponse({"runs": runs})


@app.get("/api/enrich/run/{run_id}")
async def api_enrich_run_detail(run_id: int):
    with db.connect() as conn:
        run = conn.execute(
            "SELECT * FROM enrichment_runs WHERE id = ?", (run_id,),
        ).fetchone()
        if not run:
            return JSONResponse({"error": "not found"}, status_code=404)
        results = [dict(r) for r in conn.execute(
            "SELECT id, result_type, title, summary, url, raw_json, confidence, decision "
            "FROM enrichment_results WHERE run_id = ?",
            (run_id,),
        ).fetchall()]
    return JSONResponse({"run": dict(run), "results": results})


@app.get("/api/enrich/stats")
async def api_enrich_stats(investigation: str | None = None):
    where = "WHERE investigation = ?" if investigation else ""
    params = (investigation,) if investigation else ()
    with db.connect() as conn:
        row = conn.execute(
            f"SELECT COUNT(*) AS run_count, "
            f"COALESCE(SUM(cost_usd), 0) AS total_cost, "
            f"COUNT(DISTINCT entity_id) AS distinct_entities, "
            f"SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) AS successes, "
            f"SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors "
            f"FROM enrichment_runs {where}",
            params,
        ).fetchone()
        by_provider = [dict(r) for r in conn.execute(
            f"SELECT provider_slug, COUNT(*) AS n, SUM(cost_usd) AS cost "
            f"FROM enrichment_runs {where} "
            f"GROUP BY provider_slug ORDER BY n DESC",
            params,
        ).fetchall()]
    return JSONResponse({"summary": dict(row), "by_provider": by_provider})


@app.get("/api/briefs")
async def api_briefs():
    briefs_dir = VAULT_DIR / "briefs"
    out = {"groups": [], "standalone": None, "index": None}
    if not briefs_dir.exists():
        return JSONResponse(out)
    index = briefs_dir / "INDEX.md"
    if index.exists():
        out["index"] = index.read_text(encoding="utf-8")
    standalone = briefs_dir / "standalone.md"
    if standalone.exists():
        out["standalone"] = standalone.read_text(encoding="utf-8")
    for f in sorted(briefs_dir.glob("group-*.md")):
        out["groups"].append({
            "name": f.stem,
            "content": f.read_text(encoding="utf-8"),
        })
    return JSONResponse(out)


@app.get("/api/focus")
async def api_focus(request: Request):
    case = _active_case(request)
    with db.connect() as conn:
        return JSONResponse(_load_focus(case, conn))


@app.get("/api/bridges")
async def api_bridges(request: Request, min_clusters: int = 2, limit: int = 100):
    """Entities that bridge multiple clusters + the typed edges between
    different clusters. These are the network structure connectors."""
    cases = _active_cases(request)
    scope_sql, scope_params = _scope(cases)
    with db.connect() as conn:
        bridges = [dict(r) for r in conn.execute(
            "SELECT e.id, e.canonical_name, e.entity_type, e.notes, "
            "e.sub_role, e.sub_role_reason, "
            "COUNT(DISTINCT cm.cluster_id) AS cluster_count, "
            "GROUP_CONCAT(DISTINCT c.name) AS cluster_names, "
            "GROUP_CONCAT(DISTINCT c.id) AS cluster_ids, "
            "COALESCE(s.threat_score, 0) AS threat_score, "
            "(SELECT MAX(weight) FROM seeds WHERE entity_id = e.id) AS seed_weight "
            "FROM entities e "
            "JOIN cluster_members cm ON cm.entity_id = e.id "
            "JOIN clusters c ON c.id = cm.cluster_id "
            "LEFT JOIN entity_scores s ON s.entity_id = e.id "
            "WHERE (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
            f"{scope_sql} "
            "GROUP BY e.id "
            "HAVING cluster_count >= ? "
            "ORDER BY cluster_count DESC, threat_score DESC "
            "LIMIT ?",
            (*scope_params, min_clusters, limit),
        ).fetchall()]
        for b in bridges:
            b["role"] = _role(b.get("notes"))
            b["clusters"] = [
                {"id": int(cid), "name": name} for cid, name in zip(
                    (b["cluster_ids"] or "").split(","),
                    (b["cluster_names"] or "").split(","),
                ) if cid
            ]

        # Cross-cluster edges — case-scoped: BOTH endpoints must belong to the
        # active case, or a case view leaks another case's edges (the bridges
        # list above is scoped; this must match it). Without this, a case with 0
        # bridges still rendered 200 cross-case edges from other investigations.
        cc_sql, cc_params = "", []
        if cases:
            inq, inp = _case_in(cases)
            ent_in_case = ("(SELECT m.entity_id FROM mentions m JOIN reports r "
                           f"ON r.id = m.report_id WHERE {inq})")
            cc_sql = f"AND es.id IN {ent_in_case} AND ed.id IN {ent_in_case} "
            cc_params = [*inp, *inp]
        cross_edges = [dict(r) for r in conn.execute(
            "SELECT t.rel_type, t.confidence, t.evidence, "
            "es.id AS src_id, es.canonical_name AS src_name, "
            "ed.id AS dst_id, ed.canonical_name AS dst_name, "
            "cs.id AS src_cluster_id, cs.name AS src_cluster, "
            "cd.id AS dst_cluster_id, cd.name AS dst_cluster "
            "FROM typed_relationships t "
            "JOIN entities es ON es.id = t.src_entity_id "
            "JOIN entities ed ON ed.id = t.dst_entity_id "
            "JOIN cluster_members cms ON cms.entity_id = es.id "
            "JOIN cluster_members cmd ON cmd.entity_id = ed.id "
            "JOIN clusters cs ON cs.id = cms.cluster_id "
            "JOIN clusters cd ON cd.id = cmd.cluster_id "
            "WHERE cs.id != cd.id AND COALESCE(t.status,'active') = 'active' "
            f"{cc_sql}"
            "ORDER BY CASE t.confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "ELSE 3 END "
            "LIMIT 200",
            cc_params,
        ).fetchall()]
    return JSONResponse({"bridges": bridges, "cross_edges": cross_edges})


@app.get("/api/seeds")
async def api_seeds(request: Request):
    scope_sql, scope_params = _scope(_active_cases(request))
    with db.connect() as conn:
        if not _table_exists(conn, "seeds"):
            return JSONResponse({"seeds": []})
        rows = [dict(r) for r in conn.execute(
            "SELECT s.entity_id, s.label, s.weight, s.source_file, s.added_at, "
            "e.canonical_name, e.entity_type, e.sub_role "
            "FROM seeds s LEFT JOIN entities e ON e.id = s.entity_id "
            f"WHERE 1=1 {scope_sql} "
            "ORDER BY s.weight DESC",
            scope_params,
        ).fetchall()]
    return JSONResponse({"seeds": rows})


@app.get("/api/stats")
async def api_stats(request: Request):
    with db.connect() as conn:
        s = _scoped_stats(conn, _active_cases(request))
        s["top_entities"] = [dict(t) for t in s["top_entities"]]
    return JSONResponse(s)


def run(host: str = "127.0.0.1", port: int = 8765, reload: bool = False):
    import uvicorn
    uvicorn.run("investigations.webapp.app:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    run()
