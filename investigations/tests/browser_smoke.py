"""Browser-level render smoke harness — the outcome-check capability the suite lacked.

Scar (prd-graph-outcome-gate / RCA rca-graph-ux-findings-recurrence-2026-06-15):
187 TestClient tests, ZERO execute JS, so a blank-canvas render bug (/graph?focus
returns nodes from the API but draws nothing) was invisible to every gate by
construction. This harness runs the REAL app under uvicorn against an ISOLATED
seeded DB and drives headless chromium, so a test can assert what the analyst
SEES — the rendered Cytoscape node count — not just the HTTP payload.

This is the single chokepoint every render-outcome test goes through (the
selfcheck here, and the focus-render gate next). Helpers:
  - seed_graph(db_path)          : seed a known, isolated small graph (or empty).
  - serve(db_path)               : run the app on an ephemeral port against it.
  - graph_state(page)            : [ready, count, painted] from the live page.
  - wait_until_graph_ready(page) : block until Cytoscape exists (raises if never).
  - wait_for_rendered_nodes(page): block until >=1 node is laid out + painted.

NOT named test_* on purpose — pytest must import it as a helper, not collect it.
"""
from __future__ import annotations

import contextlib
import socket
import threading
import time
from pathlib import Path

from investigations.storage import db

# serve() swaps the process-global db.connect for the server's lifetime. This
# lock makes overlapping serve() contexts (a nested use, or a parallel test
# runner) mutually exclusive, so one context's temp-DB redirect can never bleed
# into another's requests (codex adversarial: cross-test global-state bleed).
_SERVE_LOCK = threading.Lock()


def free_port() -> int:
    """An OS-assigned free TCP port on loopback. The socket is closed before
    uvicorn binds, so serve() retries on the rare bind race."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def seed_graph(db_path: Path, *, empty: bool = False) -> dict:
    """Seed an isolated DB with a known small connected graph.

    Nodes are entered via a `manual` report + mentions (ENRICH_NODE-exempt, so
    they bypass the score + in-cluster gates regardless of the client's filter
    state) AND joined by `active` typed edges (so the meaningful-only filter
    admits them). That makes them render under every default filter combination.

    empty=True seeds the case + report but NO entities — the negative self-test:
    the renderer must show a ready-but-empty graph (0 nodes), proving the counter
    does not false-positive.

    Returns {case, focus_id, expected_nodes}.
    """
    db.init_db(db_path)
    case = "smoke-case"
    with db.connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO investigations (slug, status) VALUES (?, 'active')",
            (case,),
        )
        rep = db.insert_report(
            conn, source_path="<smoke>", source_hash="smoke-h",
            source_type="manual", title="smoke", investigation=case, raw_text="",
        )
        if empty:
            conn.commit()
            return {"case": case, "focus_id": None, "expected_nodes": 0}
        nodes = [
            ("smoke-actor.com", "domain"),
            ("smoke-wallet-0xabc", "wallet"),
            ("smoke-ip-9.9.9.9", "ip"),
        ]
        ids = []
        for name, etype in nodes:
            eid = db.upsert_entity(conn, name, etype, rep, provenance="ingest:report")
            db.add_mention(conn, eid, rep, name, "")  # manual report -> ENRICH_NODE exempt
            ids.append(eid)
        for src, dst in ((ids[0], ids[1]), (ids[0], ids[2])):
            conn.execute(
                "INSERT INTO typed_relationships "
                "(src_entity_id, dst_entity_id, rel_type, status, provenance) "
                "VALUES (?, ?, 'linked_to', 'active', 'smoke')",
                (src, dst),
            )
        conn.commit()
        return {"case": case, "focus_id": ids[0], "expected_nodes": len(ids)}


def _start_server(app, *, attempts: int = 5):
    """Start uvicorn in a daemon thread on a free port. Retries a fresh port if
    the bind races (free_port closed the socket before uvicorn binds). Returns
    (server, thread, base_url)."""
    import uvicorn

    last = None
    for _ in range(attempts):
        port = free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)
        # We run off the main thread; uvicorn's signal handlers only install on
        # the main thread and would raise here.
        server.install_signal_handlers = lambda: None
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        for _ in range(200):  # up to ~10s
            if getattr(server, "started", False):
                return server, thread, f"http://127.0.0.1:{port}"
            if not thread.is_alive():  # died during startup (port taken) -> retry
                break
            time.sleep(0.05)
        server.should_exit = True
        thread.join(timeout=5)
        last = RuntimeError(f"uvicorn did not start on port {port}")
    raise last or RuntimeError("could not start test server")


@contextlib.contextmanager
def serve(db_path: Path):
    """Run the real app under uvicorn in a thread, pointed at db_path; yield base_url.

    The app calls `db.connect()` with no args (its default is the prod DB path),
    resolving `db.connect` as a module attribute at request time. We swap that
    attribute for a wrapper that redirects the default to db_path, so every
    request handler reads the isolated DB. The swap is held under _SERVE_LOCK and
    restored on exit. If the server thread does not stop, we raise rather than
    silently leave a lingering thread that could hit the live DB.
    """
    from investigations.webapp import app as app_module

    real_connect = db.connect
    real_default = db.DB_PATH

    def _connect(dbp=real_default, migrate=True):
        target = db_path if dbp == real_default else dbp
        return real_connect(target, migrate=migrate)

    with _SERVE_LOCK:
        db.connect = _connect
        server = thread = None
        try:
            server, thread, base_url = _start_server(app_module.app)
            yield base_url
        finally:
            if server is not None:
                server.should_exit = True
            if thread is not None:
                thread.join(timeout=10)
            db.connect = real_connect
            if thread is not None and thread.is_alive():
                raise RuntimeError(
                    "uvicorn server thread did not stop within 10s; test isolation "
                    "cannot be guaranteed (a lingering request could hit the live DB)"
                )


# Reads render state from the Alpine v3 component. The graph root is
# <div x-data="graphController()">; #cy is its descendant, so Alpine.$data(#cy)
# returns the controller whose `.cy` is the Cytoscape instance. Returns
# [ready, count, painted]: ready = the instance exists (init finished); count =
# model node count; painted = the first node has a non-zero rendered box (a real
# layout, not a blank/zero-size canvas — codex adversarial: model != pixels).
_GRAPH_STATE_JS = """
() => {
  try {
    const el = document.getElementById('cy');
    if (!el || !window.Alpine) return [false, 0, false];
    const data = window.Alpine.$data(el);
    if (!data || !data.cy) return [false, 0, false];
    const cy = data.cy;
    const n = cy.nodes().length;
    let painted = false;
    if (n > 0) {
      const bb = cy.nodes()[0].renderedBoundingBox();
      painted = !!(bb && (bb.w > 0 || bb.h > 0));
    }
    return [true, n, painted];
  } catch (e) { return [false, 0, false]; }
}
"""


def graph_state(page):
    """[ready, count, painted] for the graph page (see _GRAPH_STATE_JS)."""
    state = page.evaluate(_GRAPH_STATE_JS)
    # Normalize to a 3-tuple regardless of JS hiccups.
    ready = bool(state[0]) if state else False
    count = int(state[1]) if state and len(state) > 1 else 0
    painted = bool(state[2]) if state and len(state) > 2 else False
    return ready, count, painted


def wait_until_graph_ready(page, *, timeout_ms: int = 8000) -> int:
    """Block until the Cytoscape instance EXISTS (init finished). Returns the
    node count — 0 is valid (a ready-but-empty graph). Raises if the graph never
    initialized, so the negative self-test distinguishes 'empty' from 'page
    never loaded' (codex: do not collapse sentinels to a passing 0)."""
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline:
        ready, count, _ = graph_state(page)
        if ready:
            return count
        time.sleep(0.1)
    raise RuntimeError(
        "Cytoscape graph never initialized — the page did not load a graph "
        "(distinct from a real empty graph)"
    )


def wait_for_rendered_nodes(page, *, timeout_ms: int = 8000) -> int:
    """Block until the graph is ready AND has >=1 node with a non-zero rendered
    box. Returns the count. Raises if it stays empty/unpainted past the timeout
    (this is the blank-canvas regression the harness exists to catch)."""
    deadline = time.time() + timeout_ms / 1000.0
    last = 0
    while time.time() < deadline:
        ready, count, painted = graph_state(page)
        if ready and count > 0 and painted:
            return count
        if ready:
            last = count
        time.sleep(0.1)
    raise AssertionError(
        f"graph ready but {last} node(s) laid out/painted after {timeout_ms}ms "
        "(blank canvas: data present, render absent)"
    )
