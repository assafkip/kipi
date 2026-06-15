"""Warm investigation session manager (4pa-01).

4_points loads MCP once per session and stays warm. kipi cold-boots 5 MCP
servers on every `claude -p` spawn (investigator.py::_run_agent). 4pa-00 proved
a single long-lived ClaudeSDKClient keeps MCP booted ONCE across turns
(docs/22). This module is the warm path: a per-case session that connects the
client once and serves many analyst turns on it, gated behind KIPI_WARM_SESSION.
The cold `_run_agent` subprocess path stays the default until the 4pa-05 A/B.

Lifecycle safety (the long-lived-process risk): an idle reaper closes stale
sessions, kill/restart recovers a wedged one, and the live-session count is
capped by KIPI_MAX_AGENTS (LRU-evicted on overflow) so sessions can't leak.

Testability: WarmSessionManager takes a `client_factory`. The default builds a
real ClaudeSDKClient mirroring the cold path; tests inject a fake. The response
collector is duck-typed (no hard SDK-type coupling), so the unit test runs
offline with no API call.
"""
import asyncio
import concurrent.futures
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def _utcnow_str() -> str:
    """UTC wall-clock in SQLite CURRENT_TIMESTAMP format ('YYYY-MM-DD HH:MM:SS'), so a
    warm run's real started_at/finished_at are directly comparable to the column default."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def warm_session_enabled() -> bool:
    """True when the warm-session path is on. The chat IS the investigator: warm is the
    DEFAULT (opt-OUT). Only an explicit off value disables it; unset/absent means ON.
    KIPI_WARM_SESSION=0 is the full revert lever back to the deterministic router."""
    return os.environ.get("KIPI_WARM_SESSION", "").strip().lower() not in {
        "0", "false", "no", "off",
    }


def _max_sessions() -> int:
    """Live-session cap. Shares KIPI_MAX_AGENTS with the cold concurrency cap."""
    return int(os.environ.get("KIPI_MAX_AGENTS", "4"))


def _idle_ttl_seconds() -> float:
    """A session idle longer than this is reaped (default 15 min)."""
    return float(os.environ.get("KIPI_WARM_IDLE_TTL", "900"))


class WarmSession:
    """One warm ClaudeSDKClient bound to a case. Connects once, serves N turns."""

    def __init__(self, case_slug: str, client) -> None:
        self.case_slug = case_slug
        self._client = client
        self._connected = False
        self._closed = False
        self.boot_count = 0
        self.last_used = time.monotonic()
        self._turn_lock = asyncio.Lock()
        self._conn_lock = asyncio.Lock()

    @property
    def is_alive(self) -> bool:
        return self._connected and not self._closed

    @property
    def is_reusable(self) -> bool:
        """Reuse a registered session unless it is CLOSED. A not-yet-connected
        session is still reusable — ensure_connected is idempotent + serialized,
        so concurrent first access shares one session instead of orphaning it."""
        return not self._closed

    async def ensure_connected(self) -> None:
        """Connect exactly once. boot_count counts real MCP boots for this case.
        Double-checked under a lock so two concurrent turns can't both boot it."""
        if self._connected or self._closed:
            return
        async with self._conn_lock:
            if self._connected or self._closed:
                return
            await self._client.connect()
            self._connected = True
            self.boot_count += 1

    async def ask(self, task: str, deadline: float | None = None,
                  on_step=None, cancel=None, redirect=None) -> dict:
        """Run one analyst turn on the warm client. Turns are serialized so a single
        client is never driven by two turns at once. `deadline` (seconds) bounds the
        turn IN-STREAM: on cutoff it returns the PARTIAL text + step trail with
        capped=True (so the caller can salvage findings, like the cold path) instead
        of losing everything. `on_step(step)` streams each new step as it lands.
        `cancel` (a threading.Event) cooperatively stops the turn between stream
        messages, salvaging the partial. `redirect` (a RedirectBox) injects a NEW
        instruction INTO the live turn: the current burst is interrupted + salvaged,
        then the instruction is re-queried on the SAME warm session (full context
        kept) and the turn CONTINUES — one transcript turn. cancel wins over redirect
        if both fire."""
        if self._closed:
            raise RuntimeError(f"warm session for {self.case_slug!r} is closed")
        async with self._turn_lock:
            await self.ensure_connected()
            self.last_used = time.monotonic()
            return await self._collect(task, deadline, on_step=on_step,
                                       cancel=cancel, redirect=redirect)

    async def _collect(self, task: str, deadline: float | None,
                       on_step=None, cancel=None, redirect=None) -> dict:
        """Stream the turn, accumulating text + a tool step-trail as it goes. Stops
        at the result message, at the deadline, or when the stream ends — returning
        whatever was gathered (capped=True if cut off). Duck-typed so the fake test
        client needs no SDK types.

        A turn is one or more SEGMENTS: the initial task, plus one per analyst
        `redirect`. A redirect interrupts the live segment, drains it to its (now
        early) result so the salvage is clean, then re-queries the instruction on the
        SAME session — the trail (texts/tools/steps) carries across segments, so it
        reads as ONE continuous turn that changed direction mid-burst."""
        from investigations.agent import investigator as inv

        try:
            return await self._collect_inner(task, deadline, on_step, cancel, redirect, inv)
        except asyncio.CancelledError:
            # HARD cancel (the +30s submit backstop's future.cancel(), or a watcher) raises
            # CancelledError out of the inner await — it bypasses the cooperative cap path and
            # its _safe_interrupt(). Without this handler the chat stream closed while the
            # agent subprocess kept running ORPHANED (the lifecycle bug). Interrupt the live
            # agent before re-raising. Shielded so the interrupt completes on the persistent
            # warm loop even though THIS coroutine is being torn down.
            try:
                await asyncio.shield(self._safe_interrupt())
            except asyncio.CancelledError:
                pass  # the shielded interrupt task still runs to completion on the loop
            raise

    async def _collect_inner(self, task, deadline, on_step, cancel, redirect, inv) -> dict:
        texts: list[str] = []
        tools: list[str] = []
        steps: list[dict] = []
        pending: dict = {}
        n = 0
        capped = False
        cap_reason = None
        # Run accounting (4pa-lifecycle): the warm path used to discard the SDK
        # ResultMessage payload (raw={}), so cost/turns/wall-clock were invisible in
        # enrichment_runs (started_at==finished_at, cost_usd NULL). Capture them here.
        started_at = _utcnow_str()
        t0 = time.monotonic()
        cost_usd = None
        cost_estimated = False  # true when cost_usd is a price-table estimate, not the
        #                         exact SDK figure (a STOPPED/turn-limit turn has no Result)
        usage_acc = {"input_tokens": 0, "output_tokens": 0}  # accumulated per-message usage
        turns = None
        duration_ms = None
        saw_result = False  # a healthy turn ends on the agent's final result message;
        #                     ending WITHOUT one means the max-turns backstop cut it off.
        redirected = False
        end = (time.monotonic() + deadline) if deadline else None
        await self._client.query(task)
        pending_redirect = None
        # Segment loop: one pass per query (initial task + each redirect).
        while True:
            stream = self._client.receive_response()
            next_task = None
            interrupted = False
            try:
                while True:
                    # Cooperative Stop wins over redirect: salvage the partial (capped).
                    # Interrupt the LIVE tool RIGHT HERE (mirroring the redirect path), so an
                    # in-flight browser/web_search call is aborted via the SDK control channel
                    # immediately — not after it resolves (the ~30s Stop lag). The post-loop
                    # `if capped: _safe_interrupt()` then no-ops on the already-interrupted turn.
                    if cancel is not None and cancel.is_set():
                        capped = True
                        cap_reason = "stopped"
                        await self._safe_interrupt()
                        break
                    remaining = (end - time.monotonic()) if end is not None else None
                    if remaining is not None and remaining <= 0:
                        capped = True
                        cap_reason = "deadline"
                        break
                    # Analyst steered mid-burst: interrupt the live segment, but keep
                    # draining THIS stream to its (now-early) result BEFORE re-querying
                    # — querying before the interrupted result lands would make the next
                    # receive_response() catch the stale result and end instantly.
                    if redirect is not None and not interrupted:
                        rtext = redirect.take()
                        if rtext:
                            pending_redirect = rtext
                            interrupted = True
                            await self._safe_interrupt()
                    # Poll in short slices so Stop/redirect are responsive even mid-await.
                    slice_to = 1.0 if remaining is None else min(1.0, remaining)
                    # Keep ONE __anext__ task alive across slice ticks. asyncio.wait_for
                    # CANCELS the pending __anext__ on every timeout, which corrupts the
                    # real SDK's response iterator — the next __anext__ then raises
                    # StopAsyncIteration and the turn dies after the first >1s thinking
                    # gap (live smoke: 1 message, then empty). Polling the SAME task with
                    # asyncio.wait leaves it pending on a slice tick, so Stop + deadline
                    # stay responsive WITHOUT killing the stream.
                    if next_task is None:
                        next_task = asyncio.ensure_future(stream.__anext__())
                    done, _ = await asyncio.wait({next_task}, timeout=max(slice_to, 0.01))
                    if not done:
                        continue  # slice tick — task still pending, re-check cancel/redirect
                    try:
                        message = next_task.result()
                    except StopAsyncIteration:
                        next_task = None
                        break
                    next_task = None
                    before = len(steps)
                    n = _absorb_message(message, texts, tools, steps, pending, n, inv, usage_acc)
                    if on_step:
                        # Emit only the NEW steps this message appended (0, 1, or many).
                        # A tool_result message mutates a pending step in place (no
                        # append) and isn't re-emitted; the step is a dict held by
                        # reference, so its result-fill shows on the next poll.
                        for s in steps[before:]:
                            try:
                                on_step(s)
                            except Exception:
                                pass
                    if _is_result(message):
                        saw_result = True
                        # The SDK ResultMessage carries the run's real cost + turn count +
                        # duration — pull them so the warm run is no longer cost-blind.
                        cost_usd = getattr(message, "total_cost_usd", None)
                        turns = getattr(message, "num_turns", None)
                        duration_ms = getattr(message, "duration_ms", None)
                        break
            finally:
                # A break on cancel/deadline/redirect can leave a pending __anext__ —
                # cancel it before tearing the iterator down so it doesn't dangle.
                if next_task is not None and not next_task.done():
                    next_task.cancel()
                await _safe_aclose(stream)
            if capped:
                break
            if pending_redirect:
                # Record the analyst's steer in the trail, then continue the turn with
                # a fresh query on the same warm session (history kept).
                n += 1
                rstep = {"n": n, "type": "redirect", "text": pending_redirect[:600]}
                steps.append(rstep)
                redirected = True
                if on_step:
                    try:
                        on_step(rstep)
                    except Exception:
                        pass
                await self._client.query(pending_redirect)
                pending_redirect = None
                continue  # next segment
            break  # natural completion (result with no pending redirect)
        # Stream ended without the agent's final result message and we weren't Stopped:
        # the max-turns backstop cut it off. Mark it so the chat says so (founder: a
        # backstop hit must be visible, never a silent truncation).
        if not saw_result and not capped:
            capped = True
            cap_reason = "turn_limit"
        if capped:
            await self._safe_interrupt()
        # No ResultMessage (Stopped or turn-limit-cut) → exact cost is unavailable. Estimate
        # it from accumulated token usage so the turn reports a real ~$ figure, not null
        # (founder: a stopped turn still cost money — show it, flagged as an estimate).
        if cost_usd is None and (usage_acc["input_tokens"] or usage_acc["output_tokens"]):
            cost_usd = inv.estimate_cost_usd(
                usage_acc["input_tokens"], usage_acc["output_tokens"], inv.AGENT_MODEL)
            cost_estimated = True
        return {"ok": True, "result_text": "\n".join(texts), "tools": tools,
                "steps": steps, "capped": capped, "cap_reason": cap_reason,
                "redirected": redirected,
                # Run accounting so the landing path can write real cost/turns/wall-clock.
                "cost_usd": cost_usd, "cost_estimated": cost_estimated, "turns": turns,
                "started_at": started_at, "finished_at": _utcnow_str(),
                "elapsed_s": round(time.monotonic() - t0, 2),
                "duration_ms": duration_ms}

    async def _safe_interrupt(self) -> bool:
        """End the in-flight turn so the agent stops (and the next turn starts fresh).
        Returns True if the interrupt was sent. A FAILED interrupt is logged, never
        swallowed silently — a silent failure is exactly how the agent kept running
        orphaned after the chat said done (the lifecycle bug)."""
        interrupt = getattr(self._client, "interrupt", None)
        if interrupt is None:
            return False
        try:
            await interrupt()
            return True
        except Exception as exc:
            log.warning("warm interrupt FAILED for case %s: %s — agent may still be "
                        "running; restart the session if it wedges", self.case_slug, exc)
            return False

    async def close(self) -> None:
        """Disconnect the client and mark closed. Idempotent — no zombie leak."""
        if self._closed:
            return
        self._closed = True
        if self._connected:
            try:
                await self._client.disconnect()
            finally:
                self._connected = False


def _is_result(message) -> bool:
    return type(message).__name__ == "ResultMessage" or getattr(
        message, "is_result", False
    )


def _absorb_message(message, texts, tools, steps, pending, n, inv, usage=None) -> int:
    """Fold one SDK message into texts + tools + the step trail (same shape as the
    cold _extract_steps, so _attribute_findings / _salvage_from_trail work on it).
    Duck-typed: text block -> reasoning step; tool_use -> tool step; tool_result ->
    fills its tool step's result by tool_use_id. Returns the updated step counter.

    When `usage` (a mutable accumulator dict) is passed, this also folds the message's
    token usage into it (mirrors llm/client.py:67-70) so a STOPPED turn — which never
    emits a ResultMessage with the exact cost — can still report an estimated $ spend
    instead of a null bill."""
    if usage is not None:
        u = getattr(message, "usage", None)
        if isinstance(u, dict):
            usage["input_tokens"] += (u.get("input_tokens", 0) or 0) \
                + (u.get("cache_read_input_tokens", 0) or 0) \
                + (u.get("cache_creation_input_tokens", 0) or 0)
            usage["output_tokens"] += (u.get("output_tokens", 0) or 0)
    for block in getattr(message, "content", None) or []:
        text = getattr(block, "text", None)
        name = getattr(block, "name", None)
        tool_use_id = getattr(block, "tool_use_id", None)
        if text is not None:
            texts.append(text)
            stripped = text.strip()
            if stripped:
                n += 1
                steps.append({"n": n, "type": "reasoning", "text": stripped[:600]})
        elif name is not None:  # ToolUseBlock
            tools.append(name)
            n += 1
            step = {"n": n, "type": "tool", "tool": inv._short_tool(name),
                    "raw_tool": name, "input": inv._short_input(getattr(block, "input", None)),
                    "result": None}
            steps.append(step)
            block_id = getattr(block, "id", None)
            if block_id:
                pending[block_id] = step
        elif tool_use_id is not None:  # ToolResultBlock
            step = pending.get(tool_use_id)
            if step is not None:
                step["result"] = inv._short_result(getattr(block, "content", None))
    return n


async def _safe_aclose(stream) -> None:
    """Close the response async-iterator if it was left partway (deadline/result break)."""
    aclose = getattr(stream, "aclose", None)
    if aclose is None:
        return
    try:
        await aclose()
    except Exception:
        pass


class WarmSessionManager:
    """Registry of per-case warm sessions with a hard live-count cap + reaper."""

    def __init__(self, client_factory=None, max_sessions=None, idle_ttl=None) -> None:
        self._factory = client_factory or _default_client_factory
        self._max = max_sessions if max_sessions is not None else _max_sessions()
        self._idle_ttl = idle_ttl if idle_ttl is not None else _idle_ttl_seconds()
        self._sessions: dict[str, WarmSession] = {}
        self._lock: asyncio.Lock | None = None

    def _guard(self) -> asyncio.Lock:
        """Lazily bind the lock to the running loop (created on first async use)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def live_count(self) -> int:
        return len(self._sessions)

    async def get(self, case_slug: str) -> WarmSession:
        """Return the live warm session for the case, creating + connecting one
        if needed. Enforces the cap (LRU-evict on overflow) before creating."""
        async with self._guard():
            existing = self._sessions.get(case_slug)
            if existing is not None and existing.is_reusable:
                existing.last_used = time.monotonic()
                return existing
            if existing is not None:
                self._sessions.pop(case_slug, None)  # closed → drop
            while len(self._sessions) >= self._max:
                await self._evict_lru()
            session = WarmSession(case_slug, self._factory(case_slug))
            self._sessions[case_slug] = session
        await session.ensure_connected()
        session.last_used = time.monotonic()
        return session

    async def _evict_lru(self) -> None:
        """Close the least-recently-used session to free a slot."""
        victim = min(self._sessions.values(), key=lambda s: s.last_used)
        await victim.close()
        self._sessions.pop(victim.case_slug, None)

    async def reap(self, idle_ttl: float | None = None) -> list[str]:
        """Close sessions idle longer than the TTL. Returns the reaped case slugs."""
        ttl = self._idle_ttl if idle_ttl is None else idle_ttl
        now = time.monotonic()
        stale = [s for s in self._sessions.values() if now - s.last_used > ttl]
        for session in stale:
            await session.close()
            self._sessions.pop(session.case_slug, None)
        return [s.case_slug for s in stale]

    async def kill(self, case_slug: str) -> bool:
        """Force-close one session. Returns True if a session was killed."""
        session = self._sessions.pop(case_slug, None)
        if session is None:
            return False
        await session.close()
        return True

    async def restart(self, case_slug: str) -> WarmSession:
        """Kill a wedged session and bring up a fresh one for the same case."""
        await self.kill(case_slug)
        return await self.get(case_slug)

    async def close_all(self) -> None:
        for session in list(self._sessions.values()):
            await session.close()
        self._sessions.clear()


# --------------------------------------------------------------------------
# Default (production) client factory — mirrors the cold _run_agent contract.
# Not exercised by the unit test (which injects a fake); imported lazily so this
# module stays cheap to import and free of a circular dep on investigator.py.
# --------------------------------------------------------------------------

def _sdk_mcp_servers(inv) -> dict:
    """Convert kipi's runtime MCP config file into the SDK mcp_servers dict."""
    config_path = inv._build_mcp_config()
    raw = json.loads(Path(config_path).read_text()).get("mcpServers", {})
    servers: dict[str, dict] = {}
    for name, spec in raw.items():
        spec = dict(spec)
        if "type" not in spec:
            spec["type"] = "stdio" if "command" in spec else "http"
        servers[name] = spec
    return servers


def _warm_bounded() -> bool:
    """Warm sessions dig DEEP by default (chase the network freely, 4_points parity) —
    the leads-first/one-hop cage was the regression. Depth is the agent's OWN judgment:
    it runs to natural completion (recursive-completeness doctrine + the max-turns
    backstop), NOT a wall-clock deadline — a real dig is never killed mid-investigation
    (founder: no more deadlines). A trivial question still ends fast on its own.
    KIPI_WARM_DEEP=0 is the explicit re-cage."""
    return os.environ.get("KIPI_WARM_DEEP", "").strip().lower() in ("0", "false", "no")


def _warm_tool_budget() -> int:
    """Tool-call circuit-breaker for a warm turn (default 150; a live deep dig runs ~30-60
    tool calls). This is kipi's equivalent of 4_points' 50-call PreToolUse breaker — but
    injected through ClaudeAgentOptions, because the warm agent runs with setting_sources=[]
    and never loads repo hooks (the reason backfilling .claude/rules can't leash it). It is a
    runaway backstop, NOT the control: a normal dig concludes well under it, and on the cap
    the agent is told to emit findings + surface unreached entities as leads (graceful, never
    a hard kill — founder: 'budget the scope, never kill mid-investigation').
    KIPI_WARM_TOOL_BUDGET=0 disables it."""
    try:
        return max(0, int(os.environ.get("KIPI_WARM_TOOL_BUDGET", "150")))
    except ValueError:
        return 150


def _warm_scope_kwargs(case_slug: str) -> dict:
    """The bound-related ClaudeAgentOptions kwargs for a warm case session: the persona and,
    when bounded with a non-empty roster, the SAME PreToolUse scope hook the cold path uses
    (wired through `settings=`, the SDK's `--settings` equivalent) plus its roster env var.

    can_use_tool is deliberately NOT used: the SDK only invokes it when a permission rule
    evaluates to "ask", and the warm path runs under bypassPermissions where it never fires.
    The PreToolUse hook fires regardless of permission mode — same mechanism, live-verified
    on the cold path. Returns {system_prompt, settings, env} to merge into the options.

    A tool-call BUDGET circuit-breaker (_warm_tool_budget) is attached on EVERY path —
    bounded or deep — because the warm agent loads no repo hooks (setting_sources=[]), so
    this injected PreToolUse hook is the only deterministic leash that reaches it.

    Pure + side-effect-light (writes temp files only when a hook is attached) so it's
    unit-testable without constructing a real SDK client."""
    from investigations.agent import investigator as inv
    env = dict(inv._agent_key_env())
    budget = _warm_tool_budget()

    def _budget_only(persona):
        """Deep/unbounded run: no scope cage, but still a tool-budget breaker."""
        if budget > 0:
            settings_path, budget_path = inv._build_budget_settings(budget)
            env["KIPI_BUDGET_FILE"] = budget_path
            return {"system_prompt": persona, "settings": settings_path, "env": env}
        return {"system_prompt": persona, "settings": None, "env": env}

    if not _warm_bounded():
        return _budget_only(inv.CASE_PERSONA)
    roster = inv._case_bound_roster_for_slug(case_slug)
    if not roster:
        # Nothing to bound to yet (no entities extracted) — run unbounded, like cold.
        return _budget_only(inv.CASE_PERSONA)
    # Bounded: scope hook AND budget hook together (the cold bounded launch's full guard set).
    settings_path, roster_path, budget_path = inv._build_guard_settings(
        roster, tool_budget=budget or None)
    env["KIPI_SCOPE_ROSTER"] = roster_path
    if budget_path:
        env["KIPI_BUDGET_FILE"] = budget_path
    return {"system_prompt": inv.CASE_PERSONA_BOUNDED, "settings": settings_path, "env": env}


def _default_client_factory(case_slug: str):
    """Build a real ClaudeSDKClient configured like the cold path (same MCP, tools, model,
    persona, keys, strict config) AND with the cold default's leads-first scope bound
    (RULE-112) via _warm_scope_kwargs — so warm has the same bound cold does."""
    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
    from investigations.agent import investigator as inv
    from investigations.agent import graph_tools

    scope = _warm_scope_kwargs(case_slug)
    # Give the warm agent the graph operations as in-process tools (prd-chat-graph-tools)
    # so it can act on the graph mid-burst, not just collect. Case-bound.
    servers = dict(_sdk_mcp_servers(inv))
    servers["kipi-graph"] = graph_tools.build_graph_server(case_slug)
    options = ClaudeAgentOptions(
        mcp_servers=servers,
        allowed_tools=inv._live_allowed_tools() + graph_tools.GRAPH_TOOL_NAMES,
        disallowed_tools=["Write", "Edit", "NotebookEdit"],
        permission_mode="bypassPermissions",
        model=inv._safe_model(None),
        system_prompt=scope["system_prompt"],
        cwd=str(inv.ROOT),
        env=scope["env"],
        strict_mcp_config=True,
        setting_sources=[],
        settings=scope["settings"],
        # Turn-COUNT ceiling is now the PRIMARY backstop: the chat path runs an
        # investigation with NO wall-clock deadline (founder: no more deadlines), so this
        # is what guarantees a wedged turn still terminates. Generous so it never re-cages
        # a real deep dig; tune via KIPI_WARM_MAX_TURNS.
        max_turns=_warm_max_turns(),
    )
    return ClaudeSDKClient(options=options)


def _warm_max_turns() -> int:
    """Generous turn-count safety ceiling for a warm turn (default 80; a live deep dig
    runs ~30). Bounds runaway loops without re-caging depth. KIPI_WARM_MAX_TURNS overrides."""
    try:
        return max(1, int(os.environ.get("KIPI_WARM_MAX_TURNS", "80")))
    except ValueError:
        return 80


_DEFAULT_MANAGER: WarmSessionManager | None = None


def default_manager() -> WarmSessionManager:
    """Process-wide warm manager singleton (used by the webapp run loop in 4pa-02)."""
    global _DEFAULT_MANAGER
    if _DEFAULT_MANAGER is None:
        _DEFAULT_MANAGER = WarmSessionManager()
    return _DEFAULT_MANAGER


class RedirectBox:
    """Thread-safe one-slot mailbox for a mid-burst redirect: the webapp request
    thread drops the analyst's new instruction in via set(); the warm loop polls it
    out via take() on its next slice tick. Latest-wins (a second redirect before the
    first is taken supersedes it) — the analyst's most recent steer is the live one."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._text: str | None = None

    def set(self, text: str) -> None:
        with self._lock:
            self._text = text

    def take(self) -> str | None:
        with self._lock:
            text, self._text = self._text, None
        return text


async def run_turn_warm(case_slug: str, task: str, deadline: float | None = None,
                        on_step=None, cancel=None, redirect=None) -> dict:
    """One warm turn for a case via the default manager (async — runs ON the warm
    loop). Sync callers must go through run_turn_on_warm_loop, never asyncio.run.
    `deadline` bounds the turn in-stream and returns partial+capped on cutoff.
    `on_step` streams each new step; `cancel` (threading.Event) stops cooperatively;
    `redirect` (RedirectBox) injects a new instruction into the live turn."""
    session = await default_manager().get(case_slug)
    return await session.ask(task, deadline=deadline, on_step=on_step,
                             cancel=cancel, redirect=redirect)


class _CancelWatcher:
    """Cancel the in-flight warm future when the analyst's Stop event fires —
    parity with the cold path's cancel handling."""

    def __init__(self, future, cancel_event) -> None:
        self._future = future
        self._cancel = cancel_event
        self._done = threading.Event()
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self) -> None:
        while not self._done.is_set():
            if self._cancel.wait(0.5):
                self._future.cancel()
                return

    def stop(self) -> None:
        self._done.set()


class _WarmLoop:
    """One background asyncio loop in a daemon thread that OWNS every warm session.

    asyncio.run() per turn opens AND closes a fresh loop each call, orphaning the
    ClaudeSDKClient connected on the previous loop — warmth lost, plus 'got Future
    attached to a different loop' errors. A single persistent loop keeps the client
    connected across turns, which is the whole point (the warmth 4pa-00 measured)."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._start_lock = threading.Lock()

    def _ensure_running(self) -> asyncio.AbstractEventLoop:
        # The stored loop is the singleton once created — do NOT re-check is_running()
        # (a loop whose thread has started but not yet entered run_forever would look
        # not-running and a concurrent caller would spawn a SECOND loop). Codex P2.
        if self._loop is not None:
            return self._loop
        with self._start_lock:
            if self._loop is not None:
                return self._loop
            loop = asyncio.new_event_loop()
            started = threading.Event()
            threading.Thread(
                target=self._run_forever, args=(loop, started),
                name="kipi-warm-loop", daemon=True,
            ).start()
            started.wait()  # barrier: don't hand out the loop until it's running
            self._loop = loop
            return loop

    @staticmethod
    def _run_forever(loop: asyncio.AbstractEventLoop, started: threading.Event) -> None:
        asyncio.set_event_loop(loop)
        loop.call_soon(started.set)
        loop.run_forever()

    def submit(self, coro, timeout: float | None = None, cancel=None):
        """Run a coroutine on the warm loop from a SYNC caller, return its result.
        timeout + cancel give the warm path the cold path's safety."""
        loop = self._ensure_running()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        watcher = _CancelWatcher(future, cancel) if cancel is not None else None
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise TimeoutError(f"warm turn exceeded {timeout}s")
        finally:
            if watcher is not None:
                watcher.stop()


_WARM_LOOP = _WarmLoop()


def run_turn_on_warm_loop(case_slug: str, task: str, timeout: float | None = None,
                          cancel=None, on_step=None, redirect=None) -> dict:
    """Sync entry for the warm path: run ONE turn on the persistent warm loop so the
    per-case ClaudeSDKClient stays connected across turns (no cold-restart). This is
    what investigator._run_agent_warm and /api/chat call instead of asyncio.run.

    `timeout` is the turn's IN-STREAM deadline (returns partial+capped on cutoff);
    submit() keeps a +30s backstop in case the coroutine itself wedges. `cancel`
    (threading.Event) stops the turn COOPERATIVELY inside _collect — the loop polls
    in short slices and re-checks it mid-await, then returns the salvaged partial.
    cancel is deliberately NOT passed to submit(): a hard future.cancel() would
    raise out of the await before the cooperative break and lose the partial. The
    +30s submit backstop still guards a truly wedged stream. `on_step` streams each
    new step live. `redirect` (RedirectBox) injects a new instruction INTO the live
    turn — interrupt + re-query on the same session, one continuous turn."""
    backstop = (timeout + 30) if timeout else None
    try:
        return _WARM_LOOP.submit(
            run_turn_warm(case_slug, task, deadline=timeout, on_step=on_step,
                          cancel=cancel, redirect=redirect),
            timeout=backstop,  # no cancel= here — cooperative cancel handles Stop
        )
    except concurrent.futures.CancelledError:
        # Only reachable if some other path cancels the future; no partial to recover.
        return {"ok": False, "stopped": True, "result_text": "", "tools": [],
                "steps": [], "capped": True}


def warm_loop_id() -> int:
    """id() of the persistent warm loop (for the regression guard that proves every
    warm turn runs on the SAME loop)."""
    return id(_WARM_LOOP._ensure_running())
