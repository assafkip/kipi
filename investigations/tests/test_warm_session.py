"""4pa-01 — warm session manager: boot-once + lifecycle safety.

Deterministic + offline: a fake ClaudeSDKClient (counts connects/disconnects,
records queries) is injected, so the test proves the MANAGER's contract without
an API call. The SDK's actual warmth across turns was proven live by 4pa-00
(q-system/output/rca/warm_spike.py, boot_count==1).

Asserts:
  (a) boot_count == 1 across 2 turns on one warm session (and reuse stays warm).
  (b) lifecycle: idle reaper closes a stale session, kill/restart recovers,
      and the KIPI_MAX_AGENTS cap is enforced (LRU-evict, no zombie leak).
"""
import asyncio
import time

from investigations.agent.warm_session import WarmSessionManager, warm_session_enabled


class _Text:
    def __init__(self, text):
        self.text = text


class _Assistant:
    def __init__(self, blocks):
        self.content = blocks


class _Result:
    is_result = True
    content = []


class FakeClient:
    """Stand-in for ClaudeSDKClient: counts boots, records turns, no network."""

    def __init__(self, case_slug):
        self.case_slug = case_slug
        self.connect_count = 0
        self.disconnect_count = 0
        self.queries = []
        self.connected = False

    async def connect(self):
        await asyncio.sleep(0)  # yield so concurrent first-access can interleave
        self.connect_count += 1
        self.connected = True

    async def query(self, prompt, session_id="default"):
        self.queries.append(prompt)

    async def receive_response(self):
        yield _Assistant([_Text("ok")])
        yield _Result()

    async def disconnect(self):
        self.disconnect_count += 1
        self.connected = False


class FakeFactory:
    def __init__(self):
        self.created = {}

    def __call__(self, case_slug):
        client = FakeClient(case_slug)
        self.created.setdefault(case_slug, []).append(client)
        return client


async def _assert_boot_once():
    factory = FakeFactory()
    manager = WarmSessionManager(client_factory=factory, max_sessions=4)

    session = await manager.get("case-x")
    first = await session.ask("turn 1: dns_lookup example.com")
    second = await session.ask("turn 2: dns_lookup iana.org")

    client = factory.created["case-x"][0]
    assert session.boot_count == 1, f"expected 1 boot across turns, got {session.boot_count}"
    assert client.connect_count == 1, f"client connected {client.connect_count}x, want 1"
    assert len(client.queries) == 2, f"expected 2 turns, got {len(client.queries)}"
    assert first["result_text"] == "ok" and second["result_text"] == "ok", "turn output lost"

    # Reuse: getting the same case returns the SAME warm session, still 1 boot.
    again = await manager.get("case-x")
    assert again is session, "manager created a new session instead of reusing the warm one"
    assert again.boot_count == 1, "reuse re-booted the session"
    await manager.close_all()


async def _assert_idle_reaper():
    factory = FakeFactory()
    manager = WarmSessionManager(client_factory=factory, max_sessions=4)
    session = await manager.get("case-stale")
    await session.ask("warm it up")
    client = factory.created["case-stale"][0]

    session.last_used = time.monotonic() - 1000  # backdate so it reads as idle
    reaped = await manager.reap(idle_ttl=10)

    assert reaped == ["case-stale"], f"idle session not reaped: {reaped}"
    assert manager.live_count == 0, "reaped session still registered (leak)"
    assert client.disconnect_count == 1, "reaper did not disconnect the client (zombie)"


async def _assert_kill_restart():
    factory = FakeFactory()
    manager = WarmSessionManager(client_factory=factory, max_sessions=4)
    first = await manager.get("case-wedged")
    await first.ask("do work")
    first_client = factory.created["case-wedged"][0]

    killed = await manager.kill("case-wedged")
    assert killed and first_client.disconnect_count == 1, "kill did not close the client"
    assert manager.live_count == 0, "killed session still registered"

    fresh = await manager.restart("case-wedged")
    assert fresh is not first, "restart returned the dead session"
    assert fresh.is_alive and fresh.boot_count == 1, "restarted session not freshly booted"
    assert len(factory.created["case-wedged"]) == 2, "restart did not build a new client"
    await manager.close_all()


async def _assert_cap_enforced():
    factory = FakeFactory()
    manager = WarmSessionManager(client_factory=factory, max_sessions=2)

    await manager.get("case-a")
    await manager.get("case-b")
    await manager.get("case-c")  # third over a cap of 2 → LRU (case-a) evicted

    assert manager.live_count == 2, f"cap breached: {manager.live_count} live (max 2)"
    a_client = factory.created["case-a"][0]
    assert a_client.disconnect_count == 1, "LRU eviction did not disconnect (zombie leak)"
    assert "case-a" not in {s.case_slug for s in manager._sessions.values()}, "LRU not evicted"
    await manager.close_all()


async def _assert_concurrent_first_access():
    # Codex 4pa-01 P2: two concurrent first-access turns for the SAME new case
    # must share ONE session/ONE client/ONE boot — never orphan a connecting one.
    factory = FakeFactory()
    manager = WarmSessionManager(client_factory=factory, max_sessions=4)
    first, second = await asyncio.gather(
        manager.get("case-race"), manager.get("case-race")
    )
    assert first is second, "concurrent first access created two sessions for one case"
    assert manager.live_count == 1, f"expected 1 live session, got {manager.live_count}"
    assert len(factory.created["case-race"]) == 1, "a second client was built (leak)"
    assert first.boot_count == 1, f"expected 1 boot, got {first.boot_count}"
    assert factory.created["case-race"][0].connect_count == 1, "client connected twice"
    await manager.close_all()


class _ToolUse:
    def __init__(self, name, inp, block_id):
        self.name, self.input, self.id = name, inp, block_id


class _SlowClient:
    """Yields one tool step, then hangs past the deadline (never emits a result)."""
    def __init__(self, case_slug):
        self.case_slug = case_slug
        self.connect_count = self.disconnect_count = self.interrupt_count = 0

    async def connect(self): self.connect_count += 1
    async def query(self, prompt, session_id="default"): pass

    async def receive_response(self):
        yield _Assistant([_ToolUse("mcp__kipi-osint__dns_lookup", {"domain": "x.com"}, "t1")])
        await asyncio.sleep(5)   # hang — the deadline must cut in here
        yield _Result()

    async def interrupt(self): self.interrupt_count += 1
    async def disconnect(self): self.disconnect_count += 1


class _NoResultClient:
    """Yields a tool step + text, then the stream ENDS with no result message — exactly
    what the SDK does when the max-turns backstop cuts the agent off mid-work."""
    def __init__(self, case_slug):
        self.case_slug = case_slug
        self.connect_count = self.disconnect_count = self.interrupt_count = 0

    async def connect(self): self.connect_count += 1
    async def query(self, prompt, session_id="default"): pass

    async def receive_response(self):
        yield _Assistant([_ToolUse("mcp__kipi-osint__dns_lookup", {"domain": "x.com"}, "t1")])
        yield _Assistant([_Text("working…")])
        # no _Result — stream just ends (StopAsyncIteration), like a max-turns cutoff

    async def interrupt(self): self.interrupt_count += 1
    async def disconnect(self): self.disconnect_count += 1


def test_turn_limit_capped_when_stream_ends_without_result():
    """A run that ends with no final result message (the max-turns backstop firing) must
    be flagged capped + cap_reason='turn_limit' — never reported as a clean finish, so the
    chat can tell the analyst it hit the limit (founder directive). NO deadline here: this
    is a count cutoff, not a time cutoff."""
    async def _go():
        mgr = WarmSessionManager(client_factory=lambda c: _NoResultClient(c), max_sessions=2)
        session = await mgr.get("case-tl")
        result = await session.ask("investigate deeply", deadline=None)
        await mgr.close_all()
        return result
    result = asyncio.run(_go())
    assert result["capped"] is True, f"a no-result (turn-limit) run must be capped: {result}"
    assert result["cap_reason"] == "turn_limit", \
        f"expected cap_reason='turn_limit', got {result.get('cap_reason')!r}"
    # the partial step trail still survives for salvage
    assert any(s.get("type") == "tool" for s in result["steps"]), "lost the partial trail"


async def _assert_capped_run_salvages_steps():
    # The live-found gap: a cut-off warm turn must return the PARTIAL step trail with
    # capped=True (so investigate_entity salvages), not lose everything.
    mgr = WarmSessionManager(client_factory=lambda c: _SlowClient(c), max_sessions=2)
    session = await mgr.get("case-cap")
    result = await session.ask("investigate deeply", deadline=0.2)
    assert result["capped"] is True, "a cut-off turn must report capped=True"
    tool_steps = [s for s in result["steps"] if s.get("type") == "tool"]
    assert tool_steps and tool_steps[0]["tool"] == "dns_lookup", \
        f"capped turn lost its step trail: {result['steps']}"
    await mgr.close_all()


def _assert_warm_scope_bound():
    """4pa-bound — the warm client inherits the cold default's leads-first scope bound
    (RULE-112): bounded persona + the SAME PreToolUse scope hook (via settings=) when a
    roster exists; unbounded under KIPI_WARM_DEEP=1; unbounded when the case has no roster.
    Monkeypatches the roster lookup so it's offline + DB-free."""
    import os
    from investigations.agent import warm_session as ws
    from investigations.agent import investigator as inv

    orig = inv._case_bound_roster_for_slug
    orig_deep = os.environ.get("KIPI_WARM_DEEP")
    try:
        # bounded + non-empty roster → bounded persona + scope hook wired
        inv._case_bound_roster_for_slug = lambda slug: ["trumpstake.us", "support@trumpstake.us"]
        os.environ.pop("KIPI_WARM_DEEP", None)
        kw = ws._warm_scope_kwargs("case-x")
        assert kw["system_prompt"] is inv.CASE_PERSONA_BOUNDED, "bounded run must use the bounded persona"
        assert kw["settings"] and os.path.exists(kw["settings"]), "bounded run must write a settings file"
        assert "scope_hook.py" in open(kw["settings"]).read(), "settings must wire the scope hook"
        assert "trumpstake.us" in open(kw["env"]["KIPI_SCOPE_ROSTER"]).read(), "roster file must hold the entities"
        print("  ok  warm bounded → bounded persona + scope hook + roster env")

        # KIPI_WARM_DEEP=1 → unbounded (deep parity): plain persona, no settings
        os.environ["KIPI_WARM_DEEP"] = "1"
        kw = ws._warm_scope_kwargs("case-x")
        assert kw["system_prompt"] is inv.CASE_PERSONA and kw["settings"] is None, "deep warm must be unbounded"
        assert "KIPI_SCOPE_ROSTER" not in kw["env"], "deep warm must not set a roster"
        print("  ok  KIPI_WARM_DEEP=1 → unbounded (plain persona, no hook)")

        # bounded but empty roster → unbounded (nothing to bound to yet)
        os.environ.pop("KIPI_WARM_DEEP", None)
        inv._case_bound_roster_for_slug = lambda slug: []
        kw = ws._warm_scope_kwargs("case-empty")
        assert kw["system_prompt"] is inv.CASE_PERSONA and kw["settings"] is None, "empty roster → unbounded"
        print("  ok  empty roster → unbounded (no false bound)")
    finally:
        inv._case_bound_roster_for_slug = orig
        if orig_deep is None:
            os.environ.pop("KIPI_WARM_DEEP", None)
        else:
            os.environ["KIPI_WARM_DEEP"] = orig_deep


class _GappyClient:
    """Yields msg1, THINKS longer than one poll slice, then yields msg2 + result.

    Reproduces the live-smoke bug: _collect used asyncio.wait_for(stream.__anext__())
    which CANCELS the pending __anext__ on every slice timeout, corrupting the real
    SDK iterator so the turn died after the first >1s thinking gap (1 message, then
    empty). A correct _collect keeps the same __anext__ task alive across slices and
    collects BOTH messages."""
    def __init__(self, case_slug, gap):
        self.case_slug = case_slug
        self.gap = gap
        self.connect_count = self.disconnect_count = self.interrupt_count = 0

    async def connect(self): self.connect_count += 1
    async def query(self, prompt, session_id="default"): pass

    async def receive_response(self):
        yield _Assistant([_Text("part1")])
        await asyncio.sleep(self.gap)   # thinking gap > one poll slice
        yield _Assistant([_Text("part2")])
        yield _Result()

    async def interrupt(self): self.interrupt_count += 1
    async def disconnect(self): self.disconnect_count += 1


async def _assert_survives_thinking_gap():
    # A thinking gap LONGER than a poll slice (slice is 1.0s) but shorter than the
    # deadline must NOT end the turn. Old code cancelled the __anext__ on the slice
    # timeout and lost everything after part1.
    mgr = WarmSessionManager(client_factory=lambda c: _GappyClient(c, gap=1.3), max_sessions=2)
    session = await mgr.get("case-gap")
    result = await session.ask("investigate", deadline=10)
    assert result["capped"] is False, f"a within-deadline turn must not be capped: {result}"
    assert result["result_text"] == "part1\npart2", \
        f"thinking gap dropped messages — got {result['result_text']!r}"
    await mgr.close_all()


class _RedirectClient:
    """Segment 1 runs a dns tool then THINKS (so the analyst can steer mid-burst);
    segment 2 (after the re-query) runs a whois tool. Lets the test prove a redirect
    interrupts the live burst and continues the SAME turn with the new direction."""
    def __init__(self, case_slug, gap):
        self.case_slug = case_slug
        self.gap = gap
        self.connect_count = self.disconnect_count = self.interrupt_count = 0
        self.queries = []
        self._seg = 0

    async def connect(self): self.connect_count += 1
    async def query(self, prompt, session_id="default"): self.queries.append(prompt)
    async def interrupt(self): self.interrupt_count += 1

    async def receive_response(self):
        self._seg += 1
        if self._seg == 1:
            yield _Assistant([_ToolUse("mcp__kipi-osint__dns_lookup", {"domain": "x.com"}, "t1")])
            await asyncio.sleep(self.gap)   # live burst — analyst redirects during this gap
            yield _Assistant([_Text("dns done")])
            yield _Result()
        else:
            yield _Assistant([_ToolUse("mcp__kipi-osint__whois", {"domain": "y.com"}, "t2")])
            yield _Assistant([_Text("whois done")])
            yield _Result()

    async def disconnect(self): self.disconnect_count += 1


async def _assert_redirect_continues_turn():
    from investigations.agent.warm_session import RedirectBox
    captured = {}
    def factory(slug):
        c = _RedirectClient(slug, gap=2.0)
        captured["client"] = c
        return c
    mgr = WarmSessionManager(client_factory=factory, max_sessions=2)
    session = await mgr.get("case-redir")
    box = RedirectBox()

    async def steer():
        await asyncio.sleep(0.3)        # let segment 1 start its burst
        box.set("now run whois instead")
    asyncio.ensure_future(steer())

    result = await session.ask("investigate x.com", deadline=10, redirect=box)
    client = captured["client"]
    tool_names = [s["tool"] for s in result["steps"] if s.get("type") == "tool"]
    kinds = [s.get("type") for s in result["steps"]]

    assert result["capped"] is False, f"a redirected (not stopped) turn must complete: {result}"
    assert result["redirected"] is True, "result must flag that a redirect happened"
    assert "dns_lookup" in tool_names and "whois" in tool_names, \
        f"trail must hold BOTH pre- and post-redirect tool steps: {tool_names}"
    assert "redirect" in kinds, f"the analyst's steer must appear in the trail: {kinds}"
    assert client.interrupt_count >= 1, "redirect must interrupt the live segment"
    assert client.queries == ["investigate x.com", "now run whois instead"], \
        f"re-query on the same session expected: {client.queries}"
    await mgr.close_all()


def main():
    # Flag helper is a clean boolean (off unless explicitly enabled).
    assert warm_session_enabled() in (True, False), "flag helper must return a bool"
    _assert_warm_scope_bound()

    async def _scenario():
        await _assert_boot_once()
        await _assert_idle_reaper()
        await _assert_kill_restart()
        await _assert_cap_enforced()
        await _assert_concurrent_first_access()
        await _assert_capped_run_salvages_steps()
        await _assert_survives_thinking_gap()
        await _assert_redirect_continues_turn()

    asyncio.run(_scenario())
    print("PASS test_warm_session: boot_count==1 across turns + reuse warm; idle reaper, "
          "kill/restart, cap enforced; cut-off turn salvages its step trail (no zombie leak); "
          "turn survives a thinking gap longer than a poll slice; mid-burst redirect "
          "interrupts + continues the same turn")


if __name__ == "__main__":
    main()
