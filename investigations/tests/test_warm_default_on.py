"""The chat IS the investigator by default (issue warm-default-on).

Asserts warm is on and deep is uncaged when no env is set, and that the explicit
opt-out / re-cage levers still work. This guards against silently reverting to the
router (warm off) or the one-hop cage (deep off).
"""
from investigations.agent import warm_session as ws
from investigations.agent import investigator as inv


def _clear(monkeypatch):
    monkeypatch.delenv("KIPI_WARM_SESSION", raising=False)
    monkeypatch.delenv("KIPI_WARM_DEEP", raising=False)


def test_warm_on_by_default(monkeypatch):
    _clear(monkeypatch)
    assert ws.warm_session_enabled() is True
    # investigator.warm_run_available() reflects the same flip (the chat router uses it).
    assert inv.warm_run_available() is True


def test_deep_uncaged_by_default(monkeypatch):
    _clear(monkeypatch)
    assert ws._warm_bounded() is False  # not leads-first/one-hop


def test_explicit_optout_restores_router(monkeypatch):
    _clear(monkeypatch)
    for off in ("0", "false", "no", "off"):
        monkeypatch.setenv("KIPI_WARM_SESSION", off)
        assert ws.warm_session_enabled() is False
        assert inv.warm_run_available() is False


def test_explicit_recage_bounds_depth(monkeypatch):
    _clear(monkeypatch)
    for off in ("0", "false", "no"):
        monkeypatch.setenv("KIPI_WARM_DEEP", off)
        assert ws._warm_bounded() is True


def test_arbitrary_values_keep_warm_on(monkeypatch):
    """Any non-off value (incl. unexpected ones) keeps warm ON — opt-OUT semantics."""
    _clear(monkeypatch)
    for on in ("1", "true", "yes", "on", "anything"):
        monkeypatch.setenv("KIPI_WARM_SESSION", on)
        assert ws.warm_session_enabled() is True


def test_warm_has_turn_count_safety_ceiling(monkeypatch):
    """Warm default-on dropped the cold max_turns; a generous turn ceiling bounds runaway
    loops without re-caging depth (Codex review). Deadline is still the primary bound."""
    _clear(monkeypatch)
    monkeypatch.delenv("KIPI_WARM_MAX_TURNS", raising=False)
    assert ws._warm_max_turns() == 80           # generous default (a deep dig runs ~30)
    monkeypatch.setenv("KIPI_WARM_MAX_TURNS", "120")
    assert ws._warm_max_turns() == 120
    monkeypatch.setenv("KIPI_WARM_MAX_TURNS", "garbage")
    assert ws._warm_max_turns() == 80           # bad value -> safe default


def test_turn_deadline_is_the_cost_bound(monkeypatch):
    """Cost is bounded by the turn deadline, not a per-turn tool cap: run_turn_on_warm_loop
    passes the timeout through as the in-stream deadline (Codex finding-1)."""
    _clear(monkeypatch)
    captured = {}

    def _fake_submit(coro, timeout=None, cancel=None):
        captured["backstop"] = timeout
        coro.close()  # don't actually run the coroutine
        return {"ok": True, "result_text": "", "steps": [], "tools": [], "capped": False}

    monkeypatch.setattr(ws._WARM_LOOP, "submit", _fake_submit)
    ws.run_turn_on_warm_loop("case-x", "hi", timeout=120)
    # The deadline is threaded through (submit backstop = timeout + 30); proves the cost
    # bound is applied on the default path.
    assert captured["backstop"] == 150
