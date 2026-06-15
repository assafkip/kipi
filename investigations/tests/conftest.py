"""Shared pytest fixtures for the investigations test suite.

Many tests here were written to run two ways: via their own `main()` (which passes a
homemade `_MP` helper with `.setattr()`/`.undo()`), and as pytest tests with a `mp`
parameter. Nothing provided `mp` under pytest, so 65 such tests errored at setup
("fixture 'mp' not found"). pytest's built-in `monkeypatch` has the same interface
(setattr + auto-undo at teardown, plus setenv/delenv), so this bridges the two: under
pytest, `mp` IS monkeypatch; under `main()`, the file's own `_MP` is used.
"""
import os

import pytest


@pytest.fixture
def mp(monkeypatch):
    return monkeypatch


# --- live-test split (prd: oss-ci-marker) -------------------------------------
# A `@pytest.mark.live` test hits the real API / agent / network (bills or needs
# keys). CI and keyless local runs auto-skip them; opt in with `--run-live` or by
# setting ANTHROPIC_API_KEY. This lets CI run `pytest -m "not live"` as the offline gate.
def pytest_addoption(parser):
    parser.addoption("--run-live", action="store_true", default=False,
                     help="run @pytest.mark.live tests (real API/agent/network)")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live: hits the real API/agent/network (bills or needs keys); skipped "
        "unless --run-live is passed or ANTHROPIC_API_KEY is set",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-live") or os.environ.get("ANTHROPIC_API_KEY"):
        return
    skip_live = pytest.mark.skip(reason="live test — pass --run-live or set ANTHROPIC_API_KEY")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)


# --- warm-agent guard (sp1-migrate-agent-writers, 2026-06-11) ------------------
# The warm agent loop is a LIVE surface: an unmarked test that reaches it blocks
# forever on a real session (test_findings hung the whole suite for 16+ minutes —
# the missing-stub class behind the pytest-live-gate lesson). Default every
# offline test to warm-unavailable; a test that NEEDS warm-on either sets it
# itself (the chat suites do) or carries @pytest.mark.live.
# Exemption: test_warm_default_on tests the real availability predicate (offline,
# never calls the agent), so it keeps the unpinned function.
@pytest.fixture(autouse=True)
def _no_warm_agent_by_default(request, monkeypatch):
    if request.node.get_closest_marker("live"):
        return
    if request.node.module.__name__.endswith("test_warm_default_on"):
        return
    from investigations.agent import investigator
    monkeypatch.setattr(investigator, "warm_run_available", lambda: False)
