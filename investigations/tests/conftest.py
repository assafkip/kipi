"""Shared pytest fixtures for the investigations test suite.

Many tests here were written to run two ways: via their own `main()` (which passes a
homemade `_MP` helper with `.setattr()`/`.undo()`), and as pytest tests with a `mp`
parameter. Nothing provided `mp` under pytest, so 65 such tests errored at setup
("fixture 'mp' not found"). pytest's built-in `monkeypatch` has the same interface
(setattr + auto-undo at teardown, plus setenv/delenv), so this bridges the two: under
pytest, `mp` IS monkeypatch; under `main()`, the file's own `_MP` is used.
"""
import pytest


@pytest.fixture
def mp(monkeypatch):
    return monkeypatch
