"""The .env loader: the tool's API key comes from a gitignored repo-root .env, not the
user's global shell — so the Claude Code terminal stays on Max while the tool keeps the
key (RULE-110). Asserts: loads KEY=val (export/quotes tolerated), an explicit env var
wins, and a missing file is a no-op.

Run: .venv/bin/python -m investigations.tests.test_env_loader
"""
import os
import tempfile
from pathlib import Path

import investigations as inv


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _restore_env(saved: dict) -> None:
    """Put the real environment back. These tests clobber ANTHROPIC_API_KEY; without
    restoring the original value they'd strip the live key for every later test in the
    suite (test_llm_api ran key-less and failed). Save-then-restore, not pop."""
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_loads_from_env_file():
    saved = {k: os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "FOO")}
    try:
        with tempfile.TemporaryDirectory() as d:
            envf = Path(d) / ".env"
            envf.write_text('# a comment\nexport ANTHROPIC_API_KEY="sk-test-123"\nFOO=bar\n\n')
            os.environ.pop("ANTHROPIC_API_KEY", None)
            os.environ.pop("FOO", None)
            applied = inv.load_dotenv(envf)
            _check("applied both keys", applied == 2)
            _check("ANTHROPIC_API_KEY loaded (export + quotes stripped)",
                   os.environ.get("ANTHROPIC_API_KEY") == "sk-test-123")
            _check("plain KEY=val loaded", os.environ.get("FOO") == "bar")
    finally:
        _restore_env(saved)


def test_dotenv_overrides_injected_env():
    # .env wins over a stale/injected inherited value (Claude Code injects its own
    # ANTHROPIC_API_KEY into the bash subprocess; the old "never override" made the tool
    # use that 401 key instead of the valid .env one). 2026-06-06.
    saved = {"ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY")}
    try:
        with tempfile.TemporaryDirectory() as d:
            envf = Path(d) / ".env"
            envf.write_text("ANTHROPIC_API_KEY=from-dotenv\n")
            os.environ["ANTHROPIC_API_KEY"] = "injected-stale-key"
            inv.load_dotenv(envf)
            _check("a key present in .env overrides the inherited env",
                   os.environ["ANTHROPIC_API_KEY"] == "from-dotenv")
    finally:
        _restore_env(saved)


def test_missing_file_is_noop():
    _check("missing .env returns 0", inv.load_dotenv(Path("/nonexistent/does-not.env")) == 0)


def main():
    test_loads_from_env_file()
    test_dotenv_overrides_injected_env()
    test_missing_file_is_noop()
    print("PASS test_env_loader: tool key loads from .env, explicit env wins, missing is no-op")


if __name__ == "__main__":
    main()
