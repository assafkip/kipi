"""PRD-12 guard: the runtime must carry NO single-machine assumptions.

A hardcoded user-home path (`CLAUDE_BIN = "/Users/<name>/.local/bin/claude"`)
broke the tool the instant it left this Mac — invisible until Docker. This test greps
the shipped runtime and FAILS on any hardcoded `/Users/<name>` or `/home/<name>` literal,
so the next one can't sneak in and only surface at distribution time.

Run: .venv/bin/python -m investigations.tests.test_portability
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "investigations"

# Absolute home-dir literals. `/Users/<name>` (Mac), `/home/<name>` (Linux). The trailing
# char class avoids matching a bare `/Users` token; we want a real per-user path.
_HOME_PATH = re.compile(r'["\'](?:/Users|/home)/[A-Za-z0-9._-]+/')

# Runtime only. Tests legitimately reference paths; dev-only scripts aren't shipped.
_EXCLUDE_DIRS = {"tests", "__pycache__", "data", "vault", "assets", "reports", "inbox"}


def _runtime_files():
    for path in PKG.rglob("*.py"):
        if any(part in _EXCLUDE_DIRS for part in path.relative_to(PKG).parts):
            continue
        yield path


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_no_hardcoded_home_paths():
    offenders = []
    for path in _runtime_files():
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if _HOME_PATH.search(line):
                rel = path.relative_to(ROOT)
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    _check(
        "no hardcoded /Users/<name> or /home/<name> in runtime\n     "
        + "\n     ".join(offenders),
        not offenders,
    )


def test_claude_bin_has_no_personal_fallback():
    # The specific bug this PRD came from: the CLAUDE_BIN fallback was a personal path.
    src = (PKG / "llm" / "client.py").read_text()
    _check("CLAUDE_BIN fallback is not a /Users/ literal",
           "/Users/" not in src.split("CLAUDE_BIN", 1)[1].split("\n\n", 1)[0])


def test_guard_actually_fires():
    # Prove the regex catches a violation — a guard that never fails is theater.
    bad = 'CLAUDE_BIN = "/Users/someone/.local/bin/claude"'
    _check("regex catches a planted /Users/ literal", bool(_HOME_PATH.search(bad)))
    _check("regex ignores a clean ROOT-relative path",
           not _HOME_PATH.search('DB_PATH = ROOT / "data" / "x.db"'))


def main():
    test_no_hardcoded_home_paths()
    test_claude_bin_has_no_personal_fallback()
    test_guard_actually_fires()
    print("\nPASS: test_portability")


if __name__ == "__main__":
    main()
