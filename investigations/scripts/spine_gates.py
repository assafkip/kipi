#!/usr/bin/env python3
"""Spine bypass gates — the permanent re-proof that no choke-point is bypassed.

One gate per spine choke-point (prd-spine-architecture-2026-06-11). Each phase
PRD APPENDS its bypass checks here; nothing is ever removed. /wiring-check runs
this script as part of its definition-of-done, so "end-to-end" is re-verified
at every phase close and on demand — not promised once at ship time.

Exit codes: 0 = every gate green, 1 = at least one gate red (named on stderr).
"""

import os
import subprocess
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))


def run(cmd):
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                          shell=isinstance(cmd, str), timeout=600)


GATES = [
    # --- Phase 0 (prd-spine-phase0-2026-06-11) ---
    ("guard-actor-scope: feature+bypass suite",
     [".venv/bin/python3", "-m", "pytest",
      "q-system/.q-system/tests/test_token_guard.py", "-q"]),
    ("guard-actor-scope: PostToolUse Bash matcher wired",
     ["python3", "-c",
      "import json; hooks=json.load(open('.claude/settings.json'))['hooks']"
      "['PostToolUse']; assert any('Bash' in h.get('matcher','') for h in hooks)"]),
    ("spec-conformance: constants pinned to spec",
     [".venv/bin/python3", "-m", "pytest",
      "investigations/tests/test_spec_conformance.py", "-q"]),
    ("graph-cosmetics: zero provisional residue",
     "! grep -qi provisional investigations/webapp/templates/graph.html "
     "investigations/webapp/templates/_chat.html"),
    ("graph-cosmetics: zero addProvisional anywhere",
     "! grep -rqi addProvisional investigations/ --exclude=spine_gates.py"),
    ("graph-cosmetics: fcose present + feature-checked",
     "grep -q fcose investigations/webapp/templates/graph.html && "
     "grep -q fcoseOk investigations/webapp/templates/graph.html"),
    # --- Phase 1 (prd-spine-phase1-2026-06-11) ---
    ("one-write-path: bypass greps + allowlist state + frozen db surface",
     [".venv/bin/python3", "-m", "pytest",
      "investigations/tests/test_one_write_path.py", "-q"]),
    ("one-write-path: store feature contract",
     [".venv/bin/python3", "-m", "pytest",
      "investigations/tests/test_store.py", "-q"]),
    # --- Phase 2 (prd-spine-phase2-2026-06-12) ---
    ("typed-transforms: declarations + recipe consistency + runner gate",
     [".venv/bin/python3", "-m", "pytest",
      "investigations/tests/test_typed_transforms.py", "-q"]),
    # --- Phase 3 (prd-spine-phase3-2026-06-12) ---
    ("projection: replay idempotence + purity + genesis",
     [".venv/bin/python3", "-m", "pytest",
      "investigations/tests/test_projection_replay.py", "-q"]),
]


def main():
    failures = []
    for name, cmd in GATES:
        result = run(cmd)
        status = "green" if result.returncode == 0 else "RED"
        print(f"[{status}] {name}")
        if result.returncode != 0:
            tail = (result.stdout + result.stderr).strip().splitlines()[-8:]
            failures.append((name, "\n".join(tail)))
    if failures:
        for name, tail in failures:
            print(f"\nGATE RED: {name}\n{tail}", file=sys.stderr)
        sys.exit(1)
    print(f"\nall {len(GATES)} spine gates green")


if __name__ == "__main__":
    main()
