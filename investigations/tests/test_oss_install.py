"""One-command install story (issue oss-install-story, PRD oss-release-readiness).

Asserts: install.sh exists, is executable, syntactically valid, idempotent in
shape (no destructive commands), and free of founder-machine paths; and —
the finding-1 contract — requirements.txt covers EVERY third-party module the
codebase imports (a fresh clone that finishes install.sh must not die on a
missing import at serve or ingest time).

Run: .venv/bin/python3 -m pytest investigations/tests/test_oss_install.py -q
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "install.sh"
REQS = ROOT / "requirements.txt"

# import name -> requirements.txt distribution name (where they differ)
_IMPORT_TO_DIST = {
    "PIL": "pillow",
    "community": "python-louvain",
    "dns": "dnspython",
    "claude_agent_sdk": "claude-agent-sdk",
    "multipart": "python-multipart",
}

# Imports wrapped in their own try/ImportError fallback chain — the code works
# without them (ingest/pdf.py: fitz → pdfplumber → pypdf → pdftotext), so the
# manifest deliberately does not require them. fitz (PyMuPDF, AGPL) was
# SWAPPED for pypdfium2 2026-06-10; its guarded import in ingest/pdf.py is a
# user-optional accelerator, never a requirement.
_OPTIONAL_FALLBACKS = {"pypdf", "fitz"}


def _third_party_imports() -> set[str]:
    """Every top-level third-party module imported anywhere under
    investigations/ (module-level AND lazy in-function imports). AST-based so
    prose in docstrings that happens to start with 'from ...' doesn't count."""
    import ast
    stdlib = set(sys.stdlib_module_names)
    mods: set[str] = set()
    for py in (ROOT / "investigations").rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names = [node.module.split(".")[0]]
            else:
                continue
            for m in names:
                if m not in stdlib and m != "investigations":
                    mods.add(m)
    return mods


def test_requirements_cover_every_third_party_import():
    # Parse actual requirement LINES (comments don't count — 'pytesseract' in a
    # prose comment must not satisfy a coverage check).
    req_names = set()
    for line in REQS.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        req_names.add(re.split(r"[<>=!\[ ]", line, maxsplit=1)[0].lower())
    missing = []
    for mod in sorted(_third_party_imports() - _OPTIONAL_FALLBACKS):
        dist = _IMPORT_TO_DIST.get(mod, mod).lower()
        if dist not in req_names:
            missing.append(f"{mod} (dist: {dist})")
    assert missing == [], f"imports with no requirements.txt entry: {missing}"


def test_requirements_modules_importable_in_this_venv():
    # The manifest must not be aspirational: everything it names imports here.
    for mod in sorted(_third_party_imports() - _OPTIONAL_FALLBACKS):
        __import__(mod)


def test_install_sh_exists_executable_and_valid():
    assert INSTALL.is_file()
    assert INSTALL.stat().st_mode & 0o111, "install.sh must be executable"
    subprocess.run(["bash", "-n", str(INSTALL)], check=True)


def test_install_sh_has_no_founder_machine_paths():
    text = INSTALL.read_text()
    for bad in ("assafkip", "threat-intel-agent", "/Users/", "~/.config"):
        assert bad not in text, f"founder-machine path {bad!r} in install.sh"


def test_install_sh_is_nondestructive_and_idempotent_in_shape():
    text = INSTALL.read_text()
    assert "set -euo pipefail" in text
    for bad in ("rm -rf", "git clean", "reset --hard", "DROP TABLE"):
        assert bad not in text, f"destructive command {bad!r} in install.sh"
    # venv creation is guarded AND self-heals a partial venv (missing pip);
    # init is the idempotent path.
    assert 'if [ ! -d .venv ] || [ ! -x .venv/bin/pip ]' in text
    assert "./invctl init" in text


def test_install_sh_checks_agent_runtime_degraded_not_fatal():
    text = INSTALL.read_text()
    # The investigator agent needs the claude CLI (+ node for MCP); a clean
    # machine without them must get a WARNING, not a hard failure.
    assert "command -v claude" in text
    assert "command -v npx" in text
    assert "claude-code" in text   # the install hint


def test_install_sh_names_the_one_required_key():
    text = INSTALL.read_text()
    assert "ANTHROPIC_API_KEY" in text
    assert "OPTIONAL" in text or "optional" in text   # the degradation promise
