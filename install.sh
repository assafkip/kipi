#!/usr/bin/env bash
# kipi-investigations — one-command bootstrap (issue oss-install-story).
#
#   git clone <repo> && cd kipi-investigations && ./install.sh
#
# Idempotent: re-running upgrades dependencies and re-checks the environment;
# it never deletes anything. After it finishes:
#
#   export ANTHROPIC_API_KEY=sk-ant-...   # the ONE required key (BYO)
#   ./invctl serve                        # open http://127.0.0.1:8765
#
# Every other provider key (VirusTotal, Apify, Perplexity, Shodan, Censys,
# WhoisXML, ...) is OPTIONAL — the tool belt degrades gracefully without them.
set -euo pipefail

cd "$(dirname "$0")"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; exit 1; }

# --- python3 (>= 3.12: the codebase uses modern union syntax + sqlite features)
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || fail "python3 not found — install Python 3.12+ first"
"$PYTHON" - <<'EOF' || exit 1
import sys
if sys.version_info < (3, 12):
    print(f"FAIL Python {sys.version.split()[0]} is too old — kipi needs 3.12+")
    raise SystemExit(1)
print(f"==> Python {sys.version.split()[0]} OK")
EOF

# --- tesseract (OCR for scanned PDFs / screenshots — degraded, not fatal)
if command -v tesseract >/dev/null 2>&1; then
  say "tesseract $(tesseract --version 2>&1 | head -1 | awk '{print $2}') OK (OCR enabled)"
else
  warn "tesseract not found — scanned-PDF/screenshot OCR will be skipped."
  warn "  macOS:  brew install tesseract tesseract-lang"
  warn "  Debian: sudo apt-get install tesseract-ocr tesseract-ocr-eng"
fi

# --- Claude Code CLI + node (the investigator AGENT path — degraded, not fatal:
#     document -> entities -> graph works on the API alone; the autonomous
#     investigator + chat-led digging need the `claude` CLI, which needs node)
if command -v claude >/dev/null 2>&1; then
  say "claude CLI OK (investigator agent enabled)"
else
  warn "claude CLI not found — the autonomous investigator agent is disabled."
  warn "  install: npm install -g @anthropic-ai/claude-code   (needs node 18+)"
fi
if ! command -v npx >/dev/null 2>&1; then
  warn "node/npx not found — agent MCP tooling needs node 18+ (brew install node / apt install nodejs npm)"
fi

# --- venv + dependencies (self-healing: a partial venv without pip is repaired
#     by re-running venv over it — non-destructive, never deletes)
if [ ! -d .venv ] || [ ! -x .venv/bin/pip ]; then
  say "creating/repairing .venv"
  "$PYTHON" -m venv .venv
fi
say "installing dependencies (requirements.txt)"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

# --- database (idempotent: CREATE IF NOT EXISTS + lazy migrations)
say "initializing the database"
./invctl init >/dev/null 2>&1 || ./invctl init

say "done."
cat <<'EOF'

Next steps (2 of them):

  1. export ANTHROPIC_API_KEY=sk-ant-...     # the one required key
  2. ./invctl serve                           # http://127.0.0.1:8765

Then drop a PDF on the Reports page (or paste notes) and click Process —
the investigated graph builds itself. Optional provider keys can be added
later in the Enrich panel; everything degrades gracefully without them.
EOF
