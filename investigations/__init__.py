"""kipi-investigations package init.

Loads the repo-root `.env` (if present) into the environment on import, so the
tool's API keys — notably ANTHROPIC_API_KEY — live WITH the tool (a gitignored
`.env`) instead of the user's global shell profile.

Why: the tool bills the Anthropic API by design (RULE-110, so it's shareable). If
ANTHROPIC_API_KEY is exported in the global shell, the user's Claude Code terminal
also picks it up and bills the API instead of their Max subscription. Keeping the
key in the tool's `.env` lets the terminal stay on Max while the tool keeps the key.

Contract: a key PRESENT in `.env` wins over the inherited environment. This is
deliberate (changed 2026-06-06): Claude Code injects its OWN `ANTHROPIC_API_KEY`
into the bash-tool subprocess (an artifact, not operator intent), and the old
"never override" rule made the tool + the investigator agent use that injected key
— which 401s — instead of the valid key in `.env`. `.env` is gitignored so it's
absent in Docker; there the recipient's runtime env still wins (nothing to override).
No third-party dependency — just a small, deterministic line parser.
"""
import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent  # repo root (holds .env)


def load_dotenv(env_file: Path | None = None) -> int:
    """Fill os.environ from a `.env` file; a key present in `.env` OVERRIDES the inherited
    environment (Claude Code injects a stale ANTHROPIC_API_KEY into the bash subprocess —
    `.env` must win, or the tool/agent uses the injected 401 key).

    Returns the count of keys applied. Tolerates `export ` prefixes, single/double
    quotes, blank lines, and `#` comments. Missing file is a no-op (returns 0)."""
    path = env_file or (_ROOT / ".env")
    if not path.exists():
        return 0
    applied = 0
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        val = val.strip().strip('"').strip("'")
        if key:  # .env wins — overrides a stale/injected inherited value (e.g. Claude Code's)
            os.environ[key] = val
            applied += 1
    return applied


load_dotenv()
