"""Markdown ingestion. Strips frontmatter and code fences, keeps prose + linkable content."""
import re
from pathlib import Path

FRONTMATTER_RE = re.compile(r"^---\n.*?\n---\n", re.DOTALL)
CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


def extract_text(path: Path) -> str:
    raw = path.read_text(encoding="utf-8", errors="replace")
    raw = FRONTMATTER_RE.sub("", raw)
    raw = CODE_FENCE_RE.sub("", raw)
    return raw


def extract_title(path: Path) -> str | None:
    raw = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^#\s+(.+)$", raw, re.MULTILINE)
    if m:
        return m.group(1).strip()
    fm = FRONTMATTER_RE.match(raw)
    if fm:
        t = re.search(r"^title:\s*(.+)$", fm.group(0), re.MULTILINE)
        if t:
            return t.group(1).strip().strip("\"'")
    return None
