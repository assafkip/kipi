"""Telegram scrape ingestion. Handles both the existing kipi harvest JSON format
and Telegram's native channel-export JSON format."""
import json
from pathlib import Path


def extract_text(path: Path) -> str:
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw

    msgs: list[str] = []

    if isinstance(data, list):
        for item in data:
            msgs.append(_format_msg(item))
    elif isinstance(data, dict):
        if "messages" in data and isinstance(data["messages"], list):
            channel = data.get("name") or data.get("title") or "unknown_channel"
            msgs.append(f"# Channel: {channel}\n")
            for item in data["messages"]:
                msgs.append(_format_msg(item))
        else:
            msgs.append(_format_msg(data))
    return "\n".join(m for m in msgs if m)


def _format_msg(item) -> str:
    if not isinstance(item, dict):
        return str(item)
    parts = []
    for key in ("date", "from", "from_id", "author", "sender", "username"):
        if key in item and item[key]:
            parts.append(f"{key}={item[key]}")
    text = item.get("text") or item.get("message") or item.get("content") or ""
    if isinstance(text, list):
        text = " ".join(
            (t.get("text", "") if isinstance(t, dict) else str(t)) for t in text
        )
    if parts or text:
        prefix = f"[{' '.join(parts)}] " if parts else ""
        return f"{prefix}{text}".strip()
    return ""
