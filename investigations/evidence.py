"""Point-in-time evidence artifacts (PRD evidence-artifacts, issue ea-1).

A finding's raw provider response is the proof behind a graph node — but a scam
domain's WHOIS record / page / API response is gone the day after takedown, and
the graph keeps an edge whose evidence no longer resolves. This module captures
that raw response AT COLLECTION TIME, keyed to the entity it grounds, with a
capture timestamp, so the evidence outlives the live source.

Two capture points at different fidelity (see the PRD): the enrich-runner path
captures each result's FULL raw_json; the agent path captures the distilled
finding dict in land_findings. Both call capture_artifact.
"""
from __future__ import annotations

import hashlib
import json

# A single artifact's content is capped so one pathological provider response
# can't bloat the DB. The raw_json the DB already stores is adapter-bounded; this
# is a belt, not a budget.
_MAX_CONTENT = 200_000


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()


def _normalize(content) -> str:
    """Coerce any content (dict/list/str) to a stable string. dicts/lists are
    JSON-serialized with sorted keys so the hash is order-stable."""
    if isinstance(content, (dict, list)):
        return json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)
    return str(content if content is not None else "")


def capture_artifact(conn, entity_id: int, kind: str, content,
                     *, run_id: int | None = None, source_url: str | None = None) -> int | None:
    """Persist one evidence artifact for `entity_id`. Idempotent on
    (entity_id, content_hash) — re-capturing the same response is a no-op.
    Returns the row id (new or existing), or None when there's nothing to store.
    Never raises on a normal write: callers hook this into hot paths and a capture
    failure must never block enrichment/promotion (callers still wrap defensively)."""
    if not entity_id:
        return None
    text = _normalize(content)
    if not text.strip():
        return None
    if len(text) > _MAX_CONTENT:
        text = text[:_MAX_CONTENT] + "\n…[truncated]"
    h = _hash(text)
    existing = conn.execute(
        "SELECT id FROM evidence_artifacts WHERE entity_id = ? AND content_hash = ?",
        (entity_id, h)).fetchone()
    if existing:
        return existing["id"]
    cur = conn.execute(
        "INSERT INTO evidence_artifacts (entity_id, run_id, kind, source_url, "
        " content, content_hash) VALUES (?, ?, ?, ?, ?, ?)",
        (entity_id, run_id, kind, source_url, text, h))
    return cur.lastrowid


def artifacts_for_entity(conn, entity_id: int, limit: int = 50) -> list[dict]:
    """The captured artifacts for an entity, newest-first."""
    rows = conn.execute(
        "SELECT id, entity_id, run_id, kind, source_url, content, captured_at "
        "FROM evidence_artifacts WHERE entity_id = ? "
        "ORDER BY captured_at DESC, id DESC LIMIT ?", (entity_id, limit)).fetchall()
    return [dict(r) for r in rows]
