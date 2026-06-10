"""Assemble a branded, client-ready report for one case.

Pulls case-scoped findings (exec summary, top actors, dossiers, IOCs, cross-case
links, provenance) into a dict the report template renders into a print-ready,
branded HTML document. Everything is scoped to a single investigation.
"""
from __future__ import annotations

import re
from pathlib import Path

from investigations import focus as focus_mod
from investigations import annotations as annotations_mod

IOC_TYPES = ("ip", "domain", "email", "crypto_wallet", "phone", "url", "telegram_channel")


def _strip_frontmatter(md: str) -> str:
    if md.startswith("---"):
        parts = md.split("---", 2)
        if len(parts) == 3:
            return parts[2].lstrip("\n")
    return md


def _exec_summary(vault_dir: Path, case: str) -> str:
    f = vault_dir / f"synthesis-{case}.md"
    if f.exists():
        return _strip_frontmatter(f.read_text(encoding="utf-8"))
    return ""


def _top_actors(conn, case: str, limit: int = 12) -> list[dict]:
    try:
        actors = focus_mod._gather_top(conn, limit, case=case)
    except Exception:
        return []
    # Don't leak OTHER cases' slugs into a client-facing actor bio. The gated
    # Cross-Case section is where intentional cross-case disclosure happens.
    for a in actors:
        a["investigations"] = []
        a["why"] = focus_mod._build_why(a)
    return actors


def _dossier_matches(content: str, name: str) -> bool:
    # Anchored to the frontmatter line, so '@al' doesn't match '@alice'.
    return any(line.strip() == f"name: {name}" for line in content.splitlines()[:8])


def _dossiers(conn, vault_dir: Path, actors: list[dict], limit: int = 6) -> list[dict]:
    out = []
    profiles_dir = vault_dir / "profiles"
    for a in actors[:limit]:
        ann = annotations_mod.get(conn, a["entity_id"])
        body = ann.get("dossier_override") or ""
        source = "analyst" if body else "ai"
        if not body and profiles_dir.exists():
            for p in profiles_dir.glob("*.md"):
                content = p.read_text(encoding="utf-8")
                if _dossier_matches(content, a["name"]):
                    body = _strip_frontmatter(content)
                    break
        if body or ann.get("notes"):
            out.append({"name": a["name"], "role": a["role"], "sub_role": a.get("sub_role"),
                        "body": body, "notes": ann.get("notes") or "", "source": source})
    return out


def _iocs(conn, case: str, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        "SELECT e.canonical_name, e.entity_type, COUNT(DISTINCT m.report_id) AS reports "
        "FROM entities e JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id "
        f"WHERE r.investigation = ? AND e.entity_type IN ({','.join('?' for _ in IOC_TYPES)}) "
        "AND (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
        "GROUP BY e.id ORDER BY e.entity_type, reports DESC LIMIT ?",
        (case, *IOC_TYPES, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _cross_case(conn, case: str) -> list[dict]:
    rows = conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.notes, "
        "GROUP_CONCAT(DISTINCT r.investigation) AS cases "
        "FROM entities e JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation IS NOT NULL "
        "AND e.id IN (SELECT m2.entity_id FROM mentions m2 JOIN reports r2 ON r2.id = m2.report_id "
        "             WHERE r2.investigation = ?) "
        "GROUP BY e.id HAVING COUNT(DISTINCT r.investigation) >= 2",
        (case,),
    ).fetchall()
    from investigations.alerts import is_pivotable  # shared noise rule
    out = []
    for r in rows:
        if is_pivotable(r["canonical_name"], r["entity_type"], r["notes"]):
            others = [c for c in (r["cases"] or "").split(",") if c and c != case]
            if others:
                out.append({"name": r["canonical_name"], "type": r["entity_type"],
                            "also_in": sorted(others)})
    return out


def gather(conn, vault_dir: Path, case: str) -> dict:
    inv = conn.execute(
        "SELECT slug, client, case_name, status FROM investigations WHERE slug = ?",
        (case,)).fetchone()
    reports = [dict(r) for r in conn.execute(
        "SELECT title, source_type, ingested_at FROM reports WHERE investigation = ? "
        "ORDER BY ingested_at", (case,)).fetchall()]
    stats = {
        "reports": len(reports),
        "entities": conn.execute(
            "SELECT COUNT(DISTINCT m.entity_id) AS n FROM mentions m JOIN reports r "
            "ON r.id = m.report_id WHERE r.investigation = ?", (case,)).fetchone()["n"],
    }
    actors = _top_actors(conn, case)
    return {
        "case": dict(inv) if inv else {"slug": case, "case_name": case, "client": None},
        "reports": reports,
        "stats": stats,
        "exec_summary": _exec_summary(vault_dir, case),
        "top_actors": actors,
        "dossiers": _dossiers(conn, vault_dir, actors),
        "iocs": _iocs(conn, case),
        "cross_case": _cross_case(conn, case),
    }
