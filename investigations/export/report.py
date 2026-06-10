"""Analyst-readable report export. Markdown summary of all ingested reports."""
from pathlib import Path


def export(conn, out_path: Path) -> Path:
    reports = conn.execute(
        "SELECT id, title, source_path, source_type, investigation, ingested_at "
        "FROM reports ORDER BY ingested_at"
    ).fetchall()
    lines = ["# Investigation Summary\n"]
    for r in reports:
        entity_count = conn.execute(
            "SELECT COUNT(DISTINCT entity_id) AS n FROM mentions WHERE report_id = ?",
            (r["id"],),
        ).fetchone()["n"]
        lines.append(f"## {r['title'] or f'Report {r['id']}'}")
        lines.append(f"- Source: `{r['source_path']}`")
        lines.append(f"- Type: {r['source_type']}")
        if r["investigation"]:
            lines.append(f"- Investigation: {r['investigation']}")
        lines.append(f"- Ingested: {r['ingested_at']}")
        lines.append(f"- Entities extracted: {entity_count}\n")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
