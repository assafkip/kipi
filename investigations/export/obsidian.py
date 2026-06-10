"""Export SQLite knowledge graph to an Obsidian vault.
One MD per entity. Wikilinks for relationships. Frontmatter for graph view tags.
Image filenames are namespaced by report_id (e.g. r0001_page_001_img_00.png)
so different reports don't overwrite each other's images in vault/assets/."""
import re
import shutil
from pathlib import Path
from collections import defaultdict


SAFE_FILENAME_RE = re.compile(r"[^\w\s.-]+")


def _safe_filename(name: str) -> str:
    n = SAFE_FILENAME_RE.sub("", name).strip().replace(" ", "_")
    return n[:120] or "unnamed"


def _wikilink(name: str) -> str:
    return f"[[{name}]]"


def _vault_image_name(report_id: int, file_path: str) -> str:
    return f"r{report_id:04d}_{Path(file_path).name}"


def export(conn, vault_dir: Path, assets_root: Path | None = None) -> dict:
    vault_dir.mkdir(parents=True, exist_ok=True)
    entities_dir = vault_dir / "entities"
    reports_dir = vault_dir / "reports"
    sources_dir = vault_dir / "sources"
    vault_assets_dir = vault_dir / "assets"
    entities_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)
    sources_dir.mkdir(exist_ok=True)
    vault_assets_dir.mkdir(exist_ok=True)

    entities = conn.execute(
        "SELECT id, canonical_name, entity_type, notes FROM entities"
    ).fetchall()
    reports = conn.execute(
        "SELECT id, title, source_path, source_type, investigation, ingested_at FROM reports"
    ).fetchall()

    mentions_by_entity = defaultdict(list)
    mention_rows = conn.execute(
        "SELECT m.entity_id, m.surface_form, m.context, "
        "r.id AS report_id, r.title AS report_title "
        "FROM mentions m JOIN reports r ON m.report_id = r.id"
    ).fetchall()
    for m in mention_rows:
        mentions_by_entity[m["entity_id"]].append(dict(m))

    rels_by_entity = defaultdict(list)
    rel_rows = conn.execute(
        "SELECT rel.src_entity_id, rel.dst_entity_id, rel.rel_type, rel.evidence, "
        "es.canonical_name AS src_name, ed.canonical_name AS dst_name, "
        "r.title AS report_title "
        "FROM relationships rel "
        "JOIN entities es ON es.id = rel.src_entity_id "
        "JOIN entities ed ON ed.id = rel.dst_entity_id "
        "LEFT JOIN reports r ON r.id = rel.report_id"
    ).fetchall()
    for r in rel_rows:
        rels_by_entity[r["src_entity_id"]].append(dict(r))
        rels_by_entity[r["dst_entity_id"]].append(dict(r))

    aliases_by_entity = defaultdict(list)
    for a in conn.execute("SELECT entity_id, alias FROM aliases").fetchall():
        aliases_by_entity[a["entity_id"]].append(a["alias"])

    count_entity = 0
    for e in entities:
        path = entities_dir / f"{_safe_filename(e['canonical_name'])}.md"
        path.write_text(_render_entity_md(
            e, mentions_by_entity[e["id"]], rels_by_entity[e["id"]],
            aliases_by_entity[e["id"]],
        ), encoding="utf-8")
        count_entity += 1

    count_report = 0
    count_assets = 0
    project_root = assets_root.parent.parent if assets_root else None
    for r in reports:
        path = reports_dir / f"{_safe_filename(r['title'] or str(r['id']))}.md"
        report_entities = conn.execute(
            "SELECT DISTINCT e.canonical_name, e.entity_type "
            "FROM entities e JOIN mentions m ON m.entity_id = e.id "
            "WHERE m.report_id = ?",
            (r["id"],),
        ).fetchall()
        report_assets_rows = conn.execute(
            "SELECT * FROM assets WHERE report_id = ? "
            "ORDER BY page_number, image_index",
            (r["id"],),
        ).fetchall()
        if report_assets_rows and project_root:
            for a in report_assets_rows:
                src = project_root / a["file_path"]
                vault_name = _vault_image_name(r["id"], a["file_path"])
                if src.exists():
                    dst = vault_assets_dir / vault_name
                    if not dst.exists():
                        shutil.copy2(src, dst)
                        count_assets += 1
        path.write_text(
            _render_report_md(r, report_entities, report_assets_rows),
            encoding="utf-8",
        )
        count_report += 1

    count_sources = 0
    asset_rows = conn.execute(
        "SELECT a.id, a.file_path, a.page_number, a.image_index, a.ocr_text, "
        "a.report_id, r.title AS report_title "
        "FROM assets a JOIN reports r ON r.id = a.report_id"
    ).fetchall()
    for a in asset_rows:
        vault_name = _vault_image_name(a["report_id"], a["file_path"])
        source_md_name = f"{vault_name.replace('.', '_')}.md"
        ents = conn.execute(
            "SELECT DISTINCT e.canonical_name, e.entity_type "
            "FROM mentions m JOIN entities e ON e.id = m.entity_id "
            "WHERE m.asset_id = ? ORDER BY e.entity_type, e.canonical_name",
            (a["id"],),
        ).fetchall()
        (sources_dir / source_md_name).write_text(
            _render_source_md(a, ents, vault_name), encoding="utf-8"
        )
        count_sources += 1

    (vault_dir / "_index.md").write_text(
        _render_index(entities, reports), encoding="utf-8"
    )

    return {"entities_written": count_entity, "reports_written": count_report,
            "sources_written": count_sources,
            "assets_copied": count_assets, "vault": str(vault_dir)}


def _render_source_md(asset, entities, vault_image_name: str) -> str:
    lines = [
        "---",
        f"type: source_image",
        f"page: {asset['page_number']}",
        f"image_index: {asset['image_index']}",
        f"tags: [source, image, page-{asset['page_number']}]",
        "---\n",
        f"# Image: {vault_image_name}\n",
        f"From {_wikilink(asset['report_title'] or 'unknown report')}, "
        f"page {asset['page_number']}\n",
        f"![[{vault_image_name}]]\n",
    ]
    if asset["ocr_text"]:
        lines.append("## OCR text\n")
        lines.append(f"> {asset['ocr_text']}\n")
    if entities:
        lines.append(f"## Entities in this image ({len(entities)})\n")
        by_type: dict[str, list[str]] = {}
        for e in entities:
            by_type.setdefault(e["entity_type"], []).append(e["canonical_name"])
        for t, names in sorted(by_type.items()):
            lines.append(f"### {t}")
            for n in sorted(names):
                lines.append(f"- {_wikilink(n)}")
            lines.append("")
    return "\n".join(lines) + "\n"


def _render_entity_md(entity, mentions: list[dict], rels: list[dict],
                      aliases: list[str]) -> str:
    lines = [
        "---",
        f"name: {entity['canonical_name']}",
        f"type: {entity['entity_type']}",
        f"tags: [entity, {entity['entity_type']}]",
    ]
    if aliases:
        lines.append(f"aliases: {aliases}")
    lines.append("---\n")
    lines.append(f"# {entity['canonical_name']}\n")
    lines.append(f"**Type:** {entity['entity_type']}")

    if aliases:
        lines.append("\n## Aliases")
        for alias in aliases:
            lines.append(f"- {alias}")

    if entity["notes"]:
        lines.append("\n## Notes")
        lines.append(entity["notes"])

    if mentions:
        lines.append(f"\n## Mentions ({len(mentions)})")
        seen_reports = set()
        for m in mentions:
            if m["report_id"] in seen_reports:
                continue
            seen_reports.add(m["report_id"])
            lines.append(
                f"\n### In {_wikilink(m['report_title'] or f'report-{m['report_id']}')}"
            )
            lines.append(f"> {m['context']}")

    if rels:
        lines.append(f"\n## Connections ({len(rels)})")
        seen_pairs = set()
        for r in rels:
            other = (r["dst_name"] if r["src_entity_id"] == entity["id"]
                     else r["src_name"])
            key = (other, r["rel_type"])
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            ev = f" — _{r['evidence']}_" if r["evidence"] else ""
            ctx = (f" (in {_wikilink(r['report_title'])})"
                   if r["report_title"] else "")
            lines.append(f"- {r['rel_type']} → {_wikilink(other)}{ev}{ctx}")

    return "\n".join(lines) + "\n"


def _render_report_md(report, entities, assets=None) -> str:
    lines = [
        "---",
        f"title: {report['title'] or 'Untitled'}",
        f"source: {report['source_path']}",
        f"type: report",
        f"source_type: {report['source_type']}",
        f"tags: [report, {report['source_type']}]",
    ]
    if report["investigation"]:
        lines.append(f"investigation: {report['investigation']}")
    lines.append(f"ingested_at: {report['ingested_at']}")
    lines.append("---\n")
    lines.append(f"# {report['title'] or f'Report {report['id']}'}\n")
    lines.append(f"**Source:** `{report['source_path']}`")
    lines.append(f"**Ingested:** {report['ingested_at']}\n")
    if entities:
        lines.append(f"## Entities ({len(entities)})\n")
        by_type: dict[str, list[str]] = {}
        for e in entities:
            by_type.setdefault(e["entity_type"], []).append(e["canonical_name"])
        for t, names in sorted(by_type.items()):
            lines.append(f"### {t}")
            for n in sorted(names):
                lines.append(f"- {_wikilink(n)}")
            lines.append("")
    if assets:
        lines.append(f"## Source images ({len(assets)})\n")
        by_page: dict[int, list] = {}
        for a in assets:
            by_page.setdefault(a["page_number"] or 0, []).append(a)
        for page in sorted(by_page):
            lines.append(f"### Page {page}\n")
            for a in by_page[page]:
                img_name = _vault_image_name(report["id"], a["file_path"])
                lines.append(f"![[{img_name}]]")
                if a["ocr_text"]:
                    lines.append(f"> {a['ocr_text'][:300]}")
                lines.append("")
    return "\n".join(lines) + "\n"


def _render_index(entities, reports) -> str:
    lines = [
        "---",
        "title: Investigation Index",
        "tags: [index]",
        "---\n",
        "# Investigation Index\n",
        f"## Reports ({len(reports)})\n",
    ]
    for r in reports:
        lines.append(f"- {_wikilink(r['title'] or f'Report {r['id']}')}")
    lines.append(f"\n## Entities by type\n")
    by_type: dict[str, list[str]] = {}
    for e in entities:
        by_type.setdefault(e["entity_type"], []).append(e["canonical_name"])
    for t, names in sorted(by_type.items()):
        lines.append(f"### {t} ({len(names)})")
        for n in sorted(names):
            lines.append(f"- {_wikilink(n)}")
        lines.append("")
    return "\n".join(lines) + "\n"
