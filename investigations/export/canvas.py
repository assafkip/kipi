"""FAANG-grade Obsidian Canvas exporter.

Uses:
  - clusters as visual group rectangles
  - typed relationships as labeled edges, colored by confidence
  - node size weighted by threat_score
  - role-based node colors
  - drops noise + URL variants
  - skips low-score entities (default top 25 per cluster)

Output: vault/graph.canvas — the OSINT-analyst default view.
Also writes vault/graph_iocs.canvas and vault/diff_latest_report.canvas.
"""
import json
from collections import defaultdict
from pathlib import Path


THUMB_W = 200
THUMB_H = 150
NODE_W = 230
NODE_MIN_H = 70
NODE_MAX_H = 110
GROUP_PAD = 60
CLUSTER_GAP = 100

DEFAULT_EXCLUDE_TYPES = {"person_candidate"}

ROLE_COLOR = {
    "operator": "2",
    "channel":  "5",
    "ioc":      "1",
    "infra":    "4",
    "source":   "6",
}

CONFIDENCE_COLOR = {
    "high":   "4",
    "medium": "5",
    "low":    "6",
}

CONFIDENCE_LABEL = {
    "high":   "",
    "medium": "?",
    "low":    "??",
}


def _vault_image_name(report_id: int, file_path: str) -> str:
    return f"r{report_id:04d}_{Path(file_path).name}"


def _entity_role(notes: str | None) -> str:
    if not notes:
        return ""
    return (notes or "").split(" — ")[0].replace("role:", "").strip()


def export(conn, vault_dir: Path, canvas_path: Path | None = None,
           min_threat_score: float = 30.0,
           include_clusters: bool = True,
           include_isolated_high_score: bool = True) -> Path:
    if canvas_path is None:
        canvas_path = vault_dir / "graph.canvas"

    cluster_rows = conn.execute(
        "SELECT id, name, kind, description FROM clusters ORDER BY id"
    ).fetchall()

    cluster_members: dict[int, list[int]] = defaultdict(list)
    member_to_clusters: dict[int, list[int]] = defaultdict(list)
    for r in conn.execute("SELECT cluster_id, entity_id FROM cluster_members").fetchall():
        cluster_members[r["cluster_id"]].append(r["entity_id"])
        member_to_clusters[r["entity_id"]].append(r["cluster_id"])

    scores = {r["entity_id"]: dict(r) for r in conn.execute(
        "SELECT * FROM entity_scores"
    ).fetchall()}

    entities = {r["id"]: dict(r) for r in conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.notes "
        "FROM entities e"
    ).fetchall()}

    typed_rels = [dict(r) for r in conn.execute(
        "SELECT * FROM typed_relationships WHERE COALESCE(status,'active') = 'active'"
    ).fetchall()]

    eligible_ids: set[int] = set()
    for eid, e in entities.items():
        role = _entity_role(e["notes"])
        if role in ("noise", "source", ""):
            continue
        if e["entity_type"] in DEFAULT_EXCLUDE_TYPES:
            continue
        score = scores.get(eid, {}).get("threat_score", 0)
        if eid in member_to_clusters:
            eligible_ids.add(eid)
        elif include_isolated_high_score and score >= min_threat_score:
            eligible_ids.add(eid)

    nodes: list[dict] = []
    edges: list[dict] = []
    node_id_for: dict[int, str] = {}

    cluster_col_x = 0
    cluster_row_y = 0
    cluster_max_h = 0
    max_canvas_width = 2400

    sorted_clusters = sorted(
        cluster_rows,
        key=lambda c: -sum(scores.get(eid, {}).get("threat_score", 0)
                           for eid in cluster_members[c["id"]] if eid in eligible_ids)
    )

    for c in sorted_clusters:
        members = [eid for eid in cluster_members[c["id"]] if eid in eligible_ids]
        if not members:
            continue
        members.sort(key=lambda e: -scores.get(e, {}).get("threat_score", 0))

        inner_x = cluster_col_x + GROUP_PAD
        inner_y = cluster_row_y + GROUP_PAD + 40
        rows_in_col = (len(members) + 1) // 2
        node_height = _node_height_for_members(members, scores)
        col_width = (NODE_W + 40) * 2 + GROUP_PAD * 2
        col_height = rows_in_col * (node_height + 15) + GROUP_PAD * 2 + 60

        for idx, eid in enumerate(members):
            row = idx // 2
            col = idx % 2
            e = entities[eid]
            role = _entity_role(e["notes"])
            score_data = scores.get(eid, {})
            score = score_data.get("threat_score", 0)
            report_count = score_data.get("report_count", 0)
            degree = score_data.get("degree", 0)

            nx = inner_x + col * (NODE_W + 40)
            ny = inner_y + row * (node_height + 15)

            nodes.append({
                "id": f"ent_{eid}",
                "type": "text",
                "text": (f"**{e['canonical_name']}**\n"
                         f"_{role} · score {int(score)} · {report_count}r / deg {degree}_"),
                "x": nx,
                "y": ny,
                "width": NODE_W,
                "height": node_height,
                "color": ROLE_COLOR.get(role, "6"),
            })
            node_id_for[eid] = f"ent_{eid}"

        nodes.append({
            "id": f"cluster_{c['id']}",
            "type": "group",
            "label": f"{c['name']} ({len(members)})",
            "x": cluster_col_x,
            "y": cluster_row_y,
            "width": col_width,
            "height": col_height,
            "color": _cluster_color(c["kind"]),
        })

        if (cluster_col_x + col_width) >= max_canvas_width:
            cluster_col_x = 0
            cluster_row_y += cluster_max_h + CLUSTER_GAP
            cluster_max_h = 0
        else:
            cluster_col_x += col_width + CLUSTER_GAP
        cluster_max_h = max(cluster_max_h, col_height)

    for t in typed_rels:
        sid, did = t["src_entity_id"], t["dst_entity_id"]
        if sid not in node_id_for or did not in node_id_for:
            continue
        conf = t["confidence"] or "medium"
        label = t["rel_type"]
        if t["confidence"] != "high":
            label = f"{label} ({CONFIDENCE_LABEL.get(conf, '?')})"
        edges.append({
            "id": f"trel_{sid}_{did}_{t['rel_type']}",
            "fromNode": node_id_for[sid],
            "fromSide": "right",
            "toNode": node_id_for[did],
            "toSide": "left",
            "label": label,
            "color": CONFIDENCE_COLOR.get(conf, "6"),
        })

    canvas_data = {"nodes": nodes, "edges": edges}
    canvas_path.write_text(json.dumps(canvas_data, indent=2), encoding="utf-8")
    return canvas_path


def _cluster_color(kind: str | None) -> str:
    return {
        "crew":               "2",
        "cohort":             "1",
        "infrastructure_block": "4",
        "venue":              "5",
    }.get(kind or "", "6")


def _node_height_for_members(members: list[int], scores: dict) -> int:
    if not members:
        return NODE_MIN_H
    top = max(scores.get(m, {}).get("threat_score", 0) for m in members)
    if top >= 70:
        return NODE_MAX_H
    if top >= 50:
        return 85
    return NODE_MIN_H


def export_iocs(conn, vault_dir: Path) -> Path:
    """IoC-focused canvas: only ioc + infra entities, grouped by infrastructure cluster."""
    out = vault_dir / "graph_iocs.canvas"
    nodes: list[dict] = []
    edges: list[dict] = []
    node_id_for: dict[int, str] = {}

    clusters = conn.execute(
        "SELECT c.id, c.name, c.kind FROM clusters c "
        "WHERE c.kind IN ('infrastructure_block', 'cohort') ORDER BY c.id"
    ).fetchall()

    col_x = 0
    col_y = 0
    for c in clusters:
        members = [r["entity_id"] for r in conn.execute(
            "SELECT cm.entity_id FROM cluster_members cm "
            "JOIN entities e ON e.id = cm.entity_id "
            "WHERE cm.cluster_id = ? AND e.entity_type IN ('ip', 'crypto_wallet', 'domain', 'url')",
            (c["id"],),
        ).fetchall()]
        if not members:
            continue

        col_height = len(members) * 70 + 100
        nodes.append({
            "id": f"gp_{c['id']}",
            "type": "group",
            "label": f"{c['name']}",
            "x": col_x,
            "y": col_y,
            "width": 320,
            "height": col_height,
            "color": "1",
        })
        for i, eid in enumerate(members):
            e = conn.execute(
                "SELECT id, canonical_name, entity_type FROM entities WHERE id = ?",
                (eid,),
            ).fetchone()
            if not e:
                continue
            links = conn.execute(
                "SELECT label, url FROM enrichment_links WHERE entity_id = ? LIMIT 3",
                (eid,),
            ).fetchall()
            link_md = "\n".join(f"[{l['label']}]({l['url']})" for l in links)
            nodes.append({
                "id": f"ioc_{eid}",
                "type": "text",
                "text": f"**{e['canonical_name']}**\n_{e['entity_type']}_\n{link_md}",
                "x": col_x + 40,
                "y": col_y + 60 + i * 70,
                "width": 250,
                "height": 60,
                "color": "1",
            })
            node_id_for[eid] = f"ioc_{eid}"

        col_x += 360
        if col_x > 2000:
            col_x = 0
            col_y += col_height + 60

    canvas_data = {"nodes": nodes, "edges": edges}
    out.write_text(json.dumps(canvas_data, indent=2), encoding="utf-8")
    return out


def export_diff(conn, vault_dir: Path) -> Path:
    """Show entities first seen in the most recently ingested report."""
    out = vault_dir / "diff_latest_report.canvas"
    last_report = conn.execute(
        "SELECT id, title FROM reports ORDER BY ingested_at DESC LIMIT 1"
    ).fetchone()
    if not last_report:
        out.write_text(json.dumps({"nodes": [], "edges": []}, indent=2))
        return out

    new_entities = conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.notes, s.threat_score "
        "FROM entities e "
        "LEFT JOIN entity_scores s ON s.entity_id = e.id "
        "WHERE e.first_seen_report_id = ? "
        "AND (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
        "ORDER BY s.threat_score DESC NULLS LAST",
        (last_report["id"],),
    ).fetchall()

    nodes = [{
        "id": "title",
        "type": "text",
        "text": (f"# NEW in {last_report['title']}\n"
                 f"_{len(new_entities)} entities first seen here_"),
        "x": 0,
        "y": -120,
        "width": 600,
        "height": 80,
    }]
    edges: list[dict] = []
    per_row = 4
    for i, e in enumerate(new_entities[:60]):
        role = _entity_role(e["notes"])
        col = i % per_row
        row = i // per_row
        nodes.append({
            "id": f"new_{e['id']}",
            "type": "text",
            "text": f"**{e['canonical_name']}**\n_{role or e['entity_type']}_",
            "x": col * (NODE_W + 30),
            "y": row * 90,
            "width": NODE_W,
            "height": NODE_MIN_H,
            "color": ROLE_COLOR.get(role, "6"),
        })
    out.write_text(json.dumps({"nodes": nodes, "edges": edges}, indent=2),
                   encoding="utf-8")
    return out
