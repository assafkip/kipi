"""Cross-report relatedness briefs.

When investigators ingest data from multiple cases, the old `synthesize`
output fuses everything into one global brief — which lies about whether
the reports are actually connected.

This module:
  1. Computes pairwise relatedness between every pair of ingested reports
     (Jaccard on entity sets + shared cluster count + time-window overlap)
  2. Groups reports into connected components where pairwise relatedness
     exceeds a threshold (default 0.15 Jaccard OR ≥1 shared cluster)
  3. For each group, emits an analyst brief that EXPLICITLY names:
       - the relatedness verdict (strong / weak / disjoint)
       - the shared cross-report entities
       - the cross-cutting clusters
       - the time window
  4. For singleton / orphan reports, emits a standalone brief that
     explicitly states no significant overlap was found

Outputs:
  vault/briefs/INDEX.md          — pointer to every group + standalone
  vault/briefs/group-{N}.md      — one per related group of reports
  vault/briefs/standalone.md     — orphans (no significant overlap)

CLI: ./invctl briefs [--threshold 0.15] [--no-llm] [--report-id N]
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from investigations.storage import db
from investigations.llm import client as llm


DEFAULT_THRESHOLD = 0.15

# Stoplist — entities so generic that shared occurrence is incidental, not
# evidence of relatedness. These never count toward the Jaccard score.
# Editable list per the PRD's open-question on incidental-entity handling.
INCIDENTAL_NAMES = {
    "t.me", "telegram", "https", "http", "twitter.com", "x.com",
    "youtube.com", "google.com", "facebook.com",
}
INCIDENTAL_TYPE_LOWSIGNAL = {"person_candidate"}  # require role tag to count


SYSTEM = """You are an OSINT analyst writing a brief that ties together a
related set of intel reports. You receive: (1) the reports' titles and
investigation tags, (2) the entities that appear in MULTIPLE of them,
(3) the clusters/crews that span them, (4) the time window.

Write 4-7 sentences. Name the shared theme. Name the 2-3 cross-cutting
actors. Note open questions. No fluff. No "the data suggests" /
"below is" / preamble. Plain text only."""


STANDALONE_SYSTEM = """You are an OSINT analyst noting a standalone report
that did NOT meet the relatedness threshold with any other ingested
report. Write 1-2 sentences naming what the report is about. No fluff."""


# ---------- relatedness math ----------

def _report_entities(conn, report_id: int) -> set[int]:
    """Entity ids appearing in this report, with incidental ones filtered."""
    rows = conn.execute(
        "SELECT DISTINCT e.id, e.canonical_name, e.entity_type, e.notes "
        "FROM mentions m JOIN entities e ON e.id = m.entity_id "
        "WHERE m.report_id = ?",
        (report_id,),
    ).fetchall()
    keep = set()
    for r in rows:
        name = (r["canonical_name"] or "").strip().lower()
        if name in INCIDENTAL_NAMES:
            continue
        if r["entity_type"] in INCIDENTAL_TYPE_LOWSIGNAL and not r["notes"]:
            continue
        if (r["notes"] or "").startswith("role:noise"):
            continue
        keep.add(r["id"])
    return keep


def _report_clusters(conn, report_id: int) -> set[int]:
    rows = conn.execute(
        "SELECT DISTINCT cm.cluster_id FROM mentions m "
        "JOIN cluster_members cm ON cm.entity_id = m.entity_id "
        "WHERE m.report_id = ?",
        (report_id,),
    ).fetchall()
    return {r["cluster_id"] for r in rows}


def _report_meta(conn, report_id: int) -> dict:
    r = conn.execute(
        "SELECT id, title, investigation, ingested_at, source_type FROM reports "
        "WHERE id = ?", (report_id,),
    ).fetchone()
    return dict(r) if r else {}


def relatedness(conn, a_id: int, b_id: int) -> dict:
    """Pairwise relatedness between two reports."""
    a_ents = _report_entities(conn, a_id)
    b_ents = _report_entities(conn, b_id)
    if not a_ents or not b_ents:
        return {"a_id": a_id, "b_id": b_id, "verdict": "disjoint",
                "jaccard": 0.0, "shared_entities": [],
                "shared_clusters": [], "shared_count": 0}
    overlap = a_ents & b_ents
    jaccard = len(overlap) / max(1, len(a_ents | b_ents))
    a_cls = _report_clusters(conn, a_id)
    b_cls = _report_clusters(conn, b_id)
    shared_cls = a_cls & b_cls
    if jaccard >= DEFAULT_THRESHOLD or len(shared_cls) >= 1:
        verdict = "strong"
    elif jaccard >= 0.03:
        verdict = "weak"
    else:
        verdict = "disjoint"
    return {
        "a_id": a_id, "b_id": b_id,
        "verdict": verdict, "jaccard": jaccard,
        "shared_count": len(overlap),
        "shared_entities": sorted(overlap)[:30],
        "shared_clusters": sorted(shared_cls),
    }


def group_reports(conn, threshold: float = DEFAULT_THRESHOLD) -> tuple[list[list[int]], list[dict]]:
    """Returns (groups, edges). Each group is a list of report_ids.
       edges is a list of all pairwise relatedness records (for audit)."""
    report_ids = [r["id"] for r in conn.execute(
        "SELECT id FROM reports ORDER BY id"
    ).fetchall()]

    # Pairwise relatedness
    edges = []
    parent = {r: r for r in report_ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for i, a in enumerate(report_ids):
        for b in report_ids[i + 1:]:
            rel = relatedness(conn, a, b)
            edges.append(rel)
            # Union when verdict is "strong" — the threshold lever is
            # passed through DEFAULT_THRESHOLD inside relatedness(); we
            # honor `threshold` here by also requiring jaccard >= threshold
            if rel["verdict"] == "strong" and (rel["jaccard"] >= threshold or rel["shared_clusters"]):
                union(a, b)

    # Build components
    groups_map = defaultdict(list)
    for r in report_ids:
        groups_map[find(r)].append(r)
    groups = [sorted(v) for v in groups_map.values()]
    # Sort groups: largest first, then by smallest report id
    groups.sort(key=lambda g: (-len(g), g[0]))
    return groups, edges


# ---------- brief generation ----------

def _group_context(conn, report_ids: list[int]) -> dict:
    """Collect everything an LLM needs to write a brief for a group."""
    metas = [_report_meta(conn, rid) for rid in report_ids]
    # Entities appearing in 2+ of these reports
    cross_entities = []
    if len(report_ids) > 1:
        placeholders = ",".join("?" * len(report_ids))
        rows = conn.execute(
            f"SELECT e.id, e.canonical_name, e.entity_type, e.notes, e.sub_role, "
            f"COUNT(DISTINCT m.report_id) AS in_reports "
            f"FROM entities e JOIN mentions m ON m.entity_id = e.id "
            f"WHERE m.report_id IN ({placeholders}) "
            f"AND (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
            f"GROUP BY e.id HAVING in_reports >= 2 "
            f"ORDER BY in_reports DESC, e.canonical_name LIMIT 50",
            report_ids,
        ).fetchall()
        cross_entities = [{"name": r["canonical_name"],
                           "type": r["entity_type"],
                           "role": (r["notes"] or "").split(" — ")[0].replace("role:", "").strip(),
                           "sub_role": r["sub_role"] or "",
                           "in_reports": r["in_reports"]} for r in rows]
    # Clusters spanning this group
    cluster_rows = []
    if len(report_ids) > 1:
        placeholders = ",".join("?" * len(report_ids))
        cluster_rows = conn.execute(
            f"SELECT c.id, c.name, c.kind, c.description, "
            f"COUNT(DISTINCT m.report_id) AS in_reports "
            f"FROM clusters c "
            f"JOIN cluster_members cm ON cm.cluster_id = c.id "
            f"JOIN mentions m ON m.entity_id = cm.entity_id "
            f"WHERE m.report_id IN ({placeholders}) "
            f"GROUP BY c.id HAVING in_reports >= 2 "
            f"ORDER BY in_reports DESC LIMIT 15",
            report_ids,
        ).fetchall()
    clusters = [dict(r) for r in cluster_rows]
    # Time window
    dates = [m.get("ingested_at") for m in metas if m.get("ingested_at")]
    time_window = (min(dates), max(dates)) if dates else (None, None)
    return {
        "report_ids": report_ids,
        "reports": metas,
        "cross_entities": cross_entities,
        "clusters": clusters,
        "time_window": time_window,
    }


def _verdict_for_group(conn, report_ids: list[int], edges: list[dict]) -> str:
    if len(report_ids) == 1:
        return "standalone"
    # Look at edges within this group
    in_group = [e for e in edges
                if e["a_id"] in report_ids and e["b_id"] in report_ids]
    if any(e["verdict"] == "strong" for e in in_group):
        return "strong"
    if any(e["verdict"] == "weak" for e in in_group):
        return "weak"
    return "disjoint"


def _llm_summary(ctx: dict, verdict: str) -> str:
    payload = {
        "verdict": verdict,
        "reports": [
            {"id": r.get("id"), "title": (r.get("title") or "")[:120],
             "investigation": r.get("investigation"),
             "ingested_at": r.get("ingested_at")}
            for r in ctx["reports"]
        ],
        "cross_entities": ctx["cross_entities"][:25],
        "clusters": [{"name": c["name"], "kind": c.get("kind"),
                      "in_reports": c["in_reports"]} for c in ctx["clusters"]],
        "time_window": ctx["time_window"],
    }
    prompt = ("Group context:\n" + json.dumps(payload, indent=2, ensure_ascii=False)
              + "\n\nWrite the 4-7 sentence brief.")
    try:
        return llm.ask(prompt, system=SYSTEM, timeout=180).strip()
    except Exception as exc:
        return f"(LLM summary unavailable: {exc})"


def _llm_standalone(meta: dict, entity_count: int) -> str:
    payload = {
        "title": meta.get("title"),
        "investigation": meta.get("investigation"),
        "source_type": meta.get("source_type"),
        "entity_count": entity_count,
    }
    prompt = ("Standalone report:\n" + json.dumps(payload, indent=2, ensure_ascii=False)
              + "\n\nWrite 1-2 sentence note.")
    try:
        return llm.ask(prompt, system=STANDALONE_SYSTEM, timeout=60).strip()
    except Exception:
        return f"{meta.get('title') or '(untitled)'} — {meta.get('investigation') or 'no investigation tag'}"


def _format_group_brief(group_idx: int, ctx: dict, verdict: str,
                        summary: str) -> str:
    lines = []
    lines.append(f"# Brief: group {group_idx}")
    lines.append("")
    lines.append(f"**Relatedness verdict:** {verdict}")
    lines.append(f"**Reports in group:** {len(ctx['reports'])}")
    if ctx["time_window"][0]:
        lines.append(f"**Time window:** {ctx['time_window'][0]} → {ctx['time_window'][1]}")
    lines.append("")
    lines.append("## Reports")
    lines.append("")
    for r in ctx["reports"]:
        inv = f" ({r['investigation']})" if r.get("investigation") else ""
        lines.append(f"- id {r.get('id')}{inv} — {r.get('title') or '(untitled)'}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(summary or "(no summary)")
    lines.append("")

    if ctx["cross_entities"]:
        lines.append(f"## Cross-cutting entities ({len(ctx['cross_entities'])})")
        lines.append("")
        lines.append("Entities that appear in ≥2 reports in this group:")
        lines.append("")
        for e in ctx["cross_entities"][:25]:
            role_part = e["role"] + (f"/{e['sub_role']}" if e["sub_role"] else "")
            lines.append(f"- **{e['name']}** ({e['type']}/{role_part}) — in {e['in_reports']} reports")
        lines.append("")
    else:
        lines.append("## Cross-cutting entities")
        lines.append("")
        lines.append("None — no entity appears in more than one report in this group.")
        lines.append("")

    if ctx["clusters"]:
        lines.append(f"## Clusters spanning this group ({len(ctx['clusters'])})")
        lines.append("")
        for c in ctx["clusters"]:
            lines.append(f"- **{c['name']}** ({c.get('kind') or '?'}) — in {c['in_reports']} reports")
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_standalone(orphans: list[dict]) -> str:
    lines = []
    lines.append("# Standalone reports")
    lines.append("")
    lines.append("These reports do NOT meet the relatedness threshold with any "
                 "other ingested report. Treat each as its own case.")
    lines.append("")
    for o in orphans:
        meta = o["meta"]
        inv = f" ({meta.get('investigation')})" if meta.get("investigation") else ""
        lines.append(f"- **id {meta.get('id')}{inv}** — {meta.get('title') or '(untitled)'} "
                     f"({o['entity_count']} entities). {o['summary']}")
    lines.append("")
    return "\n".join(lines) + "\n"


def _format_index(groups_info: list[dict], standalone_count: int) -> str:
    lines = []
    lines.append("# Brief index")
    lines.append("")
    lines.append(f"_generated: {datetime.utcnow().isoformat(timespec='seconds')}Z_")
    lines.append("")
    lines.append(f"Total groups: {len(groups_info)} · Standalone reports: {standalone_count}")
    lines.append("")
    lines.append("## Groups")
    lines.append("")
    for g in groups_info:
        report_titles = ", ".join((r.get("title") or f"id {r.get('id')}")[:40] for r in g["ctx"]["reports"][:3])
        lines.append(f"- **[group-{g['idx']}.md](group-{g['idx']}.md)** — {g['verdict']} — "
                     f"{len(g['ctx']['reports'])} reports — {report_titles}{'…' if len(g['ctx']['reports']) > 3 else ''}")
    if standalone_count:
        lines.append("")
        lines.append("## Standalone")
        lines.append("")
        lines.append("- [standalone.md](standalone.md)")
    return "\n".join(lines) + "\n"


# ---------- entry point ----------

def run(conn, vault_dir: Path, threshold: float = DEFAULT_THRESHOLD,
        llm_summary: bool = True, report_id: int | None = None) -> dict:
    """Generate all briefs.

    Args:
        report_id: if set, only regenerate the group containing this report
                   (others left as-is on disk)
    """
    briefs_dir = vault_dir / "briefs"
    briefs_dir.mkdir(parents=True, exist_ok=True)

    groups, edges = group_reports(conn, threshold=threshold)

    if report_id is not None:
        groups = [g for g in groups if report_id in g]

    groups_info = []
    orphan_summaries = []

    for idx, group in enumerate(groups, start=1):
        ctx = _group_context(conn, group)
        if len(group) == 1:
            # Standalone — collect for the standalone.md file
            ents = _report_entities(conn, group[0])
            summary = _llm_standalone(ctx["reports"][0], len(ents)) if llm_summary else \
                f"{ctx['reports'][0].get('title') or '(untitled)'}"
            orphan_summaries.append({
                "meta": ctx["reports"][0],
                "entity_count": len(ents),
                "summary": summary,
            })
        else:
            verdict = _verdict_for_group(conn, group, edges)
            summary = _llm_summary(ctx, verdict) if llm_summary else \
                f"(no LLM — run with summary enabled. Verdict={verdict}, {len(ctx['cross_entities'])} shared entities)"
            md = _format_group_brief(idx, ctx, verdict, summary)
            (briefs_dir / f"group-{idx}.md").write_text(md, encoding="utf-8")
            groups_info.append({"idx": idx, "verdict": verdict, "ctx": ctx})

    if orphan_summaries:
        (briefs_dir / "standalone.md").write_text(
            _format_standalone(orphan_summaries), encoding="utf-8",
        )
    else:
        # remove a stale standalone.md if it exists
        stale = briefs_dir / "standalone.md"
        if stale.exists():
            stale.unlink()

    (briefs_dir / "INDEX.md").write_text(
        _format_index(groups_info, len(orphan_summaries)), encoding="utf-8",
    )

    return {
        "briefs_dir": str(briefs_dir),
        "groups": len(groups_info),
        "standalone": len(orphan_summaries),
        "threshold": threshold,
        "llm_summary": llm_summary,
        "edges_audited": len(edges),
    }
