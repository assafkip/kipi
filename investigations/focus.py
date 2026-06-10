"""Focus generator — the iterative loop output.

After analyze runs, focus.run writes vault/focus.md:
  - Top-N entities ranked by threat_score
  - Delta vs the previous focus.md run (NEW / +N / -N / unchanged)
  - Newly elevated and cooling-off sections
  - LLM-generated summary paragraph that names the investigator's next priorities

Each iteration sharpens the picture as more data + more seeds get added.
"""
import json
import re
from datetime import datetime
from pathlib import Path

from investigations.storage import db
from investigations.llm import client as llm

TOP_N = 12
NEWLY_ELEVATED_THRESHOLD = 20   # score delta to call out as "newly elevated"
COOLING_THRESHOLD = -15         # score delta to call out as "cooling off"


def _table_exists(conn, name: str) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (name,)
    ).fetchone())


SYSTEM = """You are an OSINT analyst writing the "next-step focus" for an investigator.
You receive: (1) a ranked list of top entities by threat score with sub_roles,
(2) entities that newly elevated this iteration, (3) entities that cooled off.

Write a tight 2–4 sentence analyst paragraph telling the investigator where to
focus next. Name the 2-3 priority targets and WHY. No fluff. No "below is".
No phrases like 'the data suggests'. No filler.

Output plain text only. No prose preamble."""


def _previous_snapshot(focus_path: Path) -> dict[str, dict]:
    """Parse a previous focus.md into {entity_id: {score, rank}}."""
    if not focus_path.exists():
        return {}
    snap = {}
    text = focus_path.read_text(encoding="utf-8")
    # Look for the JSON snapshot block at the end (we write one to make diffs reliable)
    m = re.search(r"<!-- SNAPSHOT_JSON\n(.+?)\nSNAPSHOT_JSON -->", text, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(1))
            for item in data:
                snap[str(item["entity_id"])] = item
        except Exception:
            pass
    return snap


def _gather_top(conn, limit: int = TOP_N, case: str | None = None) -> list[dict]:
    # Optional case scope: restrict to entities mentioned in the case's reports
    # (global pool, case-scoped views).
    case_sql = (
        "AND e.id IN (SELECT m.entity_id FROM mentions m "
        "JOIN reports r ON r.id = m.report_id WHERE r.investigation = ?) "
    ) if case else ""
    params = [case, limit] if case else [limit]
    rows = conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.notes, e.sub_role, "
        "e.sub_role_reason, "
        "s.threat_score, s.degree, s.report_count, "
        "(SELECT MAX(weight) FROM seeds WHERE entity_id = e.id) AS seed_weight, "
        "(SELECT notes FROM seeds WHERE entity_id = e.id LIMIT 1) AS seed_note "
        "FROM entities e JOIN entity_scores s ON s.entity_id = e.id "
        "WHERE (e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) "
        "AND e.entity_type != 'person_candidate' "
        f"{case_sql}"
        "ORDER BY s.threat_score DESC LIMIT ?",
        params,
    ).fetchall()
    # When scoped, every per-entity follow-up query must ALSO be case-restricted,
    # or the scoped Focus leaks other cases' clusters/relationships/slugs.
    in_case = (
        "AND {col} IN (SELECT m.entity_id FROM mentions m "
        "JOIN reports r ON r.id = m.report_id WHERE r.investigation = ?)"
    )
    items = []
    for i, r in enumerate(rows, start=1):
        notes = r["notes"] or ""
        role = notes.split(" — ")[0].replace("role:", "").strip()
        eid = r["id"]

        # Clusters this entity belongs to. Scoped: only clusters with a member
        # in the active case (cluster tables have no investigation column).
        if case:
            cluster_rows = conn.execute(
                "SELECT c.id, c.name FROM clusters c "
                "JOIN cluster_members cm ON cm.cluster_id = c.id "
                "WHERE cm.entity_id = ? AND c.id IN ("
                "  SELECT cm2.cluster_id FROM cluster_members cm2 "
                "  JOIN mentions m ON m.entity_id = cm2.entity_id "
                "  JOIN reports r ON r.id = m.report_id WHERE r.investigation = ?) "
                "ORDER BY c.id",
                (eid, case),
            ).fetchall()
        else:
            cluster_rows = conn.execute(
                "SELECT c.id, c.name FROM clusters c "
                "JOIN cluster_members cm ON cm.cluster_id = c.id "
                "WHERE cm.entity_id = ? ORDER BY c.id",
                (eid,),
            ).fetchall()
        cluster_objs = [{"id": r["id"], "name": r["name"]} for r in cluster_rows]
        clusters = [r["name"] for r in cluster_rows]

        # Top typed relationships (max 3, prefer high-confidence). Scoped: the
        # OTHER endpoint must also be an entity in the active case.
        rel_other_filter = (" " + in_case.format(col="e2.id") + " ") if case else " "
        rel_params = ([eid, eid, eid, eid, case] if case else [eid, eid, eid, eid])
        rel_rows = conn.execute(
            "SELECT t.rel_type, t.confidence, "
            "e2.canonical_name AS other_name, e2.id AS other_id, "
            "CASE WHEN t.src_entity_id = ? THEN 'out' ELSE 'in' END AS dir "
            "FROM typed_relationships t "
            "JOIN entities e2 ON e2.id = CASE WHEN t.src_entity_id = ? "
            "                                THEN t.dst_entity_id ELSE t.src_entity_id END "
            "WHERE (t.src_entity_id = ? OR t.dst_entity_id = ?) "
            "AND COALESCE(t.status,'active') = 'active' "
            f"{rel_other_filter}"
            "ORDER BY CASE t.confidence "
            "  WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END "
            "LIMIT 3",
            rel_params,
        ).fetchall()
        relationships = [{
            "rel_type": row["rel_type"],
            "other_name": row["other_name"],
            "other_id": row["other_id"],
            "dir": row["dir"],
            "confidence": row["confidence"],
        } for row in rel_rows]

        # Cross-case visibility: every case this entity appears in. Surfaced by
        # _build_why as "appears in cases: ..." — a labeled cross-case signal,
        # shown even inside a single-case view (policy: cross-case everywhere).
        investigations = [row["investigation"] for row in conn.execute(
            "SELECT DISTINCT r.investigation FROM mentions m "
            "JOIN reports r ON r.id = m.report_id "
            "WHERE m.entity_id = ? AND r.investigation IS NOT NULL",
            (eid,),
        ).fetchall() if row["investigation"]]

        item = {
            "rank": i,
            "entity_id": eid,
            "name": r["canonical_name"],
            "entity_type": r["entity_type"],
            "role": role,
            "sub_role": r["sub_role"] or "",
            "sub_role_reason": r["sub_role_reason"] or "",
            "score": float(r["threat_score"] or 0),
            "degree": r["degree"] or 0,
            "report_count": r["report_count"] or 0,
            "seed_weight": float(r["seed_weight"] or 0),
            "seed_note": r["seed_note"] or "",
            "clusters": clusters,
            "cluster_objs": cluster_objs,
            "top_relationships": relationships,
            "investigations": investigations,
        }
        item["why"] = _build_why(item)
        items.append(item)
    return items


GAP_TOP_N = 15   # gaps are reported against the actors that actually matter


def compute_gaps(conn, case: str | None = None) -> list[dict]:
    """Deterministic 'what's missing / what to look for next' for the case.

    Gaps are reported against the TOP-ranked actors (the ones in Focus), so the
    list stays short, named, and actionable — not "500 low-value entities are
    unenriched". Pure DB signals; recomputes live, sharpening as intel is added.
    Each gap: {kind, title, severity, action, count, entities:[{id,name}]}.
    """
    cs = ("AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r2 "
          "ON r2.id = m.report_id WHERE r2.investigation = ?)") if case else ""
    cp = [case] if case else []
    real = "(e.notes NOT LIKE 'role:noise%' OR e.notes IS NULL) AND e.entity_type != 'person_candidate'"
    has_enr = _table_exists(conn, "enrichment_runs")
    enr_col = ("(SELECT COUNT(*) FROM enrichment_runs er WHERE er.entity_id = e.id)"
               if has_enr else "0")

    top = conn.execute(
        f"SELECT e.id, e.canonical_name, COALESCE(s.degree,0) AS deg, "
        f"COALESCE(s.report_count,0) AS rc, {enr_col} AS enr "
        f"FROM entities e JOIN entity_scores s ON s.entity_id = e.id "
        f"WHERE {real} {cs} ORDER BY s.threat_score DESC LIMIT {GAP_TOP_N}",
        cp,
    ).fetchall()

    def matches(pred):
        """True count of matching top actors + a display-capped named sample."""
        ms = [r for r in top if pred(r)]
        return len(ms), [{"id": r["id"], "name": r["canonical_name"]} for r in ms][:6]

    def actors(n):
        return "actor" if n == 1 else "actors"

    gaps: list[dict] = []

    # "Not connected" (deg==0, no typed links) and "never enriched" (enr==0) are the
    # SAME next action: investigate the actor — the detective enriches it AND builds its
    # typed links. So merge them into ONE gap on the DEDUPED union, instead of flagging
    # the same actors twice as if they were two separate problems.
    def needs_investigation(r):
        return r["deg"] == 0 or (has_enr and r["enr"] == 0)
    n, ents = matches(needs_investigation)
    if ents:
        gaps.append({"kind": "uninvestigated", "severity": "medium", "count": n, "entities": ents,
                     "title": f"{n} top {actors(n)} not investigated yet",
                     "action": "Investigate them — open one on the graph and hit 🔍 Investigate "
                               "(or run a whole-case swarm). The detective enriches them AND "
                               "builds their typed connections in one pass."})

    n, ents = matches(lambda r: r["rc"] <= 1)
    if ents:
        gaps.append({"kind": "uncorroborated", "severity": "medium", "count": n, "entities": ents,
                     "title": f"{n} top {actors(n)} seen in only one report",
                     "action": "Find corroborating sources before relying on them"})

    n_pc = conn.execute(
        "SELECT COUNT(*) FROM entities e WHERE e.entity_type = 'person_candidate' " + cs, cp,
    ).fetchone()[0]
    if n_pc:
        gaps.append({"kind": "unconsolidated", "severity": "low", "count": n_pc, "entities": [],
                     "title": f"{n_pc} unresolved person candidate{'' if n_pc==1 else 's'}",
                     "action": "Mostly extraction noise. Re-running Process merges the "
                               "resolvable ones; the rest are low-signal name fragments."})

    return gaps


def _build_why(item: dict) -> str:
    """Build a deterministic 'why this entity is a priority' sentence.

    Pulls from: seed note, sub_role_reason, cluster names, top typed rels,
    report/degree counts. Skips empty signals. Short, scannable.
    """
    parts = []

    # 1. Seed prior is the strongest signal — surface it first
    if item["seed_weight"] > 0:
        if item["seed_note"]:
            parts.append(f"prior intel: {item['seed_note']}")
        else:
            parts.append(f"flagged as known-bad (seed weight {item['seed_weight']:.1f})")

    # 2. Sub_role reason (LLM's evidence for the function tag) — analyst's eye
    if item["sub_role"] and item["sub_role_reason"]:
        parts.append(item["sub_role_reason"])
    elif item["sub_role"] and item["sub_role"] not in ("unknown", "member"):
        parts.append(f"tagged as {item['sub_role']}")

    # 3. Clusters give crew/cohort context
    if item["clusters"]:
        cluster_text = ", ".join(item["clusters"][:2])
        if len(item["clusters"]) > 2:
            cluster_text += f" (+{len(item['clusters']) - 2} more)"
        parts.append(f"in {cluster_text}")

    # 4. Top typed relationships — what they're doing in the graph
    if item["top_relationships"]:
        rel_strs = []
        for r in item["top_relationships"][:2]:
            arrow = "→" if r["dir"] == "out" else "←"
            rel_strs.append(f"{r['rel_type']} {arrow} {r['other_name']}")
        parts.append("; ".join(rel_strs))

    # 5. Report/degree footprint — only if other signals are thin
    footprint_bits = []
    if item["report_count"] > 1:
        footprint_bits.append(f"{item['report_count']} reports")
    if item["degree"] > 3:
        footprint_bits.append(f"degree {item['degree']}")
    if footprint_bits and len(parts) < 2:
        parts.append(", ".join(footprint_bits))

    # 6. Investigations across cases
    if len(item["investigations"]) > 1:
        parts.append(f"appears in cases: {', '.join(item['investigations'][:3])}")

    if not parts:
        return "high score, no narrative signal yet — run profile or check mentions"

    return ". ".join(parts).rstrip(".") + "."


def _compute_deltas(current: list[dict], previous: dict[str, dict]) -> dict:
    """Annotate `current` with delta vs previous. Also return newly_elevated + cooling."""
    elevated = []
    cooling = []
    out = []
    for item in current:
        prev = previous.get(str(item["entity_id"]))
        if prev:
            delta = item["score"] - prev["score"]
            item["prev_score"] = prev["score"]
            item["prev_rank"] = prev.get("rank")
            item["delta"] = delta
            item["status"] = "+{}".format(int(round(delta))) if delta > 0 else (
                str(int(round(delta))) if delta < 0 else "unchanged"
            )
        else:
            item["prev_score"] = None
            item["prev_rank"] = None
            item["delta"] = item["score"]   # treat as full appearance
            item["status"] = "NEW"
        out.append(item)
    # newly elevated = present this run AND delta >= threshold (or NEW)
    # but pull the broader set of newly elevated from BEYOND the top-N
    # by checking previous entries not in current
    for item in current:
        if item["status"] == "NEW" or (item.get("delta", 0) >= NEWLY_ELEVATED_THRESHOLD):
            elevated.append(item)
    # cooling: previous top entries that fell out of the top-N
    current_ids = {str(x["entity_id"]) for x in current}
    for eid, prev in previous.items():
        if eid in current_ids:
            continue
        # they dropped out — that's cooling
        cooling.append({
            "rank": prev.get("rank"),
            "name": prev.get("name", "?"),
            "entity_id": prev.get("entity_id"),
            "prev_score": prev.get("score"),
            "score": None,
            "status": "DROPPED",
        })
    return {"items": out, "elevated": elevated, "cooling": cooling}


def _summary_via_llm(deltas: dict) -> str:
    items = deltas["items"]
    elevated = deltas["elevated"]
    cooling = deltas["cooling"]
    payload = {
        "top": [
            {"rank": x["rank"], "name": x["name"], "role": x["role"],
             "sub_role": x["sub_role"], "score": round(x["score"]),
             "status": x["status"], "seed": bool(x["seed_weight"] > 0)}
            for x in items[:8]
        ],
        "newly_elevated": [
            {"name": x["name"], "status": x["status"], "role": x["role"]}
            for x in elevated[:5]
        ],
        "cooling": [
            {"name": x["name"], "prev_score": round(x.get("prev_score") or 0)}
            for x in cooling[:5]
        ],
    }
    prompt = (
        "Iteration snapshot:\n"
        + json.dumps(payload, indent=2, ensure_ascii=False)
        + "\n\nWrite the 2–4 sentence focus paragraph."
    )
    try:
        return llm.ask(prompt, system=SYSTEM, timeout=120).strip()
    except Exception:
        # Fallback: template-based summary if LLM unavailable
        if not items:
            return "No scored entities yet. Ingest reports and run consolidate + analyze."
        top3 = items[:3]
        names = ", ".join(f"{x['name']} ({x['role']}/{x['sub_role'] or 'unk'})"
                          for x in top3)
        return (f"Top priority next: {names}. "
                + (f"{len(elevated)} entities newly elevated, {len(cooling)} cooling off." if (elevated or cooling) else ""))


def _format_md(deltas: dict, summary: str, generated_at: str) -> str:
    items = deltas["items"]
    elevated = deltas["elevated"]
    cooling = deltas["cooling"]

    lines = []
    lines.append(f"# Focus next — {generated_at}")
    lines.append("")
    lines.append(f"_generated: {generated_at}_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(summary)
    lines.append("")
    lines.append("## Top targets")
    lines.append("")
    for x in items:
        seed_tag = " [SEED]" if x["seed_weight"] > 0 else ""
        role_part = x["role"]
        if x["sub_role"]:
            role_part += f"/{x['sub_role']}"
        lines.append(
            f"- **#{x['rank']} {x['name']}** ({role_part}, score {int(round(x['score']))}, "
            f"{x['status']} vs last){seed_tag}"
        )
    lines.append("")

    if elevated:
        lines.append("## Newly elevated this iteration")
        lines.append("")
        for x in elevated:
            lines.append(
                f"- {x['name']} — {x['status']} (rank {x['rank']}, "
                f"score {int(round(x['score']))}, {x['role']}/{x['sub_role'] or 'unk'})"
            )
        lines.append("")

    if cooling:
        lines.append("## Cooling off (dropped out of top targets)")
        lines.append("")
        for x in cooling:
            lines.append(
                f"- {x['name']} — was rank {x['rank']} at score "
                f"{int(round(x['prev_score'] or 0))}, now below cutoff"
            )
        lines.append("")

    # Methodology — explain what the score means so the report is self-contained
    lines.append("---")
    lines.append("")
    lines.append("## How to read these scores")
    lines.append("")
    lines.append("Score is a **rank-by-attention** signal, not a maliciousness rating. "
                 "Same data produces the same scores. Higher score = look here first.")
    lines.append("")
    lines.append("**Formula:**  `score = role×10 + reports×5 + degree×1 + seed×30 + propagation`")
    lines.append("")
    lines.append("- **role × 10** — operator=5, ioc=4, channel=3, infra=1, source=0. "
                 "Operators carry the most analyst-relevant signal.")
    lines.append("- **reports × 5** — distinct reports where the entity appears. "
                 "Cross-report presence = persistent, not one-off.")
    lines.append("- **degree × 1** — typed relationships the entity is part of. "
                 "Network-central entities score higher.")
    lines.append("- **seed × 30** — if you marked this entity as a known-bad prior via `./invctl seed`, "
                 "it gets a heavy boost.")
    lines.append("- **propagation** — direct neighbors of a seed get +seed×10, two-hop neighbors get +seed×4. "
                 "Associates of known-bad light up.")
    lines.append("")
    lines.append("**Δ vs last** = score change since the previous `./invctl focus` run. "
                 "NEW = appeared in top targets for the first time. "
                 "Each iteration sharpens as more data + more seeds get fed in.")
    lines.append("")
    lines.append("**`[SEED]` flag** = entity matched a name in your case-file priors. "
                 "Not auto-discovered — you told the system this one matters.")
    lines.append("")

    # Embedded JSON snapshot so the NEXT run can compute deltas
    snapshot = [
        {"entity_id": x["entity_id"], "rank": x["rank"], "score": x["score"],
         "name": x["name"]}
        for x in items
    ]
    lines.append("<!-- SNAPSHOT_JSON")
    lines.append(json.dumps(snapshot, ensure_ascii=False))
    lines.append("SNAPSHOT_JSON -->")
    return "\n".join(lines) + "\n"


def run(conn, vault_dir: Path, llm_summary: bool = True) -> dict:
    vault_dir.mkdir(parents=True, exist_ok=True)
    focus_path = vault_dir / "focus.md"
    focus_json_path = vault_dir / "focus.json"
    history_dir = vault_dir / ".focus-history"
    history_dir.mkdir(parents=True, exist_ok=True)

    previous = _previous_snapshot(focus_path)
    current = _gather_top(conn, TOP_N)
    deltas = _compute_deltas(current, previous)
    # Also surface a wider "newly_elevated" by scanning entities outside the
    # top-N but whose previous entry showed up below score X — skipped for
    # simplicity in v1.

    generated_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    if llm_summary:
        summary = _summary_via_llm(deltas)
    else:
        # Deterministic refresh (e.g. auto-run on ingest): keep the last good
        # analyst summary rather than stomping it with a placeholder.
        summary = ""
        if focus_json_path.exists():
            try:
                summary = json.loads(
                    focus_json_path.read_text(encoding="utf-8")).get("summary", "")
            except Exception:
                summary = ""
    if not summary:
        summary = "(deterministic refresh — run ./invctl focus for an updated analyst summary)"
    md = _format_md(deltas, summary, generated_at)

    focus_path.write_text(md, encoding="utf-8")

    # Machine-readable companion — webapp prefers this over parsing the md
    focus_json = {
        "generated_at": generated_at,
        "summary": summary,
        "items": deltas["items"],
        "elevated": deltas["elevated"],
        "cooling": deltas["cooling"],
    }
    focus_json_path.write_text(
        json.dumps(focus_json, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # Snapshot history (timestamped) for record-keeping
    hist_path = history_dir / f"focus-{generated_at.replace(':', '-')}.md"
    hist_path.write_text(md, encoding="utf-8")

    return {
        "focus_path": str(focus_path),
        "focus_json_path": str(focus_json_path),
        "history_path": str(hist_path),
        "top_n": len(current),
        "newly_elevated": len(deltas["elevated"]),
        "cooling": len(deltas["cooling"]),
        "generated_at": generated_at,
    }
