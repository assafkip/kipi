"""LLM-driven actor profile generation.

For each high-value entity (role: operator | channel | ioc), gather:
  - canonical name + role + aliases
  - every mention across reports (with surrounding OCR context)
  - every related entity (from relationships table)
  - every screenshot it appears in

Send to Claude → get an analyst dossier:
  - 2-3 sentence summary (what is this, why does it matter)
  - Threat assessment (severity, novelty, links)
  - Key connections (what else this entity is tied to)
  - Open questions (what's unclear / needs more sourcing)

Write to vault/profiles/<entity>.md.
"""
import re
from pathlib import Path

from investigations.llm import client as llm

SAFE_NAME_RE = re.compile(r"[^\w.-]+")

PROFILE_ROLES = {"operator", "channel", "ioc"}

SYSTEM = """You are a FAANG-tier Senior Staff Investigator (Trust & Safety / Threat
Intelligence) producing an actor dossier. You receive structured evidence about ONE
entity (an actor, channel, or IoC) from one or more intel reports. Synthesize it into a
concise, attribution-grade profile.

EVIDENTIARY DISCIPLINE (non-negotiable):
- Every claim traces to the evidence provided. If you can't point to it, don't write it.
- Separate FACT from ASSESSMENT. Label inferences with calibrated confidence
  ("confirmed" / "assessed, high-medium-low" / "possible"). Never state an inference as
  fact. If attribution isn't established, write "unattributed" — do not guess a real
  identity, group, or nation-state.
- Treat self-reported bios / registrant WHOIS / shared-CDN IPs as trivially faked; flag
  and lower confidence unless an independent source corroborates.
- Quantify where the data allows; cite the report/tool behind each claim.
- Expertise shapes INTERPRETATION, never invents content.

Be terse. Be specific. Lead with the most operationally useful, evidenced insight.
No filler. No restating the input verbatim. No hedging adverbs, no hype.
If the evidence is thin, say so: 'Limited evidence — single mention in one report.'
Do not invent context."""


def _safe_name(s: str) -> str:
    return SAFE_NAME_RE.sub("_", s).strip("_")[:120]


def _gather_evidence(conn, entity_id: int) -> dict:
    entity = conn.execute(
        "SELECT * FROM entities WHERE id = ?", (entity_id,)
    ).fetchone()
    if not entity:
        return None

    aliases = [r["alias"] for r in conn.execute(
        "SELECT alias FROM aliases WHERE entity_id = ?", (entity_id,)
    ).fetchall()]

    mentions = conn.execute(
        "SELECT m.surface_form, m.context, r.id AS report_id, r.title AS report_title, "
        "a.page_number, a.image_index "
        "FROM mentions m JOIN reports r ON r.id = m.report_id "
        "LEFT JOIN assets a ON a.id = m.asset_id "
        "WHERE m.entity_id = ? ORDER BY r.id, a.page_number",
        (entity_id,),
    ).fetchall()

    related = conn.execute(
        "SELECT DISTINCT e.canonical_name, e.entity_type, e.notes, "
        "COUNT(*) AS co_count "
        "FROM relationships rel "
        "JOIN entities e ON e.id = CASE WHEN rel.src_entity_id = ? "
        "THEN rel.dst_entity_id ELSE rel.src_entity_id END "
        "WHERE rel.src_entity_id = ? OR rel.dst_entity_id = ? "
        "GROUP BY e.id ORDER BY co_count DESC LIMIT 30",
        (entity_id, entity_id, entity_id),
    ).fetchall()

    reports_seen = set()
    for m in mentions:
        reports_seen.add(m["report_title"])

    return {
        "entity": dict(entity),
        "aliases": aliases,
        "mentions": [dict(m) for m in mentions],
        "related": [dict(r) for r in related],
        "report_count": len(reports_seen),
        "mention_count": len(mentions),
    }


def _build_prompt(evidence: dict) -> str:
    e = evidence["entity"]
    role = (e["notes"] or "").split(" — ")[0].replace("role:", "")
    parts = [
        f"ENTITY: {e['canonical_name']}",
        f"TYPE: {e['entity_type']}",
        f"ROLE: {role}",
    ]
    if evidence["aliases"]:
        parts.append(f"ALIASES: {', '.join(evidence['aliases'])}")
    parts.append(f"APPEARS IN: {evidence['report_count']} report(s), "
                 f"{evidence['mention_count']} mention(s)")
    parts.append("")

    parts.append("MENTIONS (with surrounding context):")
    for i, m in enumerate(evidence["mentions"][:20], 1):
        loc = m["report_title"]
        if m["page_number"]:
            loc += f", page {m['page_number']}"
            if m["image_index"] is not None:
                loc += f" image {m['image_index']}"
        ctx = (m["context"] or "")[:400].replace("\n", " ")
        parts.append(f"  [{i}] {loc}: {ctx}")
    if len(evidence["mentions"]) > 20:
        parts.append(f"  ... and {len(evidence['mentions']) - 20} more mentions")
    parts.append("")

    parts.append("CONNECTED ENTITIES (co-mentioned in same context):")
    for r in evidence["related"][:20]:
        rrole = (r["notes"] or "").split(" — ")[0].replace("role:", "")
        rrole_str = f" ({rrole})" if rrole and rrole != "noise" else ""
        parts.append(f"  - {r['canonical_name']}{rrole_str} — co-mentioned {r['co_count']}x")
    parts.append("")

    parts.append("Produce an analyst dossier with these sections (use exact headers):\n"
                 "## Summary\n"
                 "## Threat assessment\n"
                 "## Key connections\n"
                 "## Open questions\n\n"
                 "Be concise. Markdown only. No preamble.")
    return "\n".join(parts)


def generate_profiles(conn, roles: set[str] = None, case: str | None = None) -> dict:
    if roles is None:
        roles = PROFILE_ROLES

    # Scope to the active case's actors. Without this, Processing one case built a
    # dossier for EVERY actor across ALL cases (659 instead of 3) — the LLM-per-actor
    # loop then crawled for 30+ min on the last step ("stuck at 88%").
    scope, params = "", []
    if case:
        scope = ("AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
                 "ON r.id = m.report_id WHERE r.investigation = ?) ")
        params = [case]
    rows = conn.execute(
        "SELECT e.id, e.canonical_name, e.notes FROM entities e "
        "WHERE e.notes IS NOT NULL " + scope +
        "ORDER BY e.id", params
    ).fetchall()

    eligible = []
    for r in rows:
        notes = r["notes"] or ""
        if not notes.startswith("role:"):
            continue
        role = notes.split(" — ")[0].replace("role:", "").strip()
        if role in roles:
            eligible.append((r["id"], r["canonical_name"], role))

    total = len(eligible)
    print(f"Generating profiles for {total} entities (roles: {sorted(roles)})…")

    profiles_generated = {}
    for idx, (eid, name, role) in enumerate(eligible, 1):
        evidence = _gather_evidence(conn, eid)
        if not evidence:
            continue
        if evidence["mention_count"] == 0:
            continue
        print(f"  [{idx}/{total}] {role}: {name}", end=" ", flush=True)
        prompt = _build_prompt(evidence)
        try:
            dossier_md = llm.ask(prompt, system=SYSTEM, timeout=120)
        except llm.LLMError as exc:
            print(f"ERR: {exc}")
            continue
        profiles_generated[eid] = {
            "name": name,
            "role": role,
            "dossier": dossier_md,
            "evidence": evidence,
        }
        print("ok")
    return profiles_generated


def write_profile_md(vault_dir: Path, profile: dict) -> Path:
    profiles_dir = vault_dir / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    name = profile["name"]
    e = profile["evidence"]["entity"]
    aliases = profile["evidence"]["aliases"]
    filename = f"{_safe_name(name)}.md"
    path = profiles_dir / filename
    lines = [
        "---",
        f"name: {name}",
        f"role: {profile['role']}",
        f"type: {e['entity_type']}",
        f"tags: [profile, {profile['role']}, {e['entity_type']}]",
    ]
    if aliases:
        lines.append(f"aliases: {aliases}")
    lines.append("---\n")
    lines.append(f"# {name}\n")
    lines.append(f"**Role:** {profile['role']}  ·  **Type:** {e['entity_type']}  ·  "
                 f"**Reports:** {profile['evidence']['report_count']}  ·  "
                 f"**Mentions:** {profile['evidence']['mention_count']}\n")
    if aliases:
        lines.append(f"**Aliases:** {', '.join(aliases)}\n")
    lines.append(profile["dossier"])

    enrichment = profile.get("enrichment_links", [])
    if enrichment:
        lines.append("\n---\n## Pivot for enrichment\n")
        for link in enrichment:
            lines.append(f"- [{link['label']}]({link['url']})")

    lines.append("\n---\n## Linked entities\n")
    for r in profile["evidence"]["related"][:30]:
        lines.append(f"- [[{r['canonical_name']}]] ({r['co_count']}x)")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _get_enrichment_links(conn, entity_id: int) -> list[dict]:
    try:
        rows = conn.execute(
            "SELECT label, url FROM enrichment_links WHERE entity_id = ?",
            (entity_id,),
        ).fetchall()
    except Exception:
        return []
    return [{"label": r["label"], "url": r["url"]} for r in rows]



def run(conn, vault_dir: Path, roles: set[str] = None, case: str | None = None) -> dict:
    profiles = generate_profiles(conn, roles=roles, case=case)
    written = []
    for eid, profile in profiles.items():
        profile["enrichment_links"] = _get_enrichment_links(conn, eid)
        p = write_profile_md(vault_dir, profile)
        written.append(p)
    return {"profiles_written": len(written),
            "profile_dir": str(vault_dir / "profiles")}
