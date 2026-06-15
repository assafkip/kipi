"""LLM-driven cross-report synthesis.

Reads:
  - all reports
  - all 'hub' entities (operator/channel/ioc roles, appearing in 2+ reports OR with
    profiles in vault/profiles/)
  - cross-report co-occurrence
  - generated dossiers (if Phase 2 already ran)

Produces:
  vault/synthesis.md — ONE narrative analyst would hand to the customer
"""
import json
from pathlib import Path

from investigations.llm import client as llm

SYSTEM = """You are a FAANG-tier Senior Staff Investigator (Trust & Safety / Threat
Intelligence) with 12+ years running attribution-grade investigations. You write the way
a senior staff investigator writes: precise, declarative, evidence-bound, no theatrics.
You receive evidence from MULTIPLE intel reports plus the investigator's findings on one
case. Produce ONE brief that connects the dots ACROSS the evidence — and ONLY the evidence.

EVIDENTIARY DISCIPLINE (non-negotiable — a single unsupported claim fails the brief):
- Every statement traces to a specific finding/report in the data provided. If you can't
  point to the evidence for it, do not write it.
- Separate FACT from ASSESSMENT. State observed facts plainly. Label inferences as
  assessments with calibrated confidence — "confirmed", "assessed (high/medium/low
  confidence)", "possible". NEVER present an inference as a fact.
- No far-fetched leaps. No narrative embellishment. No motive, actor, group, or
  nation-state you cannot evidence. If attribution is not established by the data, write
  "unattributed" — do not guess.
- Quantify when the data allows (counts, dates, addresses, infra overlaps). Cite the
  report or tool behind each claim.
- Treat self-reported bios, registrant WHOIS, and shared-CDN IPs as trivially faked —
  flag them and lower confidence; only elevate when an independent source the actor can't
  edit corroborates.
- Where evidence is thin, single-source, or contradictory, say so explicitly.
- Lead with the bottom line. Terse. No filler, no hedging adverbs, no hype.
- Expertise shapes how you INTERPRET the data — never what you ADD to it.

PRIORITIZE BY OPERATIONAL URGENCY (this decides the headline):
- LEAD with what is LIVE and operating NOW. An actively-running scam, live
  infrastructure, a fresh payout wallet, or an open victim-facing site is THE
  headline — the first sentence of the executive summary is about it.
- Dead, dormant, seized, suspended, or historical infrastructure is CONTEXT, never
  the lede. The original seed/most-documented entity being dead does NOT make it the
  story. Do not bury an active threat under a dormant one just because the dormant
  one has more findings.
- If the data shows both a dead tier and an active tier, the active tier leads and the
  dead tier is background. State plainly what is operational TODAY and what is not.
- The "OPERATIONAL STATUS" block in the input (if present) is the authoritative
  live/dead split — use it to order the brief.

GRADE EVERY PIECE OF EVIDENCE (4_points A–F reliability scale):
- A = 2+ independent / official sources. B = 1 credible source. C = inferred / single
  web source. D = single unverified / self-reported. In the target dossiers, every
  evidence row carries its source + an A–F grade. A claim's confidence cannot exceed
  what its best-graded source supports.

Output: a single markdown brief with these exact sections:
  # Synthesis brief
  ## Executive summary  (3-5 sentences, the headline)
  ## Key judgments  (the 4_points KJ structure: numbered KJ-1, KJ-2, … — each a single
       declarative judgment with its calibrated confidence, ordered by importance. These
       are the load-bearing conclusions; everything below substantiates them.)
  ## Operational picture  (what is happening, who is doing it, what infra they use)
  ## Target dossiers  (ONE subsection per investigated target — domain / operator /
       wallet / channel. For each: an identity line, an infrastructure/threat summary,
       a graded evidence table (Evidence | Source | Reliability A–F), and connections to
       the other targets. This is the per-target depth that makes the case connected, not
       a flat fact list.)
  ## Key actors  (named operators, with role assessment)
  ## Communication channels  (named channels, with assessment)
  ## Indicators of compromise  (concrete IoCs analyst can pivot on)
  ## Cross-report findings  (what each new report added)
  ## Open questions & gaps  (what could NOT be confirmed — pull the specific unverified
       LEADS + collection gaps from the investigator section; name the exact attributions
       that need corroboration, e.g. "is X the real person behind handle Y?")
  ## Where to look next  (the highest-value SPECIFIC pivots to chase — name exact entities
       to investigate and why, drawn from the leads + any actors not yet investigated. Be
       concrete: "investigate <entity> to confirm <what>", not "do more research")

Be terse. Cite report names when making claims. No filler.
If evidence is contradictory or thin, flag it explicitly.
Do not invent details — work only from the evidence provided."""


def _gather_brief_data(conn, vault_dir: Path, case: str | None = None) -> dict:
    # Deterministic sections come from THE projection (sp3: one source — the
    # same input set the replay digest pins; the brief can never render a
    # different selection than the projected surfaces).
    from investigations import projection
    proj = projection.brief_inputs(conn, case)
    # reports need source metadata beyond brief_inputs' comparable core.
    rep_ids = [r["id"] for r in proj["reports"]]
    reports = [dict(r) for r in conn.execute(
        "SELECT id, title, source_path, investigation, ingested_at FROM reports "
        f"WHERE id IN ({','.join('?' * len(rep_ids)) or 'NULL'}) ORDER BY ingested_at",
        rep_ids).fetchall()] if rep_ids else []

    # Cross-report hubs: entities in 2+ of the case's reports (parenthesize the
    # role OR before AND-ing the case filter, else precedence bites).
    cross_where = "AND r.investigation = ? " if case else ""
    cross_report = conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.notes, "
        "COUNT(DISTINCT m.report_id) AS report_count, "
        "GROUP_CONCAT(DISTINCT r.title) AS reports "
        "FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id "
        "WHERE (e.notes LIKE 'role:operator%' OR e.notes LIKE 'role:channel%' "
        "OR e.notes LIKE 'role:ioc%') "
        f"{cross_where}"
        "GROUP BY e.id HAVING report_count >= 2 "
        "ORDER BY report_count DESC",
        ([case] if case else []),
    ).fetchall()

    by_role: dict[str, list] = {"operator": [], "channel": [], "ioc": []}
    for r in cross_report:
        role = (r["notes"] or "").split(" — ")[0].replace("role:", "").strip()
        if role in by_role:
            by_role[role].append({
                "id": r["id"],
                "name": r["canonical_name"],
                "reports": r["report_count"],
                "report_titles": r["reports"],
            })

    # Dossiers: only for the global brief. Per-case briefs skip them to avoid
    # leaking other cases' actor profiles into a single case's narrative.
    dossiers = {}
    if case is None:
        profiles_dir = vault_dir / "profiles"
        if profiles_dir.exists():
            for p in profiles_dir.glob("*.md"):
                dossiers[p.stem] = p.read_text(encoding="utf-8")

    # Agent investigation findings + attribution verdicts. The brief was previously
    # BLIND to these — everything the autonomous investigator dug up never reached the
    # deliverable. Pull the (promotable + gated) findings and the assessment verdicts.
    agent_where = "AND run.investigation = ? " if case else ""
    # PROMOTED findings + unverified leads: straight from the projection
    # (same selection rules; the bespoke SQL this replaces is deleted).
    agent_findings = proj["findings"]
    agent_leads = proj["leads"]
    # Pull a wider window than we keep, THEN filter to runs that actually carry an
    # attribution — so the actor-filter doesn't silently drop verdicts behind the cap.
    assessments = []
    for r in conn.execute(
        "SELECT agent_process FROM enrichment_runs run "
        f"WHERE run.provider_slug = 'agent' {agent_where}"
        "AND agent_process IS NOT NULL ORDER BY id DESC LIMIT 60",
        ([case] if case else []),
    ).fetchall():
        try:
            a = (json.loads(r["agent_process"]) or {}).get("assessment")
            if a and a.get("attributed_actor"):
                assessments.append(a)
        except Exception:
            pass
    assessments = assessments[:12]

    # The analyst's objective (scope anchor) — the brief must answer it head-on.
    from investigations.storage import db as _db
    objective = _db.get_objective(conn, case)

    active_infra, dead_infra = _operational_status(agent_findings + agent_leads)

    return {
        "reports": reports,
        "hubs_by_role": by_role,
        "agent_leads": agent_leads,
        "dossiers": dossiers,
        "agent_findings": agent_findings,
        "assessments": assessments,
        "case": case,
        "objective": objective,
        "active_infra": active_infra,
        "dead_infra": dead_infra,
    }


import re as _re_syn
_LIVE_RE = _re_syn.compile(r"\b(resolves|live|active|operating|operational|hosted|hosting|"
                           r"up and running|currently up|http 200|reachable)\b", _re_syn.I)
_DEAD_RE = _re_syn.compile(r"\b(no dns|not found|does not resolve|nxdomain|servfail|"
                           r"unregistered|is down|currently down|dormant|seized|suspended|"
                           r"taken down|offline|dead|parked)\b", _re_syn.I)
_HOSTISH = _re_syn.compile(r"^[a-z0-9.\-]+\.[a-z]{2,}$|^\d{1,3}(\.\d{1,3}){3}$", _re_syn.I)


def _operational_status(findings: list[dict]) -> tuple[list, list]:
    """Split the case's domains/IPs into LIVE-now vs DEAD/dormant, read from the agent's
    finding text. Drives the brief's headline: the active tier leads, the dead tier is
    context. A host is 'live' only on a live cue with no dead cue (conservative — we don't
    want to headline a dead site as active)."""
    live_votes: dict[str, bool] = {}
    dead_votes: dict[str, bool] = {}
    for f in findings:
        host = (f.get("title") or "").strip().lower()
        if not _HOSTISH.match(host):
            continue
        blob = " ".join((f.get("summary") or "", f.get("title") or ""))
        if _DEAD_RE.search(blob):
            dead_votes[host] = True
        elif _LIVE_RE.search(blob):
            live_votes[host] = True
    live = sorted(h for h in live_votes if h not in dead_votes)   # dead cue wins ties
    dead = sorted(dead_votes)
    return live, dead


def _build_prompt(data: dict) -> str:
    parts = []
    objective = (data.get("objective") or "").strip()
    if objective:
        parts.append("INVESTIGATION OBJECTIVE — the brief must answer this head-on. "
                     "Lead the executive summary with where the evidence lands on it, "
                     "and call out what's still unproven against it:")
        parts.append(f"  {objective}\n")
    # Operational status — the authoritative live/dead split. The brief LEADS with the
    # active tier; the dead tier is context. This is the fix for burying the live scam
    # under a dormant one just because the dormant one had more findings.
    active = data.get("active_infra") or []
    dead = data.get("dead_infra") or []
    if active or dead:
        parts.append("OPERATIONAL STATUS (lead the brief with the ACTIVE tier; dead is context):")
        parts.append(f"  LIVE / OPERATING NOW: {', '.join(active) or '(none confirmed live)'}")
        parts.append(f"  DEAD / DORMANT: {', '.join(dead) or '(none)'}")
        if active:
            parts.append("  -> The active infrastructure above is the HEADLINE. Do not bury it.\n")
        else:
            parts.append("")
    parts.append("EVIDENCE FROM INVESTIGATION:\n")
    parts.append(f"## Reports analyzed ({len(data['reports'])}):")
    for r in data["reports"]:
        parts.append(f"  - {r['title']} (ingested {r['ingested_at']}) — {r['source_path']}")
    parts.append("")

    for role, items in data["hubs_by_role"].items():
        if not items:
            continue
        parts.append(f"## Cross-report {role}s ({len(items)} appearing in 2+ reports):")
        for it in items[:30]:
            parts.append(f"  - {it['name']} (in {it['reports']} reports: {it['report_titles']})")
        parts.append("")

    # The autonomous investigator's verdicts + findings — the agent did the digging,
    # so the brief must reflect it.
    assessments = data.get("assessments") or []
    if assessments:
        parts.append(f"## Investigator attribution verdicts ({len(assessments)}):")
        for a in assessments[:12]:
            parts.append(f"  - {a.get('attributed_actor','?')} "
                         f"[{a.get('overall_confidence','?')}]: {a.get('best_judgment','')}"
                         + (f" (gaps: {a['collection_gaps']})" if a.get('collection_gaps') else ""))
        parts.append("")
    agent_findings = data.get("agent_findings") or []
    if agent_findings:
        # k4p-03: feed the synthesizer per-TARGET dossiers (grouped by the finding's
        # entity), not a flat one-line list — so it can write connected per-target
        # dossier sections with graded evidence, the 4_points report shape, instead of
        # a fact dump. Each line keeps its confidence so the A–F grading has a basis.
        by_target: dict = {}
        for f in agent_findings:
            tgt = (f.get("title") or "?").strip() or "?"
            # Keep enough of the summary to preserve the trailing "provenance:" text —
            # the SOURCE the A–F grading needs (Codex k4p-03). 220 chars cut it off.
            line = " ".join((f.get("summary") or "").split())[:480]
            by_target.setdefault(tgt, []).append(f"[{f.get('confidence','?')}] {line}")
        _TGT_CAP, _LINE_CAP = 40, 20
        parts.append(f"## WORKED TARGET DOSSIERS — corroborated findings grouped by target "
                     f"({len(by_target)} target(s)). Write one dossier subsection per target:")
        for tgt, lines in list(by_target.items())[:_TGT_CAP]:
            parts.append(f"  ### DOSSIER: {tgt}")
            for ln in lines[:_LINE_CAP]:
                parts.append(f"      - {ln}")
            if len(lines) > _LINE_CAP:
                # No silent caps (token-discipline rule): say what was dropped.
                parts.append(f"      - (+{len(lines) - _LINE_CAP} more finding(s) on this "
                             f"target omitted for length)")
        if len(by_target) > _TGT_CAP:
            parts.append(f"  (+{len(by_target) - _TGT_CAP} more target(s) with findings "
                         f"omitted for length — present the {_TGT_CAP} above)")
        parts.append("")
    agent_leads = data.get("agent_leads") or []
    if agent_leads:
        parts.append(f"## Investigator LEADS — UNVERIFIED, single-source ({len(agent_leads)}):")
        parts.append("(Treat as leads, NOT confirmed fact. Present them as such in the brief — "
                     "they need corroboration before relying on them.)")
        for f in agent_leads[:40]:
            line = " ".join((f.get("summary") or f.get("title") or "").split())[:220]
            parts.append(f"  - [{f.get('confidence','?')}] {line}")
        parts.append("")

    if data["dossiers"]:
        parts.append(f"## Existing dossiers ({len(data['dossiers'])}):\n")
        for name, content in list(data["dossiers"].items())[:30]:
            snippet = content[:1500]
            parts.append(f"--- DOSSIER: {name} ---\n{snippet}\n")
        if len(data["dossiers"]) > 30:
            parts.append(f"... and {len(data['dossiers']) - 30} more dossiers in vault/profiles/")
    parts.append("")
    parts.append("Produce the synthesis brief now. Markdown only. "
                 "Use exact section headers from your instructions.")
    return "\n".join(parts)


def run(conn, vault_dir: Path, case: str | None = None) -> Path:
    data = _gather_brief_data(conn, vault_dir, case=case)
    if not data["reports"]:
        scope = f" for case '{case}'" if case else ""
        raise RuntimeError(f"No reports{scope} — nothing to synthesize")

    label = f" (case: {case})" if case else ""
    print(f"Synthesizing{label} across {len(data['reports'])} reports, "
          f"{sum(len(v) for v in data['hubs_by_role'].values())} cross-report hubs, "
          f"{len(data['dossiers'])} existing dossiers…")
    prompt = _build_prompt(data)
    brief_md = llm.ask(prompt, system=SYSTEM, timeout=300)

    # Per-case briefs live in their own file so they never overwrite the global
    # one (or each other). The web route picks the right file per active case.
    out_path = vault_dir / (f"synthesis-{case}.md" if case else "synthesis.md")
    header = [
        "---",
        "title: Synthesis brief" + (f" — {case}" if case else ""),
        "type: synthesis",
        "tags: [synthesis, brief]",
        f"reports: {len(data['reports'])}",
    ]
    if case:
        header.append(f"investigation: {case}")
    header.append("---\n")
    out_path.write_text("\n".join(header) + brief_md + "\n", encoding="utf-8")
    return out_path
