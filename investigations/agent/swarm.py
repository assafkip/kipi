"""Swarm volley — parallel OSINT investigation across a case's entities, and the
deep-investigate loop (the swarm x ultracode fusion).

- plan_investigation: the persona pass — a senior investigator reads the case and
  DECIDES the targets (replaces the old ORDER BY threat_score sort).
- volley: fan out the investigator agent over many targets at once (the 4_points
  first-volley -> parallel -> merge pattern). Findings auto-promote to the graph.
- deep_investigate: volley -> adversarial verify each finding -> loop on the new
  pivots the findings surfaced, until a round adds nothing (loop-until-dry). This
  is the in-app version of the ultracode workflow pattern: breadth (swarm) x depth
  (verify + iterate).

Each parallel worker opens its OWN db connection (SQLite is not thread-shareable).
Concurrency + target caps keep cost bounded — every agent run costs tokens.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from investigations.storage import db
from investigations.agent import investigator
from investigations.llm import client as llm


def _url_host(url: str) -> str:
    """Bare host for a URL seed (https://trumpstake.us/ -> trumpstake.us), '' on junk.
    Used to fold a url-typed seed into a domain roster target so it gets worked."""
    try:
        net = urlparse(url if "://" in url else "//" + url).netloc.lower()
    except Exception:
        return ""
    net = net.split("@")[-1].split(":")[0]  # strip userinfo + port
    return net[4:] if net.startswith("www.") else net

# The planning pass runs in persona: a senior investigator reading the case and
# deciding where collection effort is worth spending — NOT a SQL score sort.
PLANNER_SYSTEM = (
    "You are a Senior Staff Investigator in Security, Safety & Fraud at a FAANG-tier "
    "technology company. You run OSINT investigations end-to-end: you read a case, form "
    "a theory, and decide where collection effort is worth spending. You are precise, "
    "skeptical, and cost-aware. You do not chase noise. You prioritize the load-bearing "
    "nodes — hubs, operator personas, shared infrastructure, money rails — the entities "
    "whose exposure unravels the network. You output a concrete, prioritized plan."
)

# Entity types worth an autonomous investigation (assets with a pivot surface).
# Standalone investigation targets only. Fingerprint/infrastructure types
# (tracking_tag, walletconnect_id, nameserver) are deliberately EXCLUDED: they aren't
# investigated on their own — the domain/wallet that USES them surfaces them, and the
# deterministic fingerprint correlation (Process → cross-domain links) connects every
# entity sharing one. Targeting them separately just re-investigated the same domain in
# parallel and doubled the VirusTotal / crt.sh hits.
TARGET_TYPES = ("domain", "ip", "handle", "telegram_channel", "crypto_wallet", "email")
DEFAULT_LIMIT = 12          # cap targets per volley
DEFAULT_CONCURRENCY = 2     # 2-wide, not 4: 4 agents hammering one IP got Reddit to
                            # 403-block us and tripped VirusTotal's 4/min limit. Fewer
                            # simultaneous external calls = far less self-throttling.
# CREW DECISION (settled, prd-spine-phase0 2026-06-11): the swarm runs PARALLEL
# across targets and SEQUENTIAL within one target. Targets are independent
# units (each parallel worker opens its OWN sqlite connection, see module
# docstring), so parallelism there is safe, bounded by DEFAULT_CONCURRENCY and
# the shared provider rate limits. Within a single target the investigator is
# ONE sequential agent — fanning out interdependent slices of one
# investigation wastes tokens and worsens results (the batch-fanout lesson:
# only batch INDEPENDENT units). Change this comment if either direction is
# ever re-decided; code and rationale move together.
# PRD-09 depth engine — deeper than the old single-volley, but HARD-BOUNDED on cost so
# a whole-case run can't surprise you with a $50 bill. The dollar cap is the real
# ceiling; the round/entity caps just keep it sane. The loop stops when it's DRY, hits
# the $ cap, or hits the round/entity cap — and it SAYS which (never silent).
import os as _os
MAX_ROUNDS = 5              # loop-until-dry round cap. Spec value: the PRD-09 depth
                            # engine fixed 5; the constant shipped as 3 and drifted
                            # unnoticed (gap 1, prd-spine-phase0 2026-06-11). Pinned by
                            # tests/test_spec_conformance.py — change BOTH or the build
                            # goes red. The $ cap stays the real ceiling.
DEEP_TURNS = int(_os.environ.get("KIPI_DEEP_TURNS", "40"))  # per-target tool-call budget.
                           # Raised 20->40: a browser-heavy dig was burning all 20 turns
                           # and getting CAPPED before it could emit findings. The $ cap
                           # (DEEP_COST_CAP_USD) is the real ceiling, so more turns is safe.
DEEP_ENTITY_BUDGET = 20    # max DISTINCT entities a single deep run will investigate.
# Dollar budget per whole-case deep run. It's turned into a TARGET budget up front so the
# run commits to a scope it can FINISH (no dying mid-investigation); cost ≈ targets ×
# per-target. Override with KIPI_DEEP_COST_CAP (e.g. 2 or 15).
DEEP_COST_CAP_USD = float(_os.environ.get("KIPI_DEEP_COST_CAP", "5"))
# Rough cost of one target's agent run (used to size the target budget from the $ cap).
EST_COST_PER_TARGET = float(_os.environ.get("KIPI_EST_COST_PER_TARGET", "0.9"))
# Rough cost of a single ONE-HOP expand: deterministic infra belt (whois/dns/crtsh, free)
# + one capped suggest-next-hop LLM call. Tiny, but not zero — show it honestly.
EST_COST_PER_ONE_HOP = float(_os.environ.get("KIPI_EST_COST_PER_ONE_HOP", "0.01"))


def _targets(conn, case: str | None, limit: int) -> list[str]:
    """High-value entities to investigate: pivotable types, top by threat score,
    skipping noise."""
    scope, params = "", []
    if case:
        scope = ("AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
                 "ON r.id = m.report_id WHERE r.investigation = ?)")
        params.append(case)
    tp = ",".join("?" * len(TARGET_TYPES))
    # covered = already has a successful agent run → push to the BOTTOM so a re-run
    # spends its budget on NEW targets first instead of repeating the same volley.
    rows = conn.execute(
        f"SELECT e.canonical_name, "
        f"  (SELECT 1 FROM enrichment_runs er WHERE er.entity_id = e.id "
        f"   AND er.provider_slug = 'agent' AND er.status = 'success' LIMIT 1) AS covered "
        f"FROM entities e LEFT JOIN entity_scores s ON s.entity_id = e.id "
        f"WHERE e.entity_type IN ({tp}) "
        f"AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%') {scope} "
        f"ORDER BY COALESCE(covered,0) ASC, COALESCE(s.threat_score,0) DESC, e.id LIMIT ?",
        (*TARGET_TYPES, *params, limit)).fetchall()
    return [r["canonical_name"] for r in rows]


def _case_roster(conn, case: str | None, cap: int = 40) -> list[dict]:
    """The investigable entities the planner chooses from: anything with an OSINT
    pivot surface, non-noise, with its role + score as context. Score only CAPS the
    candidate list to a sane size — the planner does the actual selection by judgment,
    not by score."""
    scope, params = "", []
    if case:
        scope = ("AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
                 "ON r.id = m.report_id WHERE r.investigation = ?)")
        params.append(case)
    tp = ",".join("?" * len(TARGET_TYPES))
    rows = conn.execute(
        f"SELECT e.canonical_name, e.entity_type, e.notes, COALESCE(s.threat_score,0) AS score, "
        f"  (SELECT 1 FROM enrichment_runs er WHERE er.entity_id = e.id "
        f"   AND er.provider_slug = 'agent' AND er.status = 'success' LIMIT 1) AS covered "
        f"FROM entities e LEFT JOIN entity_scores s ON s.entity_id = e.id "
        f"WHERE e.entity_type IN ({tp}) "
        f"AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%') {scope} "
        f"ORDER BY COALESCE(covered,0) ASC, score DESC, e.id LIMIT ?",
        (*TARGET_TYPES, *params, cap)).fetchall()
    out = []
    seen = set()
    for r in rows:
        role = (r["notes"] or "").split(" — ")[0].replace("role:", "").strip() or "?"
        out.append({"name": r["canonical_name"], "type": r["entity_type"], "role": role,
                    "covered": bool(r["covered"])})
        seen.add(r["canonical_name"].lower())
    # A user seed handed in as a URL (e.g. https://trumpstake.us/) is stored as a
    # `url` entity, which is NOT a TARGET_TYPE — so it would silently drop off the
    # roster and never get worked (the case-031 second-seed miss). Host-normalize
    # in-scope url entities into domain targets so EVERY seed reaches the roster.
    url_rows = conn.execute(
        "SELECT DISTINCT e.canonical_name FROM entities e "
        "WHERE e.entity_type = 'url' "
        "AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%') " + scope,
        params).fetchall()
    for r in url_rows:
        host = _url_host(r["canonical_name"])
        if host and host.lower() not in seen:
            seen.add(host.lower())
            out.append({"name": host, "type": "domain", "role": "seed", "covered": False})
    return out


def ensure_seed_domains(conn, case: str | None) -> int:
    """Seed-persistence contract (k4p-01, addresses Codex finding-3): a user seed handed
    in as a URL is stored as a `url` entity, whose host never becomes a first-class
    domain NODE — so it drops off the roster AND any relationship the agent emits to the
    bare host (`trumpstake.us`) can't resolve and the edge is silently dropped (the
    case-031 second-seed miss). Materialize a `domain` entity + in-case mention for every
    in-scope url host, so every seed is a real node the agent works and edges link to.
    Idempotent (upsert + INSERT-guarded mention). Returns how many domains it added."""
    if not case:
        return 0
    # The report MUST be one IN THIS CASE (Codex k4p-01): an un-scoped report_id could
    # attach the host-domain mention to another case's report.
    rows = conn.execute(
        "SELECT DISTINCT e.canonical_name, "
        "  (SELECT m.report_id FROM mentions m JOIN reports r ON r.id = m.report_id "
        "   WHERE m.entity_id = e.id AND r.investigation = ? LIMIT 1) AS rep "
        "FROM entities e "
        "WHERE e.entity_type = 'url' "
        "AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%') "
        "AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
        "             ON r.id = m.report_id WHERE r.investigation = ?)",
        (case, case)).fetchall()
    added = 0
    for r in rows:
        host = _url_host(r["canonical_name"])
        rep = r["rep"]
        if not host or rep is None:
            continue
        from investigations import store
        # gate=False: this path never gated pre-migration (hosts derive from
        # in-case urls already past extraction admission). Tightening is
        # Phase 3+ work, not this migration (behavior preserved verbatim).
        eid = store.apply_mutation(conn, store.entity_upserted(
            case, host, "domain", rep, actor="pipeline:swarm",
            gate=False))["entity_id"]
        # Always ensure the host domain has a mention IN THIS CASE (Codex k4p-01): if the
        # entity already exists globally we must STILL scope it into this case, or it's
        # absent from the case roster + the scope-bound roster and gets denied in caged
        # runs despite being shown as a target. Idempotent: add only when missing here.
        in_case = conn.execute(
            "SELECT 1 FROM mentions m JOIN reports r ON r.id = m.report_id "
            "WHERE m.entity_id = ? AND r.investigation = ? LIMIT 1", (eid, case)).fetchone()
        if not in_case:
            db.add_mention(conn, eid, rep, host, "seed (url host)")
            added += 1
    if added:
        conn.commit()
    return added


def plan_investigation(conn, case: str | None, limit: int = DEFAULT_LIMIT) -> tuple[list[str], dict]:
    """The planning pass: a senior investigator reads the case theory + entity roster
    and DECIDES who to investigate, in priority order, with the questions to answer —
    replacing the old `ORDER BY threat_score` sort. Returns (target_names, plan_meta).
    Falls back to the deterministic _targets() seed if the LLM plan is unavailable,
    so the swarm always runs."""
    roster = _case_roster(conn, case)
    if not roster:
        return [], {"source": "none"}
    theory = ""
    try:
        row = conn.execute("SELECT schema_json FROM case_schemas WHERE case_slug = ?",
                           (case,)).fetchone()
        if row:
            import json as _json
            s = _json.loads(row["schema_json"])
            theory = f"{s.get('domain','')} — {s.get('summary','')}".strip(" —")
    except Exception:
        theory = ""
    roster_lines = "\n".join(
        f"- {e['name']}  (type={e['type']}, role={e['role']}"
        + (", ALREADY INVESTIGATED — skip unless a fresh angle" if e.get("covered") else "")
        + ")" for e in roster)
    prompt = (
        f"CASE THEORY: {theory or 'uncharacterized'}\n\n"
        f"INVESTIGABLE ENTITIES (each has an OSINT pivot surface):\n{roster_lines}\n\n"
        f"Decide which of these warrant active OSINT investigation (whois / DNS / domain "
        f"pivots / social / search), in PRIORITY order. Pick the load-bearing targets; "
        f"skip the low-value ones. Cap your list at {limit}. For each target, give a "
        f"one-line reason and the specific questions to answer.\n\n"
        f'Output JSON only: {{"plan":[{{"entity":"<name EXACTLY as listed above>",'
        f'"why":"<one line>","questions":["..."]}}],'
        f'"skip_rationale":"<why you skipped the rest>","stop_when":"<when to stop>"}}')
    names = {e["name"] for e in roster}
    try:
        raw = llm.ask_json(prompt, system=PLANNER_SYSTEM, timeout=180)
        targets, seen = [], set()
        for item in (raw.get("plan") or []):
            nm = (item.get("entity") or "").strip()
            if nm in names and nm.lower() not in seen:
                seen.add(nm.lower())
                targets.append(nm)
        targets = targets[:limit]
        if targets:
            return targets, {"source": "agent-plan", "plan": raw.get("plan"),
                             "skip_rationale": raw.get("skip_rationale"),
                             "stop_when": raw.get("stop_when")}
    except Exception:
        pass
    return _targets(conn, case, limit), {"source": "fallback-sql"}


def tool_status() -> dict:
    """Which OSINT tools the agent can actually use right now, so a degraded (no-key)
    run isn't a silent surprise. 'live' = usable (free tools + ones with a key);
    'missing' = needs a key that isn't set. Surfaced PRE-RUN by the Investigate page."""
    from investigations.enrich.registry import all_adapters
    live, missing = [], []
    for a in all_adapters():
        name = getattr(a, "display_name", "") or a.slug
        if a.is_configured():
            live.append(name)
        else:
            missing.append({"slug": a.slug, "name": name, "env_var": a.env_var})
    return {"live": sorted(live), "missing": missing,
            "live_count": len(live), "missing_count": len(missing)}


def _investigate_one(entity: str, case: str | None, max_turns: int,
                     on_event=None) -> dict:
    """Worker: own connection, investigate one entity, land gated. Each live line is
    prefixed with the target so the interleaved parallel streams stay readable.

    migrate=False: the schema is already migrated by the caller's connection. If
    every parallel worker re-ran the migration (DDL) on connect, they'd collide on
    the schema write lock → 'database is locked'. Workers only read + write rows."""
    tagged = (lambda line: on_event(f"{entity} · {line}")) if on_event else None
    # UNTAGGED per-target start signal: fires when this worker thread actually picks the
    # target up (not when it was queued), so the progress parser can flip THIS target to
    # `running`. Must NOT match any aggregate-parse marker (picked/✓/✗/crew merged) — it
    # starts with "→ start " which none of those do (run-progress-semantics, finding-4).
    if on_event:
        on_event(f"→ start {entity}")
    try:
        with db.connect(migrate=False) as conn:
            # Boss + crew: each target is investigated by focused parallel sub-agents
            # (infra/reputation/page/attribution), not one giant agent (rebuild 2026-06-03).
            # Set KIPI_SINGLE_AGENT=1 to fall back to the old single-agent per target.
            if _os.environ.get("KIPI_SINGLE_AGENT") == "1":
                return investigator.investigate_entity(conn, entity, case=case,
                                                       max_turns=max_turns, on_event=tagged)
            return investigator.investigate_entity_crew(conn, entity, case=case,
                                                        on_event=tagged)
    except Exception as exc:
        return {"ok": False, "entity": entity, "error": str(exc)[:200]}


def volley(conn, case: str | None, targets: list[str], max_turns: int = DEEP_TURNS,
           concurrency: int = DEFAULT_CONCURRENCY, on_event=None) -> list[dict]:
    """Run the investigator agent over `targets` in parallel. Returns per-target
    results (gated findings already landed by each worker)."""
    if not targets:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = {pool.submit(_investigate_one, t, case, max_turns, on_event): t
                for t in targets}
        for fut in as_completed(futs):
            r = fut.result()
            if on_event:
                ent = r.get("entity", "?")
                on_event(f"✓ {ent}: {r.get('findings', 0)} finding(s)" if r.get("ok")
                         else f"✗ {ent}: {r.get('error', 'failed')}")
            results.append(r)
    return results


def investigate_selected(conn, case: str | None, targets: list[str],
                         max_turns: int = DEEP_TURNS, concurrency: int = DEFAULT_CONCURRENCY,
                         on_event=None) -> dict:
    """Run the FULL investigator agent on an explicit, analyst-chosen set of targets —
    no planner. This is PRD-07: 'run a full investigation on specific nodes, more than
    one at a time.' Unlike a planner-driven whole-case run, the analyst picks; covered
    nodes are NOT skipped (an explicit pick overrides any skip). Dedupes + caps the set."""
    seen, clean = set(), []
    for t in targets:
        t = (t or "").strip()
        if t and t.lower() not in seen:
            seen.add(t.lower())
            clean.append(t)
    clean = clean[:DEFAULT_LIMIT]
    if not clean:
        if on_event:
            on_event("no targets selected")
        return {"ok": True, "case": case, "targets": 0, "note": "no targets selected"}
    # Emit the same "picked N" marker the live progress bar parses so it shows
    # targets_total (parsed by the web job's _update_progress).
    if on_event:
        on_event(f"picked {len(clean)} target(s): {', '.join(clean)}")
    results = volley(conn, case, clean, max_turns=max_turns,
                     concurrency=concurrency, on_event=on_event)
    ok = [r for r in results if r.get("ok")]
    findings = sum(r.get("findings", 0) for r in ok)
    promoted = sum(r.get("promoted", 0) for r in ok)
    from investigations import activity as activity_mod
    activity_mod.log(conn, "agent-swarm", f"investigated {len(ok)} analyst-selected "
                     f"target(s), {findings} findings, {promoted} graph nodes",
                     investigation=case)
    return {"ok": True, "case": case, "targets": len(clean),
            "investigated": len(ok), "failed": len(results) - len(ok),
            "findings": findings, "promoted": promoted, "tools": tool_status(),
            "results": results}


# --- deep investigate: volley -> verify -> loop-until-dry ---------------------

def _uninvestigated_targets(conn, case: str | None, seen: set[str],
                            limit: int) -> list[str]:
    """The case's pivotable entities NOT yet investigated this run — the inventory the
    next round chases. This is every promotable asset type (domains, IPs, handles,
    crypto wallets, telegram channels, emails — TARGET_TYPES), so the fan-out picks up
    the wallets and sibling domains a prior round promoted into the graph, not just one
    finding field.

    Pivoting off the INVENTORY instead of the last round's parsed findings is the fix
    for the false-'exhausted' stop: a tool-degraded round that surfaced little no longer
    looks dry — the loop keeps going on real untried targets and only stops when the
    inventory is genuinely empty (or a budget/round cap). It recovers silently."""
    return [t for t in _targets(conn, case, limit) if t.lower() not in seen]


def _historical_per_target(conn) -> tuple[float | None, str]:
    """Average real $/target from past agent runs, for a data-grounded point estimate.
    Returns (avg, basis): (avg, 'historical') when there's prior agent spend to learn from,
    else (None, 'cold-start')."""
    try:
        row = conn.execute(
            "SELECT AVG(cost_usd) FROM enrichment_runs "
            "WHERE provider_slug = 'agent' AND cost_usd IS NOT NULL AND cost_usd > 0"
        ).fetchone()
    except Exception:
        return None, "cold-start"
    avg = row[0] if row else None
    return (float(avg), "historical") if avg else (None, "cold-start")


def _historical_seconds_per_target(conn) -> tuple[float | None, str]:
    """Average real wall-clock SECONDS/target from past agent runs — the time sibling of
    `_historical_per_target`, used to ground a live ETA on the run card. Each agent
    `enrichment_runs` row is per-target (one `entity_id` per investigation call, see
    `investigator.add_findings`), so AVG(elapsed) IS per-target — no normalization needed.

    Filters `finished_at > started_at` to drop legacy cost-blind rows where `started_at`
    fell back to CURRENT_TIMESTAMP (==finished_at, elapsed 0), exactly as the $ sibling
    filters `cost_usd > 0`. Returns (avg_secs, basis): ('historical') when there's prior
    timed spend to learn from, else (None, 'cold-start') so the caller shows no ETA rather
    than a fabricated one."""
    try:
        row = conn.execute(
            "SELECT AVG(strftime('%s', finished_at) - strftime('%s', started_at)) "
            "FROM enrichment_runs "
            "WHERE provider_slug = 'agent' AND started_at IS NOT NULL "
            "AND finished_at > started_at"
        ).fetchone()
    except Exception:
        return None, "cold-start"
    avg = row[0] if row else None
    return (float(avg), "historical") if avg else (None, "cold-start")


def estimate_run(conn, case: str | None, deep: bool = True, *,
                 budget: int = DEEP_ENTITY_BUDGET, limit: int = DEFAULT_LIMIT,
                 cost_cap: float = DEEP_COST_CAP_USD) -> dict:
    """SINGLE source of truth for a run's pre-launch cost estimate. deep_investigate's own
    post-launch 'plan' line calls this too, so the before-run line and the during-run line
    can never contradict (cost transparency — the founder sees the bill before committing,
    not a surprise after).

    Returns a POINT estimate (`est_typical_usd`) — the expected spend, grounded in the
    historical average $/target when available — plus `cost_cap_usd` (the hard ceiling that
    bounds the worst case) and `basis` (how the typical was derived). NEVER used to block a
    run (cost-model-budget-the-scope rule); it's informational only.

    deep=False (one-hop expand): a fixed tiny estimate (free infra belt + one suggest call)."""
    if not deep:
        return {"deep": False, "est_targets": 1,
                "est_typical_usd": round(EST_COST_PER_ONE_HOP, 4),
                "cost_cap_usd": None, "basis": "one-hop-fixed"}
    # Same cap→target-budget math deep_investigate uses, so est_targets matches the run.
    eff_budget = budget
    if cost_cap:
        eff_budget = min(budget, max(1, int(cost_cap / max(EST_COST_PER_TARGET, 0.1))))
    avg, basis = _historical_per_target(conn)
    per_target = avg if avg else EST_COST_PER_TARGET
    return {"deep": True, "est_targets": eff_budget,
            "est_typical_usd": round(eff_budget * per_target, 2),
            "cost_cap_usd": cost_cap, "basis": basis}


def deep_investigate(conn, case: str | None, max_turns: int = DEEP_TURNS,
                     concurrency: int = DEFAULT_CONCURRENCY,
                     limit: int = DEFAULT_LIMIT, rounds: int = MAX_ROUNDS,
                     budget: int = DEEP_ENTITY_BUDGET, on_event=None,
                     cost_cap: float = DEEP_COST_CAP_USD) -> dict:
    """PRD-09 depth engine: plan targets, volley, then CHASE the new pivots the findings
    surface — round after round — until the trail goes cold (a round adds nothing new),
    the entity budget is hit, or the round cap is hit. The agent builds the graph as it
    goes (findings auto-promote). Streams each round via on_event so progress is live.

    Stops are explicit in the RESULT (`exhausted` = inventory genuinely dry; `budget`/
    `capped`/`cost-capped` = a ceiling hit with leads still open) — used by the post-run
    summary, never narrated mid-run as a "got stuck" message."""
    seen: set[str] = set()
    all_rounds, all_results = [], []
    spent = 0.0
    # Turn the DOLLAR cap into a TARGET budget up front so the run commits to a scope it
    # can finish — instead of running blind and getting axed mid-investigation. The cost
    # is then predictable (≈ targets × per-target) and the run always completes its plan.
    # Use the SHARED estimator so this run's scope + the pre-run estimate line are identical
    # (no before/after drift). est_targets is the cost-derived target budget.
    est = estimate_run(conn, case, deep=True, budget=budget, limit=limit, cost_cap=cost_cap)
    eff_budget = est["est_targets"]
    targets, _plan = plan_investigation(conn, case, limit)
    if on_event:
        # Tell the analyst the scope AND the dollar estimate up front (cost
        # transparency — they see the bill before a deep run, not after).
        on_event(f"plan: up to {eff_budget} targets this run (est ~${est['est_typical_usd']:.2f})")
    stop = "exhausted"
    for rnd in range(rounds):
        # Take only as many fresh targets as the (cost-derived) budget allows. We finish
        # whatever we start — the budget caps the SCOPE, it never kills a run mid-target.
        targets = [t for t in targets if t.lower() not in seen]
        room = eff_budget - len(seen)
        if room <= 0:
            stop = "budget"   # investigated the planned scope; more leads may remain
            break
        targets = targets[:min(limit, room)]
        if not targets:
            break
        if on_event:
            on_event(f"round {rnd + 1}: chasing {len(targets)} target(s) "
                     f"[{len(seen)}/{eff_budget} investigated]")
        for t in targets:
            seen.add(t.lower())
        results = volley(conn, case, targets, max_turns=max_turns,
                         concurrency=concurrency, on_event=on_event)
        spent += sum((r.get("cost_usd") or 0.0) for r in results)
        all_results.extend(results)
        all_rounds.append({"round": rnd + 1, "targets": len(targets),
                           "investigated": sum(1 for r in results if r.get("ok"))})
        # Runaway backstop: only if real per-target cost ran FAR over the estimate
        # (the budget normally bounds us first). Finishes the round, then stops.
        if cost_cap and spent > cost_cap * 1.5:
            stop = "cost-capped"
            if on_event:
                on_event("stopped: this run reached its planned scope")
            break
        # Next round chases the case's UNINVESTIGATED pivotable inventory — the
        # siblings/wallets/etc this round promoted into the graph, plus whatever the
        # planner left for later. Inventory, not last round's parsed findings: a
        # tool-degraded round never looks falsely "exhausted". The loop keeps going on
        # real untried targets and stops only when the inventory is genuinely empty
        # (or budget/round cap). No "stalled / got stuck" chatter — it just continues.
        with db.connect() as c2:
            next_targets = _uninvestigated_targets(c2, case, seen, limit + len(seen))
        if not next_targets:
            stop = "exhausted"   # genuinely nothing left to investigate in the case
            break
        if rnd + 1 >= rounds:
            stop = "capped"      # round cap hit with leads still open (no narration)
        targets = next_targets
    ok = [r for r in all_results if r.get("ok")]
    findings = sum(r.get("findings", 0) for r in ok)
    promoted = sum(r.get("promoted", 0) for r in ok)
    from investigations import activity as activity_mod
    activity_mod.log(conn, "agent-swarm",
                     f"deep investigation: {len(all_rounds)} round(s), {len(seen)} target(s), "
                     f"{findings} findings, ${spent:.2f} ({stop})", investigation=case)
    return {"ok": True, "case": case, "deep": True, "stop": stop,
            "rounds": all_rounds, "round_count": len(all_rounds),
            "targets": len(seen), "investigated": len(ok),
            "findings": findings, "promoted": promoted, "cost_usd": round(spent, 2),
            "cost_cap": cost_cap, "tools": tool_status(),
            "results": all_results}
