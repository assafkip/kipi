"""Deterministic infra enumeration — the Shape C engine (Stage 1, speed/cost rollout).

One call runs the whole mechanical recipe over a case's seeds in CODE: each seed gets
its type-appropriate infra belt (crt.sh + whois/RDAP + DNS for domains; reverse-DNS +
ipgeo for IPs; reverse-whois for emails), results promote to nodes + typed edges via
the SAME promote path the node dropdown uses (one graph-writer, no drift), then the
tier-2 infra those lookups surfaced (new IPs / registrant emails) gets belted once.
Zero LLM calls — the caller gets a compact digest; judgment stays on the LLM.

Wired as: `./invctl enumerate <case>` (CLI) and the `enumerate_infra` MCP tool the
agent calls instead of dispatching ~13 lookups turn by turn.

Plan: q-system/output/plans/speed-cost-staged-rollout-2026-06-09.md (Stage 1)
"""
from __future__ import annotations

from investigations.storage import db

TIER2_TYPES = ("ip", "email")
MAX_SEEDS = 25
MAX_TIER2 = 15


def _case_entity_names(conn, case: str, types: tuple[str, ...]) -> list[str]:
    """In-case entity names of the given types (mention- or first-seen-scoped)."""
    ph = ",".join("?" * len(types))
    rows = conn.execute(
        f"SELECT DISTINCT e.canonical_name FROM entities e "
        f"WHERE e.hidden = 0 AND e.entity_type IN ({ph}) "
        "AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%') "
        "AND (e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
        "              ON r.id = m.report_id WHERE r.investigation = ?) "
        "     OR e.first_seen_report_id IN "
        "        (SELECT id FROM reports WHERE investigation = ?))",
        (*types, case, case)).fetchall()
    return [r["canonical_name"] for r in rows]


def _materialize_property_nodes(conn, case: str, on_event=None) -> list[str]:
    """The deterministic edges from the recipe table: an in-case entity's `a_record`
    property becomes a real ip node + `resolves_to` edge; a `registrant` that is an
    email becomes an email node + `registered_by` edge. These are facts the lookups
    already landed as properties — connecting them needs no judgment. Idempotent
    (upsert + INSERT OR IGNORE). Returns the materialized names."""
    from investigations.enrich.promote import _enrichment_report
    from investigations.ingest import extractor as _ex
    rows = conn.execute(
        "SELECT np.entity_id, np.key, np.value FROM node_properties np "
        "JOIN entities e ON e.id = np.entity_id "
        "WHERE np.key IN ('a_record', 'registrant') AND e.hidden = 0 "
        "AND (e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
        "              ON r.id = m.report_id WHERE r.investigation = ?) "
        "     OR e.first_seen_report_id IN "
        "        (SELECT id FROM reports WHERE investigation = ?))",
        (case, case)).fetchall()
    made: list[str] = []
    rep_id = _enrichment_report(conn, case) if rows else None
    for r in rows:
        value = (r["value"] or "").strip()
        if r["key"] == "a_record" and _ex.IPV4_RE.fullmatch(value):
            etype, rel = "ip", "resolves_to"
        elif r["key"] == "registrant" and _ex.EMAIL_RE.fullmatch(value):
            etype, rel = "email", "registered_by"
        else:
            continue
        # Entity-admission contract (RCA rca-recurring-graph-noise-2026-06-11): the
        # store gates pipeline-actor creations, so a whois/DNS result can't
        # materialize boilerplate (a registry email, etc.) as a node.
        from investigations import store
        created = store.apply_mutation(conn, store.entity_upserted(
            case, value, etype, rep_id, actor="pipeline:enrich",
            provenance="enrich:infra"))
        if not created["applied"]:
            continue
        eid = created["entity_id"]
        db.add_mention(conn, eid, rep_id, value, "deterministic enumeration")
        if eid != r["entity_id"]:
            store.apply_mutation(conn, store.edge_upserted(
                case, r["entity_id"], eid, rel, actor="pipeline:enrich",
                evidence=f"{r['key']} via infra lookup",
                provenance="enrich:infra"))
            made.append(value)
            if on_event:
                on_event(f"materialized: {rel} → {value}")
    return made


def _belt_one(conn, name: str, case: str, analyst: str, on_event, cancel) -> tuple[list[int], list[str]]:
    """Run one entity's type belt + promote the results. Returns (result ids, ran slugs).
    A seed the DB hasn't met yet (the agent just surfaced it) is classified + created
    first — the gate run proved unknown seeds otherwise no-op the whole sweep."""
    from investigations.agent.investigator import _promote_infra_results, _run_infra_belt
    from investigations.enrich.promote import _classify, _enrichment_report
    row = conn.execute(
        "SELECT entity_type FROM entities WHERE canonical_name = ?", (name,)).fetchone()
    if row:
        etype = row["entity_type"]
    else:
        etype = _classify(name)
        if etype == "indicator":
            return [], []   # not a beltable artifact (prose, partial name) — skip
        rep_id = _enrichment_report(conn, case)
        from investigations import store
        # gate=False: the agent-surfaced seed was never gated here pre-migration
        # (the _classify 'indicator' skip above is the only filter). Preserved.
        eid = store.apply_mutation(conn, store.entity_upserted(
            case, name, etype, rep_id, actor="pipeline:enrich",
            provenance="enrich:infra", gate=False))["entity_id"]
        db.add_mention(conn, eid, rep_id, name, "enumeration seed")
    result_ids, ran = _run_infra_belt(conn, name, etype, case,
                                      on_event=on_event, cancel=cancel)
    if result_ids:
        _promote_infra_results(conn, result_ids, analyst)
    return result_ids, ran


def enumerate_infra(conn, case: str, seeds: list[str] | None = None,
                    analyst: str = "agent", on_event=None, cancel=None) -> dict:
    """Deterministically enumerate a case's infra graph. Idempotent: the belt's
    run_and_persist + promote paths upsert, so a re-run lands no duplicates."""
    from investigations.agent import swarm
    from investigations.agent.investigator import _infra_digest
    swarm.ensure_seed_domains(conn, case)
    if seeds is None:
        seeds = swarm._targets(conn, case, MAX_SEEDS)
    seeds = list(seeds)[:MAX_SEEDS]
    belted: set[str] = set()
    all_results: list[int] = []
    skipped: list[str] = []

    def _cancelled() -> bool:
        return cancel is not None and cancel.is_set()

    for name in seeds:
        if _cancelled():
            break
        rids, ran = _belt_one(conn, name, case, analyst, on_event, cancel)
        belted.add(name.lower())
        all_results.extend(rids)
        if not ran:
            skipped.append(name)

    # The deterministic edges tier 1's lookups imply (a_record → resolves_to,
    # registrant email → registered_by) become real nodes + edges — no judgment needed.
    _materialize_property_nodes(conn, case, on_event=on_event)

    # Tier 2: the IPs / registrant emails tier 1 just surfaced get ONE belt pass —
    # bounded, no recursion beyond this (depth is the agent's call, not code's).
    tier2 = [n for n in _case_entity_names(conn, case, TIER2_TYPES)
             if n.lower() not in belted][:MAX_TIER2]
    for name in tier2:
        if _cancelled():
            break
        rids, _ = _belt_one(conn, name, case, analyst, on_event, cancel)
        belted.add(name.lower())
        all_results.extend(rids)

    return {
        "case": case,
        "seeds": seeds,
        "tier2": tier2,
        "results": len(all_results),
        "skipped_no_recipe": skipped,
        "digest": _infra_digest(conn, all_results),
    }
