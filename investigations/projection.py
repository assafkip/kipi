"""The projection layer (sp3, prd-spine-phase3): derived state is a pure
function of the canonical sources.

Canonical: the activity event log + the claims spine + source observations
(reports / mentions / enrichment results). Derived: entity roles/sub_roles,
typed-edge supersessions (claim authority on the graph), entity scores, and
the brief's deterministic input set.

`project(conn, case)` rebuilds the derived surfaces:
    1. genesis      — first projection of a pre-log case records ONE inert
                      audit event carrying the pre-existing digest (never
                      fabricated history)
    2. claim replay — every (entity, predicate)'s authoritative ACTIVE claim
                      (latest report wins — the claims._project_active rule)
                      re-applies through claims._project, which writes ONLY
                      store events
    3. scores       — analyze.compute_threat_scores (deterministic)
    4. digest       — sha256 over canonical JSON of {graph, brief_inputs,
                      scores}

Idempotent by construction: a second project() with no intervening events
re-applies the same authority onto already-correct surfaces and returns an
IDENTICAL digest (the replay gate, tests/test_projection_replay.py).
Projection never writes canonical sources and never calls an LLM — the brief
PROSE stays LLM; its INPUTS are this projection.
"""

from __future__ import annotations

import hashlib
import json

from investigations import store
from investigations.storage import db  # noqa: F401  (connection helpers for callers)

_ROUND = 6
TOP_ENTITIES = 40


# ---------------------------------------------------------------------------
# project
# ---------------------------------------------------------------------------


def project(conn, case: str | None) -> str:
    """Rebuild the derived surfaces for `case` from the canonical sources.
    Returns the post-projection digest. Writes ONLY through store events;
    the caller owns the transaction (claims overrides commit AFTER this
    returns, so a projection failure rolls the whole decision back)."""
    _ensure_genesis(conn, case)
    _replay_claim_authority(conn, case)
    from investigations import analyze
    analyze.compute_threat_scores(conn, commit=False)
    return digest(conn, case)


def _ensure_genesis(conn, case: str | None) -> None:
    """One inert genesis audit event per pre-log case (idempotent): records
    the digest the derived state had when projection first saw it. Honest
    scoping — replay claims start here, never from fabricated history."""
    if not case:
        return
    exists = conn.execute(
        "SELECT 1 FROM activity WHERE investigation = ? AND action = 'report_ingested' "
        "AND json_extract(detail, '$.detail.genesis') = 1 LIMIT 1",
        (case,)).fetchone()
    if exists:
        return
    store.apply_mutation(conn, store.report_ingested(
        case, None, actor="pipeline:projection",
        detail={"genesis": True, "pre_log_digest": digest(conn, case)}))


def _replay_claim_authority(conn, case: str | None) -> int:
    """Re-apply every authoritative ACTIVE claim to the graph. Authority rule
    is claims._project_active's: per (entity, predicate), the active claim
    with the highest (report_id, id) wins. Deterministic order; writes ride
    claims._project's store events."""
    from investigations import claims
    scope_join, params = "", []
    if case:
        scope_join = ("JOIN mentions m ON m.entity_id = c.entity_id "
                      "JOIN reports r ON r.id = m.report_id "
                      "AND r.investigation = ? ")
        params.append(case)
    rows = conn.execute(
        "SELECT DISTINCT c.* FROM claims c "
        + scope_join +
        "WHERE c.status = 'active' "
        "ORDER BY c.entity_id, c.predicate, c.report_id DESC, c.id DESC",
        params).fetchall()
    applied, seen = 0, set()
    for row in rows:
        key = (row["entity_id"], row["predicate"])
        if key in seen:
            continue  # a lower-priority claim for the same slot — not authoritative
        seen.add(key)
        if _surface_already_matches(conn, dict(row)):
            continue  # CONVERGENT replay: apply only where the surface drifted
                      # (re-applying everything bumped last_seen + spammed the
                      # log every run — codex finding)
        claims._project(conn, dict(row))
        applied += 1
    return applied


def _surface_already_matches(conn, claim) -> bool:
    """True when the derived surface already reflects this claim's authority —
    skipping keeps replay state-idempotent (no row churn, no event spam)."""
    pred, eid = claim["predicate"], claim["entity_id"]
    val = (claim["value"] or "").strip()
    if pred == "role":
        row = conn.execute("SELECT notes, sub_role FROM entities WHERE id=?",
                           (eid,)).fetchone()
        if not row:
            return True  # entity gone — nothing to project onto
        from investigations.claims import CANONICAL_ROLES, CANONICAL_SUBROLES
        if val in CANONICAL_ROLES:
            # Exact role with a hard boundary: 'role:infra' must NOT match a
            # drifted 'role:infra_provider' (codex adversarial).
            notes = row["notes"] or ""
            return notes == f"role:{val}" or notes.startswith(f"role:{val} — ")
        if val in CANONICAL_SUBROLES:
            return (row["sub_role"] == val
                    and (conn.execute(
                        "SELECT sub_role_reason FROM entities WHERE id=?",
                        (eid,)).fetchone()["sub_role_reason"]
                        == f"corrected (claim {claim['id']})"))
        return True  # unknown vocab — _project would no-op anyway
    if pred == "sub_role":
        row = conn.execute("SELECT sub_role, sub_role_reason FROM entities "
                           "WHERE id=?", (eid,)).fetchone()
        return (bool(row) and row["sub_role"] == val
                and row["sub_role_reason"] == f"corrected (claim {claim['id']})")
    if pred.startswith("rel:") and claim.get("object_entity_id"):
        from investigations.enrich.rel_vocab import normalize_rel
        rel = normalize_rel(val, claim.get("evidence", ""), allow_novel=True)
        if rel is None:
            return True  # _project would skip it too
        # Converged = the active edge carries _project's deterministic
        # outcomes (confidence 'corrected', provenance 'analyst') AND no
        # competing rel is active. evidence is upsert-only-fills-empty, so
        # it converges on first apply and is not re-compared.
        row = conn.execute(
            "SELECT 1 FROM typed_relationships WHERE src_entity_id=? AND "
            "dst_entity_id=? AND rel_type=? AND status='active' "
            "AND confidence='corrected' AND provenance='analyst' "
            "AND NOT EXISTS (SELECT 1 FROM typed_relationships x WHERE "
            "x.src_entity_id=? AND x.dst_entity_id=? AND x.rel_type != ? "
            "AND x.status='active')",
            (eid, claim["object_entity_id"], rel,
             eid, claim["object_entity_id"], rel)).fetchone()
        return bool(row)
    return True  # attribute claims have no derived column


# ---------------------------------------------------------------------------
# brief inputs — THE deterministic input set the synthesizer consumes
# ---------------------------------------------------------------------------


def brief_inputs(conn, case: str | None) -> dict:
    """The brief's deterministic sections (binding schema, phase-3 PRD):
    reports, top entities by score, promoted findings, unverified leads,
    agent costs. Pure — no LLM, no mutation; comparable across projections."""
    rep_where = "WHERE investigation = ? " if case else ""
    rep_params = [case] if case else []
    reports = [
        {"id": r["id"], "title": r["title"]}
        for r in conn.execute(
            "SELECT id, title FROM reports "
            f"{rep_where}ORDER BY ingested_at, id", rep_params)]

    ent_scope, ent_params = "", []
    if case:
        ent_scope = ("AND e.id IN (SELECT m.entity_id FROM mentions m "
                     "JOIN reports r ON r.id = m.report_id "
                     "WHERE r.investigation = ?) ")
        ent_params.append(case)
    entities = [
        {"id": e["id"], "name": e["canonical_name"],
         "type": e["case_type"] or e["entity_type"],
         "role": ((e["notes"] or "").split(" — ")[0]
                  .replace("role:", "").strip() or None),
         "score": round(e["threat_score"] or 0.0, _ROUND)}
        for e in conn.execute(
            "SELECT e.id, e.canonical_name, e.entity_type, e.case_type, "
            "e.notes, s.threat_score FROM entities e "
            "LEFT JOIN entity_scores s ON s.entity_id = e.id "
            "WHERE e.hidden = 0 "
            f"{ent_scope}"
            "ORDER BY COALESCE(s.threat_score, 0) DESC, e.id LIMIT ?",
            (*ent_params, TOP_ENTITIES))]

    agent_where = "AND run.investigation = ? " if case else ""
    agent_params = [case] if case else []
    findings = [dict(r) for r in conn.execute(
        "SELECT er.title, er.summary, er.confidence FROM enrichment_results er "
        "JOIN enrichment_runs run ON run.id = er.run_id "
        f"WHERE run.provider_slug = 'agent' {agent_where}"
        "AND er.extracted_entity_id IS NOT NULL "
        "ORDER BY er.id DESC LIMIT 60", agent_params)]
    leads = [dict(r) for r in conn.execute(
        "SELECT er.title, er.summary, er.confidence FROM enrichment_results er "
        "JOIN enrichment_runs run ON run.id = er.run_id "
        f"WHERE run.provider_slug = 'agent' {agent_where}"
        "AND er.extracted_entity_id IS NULL "
        "ORDER BY CASE er.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 "
        "ELSE 2 END, er.id DESC LIMIT 40", agent_params)]

    cost_row = conn.execute(
        "SELECT COUNT(*) AS runs, ROUND(COALESCE(SUM(cost_usd), 0), 6) AS usd "
        "FROM enrichment_runs run "
        f"WHERE run.provider_slug = 'agent' {agent_where}",
        agent_params).fetchone()
    return {"reports": reports, "entities": entities, "findings": findings,
            "leads": leads,
            "agent_costs": {"runs": cost_row["runs"],
                            "usd": round(cost_row["usd"] or 0.0, _ROUND)}}


# ---------------------------------------------------------------------------
# digest — the replay comparator
# ---------------------------------------------------------------------------


def digest(conn, case: str | None) -> str:
    """sha256 over canonical JSON (sorted keys, stable row order, floats
    rounded) of the three derived blocks. Identical digests = identical
    derived state — the replay gate's comparator."""
    scope, params = "", []
    if case:
        scope = ("AND e.id IN (SELECT m.entity_id FROM mentions m "
                 "JOIN reports r ON r.id = m.report_id "
                 "WHERE r.investigation = ?) ")
        params.append(case)
    graph_entities = [
        [e["id"], e["canonical_name"], e["entity_type"], e["notes"],
         e["sub_role"], e["sub_role_reason"], e["hidden"]]
        for e in conn.execute(
            "SELECT e.id, e.canonical_name, e.entity_type, e.notes, "
            "e.sub_role, e.sub_role_reason, e.hidden FROM entities e WHERE 1=1 "
            f"{scope}ORDER BY e.id", params)]
    edge_scope, edge_params = "", []
    if case:
        # BOTH endpoints in-case (matching the graph view's scoping): a shared
        # entity's foreign edges must not flap this case's digest.
        in_case = ("(SELECT m.entity_id FROM mentions m JOIN reports r "
                   "ON r.id = m.report_id WHERE r.investigation = ?)")
        edge_scope = (f"AND t.src_entity_id IN {in_case} "
                      f"AND t.dst_entity_id IN {in_case} ")
        edge_params.extend([case, case])
    graph_edges = [
        [t["src_entity_id"], t["dst_entity_id"], t["rel_type"],
         t["confidence"], t["status"], t["provenance"]]
        for t in conn.execute(
            "SELECT t.src_entity_id, t.dst_entity_id, t.rel_type, "
            "t.confidence, t.status, t.provenance FROM typed_relationships t WHERE 1=1 "
            f"{edge_scope}"
            "ORDER BY t.src_entity_id, t.dst_entity_id, t.rel_type",
            edge_params)]
    score_scope, score_params = "", []
    if case:
        score_scope = ("AND s.entity_id IN (SELECT m.entity_id FROM mentions m "
                       "JOIN reports r ON r.id = m.report_id WHERE r.investigation = ?) ")
        score_params.append(case)
    scores = [
        [s["entity_id"], round(s["threat_score"] or 0.0, _ROUND), s["degree"]]
        for s in conn.execute(
            "SELECT s.entity_id, s.threat_score, s.degree FROM entity_scores s "
            f"WHERE 1=1 {score_scope}ORDER BY s.entity_id", score_params)]
    payload = json.dumps(
        {"graph": {"entities": graph_entities, "edges": graph_edges},
         "brief_inputs": brief_inputs(conn, case),
         "scores": scores},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()
