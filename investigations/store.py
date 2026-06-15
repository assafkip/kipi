"""THE one write path for case state (sp1-store-apply-mutation).

Every mutation of case state — entities, typed relationships, hidden flips,
claim status, and the action events around them — enters through
`apply_mutation(conn, event)`. It runs, in order, on the CALLER'S connection
inside the caller's transaction (no commit here; a caller rollback erases
everything this function did):

    1. admission policy   (is_admissible, per the actor/gate rules below)
    2. the canonical write (db.py primitives or the whitelisted UPDATE)
    3. event append        (the `activity` table — the case event log)
    4. case-version bump   (investigations.version, the /api/changed signal)

Why one path: refresh, admission, and event logging used to be conventions
re-remembered at 19 writer modules; each recurrence RCA traced to a site that
forgot one of them. Through this choke-point a writer CANNOT forget — the
bypass test (tests/test_one_write_path.py) greps the tree so no new direct
write can ship. See prd-spine-architecture-2026-06-11 + prd-spine-phase1.

Event contract (binding, from the phase-1 PRD):
    event = {
        "case": str | None,        # case slug ('' / None = unfiled; still logged)
        "actor": str,              # 'agent' | 'analyst:<name>' | 'pipeline:<step>'
                                   # | 'ingest:<report_id>'
        "action": str,             # one of ACTIONS (closed vocabulary)
        "entity_id": int | None,
        "report_id": int | None,
        "payload": dict,           # action-specific; stored as JSON in activity.detail
        "gate": bool,              # False = this path never gated pre-migration;
                                   # behavior preserved verbatim
    }

Admission policy (preserves today's semantics exactly):
    - analyst:* actors bypass value-noise admission (top authority — the
      pre-migration graph_chat add_node semantics).
    - gate=False constructor paths (raw-extraction ingest, typing recovery
      pass-through) skip admission, exactly as they did before migration.
    - everything else: is_admissible(entity_type, value) decides; a rejection
      writes NOTHING and returns {"applied": False, "reason": ...}.

Handlers are added per migration issue as its writers move over; this module
grows ONLY event constructors + handlers, never bespoke write helpers.
"""

import json

from investigations import admission
from investigations.storage import db


# Closed action vocabulary (phase-1 PRD, "Write-path -> event mapping").
ACTIONS = (
    "entity_upserted",
    "edge_upserted",
    "entity_hidden",
    "entity_unhidden",
    "entity_merged",
    "claim_rejected",
    "claim_resolved",
    "brief_generated",
    "entities_retyped",
    "noise_swept",
    "report_ingested",
    "analyst_annotated",
)

# Fields analyst_annotated / entity_merged may touch on `entities`. Anything
# else is a schema change, not an annotation — extend deliberately, with a test.
ANNOTATABLE_FIELDS = (
    "notes", "sub_role", "sub_role_reason", "flagged", "flagged_note",
    "thumbnail", "case_type", "hidden", "entity_type",
)
# A merge may additionally fold the loser's name onto the kept row.
MERGE_FIELDS = ANNOTATABLE_FIELDS + ("canonical_name",)


# ---------------------------------------------------------------------------
# Event constructors — the only sanctioned way to build an event dict.
# ---------------------------------------------------------------------------


def entity_upserted(case, name, entity_type, report_id, *, actor,
                    provenance=None, gate=True, phone_prevalidated=False,
                    case_type_if_unset=None):
    """case_type_if_unset: stamp entities.case_type ONLY when NULL (COALESCE
    semantics), folded into this one event — dataset ingest stamps the typed
    column without a second event per cell."""
    return {
        "case": case, "actor": actor, "action": "entity_upserted",
        "entity_id": None, "report_id": report_id, "gate": gate,
        "payload": {"name": name, "entity_type": entity_type,
                    "provenance": provenance,
                    "phone_prevalidated": phone_prevalidated,
                    "case_type_if_unset": case_type_if_unset},
    }


def edge_upserted(case, src_entity_id, dst_entity_id, rel_type, *, actor,
                  confidence="medium", evidence=None, status="active",
                  provenance=None, observed_at=None):
    return {
        "case": case, "actor": actor, "action": "edge_upserted",
        "entity_id": src_entity_id, "report_id": None, "gate": False,
        "payload": {"src": src_entity_id, "dst": dst_entity_id,
                    "rel_type": rel_type, "confidence": confidence,
                    "evidence": evidence, "status": status,
                    "provenance": provenance, "observed_at": observed_at},
    }


def edge_evidence_appended(case, src_entity_id, dst_entity_id, text, *, actor):
    """Append a verdict/note to an existing edge's evidence (both directions)."""
    return {"case": case, "actor": actor, "action": "edge_upserted",
            "entity_id": src_entity_id, "report_id": None, "gate": False,
            "payload": {"src": src_entity_id, "dst": dst_entity_id,
                        "evidence": text, "evidence_append": True}}


def edge_status_set(case, src_entity_id, dst_entity_id, status, *, actor,
                    rel_type=None, rel_type_not=None):
    """Flip typed-edge status (supersede competitors / retire / reactivate).
    WHERE shape: (src,dst) always; rel_type= narrows to one label;
    rel_type_not= excludes one label (the supersede-competitors shape).
    Idempotent bulk op: zero matched rows is a legal no-op (applied=True,
    flipped=0) — the claim decision still logs."""
    return {"case": case, "actor": actor, "action": "edge_upserted",
            "entity_id": src_entity_id, "report_id": None, "gate": False,
            "payload": {"src": src_entity_id, "dst": dst_entity_id,
                        "status_set": status, "rel_type": rel_type,
                        "rel_type_not": rel_type_not}}


def entities_retyped_batch(case, updates, *, actor, counts=None):
    """One event for a whole retype/role-tag pass: updates is a list of
    {entity_id, fields} dicts (fields whitelisted). The store applies every
    row inside the event's savepoint — one log row, one bump, zero raw SQL
    left in the pipeline step."""
    return {"case": case, "actor": actor, "action": "entities_retyped",
            "entity_id": None, "report_id": None, "gate": False,
            "payload": {"updates": [
                {"entity_id": u["entity_id"], "fields": dict(u["fields"])}
                for u in updates], "counts": dict(counts or {})}}


def edges_maintained(case, op, *, actor, **kw):
    """Constrained maintenance ops on typed edges (the retro_clean sweep
    shapes — each a parameterized, whitelisted write, never SQL transport):
      repoint        kw: frm, to       (re-key both directions + drop created self-loops)
      repoint_id     kw: edge_id, src, dst
      delete_ids     kw: edge_ids
      set_rel_type   kw: edge_id, rel_type
      set_time_bounds kw: edge_id, first_seen, last_seen
    """
    allowed_ops = ("repoint", "repoint_id", "delete_ids", "set_rel_type",
                   "set_time_bounds")
    if op not in allowed_ops:
        raise ValueError(f"unknown edge maintenance op: {op!r}")
    return {"case": case, "actor": actor, "action": "edge_upserted",
            "entity_id": None, "report_id": None, "gate": False,
            "payload": {"maintain": op, **kw}}


def noise_swept_deletes(case, sweep_class, entity_ids, *, actor, counts=None):
    """A noise sweep that DELETES entity rows (junk classes): the deletions ride
    the sweep event itself — one log row carries the class + ids + counts.
    Cross-table FK cleanup stays the caller's job (those tables aren't part of
    the canonical write surface)."""
    return {"case": case, "actor": actor, "action": "noise_swept",
            "entity_id": None, "report_id": None, "gate": False,
            "payload": {"sweep_class": sweep_class,
                        "delete_entity_ids": list(entity_ids),
                        "counts": dict(counts or {})}}


def entity_hidden(case, entity_id, *, actor):
    return {"case": case, "actor": actor, "action": "entity_hidden",
            "entity_id": entity_id, "report_id": None, "gate": False,
            "payload": {"hidden": 1}}


def entity_unhidden(case, entity_id, *, actor):
    return {"case": case, "actor": actor, "action": "entity_unhidden",
            "entity_id": entity_id, "report_id": None, "gate": False,
            "payload": {"hidden": 0}}


def analyst_annotated(case, entity_id, fields, *, actor):
    """Whitelisted field updates on one entity (notes, sub_role, flags...)."""
    return {"case": case, "actor": actor, "action": "analyst_annotated",
            "entity_id": entity_id, "report_id": None, "gate": False,
            "payload": {"fields": dict(fields)}}


def claim_resolved(case, claim_id, *, actor, superseded_ids=()):
    return {"case": case, "actor": actor, "action": "claim_resolved",
            "entity_id": None, "report_id": None, "gate": False,
            "payload": {"claim_id": claim_id,
                        "superseded_ids": list(superseded_ids)}}


def claim_rejected(case, claim_id, *, actor):
    return {"case": case, "actor": actor, "action": "claim_rejected",
            "entity_id": None, "report_id": None, "gate": False,
            "payload": {"claim_id": claim_id}}


def entity_merged(case, kept_entity_id, merged_entity_ids, *, actor,
                  fields=None, delete_merged=False):
    return {"case": case, "actor": actor, "action": "entity_merged",
            "entity_id": kept_entity_id, "report_id": None, "gate": False,
            "payload": {"kept": kept_entity_id,
                        "merged": list(merged_entity_ids),
                        "fields": dict(fields or {}),
                        "delete_merged": bool(delete_merged)}}


def brief_generated(case, *, actor, detail=None):
    return {"case": case, "actor": actor, "action": "brief_generated",
            "entity_id": None, "report_id": None, "gate": False,
            "payload": {"detail": detail or {}}}


def noise_swept(case, sweep_class, *, actor, counts=None):
    return {"case": case, "actor": actor, "action": "noise_swept",
            "entity_id": None, "report_id": None, "gate": False,
            "payload": {"sweep_class": sweep_class,
                        "counts": dict(counts or {})}}


def report_ingested(case, report_id, *, actor, detail=None):
    return {"case": case, "actor": actor, "action": "report_ingested",
            "entity_id": None, "report_id": report_id, "gate": False,
            "payload": {"detail": detail or {}}}


# ---------------------------------------------------------------------------
# The choke-point
# ---------------------------------------------------------------------------


def apply_mutation(conn, event):
    """Admission -> write -> event append -> version bump, one transaction.

    Returns {"applied": bool, "reason": str | None, ...action-specific keys}.
    Never commits; the caller owns the transaction boundary. A SAVEPOINT
    wraps write+event+bump so a failure in ANY of the three (e.g. an
    unserializable payload raising in the event append AFTER the handler
    wrote) rolls all three back before re-raising — a caller catching the
    exception and committing cannot commit a write that escaped the log
    (adversarial finding, 2026-06-11).
    """
    action = event.get("action")
    if action not in ACTIONS:
        raise ValueError(f"unknown event action: {action!r}")

    # Fail fast: an unserializable payload aborts BEFORE any write.
    event["_detail_json"] = json.dumps(event.get("payload", {}))

    handler = _HANDLERS[action]
    # SQLite subtlety: SAVEPOINT outside a transaction STARTS one, and the
    # final RELEASE then COMMITS it — which would steal the caller's rollback
    # authority. Open a real deferred transaction first so the savepoint
    # nests inside it and the caller's commit/rollback stays in charge.
    if not conn.in_transaction:
        conn.execute("BEGIN")
    conn.execute("SAVEPOINT apply_mutation")
    try:
        result = handler(conn, event)
        if result.get("applied"):
            _append_event(conn, event, result)
            result["version"] = bump_case(conn, event.get("case"))
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT apply_mutation")
        conn.execute("RELEASE SAVEPOINT apply_mutation")
        raise
    conn.execute("RELEASE SAVEPOINT apply_mutation")
    return result


def _actor_is_analyst(actor):
    # Exactly 'analyst' or 'analyst:<name>' — 'analyst-bot'/'analystic' are
    # NOT analysts and do not get the top-authority admission bypass.
    return isinstance(actor, str) and (actor == "analyst"
                                       or actor.startswith("analyst:"))


def _admission_verdict(event):
    """(ok, reason) under the actor/gate policy. Pure; no writes."""
    if not event.get("gate", True):
        return True, "ungated path (pre-migration behavior preserved)"
    if _actor_is_analyst(event.get("actor", "")):
        return True, "analyst is top authority"
    payload = event["payload"]
    return admission.is_admissible(
        payload.get("entity_type"), payload.get("name"),
        phone_prevalidated=payload.get("phone_prevalidated", False))


def _handle_entity_upserted(conn, event):
    ok, reason = _admission_verdict(event)
    if not ok:
        return {"applied": False, "reason": reason}
    payload = event["payload"]
    entity_id = db.upsert_entity(
        conn, payload["name"], payload["entity_type"],
        event.get("report_id"), provenance=payload.get("provenance"))
    if payload.get("case_type_if_unset"):
        conn.execute(
            "UPDATE entities SET case_type = COALESCE(case_type, ?) WHERE id = ?",
            (payload["case_type_if_unset"], entity_id))
    event["entity_id"] = entity_id
    return {"applied": True, "reason": None, "entity_id": entity_id}


def _maintain_edges(conn, payload):
    op = payload["maintain"]
    if op == "repoint":
        frm, to = payload["frm"], payload["to"]
        conn.execute("UPDATE OR IGNORE typed_relationships SET src_entity_id = ? "
                     "WHERE src_entity_id = ?", (to, frm))
        conn.execute("UPDATE OR IGNORE typed_relationships SET dst_entity_id = ? "
                     "WHERE dst_entity_id = ?", (to, frm))
        cur = conn.execute(
            "DELETE FROM typed_relationships WHERE src_entity_id = dst_entity_id "
            "AND (src_entity_id = ? OR dst_entity_id = ?)", (to, to))
        return {"applied": True, "reason": None}
    if op == "repoint_id":
        cur = conn.execute(
            "UPDATE OR IGNORE typed_relationships SET src_entity_id = ?, "
            "dst_entity_id = ? WHERE id = ?",
            (payload["src"], payload["dst"], payload["edge_id"]))
        return {"applied": True, "reason": None, "rows": cur.rowcount}
    if op == "delete_ids":
        deleted = 0
        for edge_id in payload["edge_ids"]:
            deleted += conn.execute(
                "DELETE FROM typed_relationships WHERE id = ?", (edge_id,)).rowcount
        return {"applied": True, "reason": None, "deleted": deleted}
    if op == "set_rel_type":
        cur = conn.execute(
            "UPDATE OR IGNORE typed_relationships SET rel_type = ? WHERE id = ?",
            (payload["rel_type"], payload["edge_id"]))
        return {"applied": True, "reason": None, "rows": cur.rowcount}
    if op == "set_time_bounds":
        cur = conn.execute(
            "UPDATE typed_relationships SET first_seen = ?, last_seen = ? "
            "WHERE id = ?",
            (payload["first_seen"], payload["last_seen"], payload["edge_id"]))
        return {"applied": True, "reason": None, "rows": cur.rowcount}
    raise ValueError(f"unknown edge maintenance op: {op!r}")


def _handle_edge_upserted(conn, event):
    payload = event["payload"]
    if payload.get("maintain"):
        return _maintain_edges(conn, payload)
    if payload.get("status_set"):
        where, params = ["src_entity_id = ?", "dst_entity_id = ?"], \
                        [payload["src"], payload["dst"]]
        if payload.get("rel_type"):
            where.append("rel_type = ?"); params.append(payload["rel_type"])
        if payload.get("rel_type_not"):
            where.append("rel_type != ?"); params.append(payload["rel_type_not"])
        cur = conn.execute(
            f"UPDATE typed_relationships SET status = ? WHERE {' AND '.join(where)}",
            (payload["status_set"], *params))
        return {"applied": True, "reason": None, "flipped": cur.rowcount}
    if payload.get("evidence_append"):
        # Append-only evidence annotation on an EXISTING edge (both
        # directions, active only) — the investigate-edge verdict path. Same
        # action verb: it is an edge-evidence write; the payload records the
        # append semantics (never clobbers the original evidence).
        cur = conn.execute(
            "UPDATE typed_relationships SET evidence = "
            "  COALESCE(NULLIF(evidence, ''), '') || ? "
            "WHERE status = 'active' AND ((src_entity_id = ? AND dst_entity_id = ?) "
            "OR (src_entity_id = ? AND dst_entity_id = ?))",
            (payload["evidence"], payload["src"], payload["dst"],
             payload["dst"], payload["src"]))
        if cur.rowcount == 0:
            return {"applied": False, "reason": "no active edge between the pair"}
        return {"applied": True, "reason": None, "annotated": cur.rowcount}
    created = db.upsert_typed_relationship(
        conn, payload["src"], payload["dst"], payload["rel_type"],
        confidence=payload.get("confidence", "medium"),
        evidence=payload.get("evidence"),
        status=payload.get("status", "active"),
        provenance=payload.get("provenance"),
        observed_at=payload.get("observed_at"))
    return {"applied": True, "reason": None, "created": created}


def _handle_hidden_flip(conn, event):
    hidden = event["payload"]["hidden"]
    cur = conn.execute("UPDATE entities SET hidden = ? WHERE id = ?",
                       (hidden, event["entity_id"]))
    if cur.rowcount == 0:
        return {"applied": False,
                "reason": f"no entity id {event['entity_id']}"}
    return {"applied": True, "reason": None}


def _handle_analyst_annotated(conn, event):
    fields = event["payload"]["fields"]
    bad = sorted(set(fields) - set(ANNOTATABLE_FIELDS))
    if bad:
        raise ValueError(f"non-annotatable entity fields: {bad}")
    sets = ", ".join(f"{k} = ?" for k in fields)
    cur = conn.execute(f"UPDATE entities SET {sets} WHERE id = ?",
                       (*fields.values(), event["entity_id"]))
    if cur.rowcount == 0:
        return {"applied": False,
                "reason": f"no entity id {event['entity_id']}"}
    return {"applied": True, "reason": None}


def _handle_claim_status(conn, event):
    """Flip claim status rows ONLY. Projection of the winning claim into the
    derived graph (entity notes/sub_role, edge supersession) and the score
    recompute REMAIN the caller's job — claims.resolve/reject orchestrate
    them as their own store events (sp1-migrate-pipeline-steps acceptance).
    This event records the decision; it does not replace the propagation."""
    payload = event["payload"]
    # ONE timestamp for the whole resolution (the old claims code materialized
    # _now once): winner + every superseded loser stamp identically, so a
    # second-boundary mid-loop can't split one decision across two times.
    now = conn.execute("SELECT CURRENT_TIMESTAMP").fetchone()[0]
    if event["action"] == "claim_rejected":
        cur = conn.execute(
            "UPDATE claims SET status = 'rejected', resolved_at = ? "
            "WHERE id = ?", (now, payload["claim_id"]))
    else:
        # Winner goes (back to) authoritative even if previously retired.
        cur = conn.execute(
            "UPDATE claims SET status = 'active', superseded_by = NULL, "
            "resolved_at = ? WHERE id = ?", (now, payload["claim_id"]))
    if cur.rowcount == 0:
        return {"applied": False,
                "reason": f"no claim id {payload['claim_id']}"}
    superseded = 0
    for loser in payload.get("superseded_ids", []):
        superseded += conn.execute(
            "UPDATE claims SET status = 'superseded', superseded_by = ?, "
            "resolved_at = ? WHERE id = ?",
            (payload["claim_id"], now, loser)).rowcount
    return {"applied": True, "reason": None, "superseded": superseded}


def _handle_entity_merged(conn, event):
    payload = event["payload"]
    fields = payload.get("fields") or {}
    if fields:
        bad = sorted(set(fields) - set(MERGE_FIELDS))
        if bad:
            raise ValueError(f"non-mergeable entity fields: {bad}")
        sets = ", ".join(f"{k} = ?" for k in fields)
        cur = conn.execute(f"UPDATE entities SET {sets} WHERE id = ?",
                           (*fields.values(), payload["kept"]))
        if cur.rowcount == 0:
            return {"applied": False,
                    "reason": f"no kept entity id {payload['kept']}"}
    deleted = 0
    if payload.get("delete_merged"):
        for merged_id in payload["merged"]:
            deleted += conn.execute("DELETE FROM entities WHERE id = ?",
                                    (merged_id,)).rowcount
    return {"applied": True, "reason": None, "deleted": deleted}


def _handle_entities_retyped(conn, event):
    """A retype/role-tag pass: apply the whitelisted field updates (if the
    event carries any) as ONE event — per-row events would spam the log on a
    500-entity pass. An updates-free event just records that the pass ran."""
    applied_rows = 0
    for update in event["payload"].get("updates", []):
        fields = update["fields"]
        bad = sorted(set(fields) - set(ANNOTATABLE_FIELDS))
        if bad:
            raise ValueError(f"non-annotatable entity fields: {bad}")
        sets = ", ".join(f"{k} = ?" for k in fields)
        applied_rows += conn.execute(
            f"UPDATE entities SET {sets} WHERE id = ?",
            (*fields.values(), update["entity_id"])).rowcount
    return {"applied": True, "reason": None, "rows": applied_rows}


def _handle_noise_swept(conn, event):
    """A sweep event; when it carries delete_entity_ids, the entity-row
    deletions ride it (cross-table FK cleanup stays with the caller)."""
    deleted = 0
    for entity_id in event["payload"].get("delete_entity_ids", []):
        deleted += conn.execute(
            "DELETE FROM entities WHERE id = ?", (entity_id,)).rowcount
    return {"applied": True, "reason": None, "deleted": deleted}


def _handle_event_only(conn, event):
    """Actions whose constituent writes are their own events; this row records
    the act itself (brief regenerated, sweep ran, report landed...)."""
    return {"applied": True, "reason": None}


_HANDLERS = {
    "entity_upserted": _handle_entity_upserted,
    "edge_upserted": _handle_edge_upserted,
    "entity_hidden": _handle_hidden_flip,
    "entity_unhidden": _handle_hidden_flip,
    "entity_merged": _handle_entity_merged,
    "claim_rejected": _handle_claim_status,
    "claim_resolved": _handle_claim_status,
    "analyst_annotated": _handle_analyst_annotated,
    "brief_generated": _handle_event_only,
    "entities_retyped": _handle_entities_retyped,
    "noise_swept": _handle_noise_swept,
    "report_ingested": _handle_event_only,
}


def _append_event(conn, event, result):
    # detail JSON was serialized up front in apply_mutation (fail-fast), but
    # the entity_id may have been resolved by the handler — re-serialize so
    # the logged payload is the post-write truth.
    conn.execute(
        "INSERT INTO activity (analyst, action, entity_id, report_id, "
        "investigation, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (event.get("actor", "unknown"), event["action"],
         event.get("entity_id"), event.get("report_id"),
         event.get("case"), json.dumps(event.get("payload", {}))))


# ---------------------------------------------------------------------------
# Case version — the /api/changed signal, DB-backed so every process shares it
# ---------------------------------------------------------------------------


def bump_case(conn, case) -> int:
    """Increment the case's change version inside the caller's transaction.
    Open views poll /api/changed and re-fetch when it moves. DB-backed
    (investigations.version) so CLI/pipeline writers refresh open views too —
    the in-memory webapp dict could not (gap 2's class)."""
    if not case:
        return 0
    conn.execute(
        "INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?, ?)",
        (case, case))
    conn.execute(
        "UPDATE investigations SET version = version + 1 WHERE slug = ?",
        (case,))
    row = conn.execute(
        "SELECT version FROM investigations WHERE slug = ?", (case,)).fetchone()
    return row[0] if row else 0


def case_version(conn, case) -> int:
    """Current change version for `case` (0 if unknown / never bumped)."""
    if not case:
        return 0
    row = conn.execute(
        "SELECT version FROM investigations WHERE slug = ?", (case,)).fetchone()
    return row[0] if row else 0


def format_recent_activity(conn, case, limit=25) -> str:
    """THE shared one-line-per-event rendering of the case's recent activity,
    consumed by BOTH the warm agent's grounding and /ask context assembly
    (sp1-ui-events-to-agent). One source — never two bespoke readers: the
    bridge test greps that neither consumer reads the activity table
    directly. Newest first; entity ids resolve to names for readability."""
    def one_line(value, cap):
        # Untrusted values render into an AUTHORITATIVE agent prefix: collapse
        # whitespace (a newline in a hostile canonical_name could forge extra
        # "activity lines"), strip the NON-whitespace control/format chars
        # \s+ misses (NUL, ESC/ANSI, BEL — Unicode Cc/Cf), and cap the length
        # (codex findings 2026-06-11).
        import re as _re
        import unicodedata as _ud
        text = _re.sub(r"\s+", " ", str(value or "")).strip()
        text = "".join(ch for ch in text
                       if _ud.category(ch) not in ("Cc", "Cf"))
        return text[:cap]

    lines = []
    for ev in recent_activity(conn, case, limit=limit):
        subject = ""
        if ev.get("entity_id"):
            row = conn.execute("SELECT canonical_name FROM entities WHERE id = ?",
                               (ev["entity_id"],)).fetchone()
            subject = f" {one_line(row[0], 80)}" if row else f" entity#{ev['entity_id']}"
        lines.append(f"[{one_line(ev['created_at'], 25)}] "
                     f"{one_line(ev['actor'], 40)} "
                     f"{one_line(ev['action'], 30)}{subject}")
    return "\n".join(lines)


def recent_activity(conn, case, limit=25):
    """Newest-first tail of the case event log. THE shared reader for agent
    grounding + /ask context (sp1-ui-events-to-agent) — one source, never two."""
    rows = conn.execute(
        "SELECT analyst, action, entity_id, report_id, detail, created_at "
        "FROM activity WHERE investigation = ? ORDER BY id DESC LIMIT ?",
        (case, limit)).fetchall()
    return [dict(zip(("actor", "action", "entity_id", "report_id",
                      "detail", "created_at"), r)) for r in rows]
