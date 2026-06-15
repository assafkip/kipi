"""Ambient identity anchor: a per-case reference identity for the investigator.

Ported idea from osint-d2 (Doble-2/osint-d2): give the agent a reference identity for the
case's CONFIRMED ACTORS and ground every run in it, so a profile that merely shares a handle
is not silently merged into a confirmed actor. kipi's promotion gate already blocks name-only
attribution (q-investigation.md crosslink floor); this adds the missing "who is confirmed in
this case" axis — the part of osint-d2 that ports cleanly (its prompt injection).

Two consumers, both in investigations/agent/investigator.py:
  - reference_prompt(): a grounding block prepended to each case-run task.
  - classify() via _promotion_gate(): annotates a finding that matches a confirmed actor
    (identity_anchor='match'). Annotation ONLY — it never holds and never promotes.

Deterministic, read-only, no LLM, no schema change. kipi stores handles BARE (`@alice`) and
globally unique, so a same-handle-different-platform COLLISION cannot be expressed soundly
per-finding; that reasoning is left to the grounded agent (it emits the conflation as its own
finding, which the existing crosslink floor grades). See
.prd-os/prds/prd-identity-anchor-2026-06-13.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# One source of truth for "this value is a person/handle identity". investigator.py imports
# this so build/classify and the promotion gate's person floor never drift (Codex adv-3).
PERSON_ENTITY_TYPES = frozenset({"person", "handle", "username"})

# Per-list cap so a large confirmed-actor set can't bloat the agent prompt (Codex minor-6).
_PROMPT_CAP = 20

# entity_types whose canonical_name is a handle (vs a real name).
_HANDLE_TYPES = frozenset({"handle", "username"})

# entity_types classify() may match: the person/handle identities PLUS email (a finding that
# IS a confirmed actor's email is corroboration). A domain/ip/etc. finding never matches.
_CLASSIFY_TYPES = PERSON_ENTITY_TYPES | frozenset({"email"})


@dataclass(frozen=True)
class Reference:
    """The case's confirmed-actor identity set. All fields normalized; empty when the analyst
    has confirmed no actor yet (the day-one no-op state)."""
    handles: frozenset
    names: frozenset
    emails: frozenset

    @property
    def is_empty(self) -> bool:
        return not (self.handles or self.names or self.emails)


_EMPTY = Reference(frozenset(), frozenset(), frozenset())


def _norm_handle(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().lstrip("@").strip().lower()


def _norm_name(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.strip()).lower()


def _norm_email(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().lower()


def _confirmed_actors(conn, case: str) -> list:
    """person/handle/username entities the analyst has confirmed (analyst-authored OR flagged),
    scoped to THIS case via mentions -> reports.investigation. The entity pool is global, so the
    case scope is the join, not canonical_name."""
    types = ",".join("?" * len(PERSON_ENTITY_TYPES))
    query = (
        f"SELECT e.id, e.entity_type, e.canonical_name FROM entities e "
        f"WHERE e.entity_type IN ({types}) "
        f"AND (e.provenance = 'analyst' OR e.provenance LIKE 'analyst:%' OR e.flagged = 1) "
        f"AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id "
        f"WHERE r.investigation = ?)"
    )
    return conn.execute(query, [*PERSON_ENTITY_TYPES, case]).fetchall()


def _confirmed_emails(conn, case: str, actor_ids: list) -> set:
    """Emails crosslinked to a confirmed actor. ENDPOINT-SYMMETRIC (Codex adv-2): the email may
    be either endpoint of a typed_relationship; the OTHER endpoint must be a confirmed actor AND
    the email node itself must be case-scoped, so a cross-case linked email cannot leak in.
    typed_relationships is created lazily (storage/db.py) — a missing table yields no emails."""
    if not actor_ids:
        return set()
    ph = ",".join("?" * len(actor_ids))
    query = (
        f"SELECT DISTINCT em.canonical_name FROM typed_relationships tr "
        f"JOIN entities em ON em.entity_type = 'email' "
        f"  AND em.id IN (tr.src_entity_id, tr.dst_entity_id) "
        f"WHERE COALESCE(tr.status, 'active') = 'active' "
        f"  AND (CASE WHEN em.id = tr.src_entity_id THEN tr.dst_entity_id ELSE tr.src_entity_id "
        f"       END) IN ({ph}) "
        f"  AND em.id IN (SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id "
        f"               WHERE r.investigation = ?)"
    )
    try:
        rows = conn.execute(query, [*actor_ids, case]).fetchall()
    except Exception:
        return set()          # typed_relationships missing / malformed — skip emails, no throw
    return {e for e in (_norm_email(r["canonical_name"]) for r in rows) if e}


def build_reference(conn, case: str | None) -> Reference:
    """The case's confirmed-actor Reference. Defensive: a falsy case, no confirmed actor, or any
    query error yields the empty Reference (a total no-op for grounding + classify)."""
    if not case:
        return _EMPTY
    try:
        actors = _confirmed_actors(conn, case)
    except Exception:
        return _EMPTY
    if not actors:
        return _EMPTY

    handles: set = set()
    names: set = set()
    actor_ids = [a["id"] for a in actors]
    for a in actors:
        etype = (a["entity_type"] or "").lower()
        cn = a["canonical_name"] or ""
        if etype in _HANDLE_TYPES:
            h = _norm_handle(cn)
            if h:
                handles.add(h)
        else:                                            # person
            n = _norm_name(cn)
            if n:
                names.add(n)

    # Aliases of confirmed actors, bucketed by the actor's own type.
    try:
        ph = ",".join("?" * len(actor_ids))
        arows = conn.execute(
            f"SELECT a.alias, e.entity_type FROM aliases a JOIN entities e ON e.id = a.entity_id "
            f"WHERE a.entity_id IN ({ph})", actor_ids).fetchall()
        for r in arows:
            etype = (r["entity_type"] or "").lower()
            if etype in _HANDLE_TYPES:
                h = _norm_handle(r["alias"])
                if h:
                    handles.add(h)
            else:
                n = _norm_name(r["alias"])
                if n:
                    names.add(n)
    except Exception:
        pass                                             # aliases optional — never block

    emails = _confirmed_emails(conn, case, actor_ids)
    return Reference(frozenset(handles), frozenset(names), frozenset(emails))


def classify(reference: Reference | None, entity_type: str | None, value: str | None) -> str:
    """'match' if this person/handle value is a confirmed actor of the case; else 'unknown'.
    No 'collision' verdict — kipi's bare/global handles can't express it soundly per-finding."""
    if reference is None or reference.is_empty or not value:
        return "unknown"
    if (entity_type or "").lower() not in _CLASSIFY_TYPES:
        return "unknown"
    if (_norm_handle(value) in reference.handles
            or _norm_name(value) in reference.names
            or _norm_email(value) in reference.emails):
        return "match"
    return "unknown"


def reference_prompt(reference: Reference | None) -> str:
    """The grounding block prepended to a case-run task. '' for an empty Reference (the no-op).
    Each list is sorted + capped so the block is deterministic and bounded (Codex minor-6)."""
    if reference is None or reference.is_empty:
        return ""
    parts: list = []
    if reference.handles:
        parts.append("handles: " + ", ".join("@" + h for h in sorted(reference.handles)[:_PROMPT_CAP]))
    if reference.names:
        parts.append("names: " + ", ".join(sorted(reference.names)[:_PROMPT_CAP]))
    if reference.emails:
        parts.append("emails: " + ", ".join(sorted(reference.emails)[:_PROMPT_CAP]))
    return (
        "\n\nCONFIRMED ACTORS IN THIS CASE (analyst-confirmed identity — treat as ground truth):\n"
        f"  {'; '.join(parts)}\n"
        "A profile that shares one of these handles or names but presents a DIFFERENT real name "
        "or email is likely ANOTHER person. Report it as a separate finding with its own "
        "evidence; do NOT merge it into a confirmed actor on a name/handle match alone.\n"
    )
