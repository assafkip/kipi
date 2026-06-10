"""Claims layer — provenance + correction/supersession behind the graph.

Every assertion is a claim tied to its source report:
  - role        predicate 'role' / 'sub_role', value = the role
  - attribute   predicate 'location' / 'alias' / ...,  value = the attribute
  - relationship predicate 'rel:<object_entity_id>',   value = rel_type

A contradiction is two ACTIVE claims for the same (entity, predicate) with
different values from different reports. The analyst resolves it: the winner
stays active, the losers are marked superseded (kept for audit), and the
derived graph (entities role, typed_relationships) is reprojected. Nothing is
ever deleted, so you can always show the client why the picture changed.
"""
from __future__ import annotations

import json

from investigations.storage import db
from investigations.llm import client as llm
from investigations.enrich.rel_vocab import normalize_rel


# ---------- helpers ----------

def _has(conn, table) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())


def _now(conn) -> str:
    return conn.execute("SELECT CURRENT_TIMESTAMP").fetchone()[0]


def _insert_claim(conn, *, entity_id, report_id, claim_type, predicate, value,
                  object_entity_id=None, confidence=None, evidence=None, source="backfill"):
    # NULL-safe idempotency: INSERT OR IGNORE can't enforce the UNIQUE when any
    # key column is NULL (SQLite treats NULLs as distinct), and role claims
    # always have NULL object_entity_id — so existence-check by hand. Without
    # this, backfill (which runs on every ingest) duplicates claims endlessly.
    val = str(value) if value is not None else None
    exists = conn.execute(
        "SELECT 1 FROM claims WHERE entity_id=? AND claim_type=? AND predicate=? "
        "AND IFNULL(value,'')=IFNULL(?,'') "
        "AND IFNULL(report_id,-1)=IFNULL(?,-1) "
        "AND IFNULL(object_entity_id,-1)=IFNULL(?,-1)",
        (entity_id, claim_type, predicate, val, report_id, object_entity_id),
    ).fetchone()
    if exists:
        return 0
    conn.execute(
        "INSERT INTO claims (entity_id, report_id, claim_type, predicate, value, "
        "object_entity_id, confidence, evidence, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (entity_id, report_id, claim_type, predicate, val, object_entity_id,
         confidence, evidence, source),
    )
    return 1


# ---------- deterministic backfill from existing structured data ----------

def backfill(conn) -> int:
    """Create claims from existing relationships + roles. Idempotent.

    Claims with a NULL report_id are skipped: SQLite's UNIQUE treats NULLs as
    distinct, so a NULL-report claim would be re-inserted on every backfill
    (and backfill runs on every ingest), manufacturing false contradictions.
    """
    new = 0
    # Relationship claims (per-report provenance already present).
    for r in conn.execute(
        "SELECT src_entity_id, dst_entity_id, rel_type, report_id, evidence, confidence "
        "FROM relationships WHERE report_id IS NOT NULL"
    ).fetchall():
        new += _insert_claim(
            conn, entity_id=r["src_entity_id"], report_id=r["report_id"],
            claim_type="relationship", predicate=f"rel:{r['dst_entity_id']}",
            value=r["rel_type"], object_entity_id=r["dst_entity_id"],
            confidence=str(r["confidence"]) if r["confidence"] is not None else None,
            evidence=r["evidence"], source="backfill",
        )
    # Role claims (current derived role, provenanced to first-seen report).
    for e in conn.execute(
        "SELECT id, notes, sub_role, first_seen_report_id FROM entities "
        "WHERE notes LIKE 'role:%' AND first_seen_report_id IS NOT NULL"
    ).fetchall():
        role = (e["notes"] or "").split(" — ")[0].replace("role:", "").strip()
        if role and role != "noise":
            new += _insert_claim(
                conn, entity_id=e["id"], report_id=e["first_seen_report_id"],
                claim_type="role", predicate="role", value=role, source="backfill")
        if e["sub_role"] and e["sub_role"] not in ("unknown", ""):
            new += _insert_claim(
                conn, entity_id=e["id"], report_id=e["first_seen_report_id"],
                claim_type="role", predicate="sub_role", value=e["sub_role"], source="backfill")
    conn.commit()
    return new


# ---------- contradiction detection ----------

def _case_clause(case):
    """Scope predicate for a single case slug, a list of slugs, or None (all)."""
    cases = [case] if isinstance(case, str) else [c for c in (case or []) if c]
    if not cases:
        return "", []
    ph = ",".join("?" for _ in cases)
    return (f" AND c.entity_id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
            f"ON r.id = m.report_id WHERE r.investigation IN ({ph}))", list(cases))


def detect_contradictions(conn, case: str | None = None) -> list[dict]:
    """(entity, predicate) groups with 2+ active claims of differing value."""
    if not _has(conn, "claims"):
        return []
    cc, cp = _case_clause(case)
    groups = conn.execute(
        "SELECT c.entity_id, c.predicate, c.claim_type, "
        "COUNT(DISTINCT c.value) AS nv, COUNT(DISTINCT c.report_id) AS nr "
        "FROM claims c WHERE c.status = 'active' " + cc +
        " GROUP BY c.entity_id, c.predicate HAVING nv >= 2",
        cp,
    ).fetchall()
    out = []
    for g in groups:
        ent = conn.execute(
            "SELECT canonical_name, entity_type FROM entities WHERE id = ?",
            (g["entity_id"],)).fetchone()
        claims = [dict(r) for r in conn.execute(
            "SELECT cl.id, cl.value, cl.report_id, cl.confidence, cl.evidence, "
            "cl.object_entity_id, cl.created_at, r.title AS report_title, r.investigation "
            "FROM claims cl LEFT JOIN reports r ON r.id = cl.report_id "
            "WHERE cl.entity_id = ? AND cl.predicate = ? AND cl.status = 'active' "
            "ORDER BY cl.report_id",
            (g["entity_id"], g["predicate"]),
        ).fetchall()]
        # human label for the predicate
        pred = g["predicate"]
        label = pred
        if pred.startswith("rel:"):
            obj = conn.execute("SELECT canonical_name FROM entities WHERE id = ?",
                               (int(pred.split(":")[1]),)).fetchone()
            label = f"relationship to {obj['canonical_name']}" if obj else pred
        out.append({
            "entity_id": g["entity_id"],
            "entity_name": ent["canonical_name"] if ent else "?",
            "claim_type": g["claim_type"],
            "predicate": pred,
            "label": label,
            "claims": claims,
        })
    return out


def list_contradictions(conn, case=None):
    return detect_contradictions(conn, case)


def count_contradictions(conn, case=None) -> int:
    """Cheap count of contradiction groups (for the nav badge)."""
    if not _has(conn, "claims"):
        return 0
    cc, cp = _case_clause(case)
    rows = conn.execute(
        "SELECT 1 FROM claims c WHERE c.status='active' " + cc +
        " GROUP BY c.entity_id, c.predicate HAVING COUNT(DISTINCT c.value) >= 2", cp,
    ).fetchall()
    return len(rows)


def open_count(conn, case=None) -> int:
    return count_contradictions(conn, case)


# ---------- analyst-confirmed resolution ----------

# Canonical vocab so a correction can't write a junk role that zeroes a score.
CANONICAL_ROLES = {"operator", "channel", "ioc", "infra", "source", "noise"}
CANONICAL_SUBROLES = {"leadership", "member", "facilitator", "developer", "defacer",
                      "propagandist", "recruiter", "spokesperson", "infra_provider", "unknown"}


def resolve(conn, winning_claim_id: int) -> dict:
    """Make the winning claim authoritative, supersede competitors, reproject."""
    w = conn.execute("SELECT * FROM claims WHERE id = ?", (winning_claim_id,)).fetchone()
    if not w:
        return {"error": "claim not found"}
    now = _now(conn)
    conn.execute(  # ensure the winner is active even if it was previously retired
        "UPDATE claims SET status='active', superseded_by=NULL, resolved_at=? WHERE id=?",
        (now, winning_claim_id))
    losers = conn.execute(
        "SELECT id FROM claims WHERE entity_id = ? AND predicate = ? AND status = 'active' "
        "AND id != ?", (w["entity_id"], w["predicate"], winning_claim_id)).fetchall()
    for l in losers:
        conn.execute(
            "UPDATE claims SET status='superseded', superseded_by=?, resolved_at=? WHERE id=?",
            (winning_claim_id, now, l["id"]))
    _project(conn, dict(w))
    _recompute_scores(conn)
    conn.commit()
    return {"ok": True, "superseded": len(losers)}


def assert_claim(conn, entity_id: int, *, claim_type: str, predicate: str,
                 value: str, analyst: str, rationale: str | None = None,
                 object_entity_id: int | None = None) -> dict:
    """Analyst override — the analyst is the top authority.

    Records an attributed manual claim and IMMEDIATELY makes it authoritative:
    any conflicting report/AI claim for the same (entity, predicate) is superseded
    (kept for audit), and the derived graph (role, sub_role, typed_relationships)
    + scores reproject. So the analyst's word wins everywhere the app reads.

    Idempotent on (entity, claim_type, predicate, value, object) — re-asserting
    the same fact just re-activates + re-attributes it.
    """
    if not _has(conn, "claims"):
        return {"error": "claims table missing"}
    val = str(value).strip() if value is not None else None
    pred = (predicate or "").strip()
    if not pred or not val:
        return {"error": "predicate and value are required"}

    existing = conn.execute(
        "SELECT id FROM claims WHERE entity_id=? AND claim_type=? AND predicate=? "
        "AND IFNULL(value,'')=IFNULL(?,'') AND source='manual' "
        "AND IFNULL(object_entity_id,-1)=IFNULL(?,-1)",
        (entity_id, claim_type, pred, val, object_entity_id),
    ).fetchone()
    if existing:
        claim_id = existing["id"]
        conn.execute(
            "UPDATE claims SET status='active', superseded_by=NULL, author=?, "
            "evidence=?, confidence='analyst' WHERE id=?",
            (analyst, rationale, claim_id))
    else:
        cur = conn.execute(
            "INSERT INTO claims (entity_id, report_id, claim_type, predicate, value, "
            "object_entity_id, confidence, evidence, status, source, author) "
            "VALUES (?, NULL, ?, ?, ?, ?, 'analyst', ?, 'active', 'manual', ?)",
            (entity_id, claim_type, pred, val, object_entity_id, rationale, analyst))
        claim_id = cur.lastrowid
    conn.commit()
    result = resolve(conn, claim_id)   # authoritative + supersede + project + rescore
    result["claim_id"] = claim_id
    result["asserted"] = {"predicate": pred, "value": val, "by": analyst}
    return result


def reject(conn, claim_id: int) -> dict:
    """Mark a claim wrong, then reproject from whatever's still active."""
    c = conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
    if not c:
        return {"error": "claim not found"}
    conn.execute("UPDATE claims SET status='rejected', resolved_at=? WHERE id=?",
                 (_now(conn), claim_id))
    _project_active(conn, c["entity_id"], c["predicate"])
    _recompute_scores(conn)
    conn.commit()
    return {"ok": True}


def _project_active(conn, entity_id, predicate) -> None:
    """Reproject the derived graph from the current authoritative active claim
    (latest report wins). If none remains active, retire the derived edge."""
    row = conn.execute(
        "SELECT * FROM claims WHERE entity_id=? AND predicate=? AND status='active' "
        "ORDER BY report_id DESC, id DESC LIMIT 1", (entity_id, predicate)).fetchone()
    if row:
        _project(conn, dict(row))
    elif predicate.startswith("rel:"):
        try:
            obj = int(predicate.split(":")[1])
            conn.execute(
                "UPDATE typed_relationships SET status='superseded' "
                "WHERE src_entity_id=? AND dst_entity_id=?", (entity_id, obj))
        except (ValueError, IndexError):
            pass


def _recompute_scores(conn) -> None:
    """Keep entity_scores.degree honest after the graph changes (deterministic)."""
    try:
        from investigations import analyze
        analyze.compute_threat_scores(conn)
    except Exception:
        pass


def _project(conn, claim) -> None:
    """Push the winning claim into the derived graph the app reads."""
    pred = claim["predicate"]
    eid = claim["entity_id"]
    val = (claim["value"] or "").strip()
    if pred == "role":
        if val in CANONICAL_ROLES:
            # Preserve the existing rationale after ' — ', just swap the role.
            cur = conn.execute("SELECT notes FROM entities WHERE id=?", (eid,)).fetchone()
            reason = ""
            if cur and cur["notes"] and " — " in cur["notes"]:
                reason = cur["notes"].split(" — ", 1)[1]
            notes = f"role:{val} — " + (reason or f"corrected (claim {claim['id']})")
            conn.execute("UPDATE entities SET notes=? WHERE id=?", (notes, eid))
        elif val in CANONICAL_SUBROLES:
            # A 'role' claim whose value is really a sub-role — set sub_role, do
            # NOT write a non-canonical role into notes (that would zero the score).
            conn.execute("UPDATE entities SET sub_role=?, sub_role_reason=? WHERE id=?",
                         (val, f"corrected (claim {claim['id']})", eid))
        # else: unknown vocab — keep the claim for audit, leave the derived role alone.
    elif pred == "sub_role":
        conn.execute("UPDATE entities SET sub_role=?, sub_role_reason=? WHERE id=?",
                     (val, f"corrected (claim {claim['id']})", eid))
    elif pred.startswith("rel:") and claim.get("object_entity_id"):
        obj = claim["object_entity_id"]
        # Analyst-authored edge: route through the single vocab gate too, so the analyst
        # spine can't open a back door for free-form labels. allow_novel respects analyst
        # authority (a clean domain label they choose passes); a typo/synonym still
        # collapses; a co-occurrence flag (None) is skipped — the claim stays for audit,
        # but no junk label reaches the graph. Normalize ONCE so supersede + match + insert
        # all key off the same label.
        rel = normalize_rel(val, claim.get("evidence", ""), allow_novel=True)
        if rel is None:
            return
        conn.execute(
            "UPDATE typed_relationships SET status='superseded' "
            "WHERE src_entity_id=? AND dst_entity_id=? AND rel_type != ?",
            (eid, obj, rel))
        # The upsert handles both branches: a new edge gets created, an existing one
        # gets its time bounds bumped (the claim IS a re-observation). Reactivation is
        # the one thing the helper deliberately won't do (retired stays retired), so a
        # claim-confirmed edge flips status explicitly after.
        db.upsert_typed_relationship(
            conn, eid, obj, rel, confidence="corrected",
            evidence=claim.get("evidence"), provenance="analyst")
        conn.execute(
            "UPDATE typed_relationships SET status='active' "
            "WHERE src_entity_id=? AND dst_entity_id=? AND rel_type=?", (eid, obj, rel))
    # attribute claims have no derived column — surfaced from the claims layer.


# ---------- entity view ----------

def entity_claims(conn, entity_id: int) -> list[dict]:
    if not _has(conn, "claims"):
        return []
    return [dict(r) for r in conn.execute(
        "SELECT cl.id, cl.claim_type, cl.predicate, cl.value, cl.status, cl.confidence, "
        "cl.evidence, cl.report_id, cl.superseded_by, cl.source, cl.author, "
        "r.title AS report_title "
        "FROM claims cl LEFT JOIN reports r ON r.id = cl.report_id "
        "WHERE cl.entity_id = ? ORDER BY cl.predicate, cl.status, cl.report_id",
        (entity_id,)).fetchall()]


# ---------- LLM per-report claim extraction (roles + attributes from prose) ----------

SYSTEM = """You extract factual CLAIMS a single intel report makes about named entities.
For each entity, output only what THIS report asserts. Claim kinds:
  - role: predicate 'role' (operator/channel/ioc/infra/source) or 'sub_role'
          (leadership/member/facilitator/developer/spokesperson/...)
  - attribute: predicate is the attribute name (location/country/nationality/
          status/affiliation/handle/etc.), value is the asserted value
Only extract claims explicitly supported by the text. Do not infer relationships.
Return JSON: {"claims":[{"name","claim_type","predicate","value","evidence"}]}.
No commentary."""


def extract_claims_for_report(conn, report_id: int, limit_entities: int = 40) -> int:
    """LLM pass: extract per-report role/attribute claims from the report text.

    This is what lets report 2 contradict report 1 on prose facts (e.g. role).
    """
    rep = conn.execute("SELECT id, title, raw_text FROM reports WHERE id=?",
                       (report_id,)).fetchone()
    if not rep or not rep["raw_text"]:
        return 0
    ents = conn.execute(
        "SELECT DISTINCT e.id, e.canonical_name FROM mentions m "
        "JOIN entities e ON e.id = m.entity_id WHERE m.report_id = ? "
        "AND e.entity_type != 'person_candidate' LIMIT ?",
        (report_id, limit_entities)).fetchall()
    if not ents:
        return 0
    name_to_id = {e["canonical_name"]: e["id"] for e in ents}
    prompt = (
        f"REPORT: {rep['title']}\nENTITIES: {', '.join(name_to_id)}\n\n"
        f"TEXT:\n{rep['raw_text'][:12000]}\n\n"
        "Extract the claims this report makes about those entities."
    )
    try:
        # CLASSIFY_MODEL (Haiku): claim extraction is mechanical, not judgment (PRD-02).
        data = llm.ask_json(prompt, system=SYSTEM, timeout=240, model=llm.CLASSIFY_MODEL)
    except Exception:
        return 0
    new = 0
    for c in (data.get("claims") or []):
        eid = name_to_id.get(c.get("name"))
        if not eid or not c.get("predicate") or c.get("value") in (None, ""):
            continue
        new += _insert_claim(
            conn, entity_id=eid, report_id=report_id,
            claim_type=c.get("claim_type") or "attribute",
            predicate=str(c["predicate"]).strip().lower(), value=c["value"],
            confidence="medium", evidence=(c.get("evidence") or "")[:300],
            source="extract")
    conn.commit()
    return new
