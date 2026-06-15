"""Retroactively apply write-time extraction fixes to data already in the DB.

The 2026-06-10 fixes only fire on NEW ingests: the phone predicate (bare digit
runs are not phones), wallet case canonicalization (EVM/bech32 lowercase, base58
case-preserved), and the strong-attribution gate (analyze.gate_attribution). Old
cases still hold pre-fix junk. Three deterministic passes clean them in place:

- clean_phones: a phone entity is junk when fresh extraction over EVERY report
  that mentions it no longer yields its number — delete it and its references.
- clean_wallet_twins: case-variant duplicates of one address merge into the
  policy form (EVM/bech32 → lowercase; base58 → the cased original, but only
  when re-extraction vouches the lowercase one was forged by the old extractor).
- gate_existing_attribution: same_operator & kin edges are re-gated by their own
  stored confidence — low dropped, medium demoted to co_listed, high kept.

Analyst is top authority: flagged entities, analyst-provenance rows, annotated
or seeded entities, and analyst-provenance edges are never deleted or demoted.

Unlike reextract.py (additive by contract, runs mid-investigation), this module
deletes — it runs as its own Process step and via `invctl retro-clean`.
"""
from __future__ import annotations

import re

from investigations import analyze, consolidate
from investigations.ingest import extractor
from investigations import store

_PHONE_SEP_RE = re.compile(r"[\s().-]")

# Tables holding rows that die with a deleted entity (mirrors the exclusive-entity
# cascade in storage/db.delete_report — foreign_keys=ON makes order matter).
_ENTITY_REF_TABLES = [
    ("mentions", "entity_id"), ("relationships", "src_entity_id"),
    ("relationships", "dst_entity_id"), ("typed_relationships", "src_entity_id"),
    ("typed_relationships", "dst_entity_id"), ("claims", "entity_id"),
    ("entity_scores", "entity_id"), ("aliases", "entity_id"),
    ("cluster_members", "entity_id"), ("entity_annotations", "entity_id"),
    ("seeds", "entity_id"), ("alerts", "entity_id"),
    ("enrichment_links", "entity_id"), ("node_properties", "entity_id"),
]


def _norm_phone(s: str) -> str:
    return _PHONE_SEP_RE.sub("", s or "")


# Dossier authors the SYSTEM writes (investigator.py, enrich/promote.py) — an agent
# annotating a node is not an analyst vouching for it, and must not shield junk from
# cleanup (the agent dossier'd the parse-mangled ngambler-partners.is, 2026-06-11).
_MACHINE_AUTHOR_MARKERS = ("(enrichment)", "quick investigate", "osint agent")


def _machine_author(author) -> bool:
    a = (author or "").strip().lower()
    return bool(a) and any(m in a for m in _MACHINE_AUTHOR_MARKERS)


def _analyst_touched(conn, row) -> bool:
    """An ANALYST vouched for this entity — retro passes must not delete it. Analyst
    signals: flagged, analyst provenance, a seed, hand-written notes, or a dossier
    override whose author is not one of the machine writers (legacy NULL-author dossiers
    count as analyst — conservative). A machine-authored dossier alone is NOT a vouch."""
    if row["flagged"]:
        return True
    if (row["provenance"] or "").strip() == "analyst":
        return True
    eid = row["id"]
    try:
        if conn.execute("SELECT 1 FROM seeds WHERE entity_id = ?", (eid,)).fetchone():
            return True
    except Exception:
        pass
    try:
        ann = conn.execute(
            "SELECT notes, dossier_override, dossier_author FROM entity_annotations "
            "WHERE entity_id = ?", (eid,)).fetchone()
    except Exception:
        return False
    if not ann:
        return False
    if (ann["notes"] or "").strip():          # notes are written only by the analyst UI
        return True
    return bool((ann["dossier_override"] or "").strip()) and not _machine_author(
        ann["dossier_author"])


from contextlib import contextmanager


@contextmanager
def _sweep_txn(conn):
    """The whole sweep (per-entity cross-table cleanup + the batched entity
    deletes) is ATOMIC: an exception mid-sweep rolls back the half-deleted
    state instead of leaving entity rows alive with their references gone
    (codex adversarial blocker, 2026-06-11). The BEGIN guard keeps the final
    RELEASE from committing the caller's transaction (SQLite: a SAVEPOINT
    opened outside a transaction commits on RELEASE)."""
    if not conn.in_transaction:
        conn.execute("BEGIN")
    conn.execute("SAVEPOINT retro_sweep")
    try:
        yield
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT retro_sweep")
        conn.execute("RELEASE SAVEPOINT retro_sweep")
        raise
    conn.execute("RELEASE SAVEPOINT retro_sweep")


def _flush_sweep_deletes(conn, case, sweep_class, ids) -> None:
    """ONE noise_swept event per sweep class carrying every deleted id (one
    log row, one bump) — per-entity events flooded the log on large sweeps
    (codex finding). The entity-row deletes ride the event; cross-table
    cleanup already happened per entity in _delete_entity."""
    if ids:
        store.apply_mutation(conn, store.noise_swept_deletes(
            case, sweep_class, ids, actor="pipeline:retro_clean",
            counts={"deleted": len(ids)}))


def _delete_entity(conn, entity_id: int, case: str | None = None,
                   sweep_class: str = "junk",
                   collect: list | None = None) -> None:
    """FK-safe cascade delete (the delete_report exclusive-entity pattern)."""
    for sql, params in (
        ("DELETE FROM enrichment_results WHERE extracted_entity_id = ?", (entity_id,)),
        ("DELETE FROM enrichment_results WHERE run_id IN "
         "(SELECT id FROM enrichment_runs WHERE entity_id = ?)", (entity_id,)),
        ("DELETE FROM enrichment_runs WHERE entity_id = ?", (entity_id,)),
    ):
        try:
            conn.execute(sql, params)
        except Exception:
            pass
    for tbl, col in _ENTITY_REF_TABLES:
        try:
            conn.execute(f"DELETE FROM {tbl} WHERE {col} = ?", (entity_id,))
        except Exception:
            pass
    if collect is not None:
        collect.append(entity_id)   # the sweep flushes one batch event
        return
    store.apply_mutation(conn, store.noise_swept_deletes(
        case, sweep_class, [entity_id], actor="pipeline:retro_clean"))


def _case_entities(conn, case: str | None, entity_type: str):
    """Entities of one type, scoped to a case via its reports' mentions (or all)."""
    if case:
        return conn.execute(
            "SELECT DISTINCT e.* FROM entities e "
            "JOIN mentions m ON m.entity_id = e.id "
            "JOIN reports r ON r.id = m.report_id "
            "WHERE e.entity_type = ? AND r.investigation = ?",
            (entity_type, case)).fetchall()
    return conn.execute(
        "SELECT * FROM entities WHERE entity_type = ?", (entity_type,)).fetchall()


def _fresh_extraction(conn, report_id: int, cache: dict) -> list:
    if report_id not in cache:
        row = conn.execute("SELECT raw_text FROM reports WHERE id = ?",
                           (report_id,)).fetchone()
        cache[report_id] = extractor.extract_all((row["raw_text"] or "") if row else "")
    return cache[report_id]


def _mention_report_ids(conn, entity_id: int) -> list[int]:
    return [r["report_id"] for r in conn.execute(
        "SELECT DISTINCT report_id FROM mentions WHERE entity_id = ?", (entity_id,))]


# --- pass 1: junk phones -----------------------------------------------------

def _is_junk_number(digits: str) -> bool:
    """A phone-typed entity that is UNAMBIGUOUSLY not a phone, judged from its digits
    alone (no source text needed): an all-same-digit run (000000000) or a date in
    YYYYMMDD shape (20260419 = 2026-04-19). Deliberately conservative — an ambiguous
    bare number (a 9-digit ID) is NOT matched here; it's left alone, not guessed at."""
    if not digits or not digits.isdigit():
        return False
    if len(set(digits)) <= 1:           # 000000000 / 111111111 — placeholder junk
        return True
    if len(digits) == 8:                # YYYYMMDD date stripped of its dashes
        y, mo, d = int(digits[:4]), int(digits[4:6]), int(digits[6:8])
        if 2000 <= y <= 2099 and 1 <= mo <= 12 and 1 <= d <= 31:
            return True
    return False


def _repoint_typed_edges(conn, frm: int, to: int, case: str | None = None) -> None:
    """Move graph edges (typed_relationships) from `frm` onto `to`, collapsing duplicates
    (UPDATE OR IGNORE keeps the edge `to` already has) and dropping any self-loop the move
    creates. NEEDED because consolidate._absorb treats typed_relationships as regenerable
    and DROPS them — but an IP-twin recovery must preserve the edges on the real IP node
    (founder's 'recover, don't lose data'). Runs BEFORE _absorb, which then cleans the
    leftover (collided) frm-edges."""
    store.apply_mutation(conn, store.edges_maintained(
        case, "repoint", actor="pipeline:retro_clean", frm=frm, to=to))


def _ip_digit_index(conn, case: str | None) -> dict[str, int]:
    """{dot-stripped IPv4 digits -> ip entity id} for the case's IP nodes, so a phone
    entity whose digits ARE an IP-with-the-dots-stripped (1042168184 = 104.21.68.184)
    can be recognised as that IP and recovered, not just deleted."""
    idx: dict[str, int] = {}
    for row in _case_entities(conn, case, "ip"):
        idx.setdefault(_norm_phone(row["canonical_name"]), row["id"])
    return idx


def _report_has_text(conn, report_id: int, cache: dict) -> bool:
    """True if the report carries non-empty raw_text — i.e. re-extraction can actually
    judge it. A phone from a text-less (structured) source is left alone, never deleted
    on a vacuous 'fresh extraction yielded nothing'."""
    if report_id not in cache:
        row = conn.execute("SELECT raw_text FROM reports WHERE id = ?",
                           (report_id,)).fetchone()
        cache[report_id] = bool(row and (row["raw_text"] or "").strip())
    return cache[report_id]


def clean_phones(conn, case: str | None = None, dry: bool = False) -> dict:
    with _sweep_txn(conn):
        return _clean_phones_impl(conn, case, dry)


def _clean_phones_impl(conn, case: str | None = None, dry: bool = False) -> dict:
    """Recover or delete junk phone entities the fixed predicate no longer extracts.

    Two outcomes for a non-analyst phone:
      - RECOVER: its digits are an IP with the dots stripped (1042168184 = 104.21.68.184
        — the old extractor matched the dotted IP as a phone, then the canonicalizer
        stripped the dots). It IS that IP, so absorb its edges/mentions onto the real IP
        node, then delete the twin. Zero data loss — the relationships land on the right node.
      - DELETE: fresh extraction over EVERY text report that mentions it no longer yields
        its number as a phone (a date, an ID, a counter) — delete it and its references.
    A phone from a text-less source is never deleted (can't be re-judged). Real phones
    (+ prefix / labeled) survive because fresh extraction still yields them.
    dry=True reports candidates and writes nothing."""
    checked, names, recovered = 0, [], []
    sweep_deletes: list[int] = []
    text_cache: dict[int, list] = {}
    has_text_cache: dict[int, bool] = {}
    ip_index = _ip_digit_index(conn, case)
    for row in _case_entities(conn, case, "phone"):
        if _analyst_touched(conn, row):
            continue
        digits = _norm_phone(row["canonical_name"])
        # (1) IP-twin recovery: merge the dot-stripped IP twin onto the real IP node.
        ip_id = ip_index.get(digits)
        if ip_id and ip_id != row["id"]:
            recovered.append((row["canonical_name"], _entity_name(conn, ip_id)))
            if not dry:
                _repoint_typed_edges(conn, row["id"], ip_id, case=case)  # preserve graph edges
                consolidate._absorb(conn, row["id"], ip_id)   # mentions/aliases/FKs + delete
            continue
        # (2) unambiguous non-phone junk (a date, an all-zeros placeholder) — deletable
        # from the digits alone, so it's cleaned even when the source report has no text.
        if _is_junk_number(digits):
            names.append(row["canonical_name"])
            if not dry:
                _delete_entity(conn, row["id"], case=case, collect=sweep_deletes)
            continue
        # (3) re-extraction judgment over the report TEXT (now correct after the
        # IPv4/date predicate fix). Only judge reports that actually have text.
        report_ids = [rid for rid in _mention_report_ids(conn, row["id"])
                      if _report_has_text(conn, rid, has_text_cache)]
        if not report_ids:
            continue  # text-less source — can't re-judge, leave it alone
        checked += 1
        fresh = {_norm_phone(e.canonical)
                 for rid in report_ids
                 for e in _fresh_extraction(conn, rid, text_cache)
                 if e.entity_type == "phone"}
        if digits not in fresh:
            names.append(row["canonical_name"])
            if not dry:
                _delete_entity(conn, row["id"], case=case, collect=sweep_deletes)
    _flush_sweep_deletes(conn, case, "junk-phones", sweep_deletes)
    return {"checked": checked, "deleted": len(names), "names": names,
            "recovered": len(recovered), "recovered_pairs": recovered}


# --- pass 1b: graph noise (boilerplate/reference domains + bare-number "phones") ------

def clean_noise(conn, case: str | None = None, dry: bool = False) -> dict:
    with _sweep_txn(conn):
        return _clean_noise_impl(conn, case, dry)


def _clean_noise_impl(conn, case: str | None = None, dry: bool = False) -> dict:
    sweep_deletes: list[int] = []
    """Delete existing graph-noise nodes the promotion gate now keeps out (founder
    2026-06-11): bare-number 'phones' that aren't real phones (164736471 = an affiliate /
    tracking id), and registry / WHOIS / reference boilerplate domains (iana.org,
    whois.verisign-grs.com, krebsonsecurity.com). Runs AFTER clean_phones so IP-twins are
    recovered onto their real IP first, not deleted here. Analyst-touched entities are
    never removed. dry=True reports candidates and writes nothing."""
    # Cleanup routes through the SAME admission contract the creation paths use (RCA
    # rca-recurring-graph-noise-2026-06-11), so what gets cleaned and what gets blocked at
    # creation can never drift. A node is junk iff it would not be admitted today.
    from investigations import admission
    deleted: list[tuple[str, str]] = []
    for etype in ("phone", "domain", "subdomain", "url", "email"):
        for row in _case_entities(conn, case, etype):
            if _analyst_touched(conn, row):
                continue
            # phone_prevalidated for INGEST-sourced phones: the extractor context-validated
            # those (a bare number it kept had a 'Phone:' label), so a value-only re-check
            # must not delete them. Agent/enrichment phones had no such context → strict.
            prov = (row["provenance"] or "").strip()
            prevalidated = etype == "phone" and prov.startswith("ingest")
            ok, why = admission.is_admissible(etype, row["canonical_name"],
                                              phone_prevalidated=prevalidated)
            if not ok:
                deleted.append((row["canonical_name"], why))
                if not dry:
                    _delete_entity(conn, row["id"], case=case,
                                   collect=sweep_deletes)
    _flush_sweep_deletes(conn, case, "admission-noise", sweep_deletes)
    return {"deleted": len(deleted), "items": deleted}


# --- pass 1c: parse-mangled twins (escaped-text extraction) ----------------------

def clean_escape_twins(conn, case: str | None = None, dry: bool = False) -> dict:
    """Merge parse-mangled twins onto their real counterpart. The live-dig extractor used
    to regex JSON-escaped tool output, forging three twin shapes of an entity that already
    exists clean: a leading-'n' domain (the 'n' of a literal \\n — "ntrumpstake.us"), a
    trailing-quote URL ("https://x/'"), and a value with an "\\nconfidence: ..." tail.
    The twin's edges/mentions move onto the real entity first (recover, don't lose data —
    the clean_phones IP-twin pattern), then the husk is absorbed. A mangled value with NO
    surviving counterpart is left alone here; clean_noise judges it by admission instead.
    Analyst-touched twins are never merged. dry=True reports pairs and writes nothing."""
    merged: list[tuple[str, str]] = []
    for etype in ("domain", "subdomain", "url"):
        rows = _case_entities(conn, case, etype)
        by_name = {r["canonical_name"]: r for r in rows}
        for row in rows:
            if _analyst_touched(conn, row):
                continue
            name = row["canonical_name"]
            # strip an escaped-control tail (\nconfidence: high) + closing quotes
            target = re.split(r"\\[nrt]", name)[0].rstrip("'\"").strip()
            # leading-'n' twin: only when the un-prefixed name is a live same-type entity
            if target == name and name[:1] == "n" and name[1:] in by_name:
                target = name[1:]
            if not target or target == name:
                continue
            real = by_name.get(target)
            if real is None or real["id"] == row["id"]:
                continue
            merged.append((name, target))
            if not dry:
                _repoint_typed_edges(conn, row["id"], real["id"], case=case)   # preserve graph edges
                consolidate._absorb(conn, row["id"], real["id"])    # mentions/aliases + delete
    return {"merged": len(merged), "pairs": merged}


# --- pass 2: wallet case-twins -------------------------------------------------

def _absorb_wallet(conn, dup, survivor_id: int, case: str | None = None) -> None:
    if dup["flagged"]:  # _absorb folds annotations/seeds; flagged needs a hand
        store.apply_mutation(conn, store.entities_retyped_batch(
            case, [{"entity_id": survivor_id, "fields": {"flagged": 1}}], actor="pipeline:retro_clean"))
    consolidate._absorb(conn, dup["id"], survivor_id)


def _merge_case_insensitive(conn, low: str, group: list, pairs: list, dry: bool,
                            case: str | None = None) -> int:
    """EVM/bech32 group → one entity canonically named `low`."""
    survivor = next((g for g in group if g["canonical_name"] == low), None)
    if survivor is None:
        group.sort(key=lambda g: _mention_count(conn, g["id"]), reverse=True)
        survivor = group[0]
        pairs.append((survivor["canonical_name"], low))  # a rename, reported too
        if not dry:
            conn.execute("INSERT OR IGNORE INTO aliases (entity_id, alias) VALUES (?, ?)",
                         (survivor["id"], survivor["canonical_name"]))
            store.apply_mutation(conn, store.entity_merged(
                case, survivor["id"], [], actor="pipeline:retro_clean",
                fields={"canonical_name": low}))
    merged = 0
    for dup in group:
        if dup["id"] != survivor["id"]:
            pairs.append((dup["canonical_name"], low))
            if not dry:
                _absorb_wallet(conn, dup, survivor["id"], case=case)
            merged += 1
    return merged


def _merge_forged_base58(conn, group: list, cache: dict, pairs: list, dry: bool,
                         case: str | None = None) -> int:
    """base58 is case-SENSITIVE: merge the all-lowercase variant into the cased one
    ONLY when re-extracting its reports yields the cased form and not the lowercase
    (i.e. the old extractor forged it by lowercasing). Genuine lowercase survives."""
    cased = [g for g in group if g["canonical_name"] != g["canonical_name"].lower()]
    lows = [g for g in group if g["canonical_name"] == g["canonical_name"].lower()]
    if len(cased) != 1 or not lows:
        return 0  # no twin, or 2+ distinct cased forms (genuinely different addresses)
    target = cased[0]
    merged = 0
    for low_e in lows:
        fresh = {e.canonical for rid in _mention_report_ids(conn, low_e["id"])
                 for e in _fresh_extraction(conn, rid, cache)
                 if e.entity_type == "crypto_wallet"}
        if target["canonical_name"] in fresh and low_e["canonical_name"] not in fresh:
            pairs.append((low_e["canonical_name"], target["canonical_name"]))
            if not dry:
                _absorb_wallet(conn, low_e, target["id"], case=case)
            merged += 1
    return merged


def _mention_count(conn, entity_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM mentions WHERE entity_id = ?",
                        (entity_id,)).fetchone()[0]


def clean_wallet_twins(conn, case: str | None = None, dry: bool = False) -> dict:
    """Merge case-variant duplicates of one wallet address into its policy form.
    dry=True reports the (duplicate, survivor) pairs and writes nothing."""
    groups: dict[str, list] = {}
    for row in _case_entities(conn, case, "crypto_wallet"):
        groups.setdefault(row["canonical_name"].lower(), []).append(row)
    merged = 0
    pairs: list[tuple[str, str]] = []
    cache: dict[int, list] = {}
    for low, group in groups.items():
        if low.startswith("0x") or low.startswith("bc1"):
            if len(group) > 1 or group[0]["canonical_name"] != low:
                merged += _merge_case_insensitive(conn, low, group, pairs, dry, case=case)
        elif len(group) > 1:
            merged += _merge_forged_base58(conn, group, cache, pairs, dry, case=case)
    return {"merged": merged, "pairs": pairs}


# --- pass 3: retroactive attribution gate --------------------------------------

def _case_edge_rows(conn, case: str | None):
    strong = ",".join("?" * len(analyze._STRONG_ATTRIBUTION))
    types = tuple(analyze._STRONG_ATTRIBUTION)
    if case:
        return conn.execute(
            "SELECT t.* FROM typed_relationships t WHERE t.rel_type IN "
            f"({strong}) AND (t.src_entity_id IN ("
            "  SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id"
            "  WHERE r.investigation = ?) OR t.dst_entity_id IN ("
            "  SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id"
            "  WHERE r.investigation = ?))",
            types + (case, case)).fetchall()
    return conn.execute(
        f"SELECT * FROM typed_relationships WHERE rel_type IN ({strong})",
        types).fetchall()


def _entity_name(conn, entity_id: int) -> str:
    row = conn.execute("SELECT canonical_name FROM entities WHERE id = ?",
                       (entity_id,)).fetchone()
    return row["canonical_name"] if row else f"#{entity_id}"


def _demote_edge(conn, row, gated: str, case: str | None = None) -> None:
    store.apply_mutation(conn, store.edges_maintained(
        case, "set_rel_type", actor="pipeline:retro_clean", edge_id=row["id"], rel_type=gated))
    still = conn.execute("SELECT rel_type FROM typed_relationships WHERE id = ?",
                         (row["id"],)).fetchone()
    if still and still["rel_type"] != gated:  # UNIQUE collision: target edge exists
        store.apply_mutation(conn, store.edges_maintained(
            case, "delete_ids", actor="pipeline:retro_clean", edge_ids=[row["id"]]))


def gate_existing_attribution(conn, case: str | None = None, dry: bool = False) -> dict:
    """Re-gate stored strong-attribution edges by their own confidence:
    low → drop, medium/NULL → demote to co_listed, high → keep.
    Analyst-provenance edges are never touched (analyst is top authority).
    dry=True reports the affected edges and writes nothing."""
    dropped, demoted, edges = 0, 0, []
    for row in _case_edge_rows(conn, case):
        if (row["provenance"] or "").strip() == "analyst":
            continue
        gated = analyze.gate_attribution(row["rel_type"], row["confidence"])
        if gated == row["rel_type"]:
            continue
        edges.append({"src": _entity_name(conn, row["src_entity_id"]),
                      "dst": _entity_name(conn, row["dst_entity_id"]),
                      "rel_type": row["rel_type"], "confidence": row["confidence"],
                      "action": "drop" if gated is None else f"demote to {gated}"})
        if gated is None:
            dropped += 1
            if not dry:
                store.apply_mutation(conn, store.edges_maintained(
                    case, "delete_ids", actor="pipeline:retro_clean", edge_ids=[row["id"]]))
            continue
        demoted += 1
        if not dry:
            _demote_edge(conn, row, gated, case=case)
    return {"dropped": dropped, "demoted": demoted, "edges": edges}


# --- pass 4: legacy edge time-bounds backfill -----------------------------------

def backfill_edge_times(conn, case: str | None = None, dry: bool = False) -> dict:
    """Stamp first_seen/last_seen on legacy typed edges that predate the
    time-bounds writer (storage/db.upsert_typed_relationship).

    Source: MAX(endpoint entities.first_seen_at) — the earliest moment BOTH
    endpoints existed, the tightest sound observation-time lower bound the
    schema offers (typed_relationships has no run FK; free-text provenance is
    not a join key). Observation time, NOT event time — event-time extraction
    from finding text is explicitly out of scope (PRD graph-machinery-activation).

    Idempotent: only NULL/empty bounds are touched; a non-empty bound is never
    overwritten (the live writer's MIN/MAX contract owns those rows).
    dry=True reports the candidate edges and writes nothing."""
    scope_sql, params = "", []
    if case:
        scope_sql = (
            "AND t.src_entity_id IN ("
            "  SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id"
            "  WHERE r.investigation = ?) "
            "AND t.dst_entity_id IN ("
            "  SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id"
            "  WHERE r.investigation = ?)")
        params = [case, case]
    rows = conn.execute(
        "SELECT t.id, t.rel_type, t.first_seen, t.last_seen, "
        "  MAX(es.first_seen_at, ed.first_seen_at) AS stamp, "
        "  es.canonical_name AS src_name, ed.canonical_name AS dst_name "
        "FROM typed_relationships t "
        "JOIN entities es ON es.id = t.src_entity_id "
        "JOIN entities ed ON ed.id = t.dst_entity_id "
        "WHERE (t.first_seen IS NULL OR t.first_seen = '' "
        "       OR t.last_seen IS NULL OR t.last_seen = '') "
        f"{scope_sql}", params).fetchall()
    stamped, edges = 0, []
    for row in rows:
        stamp = row["stamp"]
        if not stamp:
            continue
        edges.append({"src": row["src_name"], "dst": row["dst_name"],
                      "rel_type": row["rel_type"], "stamp": stamp})
        stamped += 1
        if dry:
            continue
        # Only the empty side is stamped — and the stamp is clamped against the
        # existing side so a half-filled row can never end up first_seen >
        # last_seen (the writer's ordering invariant). String compare is safe:
        # one fixed 'YYYY-MM-DD HH:MM:SS' format.
        fs, ls = row["first_seen"], row["last_seen"]
        new_fs = fs if fs else (min(stamp, ls) if ls else stamp)
        new_ls = ls if ls else (max(stamp, fs) if fs else stamp)
        store.apply_mutation(conn, store.edges_maintained(
            case, "set_time_bounds", actor="pipeline:retro_clean", edge_id=row["id"],
            first_seen=new_fs, last_seen=new_ls))
    return {"stamped": stamped, "edges": edges}


# --- pass 5: CDN IP tagging + de-gating ----------------------------------------

_CDN_MEDIATED_RELS = ("shared_infra", "same_operator")


def tag_and_degate_cdn(conn, case: str | None = None, dry: bool = False) -> dict:
    """Tag CDN IP entities and drop same-operator/shared-infra edges that rest ONLY
    on a shared CDN IP (issue gtl-3). A CDN edge IP (Cloudflare 104.21.*, 172.67.*)
    is shared by thousands of unrelated sites, so "both resolve here" is not
    evidence of shared operation. A dedicated server (38.46.220.132) is untouched.

    Two actions: (1) write node_properties infra_class='cdn' for every IP entity in
    a known CDN range; (2) for each shared_infra/same_operator edge between two
    domains, drop it when EVERY infra node the two endpoints share is a CDN IP
    (an edge backed by a dedicated server survives). Analyst-provenance edges are
    never dropped. dry=True reports candidates and writes nothing."""
    from investigations import cdn_ranges

    # (1) tag CDN IP entities
    ip_rows = _case_entities(conn, case, "ip")
    tagged = []
    for row in ip_rows:
        if cdn_ranges.is_cdn_ip(row["canonical_name"]):
            tagged.append(row["canonical_name"])
            if not dry:
                conn.execute(
                    "INSERT INTO node_properties (entity_id, key, value, value_type, "
                    " provenance, confidence) VALUES (?, 'infra_class', 'cdn', 'string', "
                    " 'cdn:ranges', 'high') "
                    "ON CONFLICT(entity_id, key) DO UPDATE SET value='cdn', "
                    " provenance='cdn:ranges', confidence='high'",
                    (row["id"],))

    # (2) drop CDN-only same-operator / shared-infra edges. Case-scoped (either
    # endpoint in the case) when a case is given — a case-scoped retro-clean must
    # NOT delete another investigation's edges (Codex gtl-3 finding); the other
    # passes honor the case boundary and this one must too.
    rels = _CDN_MEDIATED_RELS
    strong = ",".join("?" * len(rels))
    if case:
        edge_rows = conn.execute(
            f"SELECT t.* FROM typed_relationships t WHERE t.rel_type IN ({strong}) "
            f"AND COALESCE(t.status,'active')='active' AND (t.src_entity_id IN ("
            f"  SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id"
            f"  WHERE r.investigation = ?) OR t.dst_entity_id IN ("
            f"  SELECT m.entity_id FROM mentions m JOIN reports r ON r.id = m.report_id"
            f"  WHERE r.investigation = ?))", (*rels, case, case)).fetchall()
    else:
        edge_rows = conn.execute(
            f"SELECT * FROM typed_relationships WHERE rel_type IN ({strong}) "
            f"AND COALESCE(status,'active')='active'", rels).fetchall()
    dropped = []
    for e in edge_rows:
        if (e["provenance"] or "").strip() == "analyst":
            continue
        shared = _shared_infra_ids(conn, e["src_entity_id"], e["dst_entity_id"])
        if not shared:
            continue   # not an IP-mediated edge — leave it alone
        # Drop only when EVERY shared infra node is a CDN IP (no dedicated server).
        names = [_entity_name(conn, i) for i in shared]
        if all(cdn_ranges.is_cdn_ip(n) for n in names):
            dropped.append({"src": _entity_name(conn, e["src_entity_id"]),
                            "dst": _entity_name(conn, e["dst_entity_id"]),
                            "rel_type": e["rel_type"], "via": names})
            if not dry:
                store.apply_mutation(conn, store.edges_maintained(
                    case, "delete_ids", actor="pipeline:retro_clean", edge_ids=[e["id"]]))
    return {"tagged": tagged, "dropped": dropped}


def _shared_infra_ids(conn, a_id: int, b_id: int) -> set[int]:
    """IP/infra nodes that BOTH a and b connect to via resolves_to/hosted_on
    (the co-hosting evidence a same-operator edge would rest on)."""
    def infra_of(eid):
        return {r["dst_entity_id"] for r in conn.execute(
            "SELECT t.dst_entity_id FROM typed_relationships t JOIN entities e "
            "ON e.id = t.dst_entity_id WHERE t.src_entity_id = ? "
            "AND t.rel_type IN ('resolves_to','hosted_on') AND e.entity_type = 'ip' "
            "AND COALESCE(t.status,'active')='active'", (eid,))}
    return infra_of(a_id) & infra_of(b_id)


# --- pass 6: edge semantic fixes -----------------------------------------------

# Bare blockchain/protocol names that are ATTRIBUTES of a scam (what it drains),
# not graph entities — a node for "Ethereum" is a hairball hub with no pivot value.
_BLOCKCHAIN_NAMES = {
    "ethereum", "eth", "bitcoin", "btc", "solana", "sol", "sui", "ton", "tron",
    "bnb", "binance smart chain", "bsc", "polygon", "matic", "base", "arbitrum",
    "avalanche", "avax", "cardano", "ada", "dogecoin", "doge", "litecoin", "ltc",
}


def _is_subdomain_of(child: str, parent: str) -> bool:
    """True when `child` is a strict hostname-suffix subdomain of `parent`
    (child = 'a.b.example.com', parent = 'b.example.com')."""
    c = (child or "").strip().lower().rstrip(".")
    p = (parent or "").strip().lower().rstrip(".")
    return bool(c) and bool(p) and c != p and c.endswith("." + p)


def fix_edge_semantics(conn, case: str | None = None, dry: bool = False) -> dict:
    with _sweep_txn(conn):
        return _fix_edge_semantics_impl(conn, case, dry)


def _fix_edge_semantics_impl(conn, case: str | None = None, dry: bool = False) -> dict:
    """Correct three modeled-wrong edge shapes (issue gtl-5):
      (a) an INVERTED has_subdomain edge — vocab is parent has_subdomain child, so
          when src is the subdomain of dst the edge points the wrong way; flip it;
      (b) a bare blockchain-name node (Ethereum/Bitcoin/…) with no role — it's an
          attribute (what the scam drains), not an entity; rewrite its `targets`
          edge into a node property on the source, then delete the node;
      (c) leftover `targets → <blockchain>` edges become a targets_chain property.
    Analyst-touched rows are never altered. Case-scoped via endpoint mentions.
    dry=True reports candidates and writes nothing."""
    def _src_in_case(src_id) -> bool:
        """Case-scope by the edge's SOURCE only — scoping by either endpoint would
        let a case that merely mentions the shared DST mutate another case's edge
        (Codex gtl-5 findings)."""
        if not case:
            return True
        return conn.execute(
            "SELECT 1 FROM mentions m JOIN reports r ON r.id = m.report_id "
            "WHERE r.investigation = ? AND m.entity_id = ? LIMIT 1",
            (case, src_id)).fetchone() is not None

    flipped, demoted_chains, deleted_nodes = [], [], []
    sweep_deletes: list[int] = []

    # (a) flip inverted has_subdomain edges
    for e in conn.execute(
        "SELECT * FROM typed_relationships WHERE rel_type = 'has_subdomain' "
        "AND COALESCE(status,'active')='active'").fetchall():
        if (e["provenance"] or "").strip() == "analyst":
            continue
        src, dst = _entity_name(conn, e["src_entity_id"]), _entity_name(conn, e["dst_entity_id"])
        if not _src_in_case(e["src_entity_id"]):
            continue
        # Inverted when SRC is the subdomain of DST (child→parent instead of parent→child).
        if _is_subdomain_of(src, dst):
            flipped.append({"was": f"{src} -[has_subdomain]-> {dst}",
                            "now": f"{dst} -[has_subdomain]-> {src}"})
            if not dry:
                # The correct-direction edge may already exist → collision; delete then.
                exists = conn.execute(
                    "SELECT 1 FROM typed_relationships WHERE src_entity_id = ? "
                    "AND dst_entity_id = ? AND rel_type = 'has_subdomain'",
                    (e["dst_entity_id"], e["src_entity_id"])).fetchone()
                if exists:
                    store.apply_mutation(conn, store.edges_maintained(
                        case, "delete_ids", actor="pipeline:retro_clean", edge_ids=[e["id"]]))
                else:
                    store.apply_mutation(conn, store.edges_maintained(
                        case, "repoint_id", actor="pipeline:retro_clean", edge_id=e["id"],
                        src=e["dst_entity_id"], dst=e["src_entity_id"]))

    # (b/c) blockchain-name nodes: rewrite targets edges to a property, drop the node.
    # A bare blockchain name is an attribute, not an entity — removed UNLESS an
    # analyst vouched for it (flagged / annotated / seeded = top authority).
    for ent in conn.execute(
        "SELECT id, canonical_name, notes, flagged, provenance FROM entities").fetchall():
        if ent["canonical_name"].strip().lower() not in _BLOCKCHAIN_NAMES:
            continue
        if _analyst_touched(conn, ent):
            continue
        chain = ent["canonical_name"].strip()
        # ACTIVE targets edges only (Codex gtl-5 adversarial): a superseded/rejected
        # edge must not be revived as a property nor have its audit row destroyed.
        targets_edges = conn.execute(
            "SELECT * FROM typed_relationships WHERE dst_entity_id = ? "
            "AND rel_type = 'targets' AND COALESCE(status,'active')='active'",
            (ent["id"],)).fetchall()
        # Rewrite ONLY this case's, non-analyst targets edges (Codex gtl-5 finding-1/2):
        # the rewrite must not reach into another case's edge (the dst being mentioned
        # here is not enough — the SOURCE domain must be in-case), and an analyst-
        # authored targets edge is top authority and left intact.
        for te in targets_edges:
            if (te["provenance"] or "").strip() == "analyst":
                continue
            if not _src_in_case(te["src_entity_id"]):
                continue
            demoted_chains.append({"src": _entity_name(conn, te["src_entity_id"]),
                                   "chain": chain})
            if not dry:
                _append_node_property(conn, te["src_entity_id"], "targets_chain", chain)
                store.apply_mutation(conn, store.edges_maintained(
                    case, "delete_ids", actor="pipeline:retro_clean", edge_ids=[te["id"]]))
        # Delete the node ONLY when NOTHING references it anymore — counting edges of
        # ANY status (other case's targets, analyst edge, other rel type, OR a retired
        # row whose audit trail must outlive this pass). A shared or audited node is
        # never removed by this case's run.
        remaining = conn.execute(
            "SELECT COUNT(*) AS n FROM typed_relationships WHERE "
            "(src_entity_id = ? OR dst_entity_id = ?)",
            (ent["id"], ent["id"])).fetchone()["n"]
        if remaining == 0:
            deleted_nodes.append(chain)
            if not dry:
                _delete_entity(conn, ent["id"], case=case,
                               collect=sweep_deletes)

    _flush_sweep_deletes(conn, case, "blockchain-name-nodes", sweep_deletes)
    return {"flipped": flipped, "demoted_chains": demoted_chains,
            "deleted_blockchain_nodes": deleted_nodes}


def _append_node_property(conn, entity_id: int, key: str, value: str) -> None:
    """Append `value` to a comma-separated node property (dedup), upsert-in-place."""
    row = conn.execute("SELECT value FROM node_properties WHERE entity_id = ? AND key = ?",
                       (entity_id, key)).fetchone()
    vals = [v.strip() for v in (row["value"].split(",") if row else []) if v.strip()]
    if value not in vals:
        vals.append(value)
    conn.execute(
        "INSERT INTO node_properties (entity_id, key, value, value_type, provenance, confidence) "
        "VALUES (?, ?, ?, 'string', 'retro:edge-fix', 'high') "
        "ON CONFLICT(entity_id, key) DO UPDATE SET value=excluded.value, "
        "provenance=excluded.provenance",
        (entity_id, key, ", ".join(vals)))


def clean_dossier_transcripts(conn, case: str | None = None, dry: bool = False) -> dict:
    """Strip model tool-call/tool-response transcripts that leaked into stored
    dossiers (issue text-admission-gate). It routes through the SAME
    admission.sanitize_model_text the write gate uses, so write-time and retro
    cannot drift (the RCA pattern: one contract, every path). Idempotent — the
    sanitizer is a no-op on already-clean text. A pure-bluff dossier is cleared;
    a mixed one keeps its real part. The transcript shape is never legitimate
    from anyone, so the sweep is author-independent and DB-wide (dossier poison
    is junk regardless of case). dry=True reports candidates and writes nothing."""
    from investigations import admission
    if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='entity_annotations'"
    ).fetchone():
        return {"cleaned": 0, "entity_ids": []}
    rows = conn.execute(
        "SELECT entity_id, dossier_override FROM entity_annotations "
        "WHERE dossier_override IS NOT NULL").fetchall()
    cleaned_ids: list[int] = []
    with _sweep_txn(conn):
        for r in rows:
            new, removed = admission.sanitize_model_text(r["dossier_override"])
            if not removed:
                continue
            cleaned_ids.append(r["entity_id"])
            if dry:
                continue
            if admission.text_is_effectively_blank(new):
                conn.execute(
                    "UPDATE entity_annotations SET dossier_override = NULL, "
                    "dossier_updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?",
                    (r["entity_id"],))
            else:
                conn.execute(
                    "UPDATE entity_annotations SET dossier_override = ?, "
                    "dossier_updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?",
                    (new, r["entity_id"]))
    return {"cleaned": len(cleaned_ids), "entity_ids": cleaned_ids}


def run(conn, case: str | None = None, dry: bool = False) -> dict:
    """All passes. Case-scoped when `case` is given, otherwise the whole DB.
    dry=True reports every candidate action by name and writes nothing.

    Order matters: the CDN pass runs BEFORE the attribution gate (Codex gtl-3
    adversarial). The attribution gate demotes a medium/NULL same_operator edge to
    co_listed; the CDN pass only scans same_operator/shared_infra, so a CDN-only
    edge demoted first would survive as co_listed — the exact false association the
    CDN pass exists to remove. Dropping it first closes that gap."""
    out = {
        "phones": clean_phones(conn, case, dry),
        # mangled twins MERGE onto their real entity before clean_noise can DELETE them —
        # merge preserves the twin's edges; deletion would drop them.
        "escape_twins": clean_escape_twins(conn, case, dry),
        "noise": clean_noise(conn, case, dry),   # after clean_phones (IP-twins recover first)
        "wallets": clean_wallet_twins(conn, case, dry),
        "cdn": tag_and_degate_cdn(conn, case, dry),
        "attribution": gate_existing_attribution(conn, case, dry),
        "edge_times": backfill_edge_times(conn, case, dry),
        "edge_semantics": fix_edge_semantics(conn, case, dry),
        "dossier_transcripts": clean_dossier_transcripts(conn, case, dry),
    }
    if not dry:
        conn.commit()
    return out
