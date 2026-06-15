"""The typing pass — make existing entities fit the case's approved schema, and
recover schema-typed entities the regex extractor missed.

Two passes, both schema-driven (run after consolidate, which already merged dups
and tagged roles):

1. retype_entities  — assign each case entity a `case_type` from the schema's
   entity_types (wallet_address, scam_domain, drainer_kit…). entity_type (the
   regex surface type: ip/domain/crypto_wallet) is LEFT ALONE so pivot links keep
   working; case_type is the analytic label the case actually uses.

2. extract_missing  — the regex taxonomy is hacktivist-shaped and misses things a
   crypto case cares about (it found 0 wallets in a wallet-fraud case). Re-read
   each report and pull entities of the schema's types that aren't captured yet,
   adding them fully classified (surface type + case_type + role + sub_role).

Both are bounded LLM passes. Nothing here runs without an APPROVED schema.
"""
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from investigations.storage import db
from investigations import store
from investigations.llm import client as llm
from investigations import understand

# 80 (not 40): fewer/larger retype batches pay the per-call boot overhead half as
# often. Override with TYPING_BATCH_SIZE.
BATCH_SIZE = max(1, int(os.environ.get("TYPING_BATCH_SIZE", "80")))
# Parallel fan-out for the LLM calls. Same proven shape as consolidate: workers only
# make the API call (no DB access), the main thread does every write — so there is one
# SQLite writer (no lock contention) and no fork-bomb (calls go tools=False). Cap kept
# at 5 to stay under the API rate limit. Override with TYPING_CONCURRENCY.
TYPING_CONCURRENCY = max(1, int(os.environ.get("TYPING_CONCURRENCY", "5")))
MAX_NEW_PER_REPORT = 60
REPORT_CHAR_BUDGET = 24_000

# Surface types pivot links + format logic understand. extract_missing must map
# every new entity onto one of these so /enrich pivots keep working.
SURFACE_TYPES = [
    "ip", "domain", "url", "email", "phone", "handle", "telegram_channel",
    "crypto_wallet", "hash_sha256", "hash_md5", "person", "org", "asn", "other",
]


# ---------------------------------------------------------------- retype pass

def _retype_system(schema: dict) -> str:
    type_lines = [f"   - {t['name']} — {t.get('description','')}"
                  for t in schema.get("entity_types", [])]
    return (
        "You are typing entities for a specific investigation.\n\n"
        f"CASE DOMAIN: {schema.get('domain','')}\n{schema.get('summary','')}\n\n"
        "You receive entities (with their crude regex type + a role + sample "
        "context). Assign each ONE case_type from this case's entity types:\n"
        + "\n".join(type_lines) + "\n"
        "Use 'other' only when none fit. Output strict JSON only."
    )


def _retype_prompt(batch: list[dict], type_names: list[str]) -> str:
    items = [{"id": e["id"], "name": e["canonical_name"], "regex_type": e["entity_type"],
              "role": e["role"], "context": (e["context"] or "")[:160]} for e in batch]
    return (
        f"Entities to type ({len(batch)}):\n{json.dumps(items, ensure_ascii=False)}\n\n"
        "Return JSON: {\"types\": [{\"id\": <int>, \"case_type\": \"<one of: "
        + ", ".join(type_names + ["other"]) + ">\"}]}\n"
        "Every input id must appear exactly once."
    )


def _case_entities(conn, case: str) -> list[dict]:
    rows = conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.notes, "
        "(SELECT m.context FROM mentions m WHERE m.entity_id = e.id LIMIT 1) AS context "
        "FROM entities e WHERE e.id IN ("
        "  SELECT m2.entity_id FROM mentions m2 JOIN reports r ON r.id = m2.report_id "
        "  WHERE r.investigation = ?) "
        "AND COALESCE(e.notes,'') NOT LIKE 'role:noise%' "
        "ORDER BY e.id", (case,)).fetchall()
    out = []
    for r in rows:
        role = (r["notes"] or "").split(" — ")[0].replace("role:", "").strip()
        out.append({"id": r["id"], "canonical_name": r["canonical_name"],
                    "entity_type": r["entity_type"], "role": role, "context": r["context"]})
    return out


def retype_entities(conn, case: str, schema: dict) -> dict:
    """Assign every non-noise case entity a case_type from the schema.

    Parallel + safe: the LLM calls fan out across a thread pool (workers touch NO DB),
    and every UPDATE happens here on the main thread — one writer, no SQLite lock. Calls
    go tools=False (no MCP boot) on Haiku (mechanical classification)."""
    entities = _case_entities(conn, case)
    type_names = understand.entity_type_names(schema)
    if not type_names:
        return {"typed": 0, "skipped": "no entity_types in schema"}
    valid = set(type_names) | {"other"}
    system = _retype_system(schema)
    batches = [entities[i:i + BATCH_SIZE] for i in range(0, len(entities), BATCH_SIZE)]
    nb = len(batches)

    def _classify(batch):
        try:
            resp = llm.ask_json(_retype_prompt(batch, type_names), system=system,
                                timeout=240, tools=False, model=llm.CLASSIFY_MODEL)
            return resp.get("types", [])
        except llm.LLMError as exc:
            print(f"  retype batch LLM error: {exc}")
            return None

    typed, done = 0, 0
    with ThreadPoolExecutor(max_workers=TYPING_CONCURRENCY) as pool:
        futures = [pool.submit(_classify, b) for b in batches]
        retype_updates = []
        for fut in as_completed(futures):
            done += 1
            rows = fut.result()
            if rows is None:
                continue
            for row in rows:
                ct = (row.get("case_type") or "").strip()
                if ct not in valid:
                    ct = "other"
                try:
                    retype_updates.append(
                        {"entity_id": int(row["id"]), "fields": {"case_type": ct}})
                    typed += 1
                except (KeyError, ValueError, TypeError):
                    continue
        if retype_updates:
            # ONE event for the whole pass: the store applies every row update
            # inside the event's savepoint (one log row, one bump).
            store.apply_mutation(conn, store.entities_retyped_batch(
                case, retype_updates, actor="pipeline:typing",
                counts={"retyped": len(retype_updates)}))
            conn.commit()
            print(f"  retype {done}/{nb} batches")
    return {"typed": typed, "total": len(entities)}


# -------------------------------------------------------------- gap extraction

def _extract_system(schema: dict) -> str:
    type_lines = [f"   - {t['name']} — {t.get('description','')}"
                  for t in schema.get("entity_types", [])]
    role_lines = []
    for r in schema.get("roles", []):
        tag = " (actor — give a sub_role)" if r.get("actor") else ""
        role_lines.append(f"   - {r['name']}{tag} — {r.get('description','')}")
    return (
        "You are an OSINT extractor recovering entities a crude regex MISSED.\n\n"
        f"CASE DOMAIN: {schema.get('domain','')}\n{schema.get('summary','')}\n\n"
        "Read the report. Find concrete entities of these case types that are "
        "PRESENT IN THE TEXT but NOT in the already-captured list:\n"
        + "\n".join(type_lines) + "\n\n"
        "Classify each into a role:\n" + "\n".join(role_lines) + "\n"
        "Actor sub_roles: " + ", ".join(s["name"] for s in schema.get("sub_roles", [])) + "\n\n"
        "Only extract entities you can point to verbatim in the text. Prefer "
        "precision over recall — do NOT invent. Output strict JSON only."
    )


def _extract_prompt(report_text: str, captured: list[str]) -> str:
    cap = ", ".join(sorted(captured)[:400])
    return (
        f"ALREADY CAPTURED (do not repeat these): {cap}\n\n"
        f"REPORT TEXT:\n{report_text[:REPORT_CHAR_BUDGET]}\n\n"
        "Return JSON: {\"entities\": [{\n"
        '  "name": "<verbatim surface form>",\n'
        f'  "surface_type": "<one of: {", ".join(SURFACE_TYPES)}>",\n'
        '  "case_type": "<a case entity_type>",\n'
        '  "role": "<a case role>",\n'
        '  "sub_role": "<function if the role is an actor, else empty>",\n'
        '  "context": "<the sentence it appears in>"\n'
        "}]}\n"
        f"Cap: at most {MAX_NEW_PER_REPORT} new entities. Skip anything already captured."
    )


def _captured_names(conn, case: str) -> set[str]:
    names = set()
    for r in conn.execute(
        "SELECT DISTINCT e.canonical_name FROM entities e JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports rp ON rp.id = m.report_id WHERE rp.investigation = ?", (case,)):
        names.add(r["canonical_name"].strip().lower())
    for r in conn.execute(
        "SELECT a.alias FROM aliases a JOIN entities e ON e.id = a.entity_id "
        "JOIN mentions m ON m.entity_id = e.id JOIN reports rp ON rp.id = m.report_id "
        "WHERE rp.investigation = ?", (case,)):
        names.add((r["alias"] or "").strip().lower())
    return names


def extract_missing(conn, case: str, schema: dict) -> dict:
    """Re-read the case's reports; add schema-typed entities the regex missed.

    Parallel + safe: each report's LLM read runs in a worker (NO DB access) against a
    read-only SNAPSHOT of the already-captured names. Every write happens here on the
    main thread, and the dedup set is updated LIVE as entities land — so two reports
    proposing the same missed entity can't double-add it. One SQLite writer, no race,
    no fork-bomb (tools=False), Haiku for the extraction."""
    reports = conn.execute(
        "SELECT id, title, raw_text FROM reports WHERE investigation = ?", (case,)).fetchall()
    actor_roles = understand.actor_roles(schema)
    valid_roles = set(understand.role_names(schema))
    valid_types = set(understand.entity_type_names(schema)) | {"other"}
    captured = _captured_names(conn, case)
    captured_snapshot = list(captured)   # frozen view the workers read; never mutated
    system = _extract_system(schema)
    nb = len(reports)

    def _read(rep):
        text = (rep["raw_text"] or "").strip()
        if not text:
            return rep, []
        try:
            resp = llm.ask_json(_extract_prompt(text, captured_snapshot), system=system,
                                timeout=300, tools=False, model=llm.CLASSIFY_MODEL)
            return rep, (resp.get("entities", []) or [])
        except llm.LLMError as exc:
            print(f"  extract report {rep['id']} LLM error: {exc}")
            return rep, None

    added, done = 0, 0
    with ThreadPoolExecutor(max_workers=TYPING_CONCURRENCY) as pool:
        futures = [pool.submit(_read, rep) for rep in reports]
        for fut in as_completed(futures):
            rep, ents = fut.result()
            done += 1
            if ents is None:
                continue
            for ent in ents[:MAX_NEW_PER_REPORT]:
                name = (ent.get("name") or "").strip()
                if not name or name.lower() in captured:   # LIVE dedup on the main thread
                    continue
                surface = (ent.get("surface_type") or "other").strip()
                if surface not in SURFACE_TYPES:
                    surface = "other"
                case_type = (ent.get("case_type") or "other").strip()
                if case_type not in valid_types:
                    case_type = "other"
                role = (ent.get("role") or "").strip().lower()
                if role not in valid_roles:
                    role = "noise"
                sub_role = (ent.get("sub_role") or "").strip().lower()
                if role not in actor_roles:
                    sub_role = ""
                elif not sub_role:
                    sub_role = "unknown"

                created = store.apply_mutation(conn, store.entity_upserted(
                    case, name, surface, rep["id"], actor="pipeline:typing"))
                if not created["applied"]:
                    continue
                eid = created["entity_id"]
                store.apply_mutation(conn, store.entities_retyped_batch(
                    case, [{"entity_id": eid, "fields": {
                        "notes": f"role:{role} — recovered by typing pass",
                        "case_type": case_type, "sub_role": sub_role or None}}],
                    actor="pipeline:typing", counts={"recovered": 1}))
                db.add_mention(conn, eid, rep["id"], name,
                               (ent.get("context") or name)[:300])
                captured.add(name.lower())
                added += 1
            conn.commit()
            print(f"  extract {done}/{nb} reports")
    return {"added": added, "reports": len(reports)}


def run(conn, case: str, schema: dict) -> dict:
    """Full typing pass: type existing entities, then recover missed ones."""
    print(f"Typing pass for '{case}' ({schema.get('domain','')})…")
    retyped = retype_entities(conn, case, schema)
    print(f"  typed {retyped.get('typed',0)}/{retyped.get('total','?')} existing entities")
    recovered = extract_missing(conn, case, schema)
    print(f"  recovered {recovered.get('added',0)} entities the regex missed")
    return {"retype": retyped, "extract": recovered}
