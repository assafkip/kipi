"""Re-run the regex extractor over already-ingested reports.

The extractor grows over time (e.g. the web/crypto fingerprint layer added
2026-05-29). New patterns only fire on new ingests, so older cases never get the
new entity types. This backfills them: idempotent, additive, never deletes.
"""
from investigations.storage import db
from investigations import store
from investigations.ingest import extractor

# When an older ingest typed something generically, a newer specific match wins.
# (The WalletConnect id fbf5b42d… was extracted as hash_md5 before the gated
# walletconnect_id pattern existed.) Only generic→specific upgrades are allowed.
SPECIFIC_TYPES = {"walletconnect_id", "tracking_tag", "saas_service_account",
                  "nameserver", "registrar", "registrant_email", "crypto_wallet"}
GENERIC_OVERRIDABLE = {"hash_md5", "hash_sha256", "domain", "person_candidate", "url"}


def reextract_report(conn, report_id: int, raw_text: str,
                     case: str | None = None) -> dict:
    """Re-extract one report. Adds entities/mentions that don't exist yet, upgrades
    generic types to specific ones; never duplicates a mention or removes anything."""
    new_entities, new_mentions, retyped = 0, 0, 0
    by_type: dict[str, int] = {}
    for e in extractor.extract_all(raw_text or ""):
        existed = conn.execute(
            "SELECT id, entity_type FROM entities WHERE canonical_name = ?", (e.canonical,)).fetchone()
        # gate=False: extractor.extract_all already ran the admission gate on
        # these values (the extraction door) — behavior preserved verbatim.
        eid = store.apply_mutation(conn, store.entity_upserted(
            case, e.canonical, e.entity_type, report_id,
            actor="pipeline:reextract", gate=False))["entity_id"]
        if not existed:
            new_entities += 1
            by_type[e.entity_type] = by_type.get(e.entity_type, 0) + 1
        elif (existed["entity_type"] != e.entity_type
              and e.entity_type in SPECIFIC_TYPES
              and existed["entity_type"] in GENERIC_OVERRIDABLE):
            store.apply_mutation(conn, store.entities_retyped_batch(
                case, [{"entity_id": eid, "fields": {"entity_type": e.entity_type}}],
                actor="pipeline:reextract", counts={"upgraded": 1}))
            retyped += 1
            by_type[e.entity_type] = by_type.get(e.entity_type, 0) + 1
        if e.surface != e.canonical:
            db.add_alias(conn, eid, e.surface)
        # Mention dedup (mentions have no unique constraint) → idempotent re-runs.
        dup = conn.execute(
            "SELECT 1 FROM mentions WHERE entity_id = ? AND report_id = ? AND surface_form = ?",
            (eid, report_id, e.surface)).fetchone()
        if not dup:
            db.add_mention(conn, eid, report_id, e.surface, e.context, e.offset)
            new_mentions += 1
    return {"new_entities": new_entities, "new_mentions": new_mentions,
            "retyped": retyped, "by_type": by_type}


def run(conn, case: str | None = None) -> dict:
    """Re-extract every report (or just one case's). Returns aggregate counts."""
    if case:
        rows = conn.execute(
            "SELECT id, raw_text FROM reports WHERE investigation = ?", (case,)).fetchall()
    else:
        rows = conn.execute("SELECT id, raw_text FROM reports").fetchall()
    total = {"reports": 0, "new_entities": 0, "new_mentions": 0, "retyped": 0, "by_type": {}}
    for r in rows:
        out = reextract_report(conn, r["id"], r["raw_text"], case=case)
        total["reports"] += 1
        total["new_entities"] += out["new_entities"]
        total["new_mentions"] += out["new_mentions"]
        total["retyped"] += out["retyped"]
        for t, n in out["by_type"].items():
            total["by_type"][t] = total["by_type"].get(t, 0) + n
    conn.commit()
    return total
