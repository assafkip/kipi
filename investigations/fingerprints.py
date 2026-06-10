"""Cross-domain correlation by shared fingerprint.

A tracking tag, WalletConnect id, service-account id, or nameserver that appears
on several sites is the strongest "same operator" signal in web/ad/affiliate
fraud. The extractor pulls these as entities; this links the things that SHARE
one. The shared fingerprint becomes a hub: every domain/handle/wallet that
co-occurs with it gets a typed `shares_*` edge to it.

Two co-occurrence signals:
- cross-report: the fingerprint appears in 2+ DISTINCT reports/records → link
  every partner in those reports (strongest; this is the "60 domains, one GA tag"
  case when each domain is its own record).
- within-report proximity: a single report → link partners mentioned within
  PROX chars of the fingerprint (so a WalletConnect id links the kit's domains,
  not every domain in a long narrative).

Deterministic. No LLM. Writes typed_relationships with status='active'.
"""
from investigations.storage import db
from investigations.enrich.rel_vocab import normalize_rel

# fingerprint entity_type → (rel_type, confidence, strength_label)
FINGERPRINT_TYPES = {
    "tracking_tag":          ("shares_tracking_tag", "high", "same operator"),
    "walletconnect_id":      ("shares_walletconnect", "high", "same kit/operator"),
    "saas_service_account":  ("shares_service_account", "high", "same operator"),
    "registrant_email":      ("shares_registrant", "high", "same registrant"),
    "nameserver":            ("shares_nameserver", "medium", "shared infrastructure"),
    "registrar":             ("shares_registrar", "low", "same registrar (weak)"),
}

# Entity types a fingerprint meaningfully links (the assets it connects).
PARTNER_TYPES = ("domain", "url", "handle", "telegram_channel", "crypto_wallet", "email")
PROX = 400          # chars: within-report proximity window


def _scoped_fp_ids(conn, case):
    q = ("SELECT DISTINCT e.id, e.entity_type, e.canonical_name FROM entities e "
         "WHERE e.entity_type IN ({})".format(",".join("?" * len(FINGERPRINT_TYPES))))
    params = list(FINGERPRINT_TYPES)
    if case:
        q += (" AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
              "ON r.id = m.report_id WHERE r.investigation = ?)")
        params.append(case)
    return conn.execute(q, params).fetchall()


def _partners_in_reports(conn, report_ids, exclude_id):
    ph = ",".join("?" * len(report_ids))
    tp = ",".join("?" * len(PARTNER_TYPES))
    rows = conn.execute(
        f"SELECT DISTINCT e.id FROM entities e JOIN mentions m ON m.entity_id = e.id "
        f"WHERE m.report_id IN ({ph}) AND e.entity_type IN ({tp}) AND e.id != ? "
        f"AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%')",
        (*report_ids, *PARTNER_TYPES, exclude_id)).fetchall()
    return {r["id"] for r in rows}


def _partners_near(conn, report_id, fp_offsets, exclude_id):
    tp = ",".join("?" * len(PARTNER_TYPES))
    rows = conn.execute(
        f"SELECT e.id, m.char_offset FROM entities e JOIN mentions m ON m.entity_id = e.id "
        f"WHERE m.report_id = ? AND e.entity_type IN ({tp}) AND e.id != ? "
        f"AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%')",
        (report_id, *PARTNER_TYPES, exclude_id)).fetchall()
    near = set()
    for r in rows:
        off = r["char_offset"]
        if off is None:
            continue
        if any(abs(off - fo) <= PROX for fo in fp_offsets):
            near.add(r["id"])
    return near


def correlate(conn, case: str | None = None) -> dict:
    """Link every partner that shares a fingerprint to it. Returns counts +
    the fingerprints that link 2+ partners (the cross-domain hits)."""
    created, hubs = 0, 0
    for fp in _scoped_fp_ids(conn, case):
        rel, conf, _ = FINGERPRINT_TYPES[fp["entity_type"]]
        # Single binding gate: every edge-write path goes through normalize_rel. These
        # shares_* labels are first-class vocab members, so they pass unchanged; the call
        # keeps the path uniform and guards against a future label drifting out of vocab.
        rel = normalize_rel(rel)
        if rel is None:
            continue
        mentions = conn.execute(
            "SELECT report_id, char_offset FROM mentions WHERE entity_id = ?",
            (fp["id"],)).fetchall()
        report_ids = sorted({m["report_id"] for m in mentions})
        if not report_ids:
            continue
        if len(report_ids) >= 2:
            partners = _partners_in_reports(conn, report_ids, fp["id"])
        else:
            offsets = [m["char_offset"] for m in mentions if m["char_offset"] is not None]
            partners = _partners_near(conn, report_ids[0], offsets, fp["id"])
        if not partners:
            continue
        if len(partners) >= 2:
            hubs += 1
        ev = f"shares {fp['entity_type']} {fp['canonical_name'][:40]}"
        for pid in partners:
            if db.upsert_typed_relationship(conn, pid, fp["id"], rel,
                                            confidence=conf, evidence=ev):
                created += 1
    conn.commit()
    return {"edges_created": created, "shared_fingerprints": hubs}


def shared(conn, case: str | None = None, min_partners: int = 2) -> list[dict]:
    """The cross-domain findings: each fingerprint that links >= min_partners,
    with the partners it connects. Powers the Cross-domain view."""
    rels = list(FINGERPRINT_TYPES)
    out = []
    for fp in _scoped_fp_ids(conn, case):
        rel, conf, strength = FINGERPRINT_TYPES[fp["entity_type"]]
        partners = conn.execute(
            "SELECT e.id, e.canonical_name, e.entity_type FROM typed_relationships t "
            "JOIN entities e ON e.id = t.src_entity_id "
            "WHERE t.dst_entity_id = ? AND t.rel_type = ? AND COALESCE(t.status,'active')='active' "
            "ORDER BY e.canonical_name",
            (fp["id"], rel)).fetchall()
        if len(partners) >= min_partners:
            out.append({
                "fingerprint": fp["canonical_name"],
                "type": fp["entity_type"],
                "strength": strength,
                "confidence": conf,
                "partner_count": len(partners),
                "partners": [{"id": p["id"], "name": p["canonical_name"],
                              "type": p["entity_type"]} for p in partners],
            })
    out.sort(key=lambda x: -x["partner_count"])
    return out
