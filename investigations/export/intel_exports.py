"""Exports for downstream operational tools.

  export_stix    — STIX 2.1 JSON bundle for sharing intel
  export_csv     — flat CSVs (entities, relationships) for spreadsheets / Notion
  export_misp    — MISP event JSON (lightweight version)
"""
import csv
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


STIX_TYPE_MAP = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "email": "email-addr",
    "telegram_channel": "user-account",
    "handle": "user-account",
    "crypto_wallet": "x-crypto-wallet",
    "hash_sha256": "file",
    "hash_md5": "file",
    "phone": "x-phone-number",
    "person": "identity",
}


def _now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _entity_role(notes: str | None) -> str:
    if not notes:
        return ""
    return (notes or "").split(" — ")[0].replace("role:", "").strip()


def export_stix(conn, out_path: Path,
                investigation_name: str = "kipi-investigations") -> Path:
    """Produce STIX 2.1 bundle. Each non-noise entity becomes a SDO or observable.
    Each typed relationship becomes a relationship SRO."""
    bundle_id = f"bundle--{uuid.uuid4()}"
    now = _now_z()
    objects = []

    identity_id = f"identity--{uuid.uuid4()}"
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now, "modified": now,
        "name": investigation_name,
        "identity_class": "organization",
    })

    id_for_entity: dict[int, str] = {}
    entities = conn.execute(
        "SELECT id, canonical_name, entity_type, notes FROM entities "
        "WHERE notes IS NULL OR notes NOT LIKE 'role:noise%'"
    ).fetchall()
    for e in entities:
        stix_type = STIX_TYPE_MAP.get(e["entity_type"])
        if not stix_type:
            continue
        role = _entity_role(e["notes"])
        oid = f"{stix_type}--{uuid.uuid4()}"
        id_for_entity[e["id"]] = oid
        obj = {
            "type": stix_type,
            "spec_version": "2.1",
            "id": oid,
            "created": now,
            "modified": now,
        }
        name = e["canonical_name"]
        if stix_type == "ipv4-addr":
            obj["value"] = name
        elif stix_type == "domain-name":
            obj["value"] = name
        elif stix_type == "url":
            obj["value"] = name
        elif stix_type == "email-addr":
            obj["value"] = name
        elif stix_type == "user-account":
            obj["user_id"] = name.lstrip("@")
            obj["account_type"] = "telegram" if "t.me/" in name else "social"
        elif stix_type == "file":
            obj["hashes"] = {"SHA-256" if e["entity_type"] == "hash_sha256" else "MD5": name}
        elif stix_type == "identity":
            obj["name"] = name
            obj["identity_class"] = "individual"
            obj["roles"] = [role] if role else []
        else:
            obj["value"] = name
        objects.append(obj)

    typed = conn.execute(
        "SELECT * FROM typed_relationships WHERE COALESCE(status,'active') = 'active'"
    ).fetchall()
    for t in typed:
        sid_s = id_for_entity.get(t["src_entity_id"])
        did_s = id_for_entity.get(t["dst_entity_id"])
        if not sid_s or not did_s:
            continue
        rid = f"relationship--{uuid.uuid4()}"
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rid,
            "created": now,
            "modified": now,
            "relationship_type": t["rel_type"],
            "source_ref": sid_s,
            "target_ref": did_s,
            "description": t["evidence"] or "",
            "x_kipi_confidence": t["confidence"],
        })

    bundle = {"type": "bundle", "id": bundle_id, "objects": objects}
    out_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return out_path


def export_csv(conn, out_dir: Path) -> dict:
    """Flat CSVs for spreadsheets / Notion / pivot analysis."""
    out_dir.mkdir(parents=True, exist_ok=True)
    entities_path = out_dir / "entities.csv"
    rels_path = out_dir / "typed_relationships.csv"
    clusters_path = out_dir / "clusters.csv"

    rows = conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.notes, "
        "s.threat_score, s.degree, s.report_count, "
        "GROUP_CONCAT(DISTINCT c.name) AS clusters "
        "FROM entities e "
        "LEFT JOIN entity_scores s ON s.entity_id = e.id "
        "LEFT JOIN cluster_members cm ON cm.entity_id = e.id "
        "LEFT JOIN clusters c ON c.id = cm.cluster_id "
        "WHERE e.notes IS NULL OR e.notes NOT LIKE 'role:noise%' "
        "GROUP BY e.id ORDER BY s.threat_score DESC NULLS LAST"
    ).fetchall()
    with entities_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "name", "type", "role", "threat_score", "degree",
                    "report_count", "clusters"])
        for r in rows:
            role = _entity_role(r["notes"])
            w.writerow([
                r["id"], r["canonical_name"], r["entity_type"], role,
                r["threat_score"] or 0, r["degree"] or 0,
                r["report_count"] or 0, r["clusters"] or "",
            ])

    with rels_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src", "rel_type", "dst", "confidence", "evidence"])
        for r in conn.execute(
            "SELECT t.rel_type, t.confidence, t.evidence, "
            "es.canonical_name AS src, ed.canonical_name AS dst "
            "FROM typed_relationships t "
            "JOIN entities es ON es.id = t.src_entity_id "
            "JOIN entities ed ON ed.id = t.dst_entity_id "
            "WHERE COALESCE(t.status,'active') = 'active' "
            "ORDER BY t.confidence, src"
        ).fetchall():
            w.writerow([r["src"], r["rel_type"], r["dst"], r["confidence"],
                        r["evidence"] or ""])

    with clusters_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cluster", "kind", "description", "members"])
        for c in conn.execute(
            "SELECT c.name, c.kind, c.description, "
            "GROUP_CONCAT(e.canonical_name, ' | ') AS members "
            "FROM clusters c "
            "LEFT JOIN cluster_members cm ON cm.cluster_id = c.id "
            "LEFT JOIN entities e ON e.id = cm.entity_id "
            "GROUP BY c.id ORDER BY c.id"
        ).fetchall():
            w.writerow([c["name"], c["kind"] or "", c["description"] or "",
                        c["members"] or ""])

    return {
        "entities_csv": str(entities_path),
        "relationships_csv": str(rels_path),
        "clusters_csv": str(clusters_path),
    }


def export_misp(conn, out_path: Path,
                investigation_name: str = "kipi-investigations") -> Path:
    """Lightweight MISP event JSON."""
    attributes = []
    misp_type_map = {
        "ip": "ip-src",
        "domain": "domain",
        "url": "url",
        "email": "email-src",
        "hash_sha256": "sha256",
        "hash_md5": "md5",
        "handle": "text",
        "telegram_channel": "text",
        "crypto_wallet": "btc",
    }
    for e in conn.execute(
        "SELECT e.canonical_name, e.entity_type, e.notes, s.threat_score "
        "FROM entities e LEFT JOIN entity_scores s ON s.entity_id = e.id "
        "WHERE e.notes IS NOT NULL AND e.notes NOT LIKE 'role:noise%' "
        "AND e.notes NOT LIKE 'role:source%' "
        "AND e.notes NOT LIKE 'role:infra%' "
        "ORDER BY s.threat_score DESC NULLS LAST"
    ).fetchall():
        misp_type = misp_type_map.get(e["entity_type"])
        if not misp_type:
            continue
        role = _entity_role(e["notes"])
        attributes.append({
            "type": misp_type,
            "category": "Network activity" if misp_type in ("ip-src", "domain", "url") else "Other",
            "value": e["canonical_name"],
            "to_ids": role in ("ioc", "operator"),
            "comment": f"role={role} score={e['threat_score'] or 0}",
        })

    event = {
        "Event": {
            "info": f"kipi-investigations: {investigation_name}",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
            "distribution": "0",
            "threat_level_id": "2",
            "analysis": "1",
            "published": False,
            "Attribute": attributes,
        }
    }
    out_path.write_text(json.dumps(event, indent=2), encoding="utf-8")
    return out_path
