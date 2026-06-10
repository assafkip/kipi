"""Typed entity properties extracted from enrichment results (issue node-properties-table).

The enrich adapters already return structured data in `raw_json` (ipgeo's country/ASN, a
whois adapter's registrar/registrant/dates). This module pulls the KNOWN typed fields out
of that raw_json and writes them onto the enriched node as `node_properties` rows — real
queryable fields instead of facts buried in a freetext dossier. A phone's facts land typed
on the phone node; they can't make it render as a domain.

extract_properties is pure (raw_json -> list of Property); upsert_properties is the single
idempotent writer (UNIQUE(entity_id,key) + ON CONFLICT DO UPDATE).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Property:
    key: str
    value: str
    value_type: str = "string"


# raw_json key -> (canonical property key, value_type). Covers the structured providers
# (ipgeo) + the whois/infra-shaped keys an adapter may carry. Unknown keys are ignored —
# we only promote fields we can type, never spray arbitrary raw_json into the graph.
PROPERTY_MAP: dict[str, tuple[str, str]] = {
    # ipgeo / network
    "country": ("country", "string"),
    "countryCode": ("country_code", "string"),
    "regionName": ("region", "string"),
    "city": ("city", "string"),
    "as": ("asn", "asn"),
    "asn": ("asn", "asn"),
    "asname": ("asn_name", "string"),
    "as_name": ("asn_name", "string"),
    "as_owner": ("asn_name", "string"),
    "isp": ("isp", "string"),
    "org": ("org", "string"),
    "reverse": ("reverse_dns", "string"),
    # whois / registration (structured-raw adapters)
    "registrar": ("registrar", "string"),
    "registrant": ("registrant", "string"),
    "registrant_org": ("registrant_org", "string"),
    "creation_date": ("created_date", "date"),
    "created": ("created_date", "date"),
    "created_date": ("created_date", "date"),
    "expiry_date": ("expiry_date", "date"),
    "expiry": ("expiry_date", "date"),
    # DNS / hosting
    "a_record": ("a_record", "ip"),
    "a": ("a_record", "ip"),
    "aaaa": ("aaaa_record", "string"),
    "nameservers": ("nameserver", "string"),
    "ns": ("nameserver", "string"),
    "mx": ("mx_record", "string"),
    # phone (so phone facts land typed on the phone node)
    "carrier": ("carrier", "string"),
    "line_type": ("line_type", "string"),
    "phone_country": ("country", "string"),
}


def _stringify(value) -> str:
    """A raw_json value as a single string. Lists collapse to a comma-joined head
    (lossless detail stays in the result's raw_json/dossier)."""
    if isinstance(value, (list, tuple)):
        parts = [str(v).strip() for v in value if str(v).strip()]
        return ", ".join(parts[:8])
    return str(value).strip()


def extract_properties(provider: str, raw_json) -> list[Property]:
    """Pull the known typed fields out of a result's raw_json. Pure — no DB.
    `provider` is accepted for future per-provider rules; the map is global today."""
    if not isinstance(raw_json, dict):
        return []
    out: dict[str, Property] = {}
    for raw_key, (canon, vtype) in PROPERTY_MAP.items():
        if raw_key not in raw_json:
            continue
        rawval = raw_json[raw_key]
        if rawval is None:
            continue  # a present-but-null field must not become the literal "None"
        val = _stringify(rawval)
        if not val:
            continue
        # First non-empty value for a canonical key wins (e.g. 'created' vs 'creation_date').
        out.setdefault(canon, Property(canon, val, vtype))
    return list(out.values())


def upsert_properties(conn, entity_id: int, props: list[Property], *,
                      provenance: str | None = None, confidence: str = "medium") -> int:
    """The single idempotent writer. Re-running UPDATEs the value in place (no dup rows)."""
    if not entity_id or not props:
        return 0
    n = 0
    for p in props:
        conn.execute(
            "INSERT INTO node_properties (entity_id, key, value, value_type, provenance, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(entity_id, key) DO UPDATE SET "
            "value=excluded.value, value_type=excluded.value_type, "
            # COALESCE so a re-upsert that omits provenance doesn't ERASE the existing
            # provenance/confidence — a null update keeps the prior stamp (Codex review).
            "provenance=COALESCE(excluded.provenance, node_properties.provenance), "
            "confidence=COALESCE(excluded.confidence, node_properties.confidence)",
            (entity_id, p.key, p.value, p.value_type, provenance, confidence),
        )
        n += 1
    return n


def extract_and_upsert(conn, entity_id: int, provider: str, raw_json, *,
                       provenance: str | None = None) -> int:
    """Convenience: extract typed properties from one result and upsert onto the node."""
    props = extract_properties(provider, raw_json)
    return upsert_properties(conn, entity_id, props,
                             provenance=provenance or f"enrich:{provider}")
