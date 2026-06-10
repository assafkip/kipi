"""Typed entity properties written by the enrich adapters (issue node-properties-table).

Asserts: extract_properties maps a structured raw_json to typed rows; upsert is idempotent
(re-enrich UPDATEs, never duplicates); execute_run lands properties on the enriched node;
a phone enrichment lands phone facts on a phone-typed node (never a domain).
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.enrich import properties as props
from investigations.enrich.base import EnrichmentResult


def _db_path():
    path = Path(tempfile.mkdtemp()) / "props.db"
    db.init_db(path)
    return path


def test_extract_properties_maps_structured_raw_to_typed_rows():
    raw = {"registrar": "NameCheap", "a": "1.2.3.4", "creation_date": "2026-01-02",
           "country": "US", "as": "AS13335 Cloudflare", "ignored_key": "x"}
    out = {p.key: (p.value, p.value_type) for p in props.extract_properties("infra", raw)}
    assert out["registrar"] == ("NameCheap", "string")
    assert out["a_record"] == ("1.2.3.4", "ip")
    assert out["created_date"] == ("2026-01-02", "date")
    assert out["asn"] == ("AS13335 Cloudflare", "asn")
    assert "ignored_key" not in out  # only mapped keys are promoted


def test_extract_handles_non_dict_and_lists():
    assert props.extract_properties("x", None) == []
    assert props.extract_properties("x", "not a dict") == []
    out = {p.key: p.value for p in props.extract_properties("infra", {"ns": ["a.ns.com", "b.ns.com"]})}
    assert out["nameserver"] == "a.ns.com, b.ns.com"


def test_present_but_none_value_is_skipped_not_stringified():
    """A mapped key whose value is None must NOT create a bogus 'None' property (Codex review)."""
    out = {p.key: p.value for p in props.extract_properties("shodan", {"asn": None, "registrar": "X"})}
    assert "asn" not in out
    assert out["registrar"] == "X"


def test_upsert_is_idempotent_no_duplicate_rows():
    with db.connect(_db_path()) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h1", source_type="manual",
                               title="t", investigation=None, raw_text="")
        eid = db.upsert_entity(conn, "evil.com", "domain", rep)
        props.upsert_properties(conn, eid, [props.Property("registrar", "NameCheap", "string")],
                                provenance="enrich:infra")
        # Re-run with a CHANGED value: UPDATE in place, not a second row.
        props.upsert_properties(conn, eid, [props.Property("registrar", "GoDaddy", "string")],
                                provenance="enrich:infra")
        rows = conn.execute("SELECT value FROM node_properties WHERE entity_id=? AND key='registrar'",
                            (eid,)).fetchall()
        assert len(rows) == 1
        assert rows[0]["value"] == "GoDaddy"


def test_asn_aliases_from_shodan_censys_vt_are_mapped():
    """ASN can arrive as as/asn/as_name/as_owner across providers — all map to vocab keys."""
    out = {p.key: p.value for p in props.extract_properties("shodan", {"asn": "AS13335"})}
    assert out["asn"] == "AS13335"
    out = {p.key: p.value for p in props.extract_properties("censys", {"as_owner": "Cloudflare"})}
    assert out["asn_name"] == "Cloudflare"


def test_reupsert_without_provenance_does_not_erase_it():
    """A later upsert that omits provenance must keep the original stamp (COALESCE)."""
    with db.connect(_db_path()) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="hp", source_type="manual",
                               title="t", investigation=None, raw_text="")
        eid = db.upsert_entity(conn, "evil2.com", "domain", rep)
        props.upsert_properties(conn, eid, [props.Property("registrar", "NameCheap")],
                                provenance="enrich:infra")
        props.upsert_properties(conn, eid, [props.Property("registrar", "GoDaddy")],
                                provenance=None)
        row = conn.execute("SELECT value, provenance FROM node_properties "
                           "WHERE entity_id=? AND key='registrar'", (eid,)).fetchone()
        assert row["value"] == "GoDaddy"
        assert row["provenance"] == "enrich:infra"  # not erased


def _stub_adapter(raw_json):
    class _Stub:
        cost_per_call_usd = 0.0
        def run(self, query, mode=None, timeout=90):
            return [EnrichmentResult(result_type="document", title="t", summary="s",
                                     url=None, raw_json=raw_json, confidence="medium")]
    return _Stub()


def test_execute_run_lands_properties_on_enriched_node(monkeypatch):
    from investigations.enrich import runner
    with db.connect(_db_path()) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h2", source_type="report",
                               title="t", investigation="case-x", raw_text="")
        dom = db.upsert_entity(conn, "evil.com", "domain", rep)
        conn.commit()
        monkeypatch.setattr(runner, "get_adapter",
                            lambda slug: _stub_adapter({"registrar": "NameCheap", "a": "9.9.9.9"}))
        runner.run_and_persist(conn, "infra", "evil.com", entity_id=dom, investigation="case-x")
        got = {r["key"]: r["value"] for r in conn.execute(
            "SELECT key, value FROM node_properties WHERE entity_id=?", (dom,)).fetchall()}
        assert got.get("registrar") == "NameCheap"
        assert got.get("a_record") == "9.9.9.9"
        prov = conn.execute("SELECT provenance FROM node_properties WHERE entity_id=? AND key='registrar'",
                           (dom,)).fetchone()
        assert prov["provenance"] == "enrich:infra"


def test_phone_enrichment_lands_on_phone_node_never_domain(monkeypatch):
    from investigations.enrich import runner
    with db.connect(_db_path()) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h3", source_type="report",
                               title="t", investigation="case-y", raw_text="")
        phone = db.upsert_entity(conn, "+1-202-555-0147", "phone", rep)
        conn.execute("INSERT INTO osint_providers (slug, display_name) VALUES ('phone_lookup','Phone Lookup')")
        conn.commit()
        monkeypatch.setattr(runner, "get_adapter",
                            lambda slug: _stub_adapter({"carrier": "Verizon", "line_type": "mobile"}))
        runner.run_and_persist(conn, "phone_lookup", "+1-202-555-0147", entity_id=phone,
                               investigation="case-y")
        etype = conn.execute("SELECT entity_type FROM entities WHERE id=?", (phone,)).fetchone()
        assert etype["entity_type"] == "phone"  # typing untouched — never becomes a domain
        got = {r["key"]: r["value"] for r in conn.execute(
            "SELECT key, value FROM node_properties WHERE entity_id=?", (phone,)).fetchall()}
        assert got.get("carrier") == "Verizon"
        assert got.get("line_type") == "mobile"
