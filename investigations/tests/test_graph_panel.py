"""Graph panel surfaces typed properties + provenance, and the transform menu is
type-filtered (issue graph-panel-and-transforms).

Asserts the /api/entity/{id}/detail endpoint returns node_properties + provenance + an
edge gloss, and that /api/enrich/providers?type=<t> is scoped to the node's transforms.
"""
import functools
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.enrich import properties as props
from investigations.webapp import app as app_module

# The real (contextmanager-decorated) connect, captured before any monkeypatch.
_REAL_CONNECT = db.connect


def _setup(monkeypatch):
    path = Path(tempfile.mkdtemp()) / "panel.db"
    db.init_db(path)
    dom = _seed_graph(path)                       # seed with the REAL connect, pre-patch
    bound = functools.partial(_REAL_CONNECT, path)  # app's db.connect() -> temp path
    monkeypatch.setattr(app_module.db, "connect", bound)
    monkeypatch.setattr(db, "connect", bound)
    return TestClient(app_module.app), dom


def _seed_graph(path):
    with _REAL_CONNECT(path) as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h1", source_type="report",
                               title="t", investigation="case-x", raw_text="")
        conn.execute("INSERT INTO investigations (slug, status) VALUES ('case-x','active')")
        dom = db.upsert_entity(conn, "evil.com", "domain", rep, provenance="enrich:infra")
        ip = db.upsert_entity(conn, "9.9.9.9", "ip", rep, provenance="enrich:infra")
        props.upsert_properties(conn, dom, [
            props.Property("registrar", "NameCheap", "string"),
            props.Property("a_record", "9.9.9.9", "ip"),
        ], provenance="enrich:infra")
        conn.execute(
            "INSERT INTO typed_relationships "
            "(src_entity_id, dst_entity_id, rel_type, confidence, evidence, status, provenance) "
            "VALUES (?, ?, 'resolves_to', 'high', 'A record', 'active', 'enrich:infra')", (dom, ip))
        # osint_providers (crtsh, infra, ipgeo, perplexity, …) are seeded by init_db.
        conn.commit()
        return dom


def test_detail_returns_properties_provenance_and_edge_gloss(monkeypatch):
    client, dom = _setup(monkeypatch)
    r = client.get(f"/api/entity/{dom}/detail")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["provenance"] == "enrich:infra"
    by_key = {p["key"]: p for p in d["properties"]}
    assert by_key["registrar"]["value"] == "NameCheap"
    assert by_key["a_record"]["value_type"] == "ip"
    # The edge carries a human-readable gloss, not just the snake_case rel_type.
    conn0 = d["connections"][0]
    assert conn0["rel_type"] == "resolves_to"
    assert conn0["rel_gloss"] == "resolves to IP"


def test_providers_are_type_scoped_for_domain(monkeypatch):
    client, dom = _setup(monkeypatch)
    domain_slugs = {p["slug"] for p in client.get("/api/enrich/providers?type=domain").json()["providers"]}
    all_slugs = {p["slug"] for p in client.get("/api/enrich/providers").json()["providers"]}
    # A domain's transforms are the infra belt only (crtsh + infra), not the full list.
    assert domain_slugs == {"crtsh", "infra"}
    assert "perplexity" in all_slugs and "perplexity" not in domain_slugs
    assert len(domain_slugs) < len(all_slugs)


def test_providers_unscoped_for_actor_type(monkeypatch):
    """A person/handle/org has no infra belt — the full provider list is returned, not empty."""
    client, dom = _setup(monkeypatch)
    person_slugs = {p["slug"] for p in client.get("/api/enrich/providers?type=person").json()["providers"]}
    all_slugs = {p["slug"] for p in client.get("/api/enrich/providers").json()["providers"]}
    assert person_slugs == all_slugs and len(person_slugs) >= 4
