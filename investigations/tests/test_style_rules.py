"""Persisted per-case style rules + metric data attrs on the graph payload
(issues graph-style-rules / graph-style-validation, PRD graph-analyst-craft).

Asserts: the style_rules table migrates (lazy CREATE, idempotent on re-connect);
GET seeds the shipped defaults (community→color DISABLED per the finding-7
mitigation; betweenness→size + origin borders enabled); PUT round-trips and
replaces; PUT validation rejects malformed rules with a named error; the graph
elements payload carries the metric keys as node data attrs (the finding-4 API
contract); the editor panel renders.

Run: .venv/bin/python3 -m pytest investigations/tests/test_style_rules.py -q
"""
import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from investigations.storage import db
from investigations.webapp import app as app_module


@pytest.fixture
def client(mp):
    dbp = Path(tempfile.mkdtemp()) / "sr.db"
    db.init_db(dbp)
    with db.connect(db_path=dbp) as conn:
        conn.execute("INSERT INTO investigations (slug, status) VALUES ('case-sr', 'active')")
        conn.commit()
    orig = db.connect
    mp.setattr(app_module.db, "connect",
               lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))
    c = TestClient(app_module.app)
    c.cookies.set("case", "case-sr")
    return c


def test_style_rules_table_migrates_idempotently():
    p = Path(tempfile.mkdtemp()) / "mig.db"
    db.init_db(p)
    for _ in range(2):   # second connect re-runs _migrate — must not error
        with db.connect(db_path=p) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(style_rules)")}
            assert {"investigation", "label", "selector", "style_json",
                    "enabled", "position"} <= cols


def test_get_seeds_defaults_with_community_disabled(client):
    data = client.get("/api/graph/style-rules?case=case-sr").json()
    rules = data["rules"]
    by_label = {r["label"]: r for r in rules}
    assert "Betweenness → size" in by_label and by_label["Betweenness → size"]["enabled"]
    assert by_label["Analyst-added → solid amber border"]["enabled"]
    community = [r for r in rules if r["label"].startswith("Community")]
    assert community and all(not r["enabled"] for r in community)   # finding-7: opt-in
    # Idempotent: a second GET doesn't re-seed.
    again = client.get("/api/graph/style-rules?case=case-sr").json()
    assert len(again["rules"]) == len(rules)


def test_put_round_trips_and_replaces(client):
    client.get("/api/graph/style-rules?case=case-sr")   # seed
    rules = [{"label": "big brokers", "selector": "node[betweenness > 0.2]",
              "style": {"background-color": "#BE185D"}, "enabled": True}]
    res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": rules})
    assert res.status_code == 200 and res.json()["count"] == 1
    got = client.get("/api/graph/style-rules?case=case-sr&seed=false").json()["rules"]
    assert len(got) == 1
    assert got[0]["selector"] == "node[betweenness > 0.2]"
    assert got[0]["style"] == {"background-color": "#BE185D"}


def test_put_rejects_malformed_rules_with_named_error(client):
    bad = [
        ({"selector": "", "style": {"color": "red"}}, "selector is required"),
        ({"selector": "node", "style": {}}, "non-empty object"),
        ({"selector": "node", "style": {"color": {"nested": 1}}}, "flat dict"),
        ("not-a-dict", "must be an object"),
    ]
    for rule, expect in bad:
        res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": [rule]})
        assert res.status_code == 400, rule
        assert expect in res.json()["error"], (rule, res.json())
    res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": "nope"})
    assert res.status_code == 400


def test_graph_payload_carries_metric_data_attrs(client):
    with db.connect() as conn:
        rep = db.insert_report(conn, source_path="<t>", source_hash="h-sr",
                               source_type="report", title="t",
                               investigation="case-sr", raw_text="")
        a = db.upsert_entity(conn, "a.example.com", "domain", rep)
        b = db.upsert_entity(conn, "b.example.com", "domain", rep)
        db.add_mention(conn, a, rep, "a.example.com", "t")
        db.add_mention(conn, b, rep, "b.example.com", "t")
        db.upsert_typed_relationship(conn, a, b, "linked_to")
        conn.commit()
        from investigations import graph_metrics
        graph_metrics.run(conn, "case-sr")
    data = client.get("/api/graph?show_all=true&meaningful_only=false").json()
    node_a = next(n["data"] for n in data["nodes"] if n["data"]["full_name"] == "a.example.com")
    # The finding-4 contract: metric keys ride as cytoscape data attrs.
    assert "betweenness" in node_a and isinstance(node_a["betweenness"], float)
    assert "degree_centrality" in node_a
    assert node_a["community"].startswith("c")
    assert node_a["metrics_provenance"] == "graph:metrics:case-sr"


def test_emptied_rule_set_stays_empty_on_next_get(client):
    client.get("/api/graph/style-rules?case=case-sr")          # seed
    res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": []})
    assert res.status_code == 200
    # The analyst chose "no rules" — the next default GET must NOT resurrect
    # the defaults (the seed marker survives the replace).
    got = client.get("/api/graph/style-rules?case=case-sr").json()["rules"]
    assert got == []


def test_reset_restores_defaults_explicitly(client):
    client.get("/api/graph/style-rules?case=case-sr")
    client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": []})
    res = client.put("/api/graph/style-rules", json={"case": "case-sr", "reset": True})
    assert res.status_code == 200 and res.json().get("reset")
    got = client.get("/api/graph/style-rules?case=case-sr").json()["rules"]
    assert any(r["label"] == "Betweenness → size" for r in got)


def test_seed_marker_never_appears_in_responses(client):
    rules = client.get("/api/graph/style-rules?case=case-sr").json()["rules"]
    assert all(r["label"] != "__seeded__" for r in rules)
    assert all(r["position"] >= 0 for r in rules)


def test_custom_rules_apply_before_interaction_styles():
    tpl = (Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html").read_text()
    # Class-based interaction selectors (selection/dim/facet/path) partition to
    # the tail so analyst rules can't override active highlighting.
    assert "isInteraction" in tpl
    assert "base.filter(s => !isInteraction(s))" in tpl


def test_validation_rejects_unparseable_selectors(client):
    for sel, expect in [
        ("node[community = 'c0'", "unbalanced brackets"),
        ("node[community = 'c0]", "unbalanced quotes"),
        ("node; alert(1)", "outside the cytoscape selector syntax"),
        ("node{evil}", "outside the cytoscape selector syntax"),
    ]:
        res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": [
            {"label": "x", "selector": sel, "style": {"opacity": 0.5}}]})
        assert res.status_code == 400, sel
        assert expect in res.json()["error"], (sel, res.json())


def test_validation_accepts_boolean_attr_selectors_rejects_reversed_brackets(client):
    # '?' boolean data selectors are part of this app's own stylesheet idiom.
    res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": [
        {"label": "bridges", "selector": "node[?is_bridge]", "style": {"shape": "diamond"}}]})
    assert res.status_code == 200
    # Reversed brackets balance by count but not by order — must reject.
    res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": [
        {"label": "x", "selector": "node]foo[", "style": {"opacity": 0.5}}]})
    assert res.status_code == 400
    assert "unbalanced brackets" in res.json()["error"]


def test_validation_rejects_unknown_style_properties(client):
    res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": [
        {"label": "x", "selector": "node", "style": {"label": "injected"}}]})
    assert res.status_code == 400
    assert "unknown style property" in res.json()["error"]
    # Known-safe visual properties (incl. mapData strings) pass.
    res = client.put("/api/graph/style-rules", json={"case": "case-sr", "rules": [
        {"label": "ok", "selector": "node[betweenness]",
         "style": {"width": "mapData(betweenness, 0, 0.3, 24, 64)"}}]})
    assert res.status_code == 200


def test_validation_shipped_defaults_pass_their_own_gate():
    # The seed must never write rules the PUT validator would reject.
    from investigations.webapp.app import _STYLE_RULE_DEFAULTS, _validate_style_rule
    for r in _STYLE_RULE_DEFAULTS:
        assert _validate_style_rule(
            {"selector": r["selector"], "style": r["style"]}) is None, r["label"]


def test_load_time_isolation_flags_and_skips_bad_rules():
    tpl = (Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html").read_text()
    # Each rule probes in its own try/catch; a cytoscape-rejected rule is
    # flagged (r.error) + skipped; a sheet-level rejection retries WITHOUT
    # custom rules so the canvas keeps rendering.
    assert "this.cy.filter(r.selector);" in tpl
    assert "r.error = true" in tpl
    assert "fromJson([...head, ...tail])" in tpl   # the no-custom-rules fallback
    assert "rule rejected — skipped" in tpl        # visible in the editor


def test_put_honors_query_param_case(client):
    client.get("/api/graph/style-rules?case=case-sr")
    rules = [{"label": "qp", "selector": "node", "style": {"shape": "diamond"}, "enabled": True}]
    res = client.put("/api/graph/style-rules?case=case-sr", json={"rules": rules})
    assert res.status_code == 200
    got = client.get("/api/graph/style-rules?case=case-sr&seed=false").json()["rules"]
    assert [r["label"] for r in got] == ["qp"]
    # The global NULL bucket was NOT touched.
    global_rules = client.get("/api/graph/style-rules?seed=false").json()["rules"]
    assert all(r["label"] != "qp" for r in global_rules)


def test_editor_panel_renders():
    tpl = (Path(__file__).resolve().parents[1] / "webapp" / "templates" / "graph.html").read_text()
    assert 'data-testid="style-rules-panel"' in tpl
    assert "rulesRestoreDefaults()" in tpl and "rulesToggle(" in tpl
    # Load-time isolation: each rule probes in its own try/catch (finding-9).
    assert "this.cy.filter(r.selector);" in tpl
    assert "r.error = true" in tpl
