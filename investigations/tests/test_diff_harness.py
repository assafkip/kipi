"""Stage 0 acceptance: the diff harness itself is proven BEFORE any behavior change.
Self-diff passes, a missing entity/edge fails with the item named, additions stay a pass
(superset-or-equal), and run_and_snapshot captures metrics without a real agent.

Run: .venv/bin/python -m pytest investigations/tests/test_diff_harness.py -q
Plan: q-system/output/plans/speed-cost-staged-rollout-2026-06-09.md (Stage 0)
"""
import json
import tempfile
from pathlib import Path

import pytest

from investigations.storage import db
from investigations.tests import diff_harness


@pytest.fixture
def case_db(mp):
    """Fresh temp DB with a small 't-case' graph (2 reports' worth of entities + edges)."""
    d = tempfile.mkdtemp()
    p = Path(d) / "t.db"
    db.init_db(p)
    orig = db.connect
    mp.setattr(db, "connect", lambda migrate=True, db_path=p: orig(db_path=db_path, migrate=migrate))
    with db.connect() as conn:
        conn.execute("INSERT INTO investigations (slug) VALUES ('t-case')")
        conn.execute(
            "INSERT INTO reports (source_path, source_hash, source_type, title, investigation) "
            "VALUES ('x', 'h1', 'manual', 't', 't-case')")
        rep = conn.execute("SELECT id FROM reports").fetchone()["id"]
        ids = {}
        for name, etype in (("trumpfundus.com", "domain"), ("1.2.3.4", "ip"),
                            ("promo.net", "domain")):
            ids[name] = db.upsert_entity(conn, name, etype, rep, provenance="osint")
        conn.execute(
            "INSERT INTO typed_relationships (src_entity_id, dst_entity_id, rel_type, "
            "confidence, status, provenance) VALUES (?, ?, 'resolves_to', 'medium', "
            "'active', 'osint')", (ids["trumpfundus.com"], ids["1.2.3.4"]))
        conn.execute(
            "INSERT INTO typed_relationships (src_entity_id, dst_entity_id, rel_type, "
            "confidence, status, provenance) VALUES (?, ?, 'shares_certificate', 'medium', "
            "'active', 'osint')", (ids["trumpfundus.com"], ids["promo.net"]))
    return p


def test_self_diff_passes(case_db):
    with db.connect() as conn:
        snap = diff_harness.snapshot_case(conn, "t-case")
    assert snap["entity_count"] == 3 and snap["edge_count"] == 2
    diff = diff_harness.diff_snapshots(snap, snap)
    assert diff["verdict"] == "pass"
    assert diff["missing_entities"] == [] and diff["missing_edges"] == []


def test_missing_entity_fails_and_is_named(case_db):
    with db.connect() as conn:
        baseline = diff_harness.snapshot_case(conn, "t-case")
        conn.execute("UPDATE entities SET hidden = 1 WHERE canonical_name = 'promo.net'")
    with db.connect() as conn:
        current = diff_harness.snapshot_case(conn, "t-case")
    diff = diff_harness.diff_snapshots(baseline, current)
    assert diff["verdict"] == "fail"
    assert ["promo.net", "domain"] in diff["missing_entities"]
    # the certificate edge to the hidden entity is named too
    assert any(e[1] == "promo.net" for e in diff["missing_edges"])


def test_retired_edge_fails(case_db):
    with db.connect() as conn:
        baseline = diff_harness.snapshot_case(conn, "t-case")
        conn.execute("UPDATE typed_relationships SET status = 'retired' "
                     "WHERE rel_type = 'resolves_to'")
    with db.connect() as conn:
        current = diff_harness.snapshot_case(conn, "t-case")
    diff = diff_harness.diff_snapshots(baseline, current)
    assert diff["verdict"] == "fail"
    assert ["trumpfundus.com", "1.2.3.4", "resolves_to"] in diff["missing_edges"]


def test_superset_still_passes(case_db):
    with db.connect() as conn:
        baseline = diff_harness.snapshot_case(conn, "t-case")
        rep = conn.execute("SELECT id FROM reports").fetchone()["id"]
        db.upsert_entity(conn, "extra.org", "domain", rep, provenance="osint")
    with db.connect() as conn:
        current = diff_harness.snapshot_case(conn, "t-case")
    diff = diff_harness.diff_snapshots(baseline, current)
    assert diff["verdict"] == "pass"
    assert diff["added_entities"] == 1


def test_run_and_snapshot_captures_metrics_without_real_agent(case_db):
    def fake_runner(conn, case):
        return {"cost_usd": 0.42, "passes": 1, "findings": 2,
                "stop_reason": "covered", "summary": "fake brief"}
    snap = diff_harness.run_and_snapshot("t-case", runner=fake_runner)
    m = snap["metrics"]
    assert m["cost_usd"] == 0.42 and m["passes"] == 1 and m["findings"] == 2
    assert m["wall_clock_s"] >= 0 and snap["brief"] == "fake brief"
    assert snap["entity_count"] == 3   # snapshot taken on the same patched DB


def test_save_and_load_baseline_roundtrip(case_db, mp, tmp_path):
    mp.setattr(diff_harness, "BASELINE_DIR", tmp_path)
    with db.connect() as conn:
        snap = diff_harness.snapshot_case(conn, "t-case")
    path = diff_harness.save_baseline(snap)
    assert path.exists()
    loaded = diff_harness.load_baseline("t-case")
    assert diff_harness.diff_snapshots(loaded, snap)["verdict"] == "pass"


def test_intersection_core_of_two_baselines(case_db, mp, tmp_path):
    """Gate v2: comma-separated baselines load as their intersection core."""
    mp.setattr(diff_harness, "BASELINE_DIR", tmp_path)
    with db.connect() as conn:
        a = diff_harness.snapshot_case(conn, "t-case")
    b = json.loads(json.dumps(a))
    b["case"] = "t-other"
    b["entities"] = [e for e in b["entities"] if e[0] != "promo.net"]  # other run missed one
    b["edges"] = [e for e in b["edges"] if e[1] != "promo.net"]
    diff_harness.save_baseline(a)
    diff_harness.save_baseline(b)
    core = diff_harness.load_baseline("t-case,t-other")
    assert core["entity_count"] == 2 and core["edge_count"] == 1
    assert ["promo.net", "domain"] not in core["entities"]
    # a run matching the core passes even though run A had more
    with db.connect() as conn:
        current = diff_harness.snapshot_case(conn, "t-case")
    assert diff_harness.diff_snapshots(core, current)["verdict"] == "pass"


def test_load_missing_baseline_says_how_to_create(case_db, mp, tmp_path):
    mp.setattr(diff_harness, "BASELINE_DIR", tmp_path)
    with pytest.raises(FileNotFoundError, match="--save"):
        diff_harness.load_baseline("t-case")
