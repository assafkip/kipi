"""Evidence artifact capture (issue ea-1-evidence-capture, PRD evidence-artifacts).

Asserts: the evidence_artifacts table is created by db._migrate; capture_artifact
writes one row, idempotent on content_hash; artifacts_for_entity returns
newest-first; the enrich runner persists each result's full raw_json as an
artifact; the agent promote path captures the finding evidence; the read API
returns them; a capture failure never blocks enrichment/promotion.
"""
import json
import tempfile
from pathlib import Path
from unittest import mock

from investigations import evidence
from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "evidence.db"
    db.init_db(path)
    return path


def _mk_entity(conn, name="evil.example.com"):
    rep = db.insert_report(conn, source_path="<t>", source_hash=f"h-{name}",
                           source_type="text", title="t", investigation="ev-case",
                           raw_text="")
    return db.upsert_entity(conn, name, "domain", rep)


def test_table_created_by_migrate():
    path = _db_path()
    with db.connect(path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(evidence_artifacts)")}
        assert {"entity_id", "kind", "content", "content_hash", "captured_at"} <= cols


def test_capture_is_idempotent_on_content_hash():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_entity(conn)
        a = evidence.capture_artifact(conn, eid, "whois", {"registrar": "NameSilo"})
        b = evidence.capture_artifact(conn, eid, "whois", {"registrar": "NameSilo"})
        assert a == b, "same content must not create a second row"
        n = conn.execute("SELECT COUNT(*) FROM evidence_artifacts WHERE entity_id = ?",
                         (eid,)).fetchone()[0]
        assert n == 1
        # Different content -> a new artifact.
        c = evidence.capture_artifact(conn, eid, "whois", {"registrar": "Dynadot"})
        assert c != a


def test_dict_content_hash_is_order_stable():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_entity(conn, "order.example.com")
        a = evidence.capture_artifact(conn, eid, "dns", {"a": 1, "b": 2})
        b = evidence.capture_artifact(conn, eid, "dns", {"b": 2, "a": 1})
        assert a == b, "key order must not change the hash"


def test_artifacts_for_entity_newest_first():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_entity(conn, "n.example.com")
        evidence.capture_artifact(conn, eid, "k1", "first")
        evidence.capture_artifact(conn, eid, "k2", "second")
        rows = evidence.artifacts_for_entity(conn, eid)
        assert len(rows) == 2
        assert rows[0]["id"] > rows[1]["id"], "newest first"


def test_empty_content_captures_nothing():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_entity(conn, "empty.example.com")
        assert evidence.capture_artifact(conn, eid, "k", "") is None
        assert evidence.capture_artifact(conn, eid, "k", None) is None
        assert evidence.capture_artifact(conn, 0, "k", "x") is None


def test_large_content_truncated():
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_entity(conn, "big.example.com")
        evidence.capture_artifact(conn, eid, "k", "x" * 500_000)
        row = conn.execute("SELECT content FROM evidence_artifacts WHERE entity_id = ?",
                           (eid,)).fetchone()
        assert row["content"].endswith("…[truncated]")
        assert len(row["content"]) < 250_000


def test_enrich_runner_captures_raw_json():
    """The enrich runner persists each result's full raw_json as an artifact."""
    from investigations.enrich import runner, base
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_entity(conn, "runner.example.com")
        # A fake adapter returning one result with raw_json.
        result = base.EnrichmentResult(
            result_type="document", title="whois", summary="s",
            raw_json={"registrar": "NameSilo", "created": "2026-04-19"}, confidence="high")

        class FakeAdapter:
            slug = "infra"
            cost_per_call_usd = 0.0
            def run(self, query, mode=None, timeout=60):
                return [result]

        with mock.patch.object(runner, "get_adapter", return_value=FakeAdapter()):
            runner.run_and_persist(conn, "infra", "runner.example.com", entity_id=eid, mode="auto")
        arts = evidence.artifacts_for_entity(conn, eid)
        assert any("NameSilo" in a["content"] for a in arts), \
            "the enrich runner must capture the raw provider response"
        assert any(a["kind"] == "enrich:infra" for a in arts)


def test_promote_captures_evidence_on_promoted_node():
    """Codex ea-1 finding-2: a promoted result must ground the PROMOTED node, which
    may differ from the run's source entity."""
    from investigations.enrich import promote
    path = _db_path()
    with db.connect(path) as conn:
        conn.execute("INSERT INTO investigations (slug, case_name) VALUES ('p-case','p')")
        rep = db.insert_report(conn, source_path="<t>", source_hash="h-p",
                               source_type="enrichment", title="t",
                               investigation="p-case", raw_text="")
        actor = db.upsert_entity(conn, "actor.example.com", "domain", rep)
        db.add_mention(conn, actor, rep, "x", "ctx")
        run = conn.execute(
            "INSERT INTO enrichment_runs (entity_id, provider_slug, query, mode, status, "
            "investigation) VALUES (?, 'infra', 'q', 'auto', 'success', 'p-case')",
            (actor,)).lastrowid
        res = conn.execute(
            "INSERT INTO enrichment_results (run_id, result_type, title, summary, url, "
            "raw_json, confidence) VALUES (?, 'url', 'newnode.example.com', 's', "
            "'http://newnode.example.com', ?, 'high')",
            (run, json.dumps({"a_record": "1.2.3.4"}))).lastrowid
        conn.commit()
        out = promote.promote_result(conn, res, analyst="alice")
        eid = out["entity_id"]
        # The promoted node is a DIFFERENT entity than the actor; its artifacts exist.
        arts = evidence.artifacts_for_entity(conn, eid)
        assert any("1.2.3.4" in a["content"] for a in arts), \
            "promoted node must carry the result's evidence"


def test_deleting_entity_cascades_artifacts():
    """Codex ea-1 finding-1: the FK must ON DELETE CASCADE so existing delete/merge
    paths (DELETE FROM entities) don't hit a foreign-key constraint failure."""
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_entity(conn, "del.example.com")
        evidence.capture_artifact(conn, eid, "whois", {"x": 1})
        assert conn.execute("SELECT COUNT(*) FROM evidence_artifacts").fetchone()[0] == 1
        # A bare DELETE FROM entities (what cleanup/merge paths do) must succeed and
        # cascade the artifact away — no FK constraint failure.
        conn.execute("DELETE FROM entities WHERE id = ?", (eid,))
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM evidence_artifacts").fetchone()[0] == 0


def test_capture_failure_never_blocks_enrichment():
    from investigations.enrich import runner, base
    path = _db_path()
    with db.connect(path) as conn:
        eid = _mk_entity(conn, "safe.example.com")
        result = base.EnrichmentResult(result_type="document", title="t", summary="s",
                                       raw_json={"x": 1}, confidence="high")

        class FakeAdapter:
            slug = "infra"
            cost_per_call_usd = 0.0
            def run(self, query, mode=None, timeout=60):
                return [result]

        with mock.patch.object(runner, "get_adapter", return_value=FakeAdapter()), \
             mock.patch("investigations.evidence.capture_artifact",
                        side_effect=RuntimeError("boom")):
            out = runner.run_and_persist(conn, "infra", "safe.example.com", entity_id=eid, mode="auto")
        assert out["status"] == "success", "a capture failure must not fail enrichment"
        # The result row still persisted.
        assert conn.execute("SELECT COUNT(*) FROM enrichment_results").fetchone()[0] == 1
