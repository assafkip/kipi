"""The volume-decision control surface: a large enrichment result is captured FULLY
(nothing dropped) and the analyst chooses what to do with it — revert / open in a new
cluster / subset / reason. No capping.

Run: .venv/bin/python -m investigations.tests.test_volume_decision
"""
import json
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.enrich import promote


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def _seed(conn):
    """A wallet source entity + an enrichment run/result with 120 captured counterparties
    flagged needs_decision (over threshold)."""
    conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-x','case-x')")
    rep = db.insert_report(conn, source_path="<t>", source_hash="t::1",
                           source_type="report", title="t", investigation="case-x", raw_text="")
    src = db.upsert_entity(conn, "1SourceWalletAAAAAAAAAAAAAAAAAAAAAA", "crypto_wallet", rep)
    cps = [f"1Counterparty{i:04d}AAAAAAAAAAAAAAAAAAAA" for i in range(120)]
    cur = conn.execute(
        "INSERT INTO enrichment_runs (entity_id, provider_slug, query, mode, status, "
        "investigation, finished_at) VALUES (?, 'wallet', ?, 'auto', 'success', 'case-x', "
        "CURRENT_TIMESTAMP)", (src, "1SourceWallet..."))
    run_id = cur.lastrowid
    raw = {"address": "1SourceWallet...", "chain": "btc", "counterparties": cps,
           "counterparty_count": len(cps), "needs_decision": True}
    rcur = conn.execute(
        "INSERT INTO enrichment_results (run_id, result_type, title, summary, raw_json, "
        "confidence) VALUES (?, 'document', 'BTC wallet', 'big', ?, 'high')",
        (run_id, json.dumps(raw)))
    return src, run_id, rcur.lastrowid, cps


def test_cluster_materializes_full_set():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            src, run_id, rid, cps = _seed(conn)
            out = promote.materialize_to_cluster(conn, rid)
            _check("cluster created", out.get("ok") and out.get("cluster_id"))
            _check("all 120 items added", out.get("added") == 120)
            members = conn.execute(
                "SELECT COUNT(*) n FROM cluster_members WHERE cluster_id = ?",
                (out["cluster_id"],)).fetchone()["n"]
            # 120 counterparties + the source wallet itself.
            _check("cluster has 121 members (120 + source)", members == 121)
            # The materialized edge carries the provider-typed vocab label (wallet ->
            # transacts_with), not the old free-form 'enriched' (which the controlled
            # vocab now maps to linked_to anyway).
            _check("source linked to a counterparty",
                   conn.execute("SELECT 1 FROM typed_relationships WHERE src_entity_id = ? "
                                "AND rel_type='transacts_with' LIMIT 1", (src,)).fetchone() is not None)
            _check("result marked decided",
                   (conn.execute("SELECT decision FROM enrichment_results WHERE id = ?",
                                 (rid,)).fetchone()["decision"] or "").startswith("cluster:"))


def test_no_double_materialize():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            src, run_id, rid, cps = _seed(conn)
            first = promote.materialize_to_cluster(conn, rid)
            _check("first materialize ok", first.get("ok"))
            again = promote.materialize_to_cluster(conn, rid)
            _check("second materialize blocked (idempotent)", "already decided" in (again.get("error") or ""))
            # Exactly ONE cluster was created, not two.
            n_clusters = conn.execute("SELECT COUNT(*) c FROM clusters").fetchone()["c"]
            _check("only one cluster exists", n_clusters == 1)


def test_subset_takes_first_n():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            src, run_id, rid, cps = _seed(conn)
            out = promote.materialize_to_cluster(conn, rid, subset=10)
            _check("subset added exactly 10", out.get("added") == 10)
            _check("subset flagged", out.get("subset") is True)


def test_revert_discards():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            src, run_id, rid, cps = _seed(conn)
            out = promote.revert_result(conn, rid)
            _check("reverted ok", out.get("reverted"))
            _check("result row gone",
                   conn.execute("SELECT 1 FROM enrichment_results WHERE id = ?",
                                (rid,)).fetchone() is None)
            _check("empty run deleted too", out.get("run_deleted") is True)


def test_reason_keeps_evidence():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            src, run_id, rid, cps = _seed(conn)
            out = promote.mark_reasoned(conn, rid)
            _check("reasoned ok", out.get("reasoned"))
            row = conn.execute("SELECT decision, raw_json FROM enrichment_results WHERE id = ?",
                               (rid,)).fetchone()
            _check("decision = reason", row["decision"] == "reason")
            # Evidence untouched: the full set is STILL in raw_json.
            _check("full set still captured (nothing dropped)",
                   len(json.loads(row["raw_json"])["counterparties"]) == 120)


def test_extracts_items_from_various_keys():
    # The extractor finds the list under any known key, and handles dict items (urls).
    _check("counterparties key", promote._materializable_items({"counterparties": ["a", "b"]}) == ["a", "b"])
    _check("domains key", promote._materializable_items({"domains": ["x.com"]}) == ["x.com"])
    _check("dict items -> url", promote._materializable_items(
        {"found": [{"url": "https://t.me/x"}]}) == ["https://t.me/x"])
    _check("empty -> []", promote._materializable_items({}) == [])


def main():
    test_cluster_materializes_full_set()
    test_no_double_materialize()
    test_subset_takes_first_n()
    test_revert_discards()
    test_reason_keeps_evidence()
    test_extracts_items_from_various_keys()
    print("\nPASS: test_volume_decision")


if __name__ == "__main__":
    main()
