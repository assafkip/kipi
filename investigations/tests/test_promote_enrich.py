"""Enrichment promotion tests: result -> graph node, linked + scoped + briefed,
and bridging across investigations via the global entity pool.

Run: .venv/bin/python -m investigations.tests.test_promote_enrich
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.enrich import promote
from investigations import annotations


def _run(conn, entity_id, provider, investigation):
    cur = conn.execute(
        "INSERT INTO enrichment_runs (entity_id, provider_slug, query, status, investigation) "
        "VALUES (?, ?, 'q', 'success', ?)", (entity_id, provider, investigation))
    return cur.lastrowid


def _result(conn, run_id, *, url=None, title="", summary=""):
    cur = conn.execute(
        "INSERT INTO enrichment_results (run_id, result_type, title, summary, url, confidence) "
        "VALUES (?, 'url', ?, ?, ?, 'medium')", (run_id, title, summary, url))
    return cur.lastrowid


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def main():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            # Case A: a source actor in a cluster. (Promotion requires a live
            # investigations row — a node can't be scoped into a case that
            # doesn't exist; see CaseDeletedError guard.)
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-a','case-a')")
            ra = db.insert_report(conn, "a.md", "ha", "markdown", "Report A", "case-a", "x")
            actor = db.upsert_entity(conn, "@actor", "username", ra)
            db.add_mention(conn, actor, ra, "@actor", "ctx")
            conn.execute("INSERT INTO clusters (name, kind) VALUES ('ring', 'cluster')")
            cid = conn.execute("SELECT id FROM clusters WHERE name='ring'").fetchone()["id"]
            conn.execute("INSERT INTO cluster_members (cluster_id, entity_id) VALUES (?, ?)", (cid, actor))
            conn.commit()

            run = _run(conn, actor, "perplexity", "case-a")
            res = _result(conn, run, url="https://evil-domain.com/path",
                          title="Evil Domain", summary="Hosts the C2 panel.")

            out = promote.promote_result(conn, res, analyst="ally")
            assert out.get("ok"), out
            _check("promoted node name (url host)", out["name"], "evil-domain.com")
            _check("node type", out["type"], "domain")
            _check("linked to source actor", out["linked_to"], actor)
            new_id = out["entity_id"]

            # Edge: source --enriched--> new node, active.
            edge = conn.execute(
                "SELECT rel_type, status FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=?",
                (actor, new_id)).fetchone()
            _check("enriched edge present + active", (edge["rel_type"], edge["status"]), ("enriched", "active"))

            # Scoped into case-a via the synthetic enrichment report.
            inv = conn.execute(
                "SELECT DISTINCT r.investigation FROM mentions m JOIN reports r ON r.id=m.report_id "
                "WHERE m.entity_id=?", (new_id,)).fetchall()
            _check("new node scoped to case-a", sorted(x[0] for x in inv), ["case-a"])
            rep_type = conn.execute(
                "SELECT r.source_type FROM mentions m JOIN reports r ON r.id=m.report_id "
                "WHERE m.entity_id=? LIMIT 1", (new_id,)).fetchone()["source_type"]
            _check("scoped via an enrichment report", rep_type, "enrichment")

            # Carried into the source actor's cluster.
            in_cluster = conn.execute(
                "SELECT 1 FROM cluster_members WHERE cluster_id=? AND entity_id=?", (cid, new_id)).fetchone()
            _check("new node joined source cluster", bool(in_cluster), True)

            # Result tagged as promoted.
            _check("result.extracted_entity_id set", conn.execute(
                "SELECT extracted_entity_id FROM enrichment_results WHERE id=?", (res,)).fetchone()[0], new_id)

            # Its own brief: dossier seeded from the evidence.
            ann = annotations.get(conn, new_id)
            assert ann["dossier_override"] and "C2 panel" in ann["dossier_override"], ann
            assert "evil-domain.com" in ann["dossier_override"] or "source" in ann["dossier_override"].lower()
            print("  ok  new node has a seeded brief from the enrichment evidence")

            # Idempotent: re-promoting the same result reuses the entity (no dup).
            out2 = promote.promote_result(conn, res, analyst="ally")
            _check("re-promote reuses same node", out2["entity_id"], new_id)

            # --- Cross-case: same indicator already lives in case-b ---
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-b','case-b')")
            rb = db.insert_report(conn, "b.md", "hb", "markdown", "Report B", "case-b", "x")
            shared_b = db.upsert_entity(conn, "shared-host.com", "domain", rb)
            db.add_mention(conn, shared_b, rb, "shared-host.com", "ctx")
            actor2 = db.upsert_entity(conn, "@actor2", "username", ra)
            db.add_mention(conn, actor2, ra, "@actor2", "ctx")
            conn.commit()
            run2 = _run(conn, actor2, "crtsh", "case-a")
            res2 = _result(conn, run2, url="https://shared-host.com", title="Shared host")
            out3 = promote.promote_result(conn, res2, analyst="ally")
            _check("promote dedups to existing global entity", out3["entity_id"], shared_b)
            _check("cross-case bridge detected", out3["cross_case"], ["case-b"])

            # --- Precise typing: ip / telegram, not a vague 'indicator' ---
            ipr = _result(conn, _run(conn, actor, "virustotal", "case-a"),
                          url="https://198.51.100.5/panel", title="C2 IP")
            ip_out = promote.promote_result(conn, ipr, analyst="ally")
            _check("IP result typed as ip", (ip_out["name"], ip_out["type"]), ("198.51.100.5", "ip"))

            tgr = _result(conn, _run(conn, actor, "perplexity", "case-a"),
                          url="https://t.me/order403", title="hub channel")
            tg_out = promote.promote_result(conn, tgr, analyst="ally")
            _check("telegram url typed as telegram_channel",
                   (tg_out["name"], tg_out["type"]), ("t.me/order403", "telegram_channel"))

            # --- Refuse to promote a summary/answer (no link, not an indicator) ---
            ansr = _result(conn, _run(conn, actor, "perplexity", "case-a"),
                           url=None, title="Perplexity sonar", summary="It appears in proxy lists...")
            ans_out = promote.promote_result(conn, ansr, analyst="ally")
            assert ans_out.get("error") and "summary" in ans_out["error"], ans_out
            print("  ok  summary/answer result is refused (no garbage node)")

    print("\nPASS: test_promote_enrich")


if __name__ == "__main__":
    main()
