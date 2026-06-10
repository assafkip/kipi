"""k4p-04 reproducer: the entity list (and graph) surface EVERY worked entity —
including the findings the gate held back — badged unconfirmed, instead of hiding the
network in /enrich. The gate stops auto-FACT, not auto-VISIBILITY.

Run: .venv/bin/python -m investigations.tests.test_visuals_show_all
"""
from pathlib import Path
import json
import tempfile

from investigations.storage import db
from investigations.webapp import app as appmod
from investigations.agent import investigator


def _ok(label, cond):
    assert cond, f"{label}: FAILED"
    print(f"  ok  {label}")


def _gated_finding(conn, case, title, etype, confidence="low"):
    investigator._ensure_agent_provider(conn)  # FK: enrichment_runs.provider_slug -> osint_providers
    cur = conn.execute(
        "INSERT INTO enrichment_runs (provider_slug, query, mode, status, investigation, "
        "finished_at) VALUES ('agent', ?, 'investigate', 'success', ?, CURRENT_TIMESTAMP)",
        (title, case))
    run_id = cur.lastrowid
    conn.execute(
        "INSERT INTO enrichment_results (run_id, result_type, title, summary, raw_json, "
        "confidence, extracted_entity_id) VALUES (?, 'finding', ?, 'gated lead', ?, ?, NULL)",
        (run_id, title, json.dumps({"entity_type": etype}), confidence))


def test_gated_findings_surface_as_badged_leads():
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('casino','casino')")
            r = db.insert_report(conn, "s.md", "h", "markdown", "S", "casino", "x")
            # A CONFIRMED entity (promoted node).
            db.add_mention(conn, db.upsert_entity(conn, "trumpfundus.com", "domain", r), r, "trumpfundus.com", "c")
            # GATED findings the agent surfaced but the gate held back (not promoted).
            _gated_finding(conn, "casino", "trumpcoin.vip", "domain")
            _gated_finding(conn, "casino", "trumpstake.us", "domain")
            # A gated finding whose name IS already a confirmed node must NOT double-list.
            _gated_finding(conn, "casino", "trumpfundus.com", "domain")
            conn.commit()

            # The caller passes the in-scope confirmed names (case-scoped dedup, Codex).
            leads = appmod._gated_leads(conn, ["casino"], exclude_names=["trumpfundus.com"])
            names = {l["canonical_name"] for l in leads}
            _ok("the held-back network surfaces as leads (trumpcoin.vip)", "trumpcoin.vip" in names)
            _ok("the second held-back domain surfaces too (trumpstake.us)", "trumpstake.us" in names)
            _ok("a confirmed in-scope node is NOT also listed as a lead (dedup)",
                "trumpfundus.com" not in names)
            _ok("every lead is badged unconfirmed (lead=True)", all(l.get("lead") for l in leads))
            _ok("leads carry a confidence badge", all(l.get("confidence") for l in leads))
            ids = [l["id"] for l in leads]
            _ok("every lead has a unique, non-null id (no null-key collision)",
                all(i for i in ids) and len(set(ids)) == len(ids))
            _ok("limit is honored", len(appmod._gated_leads(conn, ["casino"], limit=1)) <= 1)


def test_leads_scoped_to_case():
    with tempfile.TemporaryDirectory() as t:
        dbp = Path(t) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('a','a')")
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('b','b')")
            _gated_finding(conn, "a", "only-in-a.com", "domain")
            _gated_finding(conn, "b", "only-in-b.com", "domain")
            conn.commit()
            names_a = {l["canonical_name"] for l in appmod._gated_leads(conn, ["a"])}
            _ok("case A leads do not bleed case B", "only-in-a.com" in names_a and "only-in-b.com" not in names_a)


if __name__ == "__main__":
    test_gated_findings_surface_as_badged_leads()
    test_leads_scoped_to_case()
    print("\nall green")
