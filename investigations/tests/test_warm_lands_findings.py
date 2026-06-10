"""Talking to the warm investigator BUILDS the graph (issue warm-lands-findings).

A warm chat turn emits narration + a findings JSON; land_warm_chat parses the JSON,
lands it via the SAME cold land path (so it inherits rel-vocab + provenance), and returns
the narration with the JSON stripped. Malformed/missing JSON lands nothing and never crashes.
"""
import json
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.agent import investigator as inv
from investigations.enrich.rel_vocab import REL_VOCAB


def _case_db():
    path = Path(tempfile.mkdtemp()) / "warm.db"
    db.init_db(path)
    with db.connect(path) as conn:
        conn.execute("INSERT INTO investigations (slug, status) VALUES ('case-w','active')")
        rep = db.insert_report(conn, source_path="<t>", source_hash="hw", source_type="report",
                               title="t", investigation="case-w", raw_text="")
        for name in ("trumpfundus.com", "evil-sibling.com"):
            eid = db.upsert_entity(conn, name, "domain", rep, provenance="ingest:report")
            db.add_mention(conn, eid, rep, name, "seed")
        conn.commit()
    return path


def _run_with_findings():
    findings = {
        "findings": [{"entity": "evil-sibling.com", "entity_type": "domain",
                      "claim": "sibling via shared A record", "confidence": "high",
                      "provenance": "dns: 1.2.3.4", "unvalidated": False}],
        "relationships": [{"src": "trumpfundus.com", "dst": "evil-sibling.com",
                           "rel_type": "resolves_to", "direction": "src_to_dst",
                           "confidence": "high", "provenance": "dns: A record"}],
        "summary": "found a sibling",
    }
    narration = ("I dug into trumpfundus.com — it shares an A record with a sibling, "
                 "evil-sibling.com. Chasing that next.")
    # A real turn OBSERVES both endpoints in a tool result — the corroboration gate
    # (_attribute_findings) only lands an edge whose endpoints appear in real output.
    steps = [{"n": 1, "type": "tool", "tool": "Bash",
              "result": "dns A records: trumpfundus.com -> 1.2.3.4 ; evil-sibling.com -> 1.2.3.4"}]
    return {"ok": True, "result_text": narration + "\n\n" + json.dumps(findings),
            "steps": steps, "tools": ["Bash"], "capped": False, "raw": {}}, narration


def test_warm_chat_turn_lands_findings_into_graph():
    path = _case_db()
    run, narration = _run_with_findings()
    with db.connect(path) as conn:
        out = inv.land_warm_chat(conn, "case-w", "who is behind trumpfundus.com?", run)
        # The new entity landed.
        ent = conn.execute("SELECT id, provenance FROM entities WHERE canonical_name='evil-sibling.com'").fetchone()
        assert ent is not None
        # The typed edge landed, vocab-bound, provenance stamped.
        src = conn.execute("SELECT id FROM entities WHERE canonical_name='trumpfundus.com'").fetchone()["id"]
        edge = conn.execute(
            "SELECT rel_type, provenance FROM typed_relationships "
            "WHERE src_entity_id=? AND dst_entity_id=?", (src, ent["id"])).fetchone()
        assert edge is not None, "warm turn did not build the edge"
        assert edge["rel_type"] in REL_VOCAB
        assert edge["provenance"]  # stamped, not null
    # The displayed reply is the narration, NOT the raw JSON.
    assert "evil-sibling.com" in out["reply"]
    assert '"findings"' not in out["reply"]
    assert "{" not in out["reply"]


def test_missing_json_lands_nothing_and_returns_narration():
    path = _case_db()
    narration = "Just a thought: trumpfundus.com looks suspicious, but I checked nothing yet."
    run = {"ok": True, "result_text": narration, "steps": [], "tools": [], "capped": False}
    with db.connect(path) as conn:
        out = inv.land_warm_chat(conn, "case-w", "thoughts?", run)
        # No new entity, no new edge.
        assert conn.execute("SELECT COUNT(*) c FROM typed_relationships").fetchone()["c"] == 0
    assert out["reply"] == narration
    assert out["findings"] == 0


def test_malformed_json_does_not_crash_and_shows_narration():
    path = _case_db()
    narration = "Here is what I found."
    # A broken/truncated findings blob.
    run = {"ok": True, "result_text": narration + '\n\n{"findings": [ {"entity": "x.com" ',
           "steps": [], "tools": [], "capped": False}
    with db.connect(path) as conn:
        out = inv.land_warm_chat(conn, "case-w", "go", run)
        assert conn.execute("SELECT COUNT(*) c FROM typed_relationships").fetchone()["c"] == 0
    assert narration in out["reply"]


def test_strip_findings_json_handles_fence():
    text = 'Talked it through.\n\n```json\n{"findings": [], "summary": "x"}\n```'
    stripped = inv._strip_findings_json(text)
    assert "findings" not in stripped
    assert "Talked it through." in stripped
    assert "```" not in stripped


def test_strip_uses_last_object_keeps_intervening_narration():
    """An example findings object earlier in the narration must NOT cause the real
    narration between it and the trailing object to be deleted (Codex review)."""
    text = ('Schema looks like {"findings": []} for reference. '
            'IMPORTANT MIDDLE NARRATION the analyst must see. '
            '{"findings": [], "summary": "real"}')
    stripped = inv._strip_findings_json(text)
    assert "IMPORTANT MIDDLE NARRATION the analyst must see." in stripped
    assert '"summary": "real"' not in stripped


def test_relationship_only_turn_reports_landed_any():
    """A turn that lands only an edge (no findings) still flags landed_any so the client
    refreshes the canvas (Codex review)."""
    path = _case_db()
    rel_json = {"findings": [], "relationships": [
        {"src": "trumpfundus.com", "dst": "evil-sibling.com", "rel_type": "resolves_to",
         "direction": "src_to_dst", "confidence": "high", "provenance": "dns"}], "summary": ""}
    steps = [{"n": 1, "type": "tool", "tool": "Bash",
              "result": "trumpfundus.com 1.2.3.4 evil-sibling.com 1.2.3.4"}]
    run = {"ok": True, "result_text": "linked them.\n\n" + json.dumps(rel_json),
           "steps": steps, "tools": ["Bash"], "capped": False, "raw": {}}
    with db.connect(path) as conn:
        out = inv.land_warm_chat(conn, "case-w", "connect them", run)
        assert out["findings"] == 0
        assert out["landed_any"] is True   # edge landed -> client must refresh
