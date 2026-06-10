"""Agent process trail is stored on the run + the Findings aggregation returns it.

Run: .venv/bin/python -m investigations.tests.test_findings
"""
import json
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.agent import investigator
from investigations.webapp import app as app_module


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


AGENT_JSON = (
    '{"findings":['
    '{"entity":"sub.evil.com","entity_type":"subdomain","claim":"CT subdomain",'
    '"confidence":"high","provenance":"crtsh: evil.com","unvalidated":false},'
    '{"entity":"9.9.9.9","entity_type":"ip","claim":"resolves","confidence":"medium",'
    '"provenance":"dns: evil.com","unvalidated":false}],'
    '"summary":"two pivots found"}'
)
NARRATION = "I started with crt.sh, then ran dns on the domain.\n"
FULL_TEXT = NARRATION + AGENT_JSON
# A real run produces a tool step trail; the A-F grading promotes a finding only when
# the trail CORROBORATES its entity (not on the agent's self-declared unvalidated:false).
# crt.sh surfaced the subdomain, dns surfaced the IP -> both grade A/B -> both promote.
STEPS = [
    {"n": 1, "type": "tool", "tool": "crtsh_subdomains", "input": "evil.com",
     "result": "found sub.evil.com in CT logs"},
    {"n": 2, "type": "tool", "tool": "dns_lookup", "input": "evil.com",
     "result": "evil.com A 9.9.9.9"},
]


def test_process_stored_on_run(mp):
    mp.setattr(investigator, "_run_agent", lambda task, **k: {
        "ok": True, "result_text": FULL_TEXT, "steps": STEPS,
        "raw": {"num_turns": 4, "total_cost_usd": 0.021}, "capped": False})
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-a','case-a')")
            r = db.insert_report(conn, "r.md", "h", "markdown", "R", "case-a", "evil.com")
            e = db.upsert_entity(conn, "evil.com", "domain", r)
            db.add_mention(conn, e, r, "evil.com", "c")
            conn.commit()
            investigator.investigate_entity(conn, "evil.com", case="case-a")
            raw = conn.execute("SELECT agent_process FROM enrichment_runs WHERE provider_slug='agent'").fetchone()[0]
            proc = json.loads(raw)
            _check("process stored on the run", proc is not None)
            _check("tools_used from the real step trail",
                   set(proc["tools_used"]) == {"crtsh_subdomains", "dns_lookup"})
            _check("turns captured", proc["turns"] == 4)
            _check("cost captured", abs(proc["cost_usd"] - 0.021) < 1e-6)
            _check("narration kept (JSON stripped)", "crt.sh" in proc["narration"] and "{" not in proc["narration"])

            # Aggregation: the Findings page query returns the run + its findings + process.
            agg = app_module._agent_findings(conn, ["case-a"])
            _check("one agent run aggregated", len(agg) == 1)
            run = agg[0]
            _check("entity name resolved", run["entity_name"] == "evil.com")
            _check("two findings under the run", len(run["results"]) == 2)
            _check("process attached to the run", run["process"] and run["process"]["turns"] == 4)
            # Agent builds the graph: both validated findings auto-promote to nodes.
            _check("validated findings auto-promoted", run["promoted"] == 2)


def test_aggregation_scopes_by_case(mp):
    mp.setattr(investigator, "_run_agent", lambda task, **k: {
        "ok": True, "result_text": AGENT_JSON, "raw": {}, "capped": False})
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            for case in ("case-a", "case-b"):
                conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES (?,?)", (case, case))
                r = db.insert_report(conn, f"{case}.md", case, "markdown", case, case, "x")
                e = db.upsert_entity(conn, f"@{case}", "handle", r)
                db.add_mention(conn, e, r, f"@{case}", "c")
                conn.commit()
                investigator.investigate_entity(conn, f"@{case}", case=case)
            a = app_module._agent_findings(conn, ["case-a"])
            _check("case scoping returns only that case's run", len(a) == 1 and a[0]["case"] == "case-a")
            both = app_module._agent_findings(conn, [])
            _check("empty scope returns all runs", len(both) == 2)


def main():
    mp = _MP()
    try: test_process_stored_on_run(mp)
    finally: mp.undo()
    mp = _MP()
    try: test_aggregation_scopes_by_case(mp)
    finally: mp.undo()
    print("\nPASS: test_findings")


if __name__ == "__main__":
    main()
