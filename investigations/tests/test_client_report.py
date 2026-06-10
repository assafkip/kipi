"""Branded client report: case-scoped data assembly.

Run: .venv/bin/python -m investigations.tests.test_client_report
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import annotations
from investigations import client_report


def main():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        vault = Path(tmp) / "vault"
        vault.mkdir()
        db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "a.md", "h", "markdown", "Source One", "acme", "x")
            other = db.insert_report(conn, "b.md", "h2", "markdown", "B", "beta", "x")
            op = db.upsert_entity(conn, "@leader", "handle", r)
            conn.execute("UPDATE entities SET notes='role:operator — runs it' WHERE id=?", (op,))
            ip = db.upsert_entity(conn, "192.168.4.4", "ip", r)
            shared = db.upsert_entity(conn, "@shared", "handle", r)
            for e in (op, ip, shared):
                db.add_mention(conn, e, r, "s", "c")
            db.add_mention(conn, shared, other, "s", "c")  # shared also in beta (cross-case)
            conn.execute("UPDATE entities SET notes='role:operator — x' WHERE id=?", (shared,))
            conn.execute("INSERT INTO entity_scores VALUES (?,70,1,1),(?,40,0,2)", (op, shared))
            annotations.set_notes(conn, op, "knew this actor from 2023", author="ally")
            conn.commit()
        # Per-case exec summary file.
        (vault / "synthesis-acme.md").write_text(
            "---\ntitle: x\nreports: 1\n---\n# Synthesis brief\n\nAcme is targeted by @leader.\n")

        with db.connect(dbp) as conn:
            d = client_report.gather(conn, vault, "acme")

        assert d["case"]["slug"] == "acme"
        assert d["stats"]["reports"] == 1, d["stats"]
        assert "Acme is targeted" in d["exec_summary"], "exec summary not pulled/stripped"
        assert "---" not in d["exec_summary"].split("\n")[0], "frontmatter not stripped"
        assert any(a["name"] == "@leader" for a in d["top_actors"]), "top actor missing"
        assert any(i["canonical_name"] == "192.168.4.4" and i["entity_type"] == "ip"
                   for i in d["iocs"]), f"IOC missing: {d['iocs']}"
        assert any(x["name"] == "@leader" and "knew this actor" in x["notes"]
                   for x in d["dossiers"]), "dossier/note missing"
        # cross-case: @shared appears in acme + beta -> listed; @leader (acme only) not.
        names = {c["name"] for c in d["cross_case"]}
        assert "@shared" in names, f"cross-case link missing: {d['cross_case']}"
        assert "@leader" not in names, "single-case actor wrongly listed as cross-case"

        # Confidentiality: the OTHER case slug ('beta') must NOT leak into any
        # actor bio. Cross-case disclosure belongs only in the gated section.
        assert not any("beta" in (a.get("why") or "") for a in d["top_actors"]), \
            f"other case slug leaked into actor why: {[a.get('why') for a in d['top_actors']]}"

    print("PASS test_client_report: case-scoped report assembles exec summary (frontmatter "
          "stripped), priority actors, IOCs, dossiers+notes, and cross-case links")


if __name__ == "__main__":
    main()
