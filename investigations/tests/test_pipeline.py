"""End-to-end pipeline smoke test.
Verifies: init → ingest synthetic markdown reports → correlate → export vault."""
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from investigations.storage import db as dbmod
from investigations.ingest import extractor, markdown
from investigations.correlate import engine as correlate_engine
from investigations.export import obsidian as obsidian_export


SAMPLE_A = """---
title: Handala-Op-Alpha
---
# Handala Op Alpha

Threat actor Ali Khorasani operates from t.me/case-b_team and uses
the email ali.khorasani@protonmail.com. Connected to wallet
0x742d35Cc6634C0532925a3b844Bc454e4438f44e and posts from 192.168.4.4.

The Handala team coordinates with Ali Khorasani via Telegram channel
t.me/case-b_team. Mr. Reza Mohajer has been seen in the same channel.
"""

SAMPLE_B = """---
title: Iran-NVE-Bravo
---
# Iran NVE Bravo

Investigation of nihilist violent extremists. Reza Mohajer maintains
contact with ali.khorasani@protonmail.com. Channel t.me/case-b_team
appears across multiple ops.

New actor: Sahar Nasiri operating wallet 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
contacts +1-415-555-0142.
"""


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        db_path = tmp_path / "test.db"
        vault_path = tmp_path / "vault"

        # init
        dbmod.init_db(db_path)
        assert db_path.exists(), "DB not created"
        print("[ok] init_db created DB")

        # ingest two synthetic reports
        reports = [("a.md", SAMPLE_A), ("b.md", SAMPLE_B)]
        with dbmod.connect(db_path) as conn:
            for name, body in reports:
                p = tmp_path / name
                p.write_text(body)
                text = markdown.extract_text(p)
                title = markdown.extract_title(p) or p.stem
                rid = dbmod.insert_report(
                    conn, str(p), name, "markdown", title, "smoke-test", text
                )
                extracted = extractor.extract_all(text)
                assert extracted, f"No entities extracted from {name}"
                for e in extracted:
                    eid = dbmod.upsert_entity(conn, e.canonical, e.entity_type, rid)
                    if e.surface != e.canonical:
                        dbmod.add_alias(conn, eid, e.surface)
                    dbmod.add_mention(conn, eid, rid, e.surface, e.context, e.offset)
                rels = extractor.infer_relationships(text, extracted)
                for a, b, rel_type in rels:
                    a_id = dbmod.upsert_entity(conn, a.canonical, a.entity_type, rid)
                    b_id = dbmod.upsert_entity(conn, b.canonical, b.entity_type, rid)
                    if a_id != b_id:
                        dbmod.add_relationship(
                            conn, a_id, b_id, rel_type, rid, a.context[:120], 0.4
                        )
        print("[ok] ingested 2 reports")

        # verify cross-report correlation finds shared entities
        with dbmod.connect(db_path) as conn:
            overlap = correlate_engine.cross_report_overlap(conn)
            assert len(overlap) >= 2, (
                f"Expected ≥2 cross-report entities, got {len(overlap)}: {overlap}"
            )
            shared_names = {o["canonical_name"] for o in overlap}
            expected_shared = {"t.me/case-b_team", "ali.khorasani@protonmail.com"}
            missing = expected_shared - shared_names
            assert not missing, f"Missing expected cross-report entities: {missing}"
        print(f"[ok] correlation found {len(overlap)} cross-report entities, "
              f"including the expected shared ones")

        # export vault
        with dbmod.connect(db_path) as conn:
            result = obsidian_export.export(conn, vault_path)
        assert vault_path.exists(), "Vault dir not created"
        assert (vault_path / "_index.md").exists(), "Index not written"
        assert (vault_path / "entities").is_dir(), "entities/ not created"
        assert (vault_path / "reports").is_dir(), "reports/ not created"
        assert result["entities_written"] > 0, "No entity files written"
        assert result["reports_written"] == 2, (
            f"Expected 2 report files, got {result['reports_written']}"
        )
        # spot-check one entity file has wikilinks
        entity_files = list((vault_path / "entities").glob("*.md"))
        contents = "\n".join(p.read_text() for p in entity_files)
        assert "[[" in contents, "No wikilinks in entity files"
        print(f"[ok] exported vault: {result['entities_written']} entities, "
              f"{result['reports_written']} reports, wikilinks present")

        print("\n=== ALL TESTS PASSED ===")


if __name__ == "__main__":
    main()
