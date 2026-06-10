"""Analyst annotation tests: notes + dossier override, regen-safe.

Run: .venv/bin/python -m investigations.tests.test_annotations
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import annotations
from investigations import profile as profile_mod


def main():
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        vault = Path(tmp) / "vault"
        db.init_db(dbp)
        with db.connect(dbp) as conn:  # migrate creates entity_annotations
            r = db.insert_report(conn, "a.md", "h", "markdown", "R", "c", "x")
            x = db.upsert_entity(conn, "@x", "handle", r)
            conn.commit()

            # Empty defaults.
            a = annotations.get(conn, x)
            assert a["notes"] in (None, "") and a["dossier_override"] is None, a

            # Notes round-trip.
            annotations.set_notes(conn, x, "knew this guy from a prior case")
            assert annotations.get(conn, x)["notes"] == "knew this guy from a prior case"

            # Dossier override round-trip.
            annotations.set_dossier_override(conn, x, "# My take\nThe report is wrong about X.")
            a = annotations.get(conn, x)
            assert a["dossier_override"].startswith("# My take")
            assert a["notes"] == "knew this guy from a prior case", "override clobbered notes"

            # Upsert stays single-row.
            annotations.set_notes(conn, x, "updated note")
            n = conn.execute("SELECT COUNT(*) FROM entity_annotations WHERE entity_id=?", (x,)).fetchone()[0]
            assert n == 1, f"annotations duplicated rows: {n}"

            # Revert drops the override but KEEPS notes.
            annotations.clear_dossier_override(conn, x)
            a = annotations.get(conn, x)
            assert a["dossier_override"] is None and a["notes"] == "updated note", \
                "revert wrongly touched notes"

            # Regen-safety: regenerating the AI dossier file must not touch annotations.
            annotations.set_dossier_override(conn, x, "analyst dossier kept")
            annotations.set_notes(conn, x, "analyst note kept")
            profile_mod.write_profile_md(vault, {
                "name": "@x", "role": "operator", "dossier": "AI regenerated body",
                "enrichment_links": [],
                "evidence": {"entity": {"entity_type": "handle"}, "aliases": [],
                             "report_count": 1, "mention_count": 1, "related": []},
            })
            a = annotations.get(conn, x)
            assert a["dossier_override"] == "analyst dossier kept", "regen wiped dossier override"
            assert a["notes"] == "analyst note kept", "regen wiped notes"

    print("PASS test_annotations: notes + dossier override round-trip, single-row upsert, "
          "revert keeps notes, AI regen never touches the analyst layer")


if __name__ == "__main__":
    main()
