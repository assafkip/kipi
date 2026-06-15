"""Score coverage (issue gma-1-score-coverage, PRD graph-machinery-activation).

Asserts the four fixes for the gate2 scoring-dormancy bug:
1. degree term — an entity with active typed edges scores even with no role
   notes, no approved schema, and no seeds (the old gate skipped it outright);
2. write_case_seeds — intake entities become `seeds` rows, raising scores via
   the seed prior + propagation, and the writer is idempotent;
3. land_findings recomputes scores AFTER its late edge writes
   (_land_relationships et al.), so agent-built graphs are never score-blind;
4. the two webapp scoring call sites log failures instead of `except: pass`,
   and the Process pipeline has a dedicated `score` step emitting `scored N`.
"""
import tempfile
from pathlib import Path

from investigations import analyze
from investigations.storage import db


def _db_path():
    path = Path(tempfile.mkdtemp()) / "score.db"
    db.init_db(path)
    return path


def _mk_case(conn, slug="case-x"):
    conn.execute("INSERT INTO investigations (slug, case_name) VALUES (?, ?)",
                 (slug, slug))
    rep = db.insert_report(conn, source_path="<intake>", source_hash=f"h-{slug}",
                           source_type="text", title="intake", investigation=slug,
                           raw_text="")
    return rep


def test_connected_entity_scores_without_roles_schema_or_seeds():
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn)
        a = db.upsert_entity(conn, "a.example.com", "domain", rep)
        b = db.upsert_entity(conn, "b.example.com", "domain", rep)
        lone = db.upsert_entity(conn, "lone.example.com", "domain", rep)
        db.upsert_typed_relationship(conn, a, b, "resolves_to",
                                     confidence="high", evidence="t")
        n = analyze.compute_threat_scores(conn)
        assert n >= 2, f"connected entities must score, got {n}"
        rows = {r["entity_id"]: r["threat_score"] for r in conn.execute(
            "SELECT entity_id, threat_score FROM entity_scores")}
        assert a in rows and b in rows, "both edge endpoints must have scores"
        assert rows[a] > 0 and rows[b] > 0
        # The unconnected, unroled, unseeded entity still skips — the gate only
        # opened for connectivity, not for everything.
        assert lone not in rows, "orphan with no role/seed/edges must not score"


def test_write_case_seeds_raises_scores_and_is_idempotent():
    from investigations.agent.investigator import write_case_seeds
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="case-seeded")
        a = db.upsert_entity(conn, "seed.example.com", "domain", rep)
        b = db.upsert_entity(conn, "n1.example.com", "domain", rep)
        db.add_mention(conn, a, rep, "seed.example.com", "ctx")
        db.add_mention(conn, b, rep, "n1.example.com", "ctx")
        db.upsert_typed_relationship(conn, a, b, "resolves_to",
                                     confidence="high", evidence="t")
        analyze.compute_threat_scores(conn)
        before = conn.execute(
            "SELECT threat_score FROM entity_scores WHERE entity_id = ?",
            (a,)).fetchone()["threat_score"]

        added = write_case_seeds(conn, "case-seeded")
        assert added >= 2, f"intake entities must become seeds, got {added}"
        assert write_case_seeds(conn, "case-seeded") == 0, "re-run must be a no-op"
        assert write_case_seeds(conn, None) == 0

        analyze.compute_threat_scores(conn)
        after = conn.execute(
            "SELECT threat_score FROM entity_scores WHERE entity_id = ?",
            (a,)).fetchone()["threat_score"]
        assert after > before, (
            f"seed prior must raise the seed's score ({before} -> {after})")


def test_land_findings_rescored_after_late_edge_writes():
    from investigations.agent import investigator
    path = _db_path()
    with db.connect(path) as conn:
        rep = _mk_case(conn, slug="case-land")
        a = db.upsert_entity(conn, "x.example.com", "domain", rep)
        b = db.upsert_entity(conn, "y.example.com", "domain", rep)
        db.add_mention(conn, a, rep, "x.example.com", "ctx")
        db.add_mention(conn, b, rep, "y.example.com", "ctx")
        assert conn.execute("SELECT COUNT(*) FROM entity_scores").fetchone()[0] == 0
        parsed = {
            "summary": "test run",
            "findings": [],
            "relationships": [
                {"src": "x.example.com", "dst": "y.example.com",
                 "rel_type": "resolves_to", "confidence": "high",
                 "provenance": "test edge"}
            ],
        }
        out = investigator.land_findings(
            conn, "case-land", "x.example.com", "test task", parsed,
            auto_promote=False)
        assert out["relationships"] >= 1, "the late edge write must land"
        scored = conn.execute("SELECT COUNT(*) FROM entity_scores").fetchone()[0]
        assert scored >= 2, (
            "land_findings must recompute scores AFTER its edge writes; "
            f"entity_scores has {scored} rows")


def test_webapp_scoring_sites_log_instead_of_swallowing():
    src = (Path(__file__).resolve().parents[1] / "webapp" / "app.py").read_text()
    assert "upload: threat-score recompute failed" in src
    assert "link-finder: threat-score recompute failed" in src
    # The dedicated Process score step exists and emits the count.
    assert '("score", "Recompute threat scores")' in src
    assert 'on_step(f"scored {n}", "ok")' in src
    # No silent except-pass remains directly around a compute_threat_scores call.
    for i, line in enumerate(src.splitlines()):
        if "compute_threat_scores(conn)" in line and "def " not in line:
            window = "\n".join(src.splitlines()[i:i + 3])
            assert "except Exception:\n" not in window or "pass" not in window, (
                f"silent swallow near line {i + 1}: {window}")
