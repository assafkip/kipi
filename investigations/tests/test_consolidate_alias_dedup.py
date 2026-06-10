"""Stage 3 (speed-cost-staged-rollout): type-scoped alias keys in consolidate's
deterministic pre-pass. The bench corpus proved @handle and t.me/handle survive as two
nodes — the LLM batch missed the merge (merged: 0). Known-shape identity is code's job.

Safety contract (the reason _norm_key never stripped '@'): merging is allowed ONLY
within a type bucket — a handle can never collapse into a same-named domain or wallet.

Run: .venv/bin/python -m pytest investigations/tests/test_consolidate_alias_dedup.py -q
"""
import tempfile
from pathlib import Path

import pytest

from investigations import consolidate
from investigations.storage import db


@pytest.fixture
def case_db(mp):
    d = tempfile.mkdtemp()
    p = Path(d) / "t.db"
    db.init_db(p)
    orig = db.connect
    mp.setattr(db, "connect", lambda migrate=True, db_path=p: orig(db_path=db_path, migrate=migrate))
    with db.connect() as conn:
        conn.execute("INSERT INTO investigations (slug) VALUES ('t-case')")
        rep = db.insert_report(conn, "r.txt", "h", "markdown", "r", "t-case", "x")
        conn.commit()
    return rep


def _mk(conn, name, etype, rep, mentions=1):
    eid = db.upsert_entity(conn, name, etype, rep)
    for _ in range(mentions):
        db.add_mention(conn, eid, rep, name, "ctx")
    return eid


def _names(conn):
    return {r["canonical_name"] for r in conn.execute(
        "SELECT canonical_name FROM entities WHERE hidden = 0")}


def test_handle_and_telegram_channel_merge(case_db):
    with db.connect() as conn:
        _mk(conn, "@kambala_boss", "handle", case_db, mentions=1)
        _mk(conn, "t.me/kambala_boss", "telegram_channel", case_db, mentions=3)
        ents = consolidate._candidate_entities(conn)
        survivors, merged = consolidate._dedup_exact(conn, ents)
        assert merged == 1
        kept = {s["canonical_name"] for s in survivors}
        # richest (most-mentioned) survives; the other becomes its alias
        assert "t.me/kambala_boss" in kept and "@kambala_boss" not in kept
        alias = conn.execute("SELECT alias FROM aliases").fetchone()
        assert alias and alias["alias"] == "@kambala_boss"


def test_handle_never_merges_into_domain_or_wallet(case_db):
    with db.connect() as conn:
        _mk(conn, "@stake", "handle", case_db)
        _mk(conn, "stake.com", "domain", case_db)
        _mk(conn, "stake", "person_candidate", case_db)
        ents = consolidate._candidate_entities(conn)
        _, merged = consolidate._dedup_exact(conn, ents)
        assert merged == 0
        assert {"@stake", "stake.com", "stake"} <= _names(conn)


def test_pathless_url_merges_into_domain(case_db):
    with db.connect() as conn:
        _mk(conn, "https://kambala-panel.example/", "url", case_db, mentions=1)
        _mk(conn, "kambala-panel.example", "domain", case_db, mentions=2)
        ents = consolidate._candidate_entities(conn)
        survivors, merged = consolidate._dedup_exact(conn, ents)
        assert merged == 1
        assert "kambala-panel.example" in {s["canonical_name"] for s in survivors}


def test_url_with_path_stays_separate(case_db):
    with db.connect() as conn:
        _mk(conn, "https://kambala-panel.example/affiliates", "url", case_db)
        _mk(conn, "kambala-panel.example", "domain", case_db)
        ents = consolidate._candidate_entities(conn)
        _, merged = consolidate._dedup_exact(conn, ents)
        assert merged == 0


def test_existing_exact_dedup_still_works(case_db):
    with db.connect() as conn:
        _mk(conn, "HTTPS://www.Kambala-Mirror.example/", "domain", case_db)
        _mk(conn, "kambala-mirror.example", "domain", case_db, mentions=2)
        ents = consolidate._candidate_entities(conn)
        _, merged = consolidate._dedup_exact(conn, ents)
        assert merged == 1
