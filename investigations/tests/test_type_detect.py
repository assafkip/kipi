"""Investigation-type detection: deterministic signals, gate, no-clobber.

Run: .venv/bin/python -m investigations.tests.test_type_detect
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.intake import types


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def test_score_signals_picks_domain():
    crypto_text = "The rugpull drained the wallet via a MetaMask drainer on the token contract."
    s = types.score_signals(crypto_text, {"crypto_wallet": 8, "domain": 5})
    assert max(s, key=s.get) == "crypto-fraud", s
    apt_text = "The malware C2 backdoor implant beacons to the command and control server."
    s2 = types.score_signals(apt_text, {"ip": 10, "hash_sha256": 6})
    assert max(s2, key=s2.get) == "intrusion-apt", s2
    print("  ok  deterministic signals separate crypto-fraud from intrusion-apt")


def test_detect_stores_proposed():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "a.md", "h", "markdown", "A", "case-c",
                                 "rugpull wallet drainer metamask token solana airdrop scam")
            e = db.upsert_entity(conn, "0xabc", "crypto_wallet", r)
            db.add_mention(conn, e, r, "0xabc", "c")
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-c','case-c')")
            conn.commit()
            out = types.detect(conn, "case-c", use_llm=False)
            _check("detected crypto-fraud", out["type"], "crypto-fraud")
            _check("stored proposed", out["status"], "proposed")
            got = types.get_type(conn, "case-c")
            _check("readback type", got["type"], "crypto-fraud")
            assert got["confidence"] and got["confidence"] > 0, got
            _check("seed roles present for type", bool(types.seed_roles_for("crypto-fraud")), True)


def test_does_not_clobber_approved():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            r = db.insert_report(conn, "a.md", "h", "markdown", "A", "case-c", "malware c2 implant")
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-c','case-c')")
            conn.commit()
            types.set_type(conn, "case-c", "person-of-interest", status="approved")
            out = types.detect(conn, "case-c", use_llm=False)
            _check("approved type not overwritten", out.get("unchanged"), True)
            _check("type still the analyst's", types.get_type(conn, "case-c")["type"], "person-of-interest")


def test_thin_signal_general_without_llm():
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            db.insert_report(conn, "a.md", "h", "markdown", "A", "case-c", "nondescript notes here")
            conn.execute("INSERT OR IGNORE INTO investigations (slug,case_name) VALUES ('case-c','case-c')")
            conn.commit()
            out = types.detect(conn, "case-c", use_llm=False)
            _check("thin signal falls back to general (no LLM)", out["type"], "general")


def main():
    test_score_signals_picks_domain()
    test_detect_stores_proposed()
    test_does_not_clobber_approved()
    test_thin_signal_general_without_llm()
    print("\nPASS: test_type_detect")


if __name__ == "__main__":
    main()
