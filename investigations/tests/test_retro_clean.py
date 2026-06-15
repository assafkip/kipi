"""Retro-clean: old cases get the phone/wallet/attribution fixes retroactively.

The 2026-06-10 fixes (phone predicate, wallet casing, attribution gate) only fire
at write-time. retro_clean applies them to data already in the DB:

- a `phone` entity is junk when fresh extraction over every report that mentions
  it no longer yields its canonical (the predicate rejects bare digit runs)
- wallet case-twins merge per family: EVM/bech32 into the lowercase form;
  base58 lowercase merges into the cased form only when re-extraction vouches
  for the cased form (forged twin), never when the text is genuinely lowercase
- strong-attribution edges are gated in place: low dropped, medium demoted to
  co_listed, high kept; analyst-provenance rows are never touched

Run: .venv/bin/python3 -m pytest investigations/tests/test_retro_clean.py -q
"""
import tempfile
from pathlib import Path

from investigations.maintenance import retro_clean
from investigations.storage import db


def _conn():
    p = Path(tempfile.mkdtemp()) / "retro.db"
    db.init_db(p)
    return db.connect(p)


def _report(conn, text, case="case-a", n=[0]):
    n[0] += 1
    return db.insert_report(conn, source_path=f"<t{n[0]}>", source_hash=f"h{n[0]}",
                            source_type="report", title=f"t{n[0]}",
                            investigation=case, raw_text=text)


def _entity(conn, name, etype, rep, provenance=None, surface=None):
    eid = db.upsert_entity(conn, name, etype, rep, provenance=provenance)
    db.add_mention(conn, eid, rep, surface or name, "ctx")
    return eid


def _names(conn, etype):
    return {r["canonical_name"] for r in conn.execute(
        "SELECT canonical_name FROM entities WHERE entity_type = ?", (etype,))}


# --- pass 1: junk phones ---------------------------------------------------

def test_junk_bare_digit_phone_deleted_real_phones_survive():
    with _conn() as conn:
        rep = _report(conn, "wire ref 1234567890 then call us at +1 415 555 0199 "
                            "or Phone: 4155550100 for support")
        junk = _entity(conn, "1234567890", "phone", rep)        # pre-predicate junk
        _entity(conn, "+14155550199", "phone", rep, surface="+1 415 555 0199")
        _entity(conn, "4155550100", "phone", rep)               # labeled → real
        out = retro_clean.clean_phones(conn, "case-a")
        assert out["deleted"] == 1, out
        assert _names(conn, "phone") == {"+14155550199", "4155550100"}
        assert conn.execute("SELECT 1 FROM mentions WHERE entity_id = ?",
                            (junk,)).fetchone() is None


def test_ip_twin_phone_recovered_into_ip_with_edges():
    """The dominant junk-phone shape: an IP (104.21.68.184) matched the old phone
    predicate (dots = formatting), then the canonicalizer stripped the dots → bare-digit
    phone twin 1042168184. clean_phones recognises the twin IS that IP and ABSORBS its
    edges onto the real IP node (founder's 'recover, don't lose data' choice), then deletes
    the twin — the relationship lands on the correct node, nothing is dropped."""
    with _conn() as conn:
        rep = _report(conn, "host data")
        ip = _entity(conn, "104.21.68.184", "ip", rep)
        twin = _entity(conn, "1042168184", "phone", rep)         # IP with dots stripped
        dom = _entity(conn, "evil.com", "domain", rep)
        db.upsert_typed_relationship(conn, dom, twin, "resolves_to",
                                     confidence="high", evidence="e")
        out = retro_clean.clean_phones(conn, "case-a")
        assert out["recovered"] == 1 and out["deleted"] == 0, out
        # the twin is gone, the real IP survives
        assert _names(conn, "phone") == set()
        assert conn.execute("SELECT 1 FROM entities WHERE id = ?", (twin,)).fetchone() is None
        assert conn.execute("SELECT 1 FROM entities WHERE id = ?", (ip,)).fetchone() is not None
        # the edge moved onto the IP (dom -resolves_to-> 104.21.68.184, not the dead twin)
        dst = conn.execute("SELECT dst_entity_id FROM typed_relationships "
                           "WHERE src_entity_id = ?", (dom,)).fetchone()
        assert dst and dst["dst_entity_id"] == ip, "edge did not move to the real IP"


def test_clean_noise_drops_boilerplate_and_bare_phones_keeps_real():
    """Graph-noise cleanup: bare-number 'phones' (affiliate/tracking ids) and registry/
    reference boilerplate domains are deleted; real + phones and real target domains stay.
    Analyst-touched entities are never removed."""
    with _conn() as conn:
        rep = _report(conn, "noise")
        junk_phone = _entity(conn, "164736471", "phone", rep)            # affiliate id, not a phone
        iana = _entity(conn, "iana.org", "domain", rep)                  # registry boilerplate
        krebs = _entity(conn, "krebsonsecurity.com", "domain", rep)      # reporting outlet
        real_phone = _entity(conn, "+14805058800", "phone", rep, surface="+1 480 505 8800")
        target = _entity(conn, "trumpfundus.com", "domain", rep)         # real target
        flagged = _entity(conn, "verisign-grs.com", "domain", rep)       # noise BUT analyst-vouched
        conn.execute("UPDATE entities SET flagged = 1 WHERE id = ?", (flagged,))
        out = retro_clean.clean_noise(conn, "case-a")
        assert out["deleted"] == 3, out
        names = {n for n, _ in out["items"]}
        assert names == {"164736471", "iana.org", "krebsonsecurity.com"}, out["items"]
        # real entities + the analyst-flagged one survive
        for keep in (real_phone, target, flagged):
            assert conn.execute("SELECT 1 FROM entities WHERE id = ?", (keep,)).fetchone(), \
                f"entity {keep} should have survived"


def test_date_and_zeros_phone_deleted_ambiguous_kept():
    """Date-shaped (20260419 = 2026-04-19) and all-zeros (000000000) phone entities are
    unambiguous non-phones — deleted from their digits alone, even with no source text to
    re-extract. A genuinely ambiguous bare number (a 9-digit ID) and a real + phone are
    left untouched (never guessed at)."""
    with _conn() as conn:
        rep = _report(conn, "")   # no raw_text on purpose — re-extraction can't judge
        date_p = _entity(conn, "20260419", "phone", rep)
        zeros = _entity(conn, "000000000", "phone", rep)
        ambiguous = _entity(conn, "042134014", "phone", rep)     # 9-digit ID — leave alone
        _entity(conn, "+14805058800", "phone", rep, surface="+1 480 505 8800")
        out = retro_clean.clean_phones(conn, "case-a")
        assert out["deleted"] == 2 and out["recovered"] == 0, out
        assert set(out["names"]) == {"20260419", "000000000"}
        assert _names(conn, "phone") == {"042134014", "+14805058800"}
        for gone in (date_p, zeros):
            assert conn.execute("SELECT 1 FROM entities WHERE id = ?", (gone,)).fetchone() is None
        assert conn.execute("SELECT 1 FROM entities WHERE id = ?", (ambiguous,)).fetchone() is not None


def test_analyst_touched_phone_survives():
    with _conn() as conn:
        rep = _report(conn, "ref 9998887776 in the ledger")
        flagged = _entity(conn, "9998887776", "phone", rep)
        conn.execute("UPDATE entities SET flagged = 1 WHERE id = ?", (flagged,))
        _entity(conn, "5554443332", "phone", rep, provenance="analyst")
        out = retro_clean.clean_phones(conn, "case-a")
        assert out["deleted"] == 0, out
        assert _names(conn, "phone") == {"9998887776", "5554443332"}


def test_phone_shared_with_other_case_judged_on_all_its_reports():
    with _conn() as conn:
        rep_a = _report(conn, "id 2125550123 appears here unlabeled")
        rep_b = _report(conn, "Phone: 2125550123", case="case-b")
        eid = _entity(conn, "2125550123", "phone", rep_a)
        db.add_mention(conn, eid, rep_b, "2125550123", "ctx")
        out = retro_clean.clean_phones(conn, "case-a")   # case-b's label vouches
        assert out["deleted"] == 0, out


# --- pass 1c: parse-mangled twins --------------------------------------------

def test_escape_twins_merge_onto_real_entity_with_edges():
    with _conn() as conn:
        rep = _report(conn, "trumpstake.us and friends")
        real = _entity(conn, "trumpstake.us", "domain", rep)
        twin = _entity(conn, "ntrumpstake.us", "domain", rep)       # \n-forged
        quote = _entity(conn, "https://trumpstake.us/a.js'", "url", rep)
        clean = _entity(conn, "https://trumpstake.us/a.js", "url", rep)
        ip = _entity(conn, "1.2.3.4", "ip", rep)
        db.upsert_typed_relationship(conn, twin, ip, "resolves_to")  # edge must survive
        out = retro_clean.clean_escape_twins(conn, "case-a")
        assert sorted(out["pairs"]) == [
            ("https://trumpstake.us/a.js'", "https://trumpstake.us/a.js"),
            ("ntrumpstake.us", "trumpstake.us")], out
        assert _names(conn, "domain") == {"trumpstake.us"}
        assert _names(conn, "url") == {"https://trumpstake.us/a.js"}
        moved = conn.execute(
            "SELECT 1 FROM typed_relationships WHERE src_entity_id = ? AND "
            "dst_entity_id = ? AND rel_type = 'resolves_to'", (real, ip)).fetchone()
        assert moved, "twin's edge must move onto the real entity"
        _ = clean, quote


def test_escape_twin_without_counterpart_left_alone():
    with _conn() as conn:
        rep = _report(conn, "standalone")
        _entity(conn, "niceservers.net", "domain", rep)   # no iceservers.net here
        out = retro_clean.clean_escape_twins(conn, "case-a")
        assert out["merged"] == 0, out
        assert _names(conn, "domain") == {"niceservers.net"}


# --- analyst shield: authors, not row existence -------------------------------

def test_machine_dossier_does_not_shield_but_analyst_notes_do():
    with _conn() as conn:
        rep = _report(conn, "twins everywhere")
        _entity(conn, "gambler-partners.is", "domain", rep)
        agent_twin = _entity(conn, "ngambler-partners.is", "domain", rep)
        analyst_twin = _entity(conn, "ntrumpfundus.com", "domain", rep)
        _entity(conn, "trumpfundus.com", "domain", rep)
        conn.execute("INSERT INTO entity_annotations (entity_id, dossier_override, "
                     "dossier_author) VALUES (?, 'agent says hi', 'quick investigate')",
                     (agent_twin,))
        conn.execute("INSERT INTO entity_annotations (entity_id, notes, notes_author) "
                     "VALUES (?, 'keep this, checking by hand', 'assaf')",
                     (analyst_twin,))
        out = retro_clean.clean_escape_twins(conn, "case-a")
        assert out["pairs"] == [("ngambler-partners.is", "gambler-partners.is")], out
        assert "ntrumpfundus.com" in _names(conn, "domain"), "analyst notes must shield"


# --- pass 2: wallet case-twins ----------------------------------------------

EVM_LOW = "0x" + "ab12" * 10
EVM_MIX = "0x" + "Ab12" * 10
B58_CASED = "1MuskSEpms6rj1GqJU5zUmrqXHHrCmA9zF"
B58_LOW = B58_CASED.lower()
B58_GENUINE = "1" + "x2kq" * 8     # all-lowercase in the source text, no twin


def test_evm_case_twins_merge_into_lowercase():
    with _conn() as conn:
        rep = _report(conn, f"funds moved to {EVM_MIX}")
        keep = _entity(conn, EVM_LOW, "crypto_wallet", rep)
        dup = _entity(conn, EVM_MIX, "crypto_wallet", rep)
        out = retro_clean.clean_wallet_twins(conn, "case-a")
        assert out["merged"] == 1, out
        assert _names(conn, "crypto_wallet") == {EVM_LOW}
        # dup's mention re-pointed, old name kept as alias
        assert conn.execute("SELECT COUNT(*) FROM mentions WHERE entity_id = ?",
                            (keep,)).fetchone()[0] == 2
        aliases = {r["alias"] for r in conn.execute(
            "SELECT alias FROM aliases WHERE entity_id = ?", (keep,))}
        assert EVM_MIX in aliases
        assert conn.execute("SELECT 1 FROM entities WHERE id = ?", (dup,)).fetchone() is None


def test_forged_lowercase_base58_twin_merges_into_cased():
    with _conn() as conn:
        rep = _report(conn, f"deposit address {B58_CASED} on the lure page")
        _entity(conn, B58_LOW, "crypto_wallet", rep)     # old extractor forged this
        _entity(conn, B58_CASED, "crypto_wallet", rep)   # reextract added the real one
        out = retro_clean.clean_wallet_twins(conn, "case-a")
        assert out["merged"] == 1, out
        assert _names(conn, "crypto_wallet") == {B58_CASED}


def test_genuine_lowercase_base58_untouched():
    with _conn() as conn:
        rep = _report(conn, f"deposit address {B58_GENUINE} on the page")
        _entity(conn, B58_GENUINE, "crypto_wallet", rep)
        out = retro_clean.clean_wallet_twins(conn, "case-a")
        assert out["merged"] == 0, out
        assert _names(conn, "crypto_wallet") == {B58_GENUINE}


# --- pass 3: retroactive attribution gate -----------------------------------

def _edge(conn, src, dst, rel, confidence, provenance=None):
    db.upsert_typed_relationship(conn, src, dst, rel, confidence=confidence,
                                 evidence="e", provenance=provenance)


def test_attribution_gate_applies_to_existing_edges():
    with _conn() as conn:
        rep = _report(conn, "wallets")
        a, b, c, d = (_entity(conn, f"0x{str(i) * 40}", "crypto_wallet", rep)
                      for i in range(1, 5))
        _edge(conn, a, b, "same_operator", "low")            # → dropped
        _edge(conn, a, c, "same_operator", "medium")         # → co_listed
        _edge(conn, a, d, "same_operator", "high")           # → kept
        _edge(conn, b, c, "same_operator", None)             # NULL = medium → co_listed
        _edge(conn, b, d, "same_operator", "medium", provenance="analyst")  # → kept
        _edge(conn, c, d, "drains_to", "low")                # non-attribution → kept
        out = retro_clean.gate_existing_attribution(conn, "case-a")
        assert out["dropped"] == 1 and out["demoted"] == 2, out
        edges = {(r["src_entity_id"], r["dst_entity_id"], r["rel_type"])
                 for r in conn.execute(
                     "SELECT src_entity_id, dst_entity_id, rel_type FROM typed_relationships")}
        assert (a, b, "same_operator") not in edges
        assert (a, c, "co_listed") in edges
        assert (a, d, "same_operator") in edges
        assert (b, c, "co_listed") in edges
        assert (b, d, "same_operator") in edges              # analyst edge untouched
        assert (c, d, "drains_to") in edges


def test_demotion_collision_with_existing_co_listed_dedupes():
    with _conn() as conn:
        rep = _report(conn, "wallets")
        a = _entity(conn, "0x" + "a" * 40, "crypto_wallet", rep)
        b = _entity(conn, "0x" + "b" * 40, "crypto_wallet", rep)
        _edge(conn, a, b, "co_listed", "medium")
        _edge(conn, a, b, "same_operator", "medium")
        out = retro_clean.gate_existing_attribution(conn, "case-a")
        rows = conn.execute(
            "SELECT rel_type FROM typed_relationships WHERE src_entity_id=? AND dst_entity_id=?",
            (a, b)).fetchall()
        assert [r["rel_type"] for r in rows] == ["co_listed"], (out, rows)


# --- run() wraps all three ---------------------------------------------------

def test_run_returns_all_pass_counts():
    with _conn() as conn:
        _report(conn, "empty")
        out = retro_clean.run(conn, "case-a")
        assert set(out) >= {"phones", "wallets", "attribution"}, out


# --- dry run -------------------------------------------------------------------

def _counts(conn):
    return (conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM typed_relationships").fetchone()[0])


def test_dry_run_reports_candidates_and_writes_nothing():
    with _conn() as conn:
        rep = _report(conn, f"junk ref 1234567890 then {EVM_MIX} moved funds")
        _entity(conn, "1234567890", "phone", rep)
        _entity(conn, EVM_LOW, "crypto_wallet", rep)
        _entity(conn, EVM_MIX, "crypto_wallet", rep)
        a = _entity(conn, "0x" + "1" * 40, "crypto_wallet", rep)
        b = _entity(conn, "0x" + "2" * 40, "crypto_wallet", rep)
        _edge(conn, a, b, "same_operator", "low")
        before = _counts(conn)

        dry = retro_clean.run(conn, "case-a", dry=True)
        assert dry["phones"]["deleted"] == 1, dry
        assert dry["phones"]["names"] == ["1234567890"]
        assert dry["wallets"]["merged"] == 1
        assert dry["wallets"]["pairs"] == [(EVM_MIX, EVM_LOW)]
        assert dry["attribution"]["dropped"] == 1
        assert dry["attribution"]["edges"][0]["action"] == "drop"
        assert _counts(conn) == before, "dry run must not write"

        real = retro_clean.run(conn, "case-a")
        assert (real["phones"]["deleted"], real["wallets"]["merged"],
                real["attribution"]["dropped"]) == (1, 1, 1), real
        assert _counts(conn) != before
