"""Text-admission gate (issue text-admission-gate).

A tool-less model prompted to "investigate" can role-play a fake
<tool_call>/<tool_response> transcript that lands in a node's dossier as a
finding (verified: a quick-read stored phonebook_lookup on a phone node). This
pins the deterministic gate that strips that shape at the single write
choke-point (annotations.set_dossier_override) and in the retro sweep
(maintenance.retro_clean.clean_dossier_transcripts), plus a negative self-test
proving the gate has teeth.

Run: .venv/bin/python -m investigations.tests.test_text_admission
"""
import tempfile
import time
from pathlib import Path

from investigations.storage import db
from investigations import admission
from investigations import annotations as ann
from investigations.maintenance import retro_clean

PAIRED = ('<tool_call>\n{"name": "phonebook_lookup"}\n</tool_call>\n'
          '<tool_response>\nError: not available\n</tool_response>')
BLUFF = ("**Quick read:** I'll investigate this phone number using available "
         "OSINT tools.\n\n" + PAIRED)
GOOD = "## Node Assessment\nUS phone, Virginia, used as a registrant contact."


def _ok(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label}")


def _truthy(label, cond):
    assert cond, f"{label}: expected truthy"
    print(f"  ok  {label}")


def _new_entity(conn, name, etype="phone"):
    cur = conn.execute(
        "INSERT INTO entities (canonical_name, entity_type) VALUES (?, ?)", (name, etype))
    conn.commit()
    return cur.lastrowid


def main():
    # 1) SANITIZER variants -------------------------------------------------
    _truthy("paired tool_call/tool_response stripped",
            "<tool_call>" not in admission.sanitize_model_text(PAIRED)[0].lower())
    _ok("clean text is a no-op (removed=False)", admission.sanitize_model_text(GOOD)[1], False)
    _truthy("uppercase <TOOL_CALL> stripped (case-insensitive)",
            admission.sanitize_model_text('<TOOL_CALL>\n{}\n</TOOL_CALL>')[1])
    _truthy("attribute-bearing <tool_call id=...> stripped",
            admission.sanitize_model_text('<tool_call id="x7">\n{}\n</tool_call>')[1])
    # orphaned / truncated final block (no closing tag) -> stripped to EOF
    trunc = "real finding here.\n\n<tool_response>\nError: the tool whois_lookup is n"
    c_trunc, r_trunc = admission.sanitize_model_text(trunc)
    _truthy("truncated orphan block stripped", r_trunc and "<tool_response>" not in c_trunc)
    _truthy("orphan strip kept the real finding", "real finding here." in c_trunc)
    # an inline prose mention of the tag (no newline/brace after) is NOT stripped
    prose = "The agent emits a `<tool_call>` tag when it has tools."
    _ok("inline prose mention of <tool_call> preserved",
        admission.sanitize_model_text(prose)[1], False)
    # a legit read naming a 'next pivot to look up ... using tools' is NOT stripped
    legit = "Assessment.\nBest next pivot: look up the wallet using on-chain tools."
    _ok("legit 'next pivot ... tools' read preserved",
        admission.sanitize_model_text(legit)[1], False)

    # 2) pure bluff -> effectively blank; mixed -> keeps the real part -------
    cb, rb = admission.sanitize_model_text(BLUFF)
    _truthy("pure bluff removed", rb)
    _truthy("pure bluff is effectively blank", admission.text_is_effectively_blank(cb))
    mixed = BLUFF + "\n\n**Quick read:** " + GOOD
    cm, rm = admission.sanitize_model_text(mixed)
    _truthy("mixed bluff+read removed the transcript", "<tool_call>" not in cm.lower())
    _truthy("mixed kept the real read", "Node Assessment" in cm)
    _truthy("mixed is NOT effectively blank", not admission.text_is_effectively_blank(cm))
    # a real finding on the SAME line right after the bluff sentence must survive
    # (preamble strip ends at the sentence period, not end-of-line) — codex review.
    same_line = ("**Quick read:** I'll investigate using available OSINT tools. "
                 "The phone is tied to evil.com.\n\n" + PAIRED)
    cs, _ = admission.sanitize_model_text(same_line)
    _truthy("same-line finding after bluff is preserved", "tied to evil.com" in cs)
    _truthy("same-line case is NOT blank (no data loss)",
            not admission.text_is_effectively_blank(cs))
    # a vacuous shell with a unicode em dash is still effectively blank — codex review.
    _truthy("em-dash shell is effectively blank",
            admission.text_is_effectively_blank("**Quick read:** —"))

    # --- adversarial-review fixes ----------------------------------------
    # ReDoS: a flood of unclosed openers must sanitize in linear time (the
    # tempered paired regex), not quadratic. 20k tags completed in <<1s locally.
    flood = "<tool_call>\n" * 20000
    t0 = time.time()
    admission.sanitize_model_text(flood)
    _truthy(f"no ReDoS on 20k unclosed openers ({time.time()-t0:.2f}s)", time.time() - t0 < 3.0)
    # A non-Latin finding (kipi is multilingual) must NOT be judged blank/dropped.
    non_latin = "**Quick read:** 该号码关联诈骗活动。\n\n" + PAIRED
    cn, _ = admission.sanitize_model_text(non_latin)
    _truthy("non-Latin finding survives the transcript strip", "该号码" in cn)
    _truthy("non-Latin finding is NOT effectively blank",
            not admission.text_is_effectively_blank(cn))
    # An orphan block immediately followed by a markdown finding keeps the finding.
    om = "<tool_response>\nError: boom\n## Real Finding\nevil.com is the C2."
    co, _ = admission.sanitize_model_text(om)
    _truthy("orphan stops at the markdown finding", "Real Finding" in co and "evil.com" in co)
    _truthy("orphan removed the transcript noise", "<tool_response>" not in co.lower())
    # A legit mid-text sentence matching the bluff pattern, with a transcript
    # elsewhere, must NOT be stripped (preamble is anchored to the start).
    mid = "## Assessment\nLet me search the registry using tools next.\n\n" + PAIRED
    cmid, _ = admission.sanitize_model_text(mid)
    _truthy("mid-text legit 'search ... using tools' sentence preserved",
            "search the registry using tools" in cmid)

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)

        # 3) WRITE GATE — pure bluff is skipped; prior dossier stands ---------
        with db.connect(path) as conn:
            eid = _new_entity(conn, "+17039483978")
            ann.set_dossier_override(conn, eid, GOOD, author="quick investigate")
            ann.set_dossier_override(conn, eid, BLUFF, author="quick investigate")  # pure bluff
            stored = (ann.get(conn, eid) or {}).get("dossier_override") or ""
            _truthy("pure-bluff write skipped — prior dossier stands",
                    "Node Assessment" in stored and "<tool_call>" not in stored.lower())

        # 4) WRITE GATE — mixed write stores the de-poisoned remainder --------
        with db.connect(path) as conn:
            eid2 = _new_entity(conn, "+14155550000")
            ann.set_dossier_override(conn, eid2, mixed, author="OSINT agent")
            stored2 = (ann.get(conn, eid2) or {}).get("dossier_override") or ""
            _truthy("mixed write stored, transcript gone",
                    "Node Assessment" in stored2 and "<tool_call>" not in stored2.lower())

        # 5) WRITE GATE — analyst prose is unchanged --------------------------
        with db.connect(path) as conn:
            eid3 = _new_entity(conn, "evil.com", "domain")
            ann.set_dossier_override(conn, eid3, GOOD, author="ally")
            _ok("analyst prose stored verbatim",
                (ann.get(conn, eid3) or {}).get("dossier_override"), GOOD)

        # 6) RETRO SWEEP — cleans a poisoned row, idempotent ------------------
        with db.connect(path) as conn:
            eid4 = _new_entity(conn, "+18005551234")
            # write the poison directly (bypassing the gate) to simulate legacy data
            ann._ensure_row(conn, eid4)
            conn.execute("UPDATE entity_annotations SET dossier_override = ?, "
                         "dossier_author = ? WHERE entity_id = ?",
                         (BLUFF + "\n\n**Quick read:** " + GOOD, "quick investigate", eid4))
            conn.commit()
            res = retro_clean.clean_dossier_transcripts(conn)
            _truthy("retro sweep cleaned the poisoned row", res["cleaned"] >= 1)
            swept = (ann.get(conn, eid4) or {}).get("dossier_override") or ""
            _truthy("retro left the real read, dropped the transcript",
                    "Node Assessment" in swept and "<tool_call>" not in swept.lower())
            res2 = retro_clean.clean_dossier_transcripts(conn)
            _ok("retro sweep is idempotent (re-run cleans 0)", res2["cleaned"], 0)

        # 7) NEGATIVE SELF-TEST — without the sanitizer, the bluff persists ---
        original = admission.sanitize_model_text
        try:
            admission.sanitize_model_text = lambda t: ((t or ""), False)  # defeat the gate
            with db.connect(path) as conn:
                eid5 = _new_entity(conn, "+19998887777")
                ann.set_dossier_override(conn, eid5, BLUFF, author="quick investigate")
                leaked = (ann.get(conn, eid5) or {}).get("dossier_override") or ""
                _truthy("NEG: gate defeated -> the bluff persists (proves teeth)",
                        "<tool_call>" in leaked.lower())
        finally:
            admission.sanitize_model_text = original

    print("\nPASS: test_text_admission")


if __name__ == "__main__":
    main()
