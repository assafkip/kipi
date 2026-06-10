"""PRD-01: the chat must read the WHOLE corpus, not a relevance prefix, and never
surface a bare "52%". Small cases answer in one call (100%); big cases sweep
(map-reduce) over every passage — including text that lives late / low-keyword.

Run: .venv/bin/python -m investigations.tests.test_ask_full_sweep
"""
import re
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations import ask


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


def _seed(dbp, chunks):
    db.init_db(dbp)
    with db.connect(dbp) as conn:
        conn.execute("INSERT OR IGNORE INTO investigations(slug,case_name) VALUES('cx','CX')")
        for i, text in enumerate(chunks):
            db.insert_report(conn, f"r{i}.md", f"h{i}", "markdown", f"Report {i}", "cx", text)
        conn.commit()


def _mock_llm(mp):
    """MAP echoes the [n] tags it saw (so we can prove every passage was read);
    REDUCE/single-shot returns a canned answer. Records all tags seen by MAP."""
    seen = set()

    def fake_ask(prompt, system=None, timeout=None, model=None, max_tokens=None):
        tags = re.findall(r"\[(\d+)\]", prompt)
        if system == ask.MAP_SYSTEM:
            seen.update(tags)
            return "; ".join(f"fact [{t}]" for t in tags) if tags else "NONE"
        return "Answer " + " ".join(f"[{t}]" for t in tags)

    mp.setattr(ask.llm, "ask", fake_ask)
    return seen


def test_small_case_single_shot(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        _seed(dbp, ["alpha bravo charlie", "delta echo foxtrot"])
        _mock_llm(mp)
        with db.connect(dbp) as conn:
            res = ask.answer(conn, "cx", "bravo")
        _check("small case → single-shot full coverage", res["coverage"]["mode"] == "full")
        _check("swept == total (read everything)",
               res["coverage"]["passages_swept"] == res["coverage"]["passages_total"])


def test_big_case_sweeps_everything_incl_late(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        # Many chunks; the ANSWER token 'zzlatefact' lives only in the last chunk and
        # shares NO keyword with the question — a relevance-prefix would miss it.
        chunks = [f"chunk {i} about widgets and gadgets " * 3 for i in range(8)]
        chunks.append("zzlatefact buried at the end with no query overlap")
        _seed(dbp, chunks)
        mp.setattr(ask, "CHAR_BUDGET", 200)   # force the too-big sweep path
        mp.setattr(ask, "BATCH_CAP", 20)      # high cap → read all
        seen = _mock_llm(mp)
        with db.connect(dbp) as conn:
            res = ask.answer(conn, "cx", "widgets")
            total = res["coverage"]["passages_total"]
            # which global [n] is the late chunk? rebuild the ranked order the same way.
            cands = ask._candidates(conn, "cx")
            for c in cands:
                c["score"] = ask._score(c["text"], ask._terms("widgets"))
            ranked = sorted(cands, key=lambda c: c["score"], reverse=True)
        late_n = next(str(i) for i, c in enumerate(ranked, 1) if "zzlatefact" in c["text"])
        _check("big case → full-sweep mode", res["coverage"]["mode"] == "full-sweep")
        _check("not capped at high cap", res["coverage"]["capped"] is False)
        _check("swept every passage", res["coverage"]["passages_swept"] == total)
        _check("the late low-keyword passage WAS read (no relevance-prefix miss)",
               late_n in seen)
        _check("no bare pct field surfaced", "pct" not in res["coverage"])


def test_capped_is_disclosed(mp):
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "t.db"
        _seed(dbp, [f"chunk number {i} text text text" for i in range(10)])
        mp.setattr(ask, "CHAR_BUDGET", 60)   # tiny → 1 passage per batch
        mp.setattr(ask, "BATCH_CAP", 3)      # only 3 batches allowed
        _mock_llm(mp)
        with db.connect(dbp) as conn:
            res = ask.answer(conn, "cx", "chunk")
        cov = res["coverage"]
        _check("capped flag set when batches exceed BATCH_CAP", cov["capped"] is True)
        _check("swept fewer than total (disclosed, not silent)",
               cov["passages_swept"] < cov["passages_total"])


def main():
    for fn in (test_small_case_single_shot, test_big_case_sweeps_everything_incl_late,
               test_capped_is_disclosed):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_ask_full_sweep")


if __name__ == "__main__":
    main()
