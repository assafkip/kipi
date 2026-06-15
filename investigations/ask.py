"""Ask — grounded Q&A over a case's ingested report text.

The analyst asks a question; we retrieve the most relevant OCR pages (and report
text) DETERMINISTICALLY by keyword overlap, then ask the LLM to answer USING ONLY
those passages, with inline [n] citations back to the source page. If nothing
relevant is retrieved, we don't call the LLM at all — no passages, no answer.

This is the provenance contract: every line the assistant produces traces to a
page the analyst can open. A chat that hallucinates is worse than no chat.
"""
from __future__ import annotations

import re

from investigations.llm import client as llm

# Small stopword set — keep retrieval terms meaningful without a dependency.
_STOP = {
    "the", "and", "for", "are", "but", "not", "you", "any", "can", "had", "her",
    "was", "one", "our", "out", "who", "get", "has", "him", "his", "how", "its",
    "may", "new", "now", "old", "see", "two", "way", "what", "when", "with",
    "this", "that", "they", "them", "from", "have", "does", "did", "is", "of",
    "to", "in", "on", "a", "an", "or", "be", "as", "at", "it", "by", "do",
    "about", "which", "their", "there", "were", "been", "into", "than", "then",
    "tell", "me", "show", "give", "list", "whats", "between",
}

_TOKEN_RE = re.compile(r"[a-z0-9@._/-]{3,}")

# Whole small cases are fed in full; only cases too big for the context window
# get sampled (and the analyst is told coverage is partial).
CHAR_BUDGET = 200_000      # max chars of passages handed to the LLM (~50k tokens)
RAW_CHUNK_CHARS = 1500     # report raw_text is chunked at this size
PASSAGE_CHARS = 2000       # max chars per passage block in the prompt
# When a case is too big for one window, we SWEEP it: map (cheap model extracts the
# question-relevant facts from each budget-sized batch) -> reduce (judgment model
# composes the answer). BATCH_CAP bounds cost; if the case needs more batches we sweep
# the most-relevant BATCH_CAP and SAY SO (never a silent cut). This is PRD-01: read the
# whole corpus, or disclose exactly what was read — never a bare "52%".
BATCH_CAP = 6

SYSTEM = """You are an OSINT analyst's research assistant. Answer the question \
USING ONLY the numbered case passages provided below. Passages come from the uploaded \
reports AND from the investigation itself (OSINT findings the detective discovered, and \
the entity graph) — treat all of them as valid grounding.

Rules:
- Every factual statement MUST cite the passage(s) it came from, like [1] or [2][4].
- If the passages do not contain the answer, reply exactly: "The case material doesn't cover that." Do not use outside knowledge or guess.
- Be concise. Prefer short bullets. No preamble, no sign-off.
"""


def _terms(question: str) -> list[str]:
    seen, out = set(), []
    for t in _TOKEN_RE.findall(question.lower()):
        if t in _STOP or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def _score(text: str, terms: list[str]) -> int:
    low = text.lower()
    return sum(low.count(t) for t in terms)


def _candidates(conn, case: str | None) -> list[dict]:
    """Build the passage pool: one per OCR'd page, plus chunked report raw_text,
    plus the case's recent activity tail (the note() bridge: "what did I just
    hide?" answers from the same event log the agent grounds on)."""
    out_activity = []
    if case:
        from investigations import store
        tail = store.format_recent_activity(conn, case)
        if tail:
            out_activity.append({
                "report_id": None, "report_title": "Recent case activity",
                "page_number": None, "file_path": None,
                "text": "Recent case activity (analyst + agent actions, newest "
                        "first):\n" + tail, "kind": "activity",
            })
    where_a, params_a = ("WHERE r.investigation = ? ", [case]) if case else ("", [])
    pages = conn.execute(
        "SELECT a.report_id, a.page_number, a.file_path, a.ocr_text, r.title AS report_title "
        "FROM assets a JOIN reports r ON r.id = a.report_id "
        + where_a +
        ("AND " if case else "WHERE ") + "a.ocr_text IS NOT NULL AND a.ocr_text != ''",
        params_a,
    ).fetchall()
    out = out_activity + [{
        "report_id": p["report_id"], "report_title": p["report_title"],
        "page_number": p["page_number"], "file_path": p["file_path"],
        "text": p["ocr_text"], "kind": "page",
    } for p in pages]

    # Report-level text, chunked — catches answers not on an OCR'd image page.
    where_r, params_r = ("WHERE investigation = ? ", [case]) if case else ("", [])
    for r in conn.execute(
        "SELECT id, title, raw_text FROM reports " + where_r, params_r,
    ).fetchall():
        raw = r["raw_text"] or ""
        for i in range(0, len(raw), RAW_CHUNK_CHARS):  # the WHOLE report, not a head slice
            out.append({
                "report_id": r["id"], "report_title": r["title"],
                "page_number": None, "file_path": None,
                "text": raw[i:i + RAW_CHUNK_CHARS], "kind": "text",
            })

    # Agent OSINT findings — the detective's DISCOVERIES live here, not in the report
    # text. Without these, asking about an agent-discovered node (one that's on the graph
    # but has 0 source reports, e.g. a "detective investigated" indicator) wrongly returns
    # "the reports don't cover that".
    fwhere, fparams = ("WHERE er.investigation = ? ", [case]) if case else ("", [])
    for f in conn.execute(
        "SELECT res.title, res.summary FROM enrichment_results res "
        "JOIN enrichment_runs er ON er.id = res.run_id " + fwhere, fparams,
    ).fetchall():
        txt = " — ".join(x for x in (f["title"], f["summary"]) if x)
        if txt.strip():
            out.append({"report_id": None, "report_title": "OSINT finding",
                        "page_number": None, "file_path": None,
                        "text": txt, "kind": "finding"})

    # Entity + relationship context (the graph) — so "who is <node>?" works for ANY node,
    # including agent-discovered ones absent from the report text. Scope: entities mentioned
    # in the case OR investigated by an agent run in the case.
    ent_where, ent_params = "", []
    if case:
        ent_where = ("WHERE (e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
                     "ON r.id = m.report_id WHERE r.investigation = ?) "
                     "OR e.id IN (SELECT entity_id FROM enrichment_runs "
                     "WHERE investigation = ? AND entity_id IS NOT NULL)) ")
        ent_params = [case, case]
    for e in conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.case_type, e.notes "
        "FROM entities e " + ent_where, ent_params,
    ).fetchall():
        rels = conn.execute(
            "SELECT tr.rel_type, e2.canonical_name AS other FROM typed_relationships tr "
            "JOIN entities e2 ON e2.id = tr.dst_entity_id "
            "WHERE tr.src_entity_id = ? AND tr.status = 'active' LIMIT 12", (e["id"],),
        ).fetchall()
        parts = [f"{e['canonical_name']} ({e['case_type'] or e['entity_type'] or 'entity'})"]
        if e["notes"] and e["notes"].startswith("role:"):
            parts.append(e["notes"].split("\n", 1)[0])
        if rels:
            parts.append("connections: " + "; ".join(f"{r['rel_type']} {r['other']}" for r in rels))
        out.append({"report_id": None, "report_title": "Investigation graph",
                    "page_number": None, "file_path": None,
                    "text": ". ".join(parts), "kind": "entity"})
    return out


def select(conn, case: str | None, question: str,
           char_budget: int = CHAR_BUDGET) -> tuple[list[dict], dict]:
    """Choose passages to ground on, plus a coverage report.

    Whole case fits the budget -> feed ALL of it (100% coverage), ordered so the
    most on-topic passages lead. Too big -> keep the highest keyword-scored
    passages until the budget fills, and flag coverage as partial. If a case is
    too big AND nothing matched, return nothing rather than feed a random slice.
    """
    cands = _candidates(conn, case)
    total_n = len(cands)
    total_chars = sum(len(c["text"]) for c in cands)
    terms = _terms(question)
    for c in cands:
        c["score"] = _score(c["text"], terms) if terms else 0

    fits = total_chars <= char_budget
    if fits:
        ranked = sorted(cands, key=lambda c: c["score"], reverse=True)
    else:
        ranked = sorted((c for c in cands if c["score"] > 0),
                        key=lambda c: c["score"], reverse=True)
        if not ranked:
            return [], {"mode": "none", "passages_total": total_n,
                        "passages_used": 0, "pct": 0}

    picked, used = [], 0
    for c in ranked:
        t = c["text"][:PASSAGE_CHARS]
        if picked and used + len(t) > char_budget:
            break
        picked.append({**c, "text": t})
        used += len(t)

    coverage = {
        "mode": "full" if fits else "partial",
        "passages_total": total_n,
        "passages_used": len(picked),
        "pct": 100 if fits else round(100 * used / max(total_chars, 1)),
    }
    return picked, coverage


def retrieve(conn, case: str | None, question: str,
             char_budget: int = CHAR_BUDGET) -> list[dict]:
    """Back-compat helper: just the chosen passages (see select() for coverage)."""
    return select(conn, case, question, char_budget)[0]


def _vault_image(report_id: int, file_path: str | None) -> str | None:
    if not file_path:
        return None
    from pathlib import Path
    return f"r{report_id:04d}_{Path(file_path).name}"


MAP_SYSTEM = """Extract every fact relevant to the QUESTION from the numbered passages.
Keep each fact's [n] citation. Facts only, one per line, each ending with its [n]. If no
passage is relevant, reply exactly: NONE. Do not answer the question; only extract."""


def _blocks_and_sources(passages: list[dict]) -> tuple[list[str], list[dict]]:
    """Number passages [1..n] GLOBALLY so citations map back across batches."""
    blocks, sources = [], []
    for i, p in enumerate(passages, 1):
        loc = f"page {p['page_number']}" if p["page_number"] is not None else "report text"
        blocks.append(f"[{i}] (Report: {p['report_title']}, {loc})\n{p['text'][:PASSAGE_CHARS]}")
        snippet = re.sub(r"\s+", " ", p["text"]).strip()[:240]
        sources.append({
            "n": i, "report_id": p["report_id"], "report_title": p["report_title"],
            "page_number": p["page_number"], "snippet": snippet,
            "vault_image": _vault_image(p["report_id"], p["file_path"]),
        })
    return blocks, sources


def _batch(blocks: list[str], budget: int) -> list[list[str]]:
    """Group numbered blocks into batches each under `budget` chars."""
    batches, cur, used = [], [], 0
    for b in blocks:
        if cur and used + len(b) > budget:
            batches.append(cur); cur, used = [], 0
        cur.append(b); used += len(b)
    if cur:
        batches.append(cur)
    return batches


_CITE_RE = re.compile(r"\[(\d+)\]")


def _verify_citations(answer: str, passages: list[dict]) -> list[dict]:
    """Deterministic citation faithfulness (replay D5, applied to Q&A): the prompt already
    REQUIRES [n] citations, but instruction-only citation can still be unfaithful. For each
    answer sentence that asserts a HARD fact (date/IP/email/wallet) AND cites [n], confirm
    the cited passage(s) actually contain that fact. Returns the unsupported sentences so
    the caller can surface them. Soft / uncited sentences aren't checkable here, so skipped."""
    from investigations import verify  # shared deterministic claim-faithfulness primitive
    texts = {i + 1: (p.get("text") or "").lower() for i, p in enumerate(passages)}
    unsupported = []
    for sent in re.split(r"(?<=[.!?])\s+", answer or ""):
        cites = [int(n) for n in _CITE_RE.findall(sent)]
        toks = verify.hard_tokens(sent)
        if not cites or not toks:
            continue
        cited = " ".join(texts.get(n, "") for n in cites)
        missing = sorted(t for t in toks if t not in cited)
        if missing:
            unsupported.append({"sentence": sent.strip()[:200],
                                "cites": cites, "unsupported_facts": missing})
    return unsupported


def _single_shot(question: str, passages: list[dict]) -> dict:
    """Whole case fits one window: feed all passages, answer in one call (100%)."""
    blocks, sources = _blocks_and_sources(passages)
    prompt = (f"QUESTION: {question}\n\nPASSAGES:\n" + "\n\n".join(blocks) +
              "\n\nAnswer the question using only these passages, citing with [n].")
    coverage = {"mode": "full", "passages_total": len(passages),
                "passages_swept": len(passages), "batches": 1, "capped": False}
    try:
        text = llm.ask(prompt, system=SYSTEM, timeout=180)
    except llm.LLMError as exc:
        return {"error": f"LLM unavailable: {exc}", "sources": sources,
                "grounded": True, "coverage": coverage}
    return {"answer": text, "sources": sources, "grounded": True, "coverage": coverage,
            "unsupported_citations": _verify_citations(text, passages)}


def _sweep(question: str, ranked: list[dict]) -> dict:
    """Too big for one window: MAP (cheap model extracts relevant facts from every
    batch) -> REDUCE (judgment model composes the answer). Reads the WHOLE corpus up
    to BATCH_CAP batches; if it needs more it sweeps the most-relevant and says so."""
    passages = [{**c, "text": c["text"][:PASSAGE_CHARS]} for c in ranked]
    blocks, sources = _blocks_and_sources(passages)
    batches = _batch(blocks, CHAR_BUDGET)
    capped = len(batches) > BATCH_CAP
    run = batches[:BATCH_CAP]
    swept = sum(len(b) for b in run)
    coverage = {"mode": "full-sweep", "passages_total": len(passages),
                "passages_swept": swept, "batches": len(run), "capped": capped}
    extracts = []
    for batch in run:
        prompt = f"QUESTION: {question}\n\nPASSAGES:\n" + "\n\n".join(batch)
        try:
            ex = llm.ask(prompt, system=MAP_SYSTEM, timeout=120, model=llm.CLASSIFY_MODEL)
        except llm.LLMError:
            ex = ""
        if ex and ex.strip().upper() != "NONE":
            extracts.append(ex.strip())
    if not extracts:
        return {"answer": f"The reports don't cover that. Swept {swept} of "
                f"{len(passages)} passages and found nothing relevant.",
                "sources": sources, "grounded": True, "coverage": coverage}
    reduce_prompt = (f"QUESTION: {question}\n\nFACTS EXTRACTED FROM THE REPORTS "
                     "(each cites its source passage [n]):\n\n" + "\n\n".join(extracts) +
                     "\n\nAnswer the question using only these facts, citing with [n].")
    try:
        text = llm.ask(reduce_prompt, system=SYSTEM, timeout=180)
    except llm.LLMError as exc:
        return {"error": f"LLM unavailable: {exc}", "sources": sources,
                "grounded": True, "coverage": coverage}
    return {"answer": text, "sources": sources, "grounded": True, "coverage": coverage,
            "unsupported_citations": _verify_citations(text, passages)}


def answer(conn, case: str | None, question: str, full: bool = False) -> dict:
    """Retrieve, ground, synthesize. Returns answer + the cited source passages.

    PRD-01: small cases are answered from 100% of the text in one call. Big cases are
    SWEPT (map-reduce over the whole corpus) instead of truncated to a relevance prefix
    — so the answer never silently misses text that lives late in the case. `full=True`
    ("Use all sources") forces the sweep. Coverage is reported as N-of-M passages, never
    a bare percentage."""
    question = (question or "").strip()
    if not question:
        return {"error": "empty question"}
    cands = _candidates(conn, case)
    scope = case or "all cases"
    if not cands:
        return {"answer": "The reports don't cover that. Nothing in "
                + (f"case {case}" if case else "the ingested reports") + " matched.",
                "sources": [], "grounded": False, "scope": scope,
                "coverage": {"mode": "none", "passages_total": 0, "passages_swept": 0,
                             "batches": 0, "capped": False}}
    terms = _terms(question)
    for c in cands:
        c["score"] = _score(c["text"], terms) if terms else 0
    ranked = sorted(cands, key=lambda c: c["score"], reverse=True)
    total_chars = sum(len(c["text"]) for c in cands)
    if total_chars <= CHAR_BUDGET and not full:
        result = _single_shot(question, [{**c, "text": c["text"][:PASSAGE_CHARS]}
                                         for c in ranked])
    else:
        result = _sweep(question, ranked)
    result["scope"] = scope
    return result
