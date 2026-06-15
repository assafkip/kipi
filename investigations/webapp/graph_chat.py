"""Graph chat agent — natural-language control of the graph.

Design: the LLM ONLY parses the message into a structured {intent, args} command
(it's good at intent, bad at being trusted with raw DB writes). The backend then
executes the command DETERMINISTICALLY — fetching detail/connections, adding a node
or edge, or SOFT-HIDING a node (reversible; the row + data stay). So a wrong "remove"
is always undoable and the analyst stays the authority.

Returns {reply, deltas} where deltas are applied to the cytoscape canvas client-side.
"""
from __future__ import annotations

from investigations.llm import client as llm
from investigations.enrich.rel_vocab import normalize_rel

INTENTS = ("detail", "connections", "find", "add_node", "add_edge",
           "hide", "unhide", "investigate", "new_case", "help")

_SYSTEM = (
    "You translate an analyst's message about an investigation GRAPH into ONE JSON "
    "command. You do NOT answer in prose — you only classify intent + extract args.\n"
    "Intents:\n"
    "- detail: facts about one node. args: {target}\n"
    "- connections: what a node links to. args: {target}\n"
    "- find: search for nodes. args: {query}\n"
    "- add_node: add a node, optionally linked. args: {name, node_type, link_to?, rel_type?}\n"
    "- add_edge: connect two existing nodes. args: {src, dst, rel_type}\n"
    "- hide: remove a node from the graph (reversible). args: {target}\n"
    "- unhide: restore a hidden node. args: {target}\n"
    "- investigate: RUN THE INVESTIGATOR AGENT to collect new intel on a target — "
    "the agent does OSINT, pivots, lands findings, grows the graph. Use this for "
    "'investigate X', 'dig into X', 'run the investigator on X', 'look into X', "
    "'investigate the whole case'/'run the investigation' (no target = whole case). "
    "args: {target?, deep?}. Set deep=true ONLY if the user says 'deep', 'fully', "
    "'exhaustive', 'go deep', or 'loop until dry'; otherwise deep=false.\n"
    "- new_case: START A BRAND-NEW investigation/case (not work inside the current one). "
    "Use for 'new case on X', 'start a new investigation into X', 'open a case about X', "
    "'create a case for X'. args: {name, target?, deep?}. name = a short case label "
    "(the subject); target = the primary thing to investigate if one is named (a domain, "
    "handle, wallet, org). deep as above.\n"
    "- help: anything else / unclear. args: {}\n"
    "target/src/dst/name/link_to are entity NAMES (or the selected node if the user "
    "says 'this'/'it'/'selected'). Output exactly: {\"intent\":\"...\",\"args\":{...}}"
)


def interpret(message: str, selected_name: str | None) -> dict:
    sel = f"\nThe currently selected node is: {selected_name}" if selected_name else ""
    try:
        # CLASSIFY_MODEL (Haiku): parsing a message into an intent is classification (PRD-02).
        out = llm.ask_json(f"Message: {message}{sel}", system=_SYSTEM, timeout=60,
                           model=llm.CLASSIFY_MODEL)
    except Exception:
        return {"intent": "help", "args": {}}
    intent = str(out.get("intent") or "help").strip()
    if intent not in INTENTS:
        intent = "help"
    args = out.get("args")
    return {"intent": intent, "args": args if isinstance(args, dict) else {}}


def _interpret(name, etype, role, contexts, co_names, typed_lines) -> str:
    """LLM reads ONLY the gathered evidence and says what this entity likely is /
    means — a grounded hypothesis, not invention. Returns '' if the LLM is unavailable."""
    ev = []
    if contexts:
        ev.append("Source text where it appears:\n" + "\n".join(f'- "{c}"' for c in contexts))
    if co_names:
        ev.append("Appears in the same report(s) as: " + ", ".join(co_names))
    if typed_lines:
        ev.append("Confirmed relationships: " + "; ".join(typed_lines))
    if not ev:
        return ""
    prompt = (
        f"Entity: {name} (type={etype}, role={role}).\n\n" + "\n\n".join(ev) +
        "\n\nIn 2-3 sentences, say what this entity most likely IS and what it MEANS "
        "in this investigation, based ONLY on the evidence above. Be concrete. If the "
        "evidence is thin, say what's unclear. This is a hypothesis — hedge with 'likely'/"
        "'appears'. No preamble.")
    try:
        return llm.ask(prompt, timeout=60).strip()
    except Exception:
        return ""


def _resolve(conn, name: str | None, case: str | None):
    """Resolve an entity name to (id, canonical_name), SCOPED to the active case so the
    chat can never read/mutate another case's entity (entities are a global pool;
    cases attach via mentions→reports). Exact match first, then a LIKE fallback so
    'dog whistle' finds '@Dog Whistle'. Returns (None, None) if no in-case match."""
    if not name:
        return None, None
    name = str(name).strip()
    scope = ("AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
             "ON r.id = m.report_id WHERE r.investigation = ?) ") if case else ""
    p = (case,) if case else ()
    row = conn.execute(
        f"SELECT e.id, e.canonical_name FROM entities e WHERE e.canonical_name = ? {scope}",
        (name, *p)).fetchone()
    if row:
        return row["id"], row["canonical_name"]
    row = conn.execute(
        f"SELECT e.id, e.canonical_name FROM entities e WHERE e.canonical_name LIKE ? {scope}"
        "ORDER BY LENGTH(e.canonical_name) LIMIT 1", (f"%{name}%", *p)).fetchone()
    return (row["id"], row["canonical_name"]) if row else (None, None)


def _node_delta(conn, eid: int) -> dict:
    """A cytoscape node payload for a freshly-added/unhidden entity."""
    e = conn.execute(
        "SELECT e.canonical_name, e.entity_type, e.case_type, rp.source_type AS osrc "
        "FROM entities e LEFT JOIN reports rp ON rp.id = e.first_seen_report_id "
        "WHERE e.id = ?", (eid,)).fetchone()
    if not e:
        return {}
    origin = ("osint" if e["osrc"] == "enrichment" else "manual" if e["osrc"] == "manual"
              else "intake")
    return {"data": {
        "id": str(eid), "label": e["canonical_name"][:40], "full_name": e["canonical_name"],
        "type": e["case_type"] or e["entity_type"], "role": "", "score": 12,
        "degree": 0, "report_count": 1, "cluster_ids": [], "is_bridge": False,
        "origin": origin,
    }}


def _store_actor(actor: str) -> str:
    """graph_chat's two actor words mapped to the store vocabulary: the human
    router is the analyst (top authority — store skips the value gate); the
    warm session's graph tools are the agent (gated like every creation path)."""
    return "analyst:graph-chat" if actor == "analyst" else "agent"


def execute(conn, intent: str, args: dict, case: str | None,
            selected_name: str | None, actor: str = "analyst") -> dict:
    """Run the parsed command. Returns {reply, deltas}.

    `actor` is WHO is acting: "analyst" (the human chat router — top authority, their
    adds are never gated and land with analyst provenance) or "agent" (the warm
    session's kipi-graph MCP tools — a graph-CREATION path, so add_node must clear
    the same admission gate as every other path, and writes provenance 'osint',
    never 'analyst')."""
    from investigations.enrich.promote import _classify, _enrichment_report
    from investigations.storage import db
    from investigations import store
    prov = "analyst" if actor == "analyst" else "osint"

    def tgt(key="target"):
        v = args.get(key)
        if v and str(v).lower() in ("this", "it", "selected", "the selected node"):
            return selected_name
        return v

    if intent == "detail":
        eid, name = _resolve(conn, tgt(), case)
        if not eid:
            return {"reply": f"I couldn't find '{tgt()}' in this case.", "deltas": {}}
        e = conn.execute("SELECT entity_type, case_type, notes FROM entities WHERE id=?",
                         (eid,)).fetchone()
        role = (e["notes"] or "").split(" — ")[0].replace("role:", "").strip() or "—"
        etype = e["case_type"] or e["entity_type"]
        # WHERE IT CAME FROM — the source report + the screenshot/OCR context (scoped).
        sc_sql, sc_p = (("AND r.investigation = ? ", (case,)) if case else ("", ()))
        ctx_rows = conn.execute(
            "SELECT r.title, r.source_type, m.context FROM mentions m "
            "JOIN reports r ON r.id = m.report_id WHERE m.entity_id = ? "
            "AND m.context IS NOT NULL AND TRIM(m.context) != '' " + sc_sql +
            "ORDER BY m.id LIMIT 3", (eid, *sc_p)).fetchall()
        contexts = [" ".join((r["context"] or "").split())[:280] for r in ctx_rows]
        src_report = ctx_rows[0]["title"] if ctx_rows else None
        src_kind = ctx_rows[0]["source_type"] if ctx_rows else None
        # APPEARS WITH — co-occurrence neighbors (names).
        co_names = []
        for r in conn.execute(
            "SELECT DISTINCT CASE WHEN src_entity_id=? THEN dst_entity_id ELSE src_entity_id END oid "
            "FROM relationships WHERE rel_type='co_mentioned' AND (src_entity_id=? OR dst_entity_id=?) LIMIT 8",
            (eid, eid, eid)).fetchall():
            o = conn.execute("SELECT canonical_name FROM entities WHERE id=? "
                             "AND (hidden IS NULL OR hidden=0)", (r["oid"],)).fetchone()
            if o:
                co_names.append(o["canonical_name"])
        # CONFIRMED relationships (typed).
        typed_lines = []
        for r in conn.execute(
            "SELECT tr.rel_type, CASE WHEN tr.src_entity_id=? THEN tr.dst_entity_id ELSE tr.src_entity_id END oid "
            "FROM typed_relationships tr WHERE (tr.src_entity_id=? OR tr.dst_entity_id=?) AND tr.status='active' LIMIT 10",
            (eid, eid, eid)).fetchall():
            o = conn.execute("SELECT canonical_name FROM entities WHERE id=? "
                             "AND (hidden IS NULL OR hidden=0)", (r["oid"],)).fetchone()
            if o:
                typed_lines.append(f"{r['rel_type']} {o['canonical_name']}")
        interp = _interpret(name, etype, role, contexts, co_names, typed_lines)
        # Build a useful reply: what / where-from (quoted) / appears-with / what-we-think.
        parts = [f"{name} — {etype}" + (f", role {role}" if role != "—" else "") + "."]
        if src_report:
            parts.append(f'Where it came from: {src_report} ({src_kind}).')
            if contexts:
                parts.append(f'Source text: "{contexts[0]}"')
        if co_names:
            shown = ", ".join(co_names[:5]) + (f" +{len(co_names)-5} more" if len(co_names) > 5 else "")
            parts.append(f"Appears with: {shown}.")
        if typed_lines:
            parts.append("Confirmed links: " + "; ".join(typed_lines[:5]) + ".")
        if interp:
            parts.append(f"What we think: {interp}")
        elif not src_report and not co_names:
            parts.append("No source context recorded for it yet.")
        return {"reply": "\n\n".join(parts), "deltas": {"focus_id": str(eid)}}

    if intent == "connections":
        eid, name = _resolve(conn, tgt(), case)
        if not eid:
            return {"reply": f"I couldn't find '{tgt()}'.", "deltas": {}}
        rows = conn.execute(
            "SELECT tr.rel_type, "
            "  CASE WHEN tr.src_entity_id=? THEN 'out' ELSE 'in' END AS dir, "
            "  CASE WHEN tr.src_entity_id=? THEN tr.dst_entity_id ELSE tr.src_entity_id END AS oid "
            "FROM typed_relationships tr WHERE (tr.src_entity_id=? OR tr.dst_entity_id=?) "
            "AND tr.status='active' LIMIT 30", (eid, eid, eid, eid)).fetchall()
        if not rows:
            return {"reply": f"{name} has no typed connections yet. Investigate it to build some.",
                    "deltas": {"focus_id": str(eid)}}
        lines = []
        for r in rows:
            o = conn.execute("SELECT canonical_name FROM entities WHERE id=? "
                             "AND (hidden IS NULL OR hidden=0)", (r["oid"],)).fetchone()
            if not o:
                continue  # skip hidden neighbors
            arrow = "→" if r["dir"] == "out" else "←"
            lines.append(f"{arrow} {r['rel_type']} {o['canonical_name']}")
        if not lines:
            return {"reply": f"{name}'s connections are all hidden or pending.",
                    "deltas": {"focus_id": str(eid)}}
        return {"reply": f"{name} connects to:\n" + "\n".join(lines),
                "deltas": {"focus_id": str(eid)}}

    if intent == "find":
        q = (args.get("query") or "").strip()
        fscope = ("AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
                  "ON r.id = m.report_id WHERE r.investigation = ?) ") if case else ""
        fp = (case,) if case else ()
        rows = conn.execute(
            "SELECT e.id, e.canonical_name FROM entities e WHERE e.canonical_name LIKE ? "
            "AND (e.hidden IS NULL OR e.hidden=0) " + fscope +
            "ORDER BY LENGTH(e.canonical_name) LIMIT 12",
            (f"%{q}%", *fp)).fetchall()
        if not rows:
            return {"reply": f"No nodes matching '{q}'.", "deltas": {}}
        names = [r["canonical_name"] for r in rows]
        return {"reply": f"Found {len(names)}: " + ", ".join(n[:30] for n in names),
                "deltas": {"highlight_ids": [str(r["id"]) for r in rows]}}

    if intent == "add_node":
        from investigations.agent.investigator import _looks_like_entity
        name = str(args.get("name") or "").strip()
        if not name:
            return {"reply": "What should I name the node?", "deltas": {}}
        if not _looks_like_entity(name):
            return {"reply": f"'{name[:60]}' doesn't look like an entity (too long or "
                             "sentence-like). Give me a name, handle, domain, IP, or wallet.",
                    "deltas": {}}
        if not case:
            return {"reply": "Pick a single case first, then I'll add the node to it.",
                    "deltas": {}}
        rep = _enrichment_report(conn, case)
        etype = (args.get("node_type") or _classify(name) or "other")
        # The store carries the admission gate: the agent's graph_add_node is a
        # creation path (gated, RCA rca-recurring-graph-noise); the ANALYST's own
        # add is never gated — analyst is top authority (store actor policy).
        res = store.apply_mutation(conn, store.entity_upserted(
            case, name, etype, rep, actor=_store_actor(actor), provenance=prov))
        if not res["applied"]:
            return {"reply": f"Not adding '{name[:60]}': {res['reason']}", "deltas": {}}
        eid = res["entity_id"]
        db.add_mention(conn, eid, rep, name, "added via graph chat")
        delta = {"add_nodes": [_node_delta(conn, eid)], "add_edges": []}
        link = tgt("link_to")
        if link:
            lid, lname = _resolve(conn, link, case)
            if lid:
                # Controlled vocabulary binds the analyst-driven edge too (issue rel-vocab-validator).
                rel = normalize_rel(args.get("rel_type"), "graph chat") or "linked_to"
                db.add_relationship(conn, lid, eid, rel, rep, "added via graph chat", 0.6)
                store.apply_mutation(conn, store.edge_upserted(
                    case, lid, eid, rel, actor=_store_actor(actor),
                    evidence="graph chat", provenance=prov))
                delta["add_edges"].append({"data": {
                    "id": f"e{lid}-{eid}-{rel}", "source": str(lid), "target": str(eid),
                    "rel_type": rel, "confidence": "medium"}})
        conn.commit()
        return {"reply": f"Added '{name}'" + (f" linked to {link}." if link else "."),
                "deltas": delta}

    if intent == "add_edge":
        sid, sname = _resolve(conn, tgt("src"), case)
        did, dname = _resolve(conn, tgt("dst"), case)
        if not sid or not did:
            return {"reply": "I need two existing nodes to connect.", "deltas": {}}
        rel = normalize_rel(args.get("rel_type"), "graph chat") or "linked_to"
        rep = _enrichment_report(conn, case)
        db.add_relationship(conn, sid, did, rel, rep, "added via graph chat", 0.6)
        store.apply_mutation(conn, store.edge_upserted(
            case, sid, did, rel, actor=_store_actor(actor),
            evidence="graph chat", provenance=prov))
        conn.commit()
        return {"reply": f"Connected {sname} → {rel} → {dname}.",
                "deltas": {"add_edges": [{"data": {
                    "id": f"e{sid}-{did}-{rel}", "source": str(sid), "target": str(did),
                    "rel_type": rel, "confidence": "medium"}}]}}

    if intent == "hide":
        eid, name = _resolve(conn, tgt(), case)
        if not eid:
            return {"reply": f"I couldn't find '{tgt()}' to hide.", "deltas": {}}
        res = store.apply_mutation(conn, store.entity_hidden(
            case, eid, actor=_store_actor(actor)))
        if not res["applied"]:
            return {"reply": f"Couldn't hide {name}: {res['reason']}", "deltas": {}}
        conn.commit()
        return {"reply": f"Hid {name}. It's reversible — say 'unhide {name}' or click Undo.",
                "deltas": {"hide_ids": [str(eid)], "undo": {"op": "unhide", "id": eid, "name": name}}}

    if intent == "unhide":
        eid, name = _resolve(conn, tgt(), case)
        if not eid:
            return {"reply": f"I couldn't find '{tgt()}'.", "deltas": {}}
        res = store.apply_mutation(conn, store.entity_unhidden(
            case, eid, actor=_store_actor(actor)))
        if not res["applied"]:
            return {"reply": f"Couldn't restore {name}: {res['reason']}", "deltas": {}}
        conn.commit()
        return {"reply": f"Restored {name}.", "deltas": {"add_nodes": [_node_delta(conn, eid)],
                                                          "focus_id": str(eid)}}

    if intent == "investigate":
        # The analyst tells the investigator to RUN. We don't start the job here — we
        # return an `action` and the frontend POSTs /api/investigate, reusing the whole
        # existing run UI (progress panel + live steps + Stop). Bounded by default;
        # `deep` opt-in (RULE-112: analyst-driven default, recursion opt-in).
        deep = bool(args.get("deep"))
        target = tgt()
        article = "a deep" if deep else "an"
        if not target:
            # No named target -> whole-case run (needs a single active case).
            if not case:
                return {"reply": "Pick a single case first, then I'll run the investigator "
                                 "across it.", "deltas": {}}
            return {"reply": f"Starting {article} investigation across the whole case. The "
                             "investigator is collecting now — watch the run panel for live "
                             "steps, and Stop anytime.",
                    "deltas": {},
                    "action": {"type": "investigate", "scope": "case", "deep": deep}}
        # Named target: resolve to a canonical node when it exists; otherwise investigate
        # the raw string (a brand-new target is valid OSINT — the agent runs unscoped).
        eid, name = _resolve(conn, target, case)
        label = name or str(target).strip()
        return {"reply": f"Starting {article} investigation on {label}. The investigator is "
                         "collecting now — watch the run panel for live steps, and Stop anytime.",
                "deltas": {"focus_id": str(eid)} if eid else {},
                "action": {"type": "investigate", "entity": label, "deep": deep}}

    if intent == "new_case":
        # Spinning up a NEW case can't happen here (execute has no cookie/session) — we
        # return an `action` and the /api/chat route materializes it: creates the case,
        # switches to it, and fires the investigator when a target is named. This branch
        # is the fallback safety net; the route also intercepts new-case phrasings up
        # front so the warm path is covered too.
        name = (args.get("name") or args.get("target") or "").strip()
        if not name:
            return {"reply": "Name the new case — e.g. 'new case on the trumpfundus scam'.",
                    "deltas": {}}
        target = (args.get("target") or "").strip() or None
        return {"reply": f"Starting a new case for {name}.", "deltas": {},
                "action": {"type": "new_case", "name": name, "target": target,
                           "deep": bool(args.get("deep"))}}

    return {"reply": ("I can: give detail about a node, show its connections, find nodes, "
                      "add a node or edge, hide/unhide a node, and INVESTIGATE a target "
                      "(run the agent). Try 'investigate trumpfundus.com', 'dig into that "
                      "wallet', or 'run the investigation'."), "deltas": {}}
