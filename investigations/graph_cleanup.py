"""Graph cleanup: bridge same-campaign clusters + declutter prose-content nodes.

Two deterministic passes run after an investigation:

- normalize_campaigns: differently-WORDED campaign/theme nodes ("trump-impersonation
  crypto-doubling campaign" vs "Trump/Musk/Truth Social crypto-doubler cluster") are the
  same concept. Merging them into one node BRIDGES two infrastructure tiers that share no
  registrar/host/wallet but run the identical scam — so the graph shows one campaign with
  two tiers instead of two disconnected islands.

- prune_content_edges: the agent promotes page-content PHRASES as nodes via `deploys`
  edges ("BIGGEST CRYPTO", "doubled returns promise"). Those are evidence text, not graph
  entities. Dropping the content edges declutters the graph (the phrase nodes fall out of
  the connected view) without deleting any real entity or its mentions.

Both reuse the proven merge primitive in consolidate (re-points mentions / relationships /
typed_relationships / FKs). Case-scoped, so nothing leaks across investigations.
"""
from __future__ import annotations

import re

from investigations import consolidate

# A campaign/theme label (not infra, not a real indicator) — the bridge candidates.
CAMPAIGN_RE = re.compile(r"campaign|cluster|scheme|operation|doubl|giveaway|impersonat|scam",
                         re.I)
# A NODE that is a campaign LABEL (structural words only) — protected from the prose
# prune. Narrower than CAMPAIGN_RE on purpose: 'doubl' would match page-content like
# "doubled returns promise", which IS prose to prune, not a label to keep.
CAMPAIGN_LABEL_RE = re.compile(r"\b(campaign|cluster|scheme|operation|network|ring|syndicate)\b",
                               re.I)
# Generic words that don't distinguish ONE campaign from another — dropped from the
# signature so two differently-worded labels still match on their distinctive tokens.
_STOP = {"the", "a", "an", "of", "and", "for", "with", "crypto", "cryptocurrency", "scam",
         "campaign", "cluster", "scheme", "operation", "social", "inc", "ltd", "llc", "co",
         "fake", "network", "site", "page", "brand", "themed", "pool"}
# Page-content relationships: the endpoint is scam-page text, not an entity.
CONTENT_RELS = {"deploys", "deployed_on", "promoted_via"}


def _case_entities(conn, case: str):
    return conn.execute(
        "SELECT DISTINCT e.id, e.canonical_name AS name FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation = ?", (case,)).fetchall()


def _case_graph_entities(conn, case: str) -> dict:
    """The case's graph NEIGHBORHOOD: every case-mentioned entity PLUS the one-hop edge
    neighbors. A campaign node the agent created can carry its mention on a differently-
    tagged enrichment report, so case-mention scoping alone misses it — but it IS wired
    by an edge to a case domain, so the neighborhood catches it. Keeps the bridge working
    on real data without going global."""
    base = {r["id"]: r["name"] for r in _case_entities(conn, case)}
    if not base:
        return base
    ids = list(base)
    ph = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT src_entity_id AS s, dst_entity_id AS d FROM typed_relationships "
        f"WHERE src_entity_id IN ({ph}) OR dst_entity_id IN ({ph})", ids + ids).fetchall()
    extra = {nid for r in rows for nid in (r["s"], r["d"]) if nid not in base}
    for nid in extra:
        row = conn.execute("SELECT canonical_name FROM entities WHERE id = ?", (nid,)).fetchone()
        if row:
            base[nid] = row["canonical_name"]
    return base


def _signature(name: str) -> set:
    """Distinctive tokens of a campaign label, with doubling/doubler/doubled stemmed to
    'doubl' so phrasings line up."""
    toks = set()
    for t in re.findall(r"[a-z0-9]+", name.lower()):
        if len(t) <= 2 or t in _STOP:
            continue
        toks.add(re.sub(r"doubl\w*", "doubl", t))
    return toks


def normalize_campaigns(conn, case: str | None) -> dict:
    """Merge differently-worded campaign/theme nodes that share >=2 distinctive tokens.
    Re-points every edge, so domains hanging off either label end up on ONE node — which
    is what bridges the clusters. Only touches multi-word, campaign-keyword, non-indicator
    names; real indicators (domains/wallets/handles — no spaces) are never merged."""
    if not case:
        return {"merged": 0, "bridged_groups": 0}
    graph_ents = _case_graph_entities(conn, case)
    cands = [(cid, nm) for cid, nm in graph_ents.items()
             if " " in nm and CAMPAIGN_RE.search(nm)]
    sigs = {cid: _signature(nm) for cid, nm in cands}
    parent = {cid: cid for cid, _ in cands}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    ids = [c for c, _ in cands]
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            if len(sigs[ids[i]] & sigs[ids[j]]) >= 2:   # share >=2 distinctive tokens
                parent[find(ids[i])] = find(ids[j])

    groups: dict = {}
    for cid, _ in cands:
        groups.setdefault(find(cid), []).append(cid)
    name_by = dict(cands)
    merged, bridged = 0, 0
    for members in groups.values():
        if len(members) < 2:
            continue
        canon = max(members, key=lambda c: len(name_by[c]))   # longest = most descriptive
        bridged += 1
        for m in members:
            if m != canon and consolidate._absorb(conn, m, canon):
                merged += 1
    conn.commit()
    return {"merged": merged, "bridged_groups": bridged}


def prune_content_edges(conn, case: str | None) -> dict:
    """Drop `deploys`/`deployed_on`/`promoted_via` edges whose endpoint is a multi-word,
    non-indicator prose phrase (scam-page text). Declutters the graph; entities + mentions
    are untouched (the phrase just stops being a connected graph node)."""
    if not case:
        return {"pruned_edges": 0}
    ents = _case_graph_entities(conn, case)

    def _is_prose(eid):
        nm = ents.get(eid, "")
        return (" " in nm and len(nm.split()) >= 3 and not CAMPAIGN_LABEL_RE.search(nm))

    ph = ",".join("?" * len(CONTENT_RELS))
    rows = conn.execute(
        f"SELECT id, src_entity_id, dst_entity_id FROM typed_relationships "
        f"WHERE rel_type IN ({ph})", tuple(CONTENT_RELS)).fetchall()
    pruned = 0
    for row in rows:
        # The content endpoint is the dst (X deploys 'prose'); prune when it's prose AND
        # in this case's entity set (don't touch other cases).
        dst = row["dst_entity_id"]
        if dst in ents and _is_prose(dst):
            from investigations import store
            store.apply_mutation(conn, store.edges_maintained(
                case, "delete_ids", actor="pipeline:graph_cleanup",
                edge_ids=[row["id"]]))
            pruned += 1
    conn.commit()
    return {"pruned_edges": pruned}


# An EXPLICIT campaign-membership assertion in finding text — narrow on purpose so
# a passing mention of a campaign name never fabricates an edge. Only a stated
# membership relation qualifies.
MEMBERSHIP_RE = re.compile(
    r"\b(member of|members of|part of|affiliate(?:d with| of)?|instance of|"
    r"deployment (?:of|within)|belongs to|node in|operated under|within the|"
    r"confirmed member|in the .{0,40}\b(?:campaign|network|operation|ring))\b",
    re.I)


def _campaign_org_entities(conn, case: str) -> dict[int, str]:
    """Case entities that can be the TARGET of a member_of edge: org/indicator
    nodes that name an actor/campaign, not infra/registrar. The campaign org
    (e.g. 'Gambler Panel') is resolved by matching its name inside a domain's
    membership-asserting finding text, so this just supplies the candidate names."""
    rows = conn.execute(
        "SELECT DISTINCT e.id, e.canonical_name FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation = ? AND e.entity_type IN ('org','indicator') "
        "AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%')", (case,)).fetchall()
    # Drop obvious infra/registrar-ish labels; a campaign org is a named actor.
    out = {}
    for r in rows:
        n = r["canonical_name"]
        if len(n) < 3:
            continue
        if re.search(r"\b(LLC|Inc|Ltd|GmbH|registrar|hosting|nameserver)\b", n, re.I):
            continue
        out[r["id"]] = n
    return out


def _domain_finding_texts(conn, entity_id: int, case: str) -> list[str]:
    """Per-finding text tied to a domain IN THIS CASE — one string per enrichment
    result, scoped through enrichment_runs.investigation so a sibling case's finding
    can't leak in (Codex gtl-4 finding-1). Returned as a LIST, not concatenated, so
    the membership marker AND the campaign name must co-occur in the SAME finding
    (finding-2). entities.notes is deliberately EXCLUDED: it is a global canonical
    field, so a shared domain could inherit marker+org text written for another
    context and fabricate an edge in a case that has no membership finding (Codex
    adversarial). Only case-scoped enrichment findings count as evidence."""
    texts = []
    for r in conn.execute(
        "SELECT er.summary, er.title FROM enrichment_results er "
        "JOIN enrichment_runs run ON run.id = er.run_id "
        "WHERE er.extracted_entity_id = ? AND run.investigation = ?",
        (entity_id, case)):
        texts.append((r["summary"] or "") + " " + (r["title"] or ""))
    return [t for t in texts if t.strip()]


def link_campaign_members(conn, case: str | None) -> dict:
    """Connect orphan confirmed-member domains to their campaign org via member_of
    edges (issue gtl-4). A domain whose finding text EXPLICITLY asserts membership
    AND names a case campaign-org entity gets a member_of edge to that org — so a
    confirmed member is no longer a floating node. Deterministic: no marker, no
    edge; confidence=medium, never attribution. Idempotent (upsert_typed_relationship
    de-dupes on src,dst,rel_type)."""
    if not case:
        return {"member_edges": 0, "links": []}
    orgs = _campaign_org_entities(conn, case)
    if not orgs:
        return {"member_edges": 0, "links": [], "note": "no campaign-org entity in case"}
    domains = conn.execute(
        "SELECT DISTINCT e.id, e.canonical_name FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation = ? AND e.entity_type = 'domain'", (case,)).fetchall()
    links = []
    for d in domains:
        # The marker AND a campaign-org name must appear in the SAME finding.
        matched_org = None
        for text in _domain_finding_texts(conn, d["id"], case):
            if not MEMBERSHIP_RE.search(text):
                continue
            named = sorted(
                [(oid, name) for oid, name in orgs.items()
                 if name.lower() in text.lower() and oid != d["id"]],
                key=lambda x: len(x[1]), reverse=True)
            if named:
                matched_org = named[0]
                break
        if not matched_org:
            continue
        oid, oname = matched_org
        from investigations import store
        store.apply_mutation(conn, store.edge_upserted(
            case, d["id"], oid, "member_of", actor="pipeline:graph_cleanup",
            confidence="medium",
            evidence=f"finding text asserts membership in {oname}",
            provenance="cleanup:campaign-membership"))
        links.append({"domain": d["canonical_name"], "campaign": oname})
    conn.commit()
    return {"member_edges": len(links), "links": links}


def cleanup(conn, case: str | None) -> dict:
    """Run the passes + recompute scores. Best-effort, case-scoped."""
    out = {}
    out.update(normalize_campaigns(conn, case))
    out.update(prune_content_edges(conn, case))
    out.update(link_campaign_members(conn, case))
    try:
        from investigations import analyze
        analyze.compute_threat_scores(conn)
    except Exception:
        pass
    return out
