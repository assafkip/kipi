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
            conn.execute("DELETE FROM typed_relationships WHERE id = ?", (row["id"],))
            pruned += 1
    conn.commit()
    return {"pruned_edges": pruned}


def cleanup(conn, case: str | None) -> dict:
    """Run both passes + recompute scores. Best-effort, case-scoped."""
    out = {}
    out.update(normalize_campaigns(conn, case))
    out.update(prune_content_edges(conn, case))
    try:
        from investigations import analyze
        analyze.compute_threat_scores(conn)
    except Exception:
        pass
    return out
