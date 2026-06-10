"""LLM-driven analytic enrichment.

Reads existing dossiers + DB state, produces:
  - typed relationships (operates / posts_in / ally_with / predecessor_of / defaced /
    hosted_by / same_as / member_of / targets / co_admin)
  - cluster assignments (e.g. 'Ring-A crew', 'Iranian convergence', 'IP cohort A')
  - per-entity threat_score (deterministic)
  - per-entity recency (first_seen date if extractable)

Writes:
  - entities.notes gets 'cluster:X' appended
  - entities.first_seen_at updated if date extracted
  - relationships rows replaced with typed rows
  - new 'clusters' table for visual grouping
  - new 'enrichment_links' table per entity (pivot URLs)
"""
import json
import os
import re
from collections import defaultdict
from pathlib import Path

# analyze emits clusters + typed_relationships in ONE call. The live run proved 8,192
# output tokens isn't enough on its own (the model spent the whole budget on 174
# relationships and never reached clusters). The fix is twofold: (1) cap relationships
# (ANALYZE_MAX_RELATIONSHIPS) so the output is bounded, and (2) a modest max_tokens bump
# for headroom. 16k is conservative — comfortably accepted by Sonnet, no beta header.
ANALYZE_MAX_TOKENS = int(os.environ.get("ANALYZE_MAX_TOKENS", "16384"))
ANALYZE_MAX_RELATIONSHIPS = int(os.environ.get("ANALYZE_MAX_RELATIONSHIPS", "150"))

from investigations.storage import db
from investigations.llm import client as llm
from investigations import understand
from investigations.enrich.rel_vocab import normalize_rel


REL_TYPES = [
    "operates",      # human/handle operates a channel
    "posts_in",      # handle posts in channel
    "ally_with",     # crew/handle public ally with another
    "predecessor_of", # UID/handle replaced/deleted by another
    "defaced",       # operator/crew defaced a domain/site
    "hosted_by",     # IP/domain hosted by ASN/provider
    "member_of",     # handle member of crew
    "targets",       # operator targets a victim/domain
    "co_admin",      # handle co-admins channel with another
    "same_as",       # alias
]

ROLE_WEIGHTS = {
    "operator": 5,
    "channel":  3,
    "ioc":      4,
    "infra":    1,
    "source":   0,
    "noise":    0,
}

SYSTEM = """You are an OSINT analyst building a typed entity graph from intel dossiers.

You receive existing actor dossiers + the raw entity list. Your job:
1. Replace soft 'co_mentioned' relationships with TYPED relationships using ONLY these labels:
   operates, posts_in, ally_with, predecessor_of, defaced, hosted_by, member_of,
   targets, co_admin, same_as
2. Assign each typed relationship a confidence: high | medium | low
3. Group entities into CREWS / COHORTS based on dossier evidence (e.g. 'Ring-A crew',
   'Iranian convergence ring', 'Egress cohort A /24', etc.)

Output strict JSON only. No prose. No markdown fences."""


def _gather_context(conn, vault_dir: Path, case: str | None = None) -> str:
    """Build the analyze prompt context. Case-scoped: without the filter this fed EVERY
    case's entities (4,031 on a multi-case DB → a ~490k-char prompt whose clustering
    output overran max_tokens and truncated), AND it leaked other cases' entities into
    this case's clusters. With `case` it sees only this investigation's entities +
    dossiers."""
    from investigations.profile import _safe_name

    scope, params = "", []
    if case:
        scope = ("AND e.id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
                 "ON r.id = m.report_id WHERE r.investigation = ?) ")
        params = [case]
    entities = conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, e.case_type, e.notes FROM entities e "
        "WHERE e.notes IS NOT NULL AND e.notes NOT LIKE 'role:noise%' " + scope +
        "ORDER BY e.id", params
    ).fetchall()
    entity_list = []
    for e in entities:
        role = (e["notes"] or "").split(" — ")[0].replace("role:", "").strip()
        entity_list.append({
            "id": e["id"],
            "name": e["canonical_name"],
            "type": e["case_type"] or e["entity_type"],
            "role": role,
        })

    # Only this case's dossiers (the profile filename is _safe_name(canonical_name)).
    case_stems = {_safe_name(e["canonical_name"]) for e in entities} if case else None
    profiles_dir = vault_dir / "profiles"
    dossiers = []
    if profiles_dir.exists():
        for p in profiles_dir.glob("*.md"):
            if case_stems is not None and p.stem not in case_stems:
                continue
            dossiers.append(f"--- {p.stem} ---\n{p.read_text(encoding='utf-8')[:2500]}\n")

    parts = [
        f"ENTITIES ({len(entity_list)}):",
        json.dumps(entity_list, ensure_ascii=False),
        "",
        f"DOSSIERS ({len(dossiers)}):",
        "\n".join(dossiers[:80]),
    ]
    return "\n".join(parts)


def _build_system(schema: dict | None) -> str:
    """Default (hacktivist) SYSTEM, or one keyed to the case domain so cluster
    names + relationship types fit the investigation instead of crew/cohort."""
    if not schema:
        return SYSTEM
    domain = schema.get("domain", "")
    summary = schema.get("summary", "")
    return (
        "You are an OSINT analyst building a typed entity graph for a specific "
        f"investigation.\n\nCASE DOMAIN: {domain}\n{summary}\n\n"
        "You receive entities (id, name, type, role) + any dossiers. Your job:\n"
        "1. Add TYPED relationships between entities. Use short snake_case "
        "rel_type labels that fit THIS domain (e.g. for crypto fraud: shills, "
        "deployed, drains_to, funded_by, same_operator, hosted_on, registered). "
        "Pick the label that states the actual relationship.\n"
        "2. Give each relationship a confidence: high | medium | low.\n"
        "3. Group entities into CLUSTERS that fit this case (e.g. a scam ring, a "
        "wallet cohort, an infrastructure block, an affiliate network). Name them "
        "for what they ARE in this investigation.\n\n"
        "Output strict JSON only. No prose. No markdown fences."
    )


def _build_prompt(context: str, schema: dict | None = None) -> str:
    if schema:
        rel_hint = ("a short snake_case label that fits the domain "
                    "(e.g. shills, deployed, drains_to, funded_by, same_operator)")
        cluster_eg = "scam ring / wallet cohort / affiliate network"
        kinds = "ring|cohort|network|infrastructure_block|venue"
    else:
        rel_hint = "one of: " + ", ".join(REL_TYPES)
        cluster_eg = "Ring-A crew"
        kinds = "crew|cohort|infrastructure_block|venue"
    return (
        f"{context}\n\n"
        "Produce JSON with this exact shape. Emit \"clusters\" FIRST and in full, THEN "
        "typed_relationships — the clusters are the priority output:\n"
        "{\n"
        '  "clusters": [\n'
        '    {\n'
        '      "name": "<cluster name, e.g. \'' + cluster_eg + '\'>",\n'
        '      "kind": "' + kinds + '",\n'
        '      "member_ids": [<int>, <int>, ...],\n'
        '      "description": "<one line>"\n'
        '    }, ...\n'
        "  ],\n"
        '  "typed_relationships": [\n'
        '    {"src_id": <int>, "dst_id": <int>, "rel_type": "<' + rel_hint + '>", '
        '"confidence": "high|medium|low", "evidence": "<one short line>"},\n'
        "    ...\n"
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "- Clusters FIRST: group entities that co-operate / co-locate / share infrastructure.\n"
        "- Only emit typed_relationships you can justify from the evidence.\n"
        "- Skip relationships if no clear type fits.\n"
        f"- Emit AT MOST {ANALYZE_MAX_RELATIONSHIPS} typed_relationships — the most "
        "important ones. Do not exceed this.\n"
        "- Use member_ids only from the ENTITIES list. Do not invent ids."
    )


def _extract_objects(text: str, key: str) -> list:
    """Brace-match every COMPLETE {...} object inside the array named `key`. Stops at the
    first incomplete object — that's the truncation point — keeping everything before it."""
    m = re.search(r'"' + re.escape(key) + r'"\s*:\s*\[', text)
    if not m:
        return []
    i, n, objs = m.end(), len(text), []
    while i < n:
        while i < n and text[i] not in "{]":
            i += 1
        if i >= n or text[i] == "]":
            break
        start, depth, in_str, esc, complete = i, 0, False, False, False
        while i < n:
            ch = text[i]
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = not in_str
            elif not in_str:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        complete = True
                        break
            i += 1
        if not complete:
            break  # truncated mid-object → stop, keep what survived
        try:
            objs.append(json.loads(text[start:i], strict=False))
        except json.JSONDecodeError:
            pass
    return objs


def _salvage_json(text: str) -> dict:
    """Parse the analyze response; on a truncated or quote-broken response (big cases run
    long, and the source data is full of quotes/emoji that the model can mis-escape),
    recover whatever complete typed_relationships / clusters objects survived instead of
    losing the entire step."""
    s = text.strip()
    if s.startswith("```"):
        lines = s.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    try:
        obj = json.loads(s, strict=False)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    return {
        "typed_relationships": _extract_objects(s, "typed_relationships"),
        "clusters": _extract_objects(s, "clusters"),
    }


def extract_typed_relationships(conn, vault_dir: Path, schema: dict | None = None,
                                case: str | None = None) -> dict:
    context = _gather_context(conn, vault_dir, case=case)
    print("Asking LLM for typed relationships + clusters…")
    prompt = _build_prompt(context, schema)
    # Raw text (not ask_json) so a truncated/quote-broken response is SALVAGED into the
    # objects that survived, instead of raising and skipping the whole step. tools=False:
    # clustering needs no MCP.
    text = llm.ask(prompt + "\n\nReply with ONLY valid JSON. No prose, no fences.",
                   system=_build_system(schema), timeout=600, tools=False,
                   max_tokens=ANALYZE_MAX_TOKENS)
    return _salvage_json(text)


# Strong-attribution rel_types assert COMMON CONTROL / shared identity — a
# definitive claim an analyst must be able to defend. The analyze LLM overclaims
# them on weak signal (wallets merely co-listed in one lure flow, or "same
# investigation cohort" — i.e. no evidence). Gate by the model's OWN confidence
# so the LABEL can't outrun its evidence (analyst-integrity fix, deterministic —
# not a prompt plea the model can ignore):
#   low    → DROP (evidence-free attribution must not render)
#   medium → DEMOTE to a defensible co-occurrence claim (co_listed)
#   high   → KEEP (real multi-signal / on-chain linkage)
_STRONG_ATTRIBUTION = {"same_operator", "same_actor", "common_operator",
                       "operated_by_same", "same_controller", "same_owner"}
_ATTRIBUTION_DEMOTED = "co_listed"


def gate_attribution(rel_type: str, confidence: str | None) -> str | None:
    """The rel_type to actually write for a strong-attribution edge — or None to
    drop it. Non-attribution rel_types pass through unchanged."""
    if rel_type not in _STRONG_ATTRIBUTION:
        return rel_type
    c = (confidence or "medium").strip().lower()
    if c == "low":
        return None
    if c == "medium":
        return _ATTRIBUTION_DEMOTED
    return rel_type


def apply_to_db(conn, llm_output: dict, allow_free_rel_types: bool = False) -> dict:
    typed = llm_output.get("typed_relationships", [])
    clusters = llm_output.get("clusters", [])

    conn.execute("CREATE TABLE IF NOT EXISTS clusters ("
                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "name TEXT NOT NULL UNIQUE, "
                 "kind TEXT, "
                 "description TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS cluster_members ("
                 "cluster_id INTEGER, entity_id INTEGER, "
                 "PRIMARY KEY (cluster_id, entity_id), "
                 "FOREIGN KEY (cluster_id) REFERENCES clusters(id), "
                 "FOREIGN KEY (entity_id) REFERENCES entities(id))")
    # Mirror storage/db.py's table shape (incl. status/provenance/first_seen/last_seen)
    # so a connection that skipped db._migrate still works with
    # db.upsert_typed_relationship — without this, the helper's INSERT would hit
    # missing columns and the broad except below would silently drop every typed edge.
    conn.execute("CREATE TABLE IF NOT EXISTS typed_relationships ("
                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "src_entity_id INTEGER NOT NULL, "
                 "dst_entity_id INTEGER NOT NULL, "
                 "rel_type TEXT NOT NULL, "
                 "confidence TEXT, "
                 "evidence TEXT, "
                 "status TEXT NOT NULL DEFAULT 'active', "
                 "provenance TEXT, "
                 "first_seen TEXT, "
                 "last_seen TEXT, "
                 "UNIQUE(src_entity_id, dst_entity_id, rel_type), "
                 "FOREIGN KEY (src_entity_id) REFERENCES entities(id), "
                 "FOREIGN KEY (dst_entity_id) REFERENCES entities(id))")
    for col, decl in (("status", "TEXT NOT NULL DEFAULT 'active'"), ("provenance", "TEXT"),
                      ("first_seen", "TEXT"), ("last_seen", "TEXT")):
        cols = {r[1] for r in conn.execute("PRAGMA table_info(typed_relationships)")}
        if col not in cols:
            conn.execute(f"ALTER TABLE typed_relationships ADD COLUMN {col} {decl}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_typed_src ON typed_relationships(src_entity_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_typed_dst ON typed_relationships(dst_entity_id)")
    conn.execute("CREATE TABLE IF NOT EXISTS enrichment_links ("
                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "entity_id INTEGER NOT NULL, "
                 "label TEXT NOT NULL, "
                 "url TEXT NOT NULL, "
                 "FOREIGN KEY (entity_id) REFERENCES entities(id))")
    conn.execute("CREATE TABLE IF NOT EXISTS entity_scores ("
                 "entity_id INTEGER PRIMARY KEY, "
                 "threat_score REAL, "
                 "degree INTEGER, "
                 "report_count INTEGER, "
                 "FOREIGN KEY (entity_id) REFERENCES entities(id))")

    typed_count = 0
    valid_ids = {r["id"] for r in conn.execute("SELECT id FROM entities").fetchall()}
    for t in typed:
        sid, did = t.get("src_id"), t.get("dst_id")
        if sid not in valid_ids or did not in valid_ids or sid == did:
            continue
        # Single binding gate (issue unify-rel-vocab-gate). allow_novel mirrors
        # allow_free_rel_types: a schema-driven run keeps clean per-case domain labels,
        # but synonyms collapse, co-occurrence flags drop, and unknown labels generalize
        # to linked_to. No raw label reaches the DB on any path now.
        rtype = normalize_rel(t.get("rel_type"), t.get("evidence", ""),
                              allow_novel=allow_free_rel_types)
        if rtype is None:
            continue
        # A strong-attribution label can't outrun its confidence: low drops,
        # medium demotes to co_listed, high keeps (analyst-integrity gate).
        rtype = gate_attribution(rtype, t.get("confidence"))
        if rtype is None:
            continue
        try:
            db.upsert_typed_relationship(
                conn, sid, did, rtype,
                confidence=t.get("confidence", "medium"),
                evidence=t.get("evidence", "")[:300])
            typed_count += 1
        except Exception:
            continue

    cluster_count = 0
    member_errors = 0
    for c in clusters:
        name = c.get("name", "").strip()
        if not name:
            continue
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO clusters (name, kind, description) VALUES (?, ?, ?)",
                (name, c.get("kind", ""), c.get("description", "")),
            )
            if cur.lastrowid:
                cluster_id = cur.lastrowid
            else:
                row = conn.execute("SELECT id FROM clusters WHERE name = ?",
                                   (name,)).fetchone()
                if not row:
                    continue
                cluster_id = row["id"]
        except Exception as exc:
            print(f"  cluster insert error ({name}): {exc}")
            continue
        for mid in c.get("member_ids", []) or []:
            if mid not in valid_ids:
                continue
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO cluster_members (cluster_id, entity_id) "
                    "VALUES (?, ?)",
                    (cluster_id, mid),
                )
            except Exception:
                member_errors += 1
                continue
        cluster_count += 1
    if member_errors:
        print(f"  skipped {member_errors} cluster_member insert(s) due to FK errors")

    conn.commit()
    return {"typed_relationships_added": typed_count,
            "clusters_added": cluster_count}


def _merged_role_weights(conn) -> dict:
    """Role name → weight. Starts from the generic defaults, then overlays every
    APPROVED case schema's role weights (max wins). Lets per-case roles
    (promoter, enabler, indicator…) score instead of falling to 0, while keeping
    the generic roles working for un-schema'd cases. Multi-case safe."""
    import json as _json
    weights = dict(ROLE_WEIGHTS)
    has = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_schemas'").fetchone()
    if not has:
        return weights
    for row in conn.execute("SELECT schema_json FROM case_schemas WHERE status='approved'"):
        try:
            schema = _json.loads(row["schema_json"])
        except (TypeError, _json.JSONDecodeError):
            continue
        for name, w in understand.role_weights(schema).items():
            weights[name] = max(weights.get(name, 0), w)
    return weights


def compute_threat_scores(conn) -> int:
    """Compute threat_score per entity:
       base  = role_weight * 10 + report_count * 5 + degree * 1
       prior = seed_weight * 30 if entity is a seed
       prop  = sum over neighbors of (seed_weight * 10) at depth 1,
               and (seed_weight * 4) at depth 2

       Seeds elevate themselves AND propagate influence along the graph,
       making associates of known-bad more visible. This is the iterative
       loop: more case files → more seeds → sharper focus.
    """
    conn.execute("DELETE FROM entity_scores")
    role_weights = _merged_role_weights(conn)

    # Pull seed weights (entity_id → max weight across seed sources)
    seed_weights: dict[int, float] = {}
    seeds_exist = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='seeds'"
    ).fetchone()
    if seeds_exist:
        for row in conn.execute(
            "SELECT entity_id, MAX(weight) AS w FROM seeds GROUP BY entity_id"
        ).fetchall():
            seed_weights[row["entity_id"]] = float(row["w"] or 1.0)

    # Adjacency from typed_relationships (undirected for propagation purposes)
    adj: dict[int, set[int]] = {}
    for rel in conn.execute(
        "SELECT src_entity_id AS s, dst_entity_id AS d FROM typed_relationships "
        "WHERE COALESCE(status,'active') = 'active'"
    ).fetchall():
        adj.setdefault(rel["s"], set()).add(rel["d"])
        adj.setdefault(rel["d"], set()).add(rel["s"])

    # Compute propagated boost per entity (depth-2 BFS from each seed)
    propagated: dict[int, float] = {}
    for seed_id, w in seed_weights.items():
        # depth 1
        for n1 in adj.get(seed_id, set()):
            if n1 == seed_id:
                continue
            propagated[n1] = propagated.get(n1, 0) + w * 10
        # depth 2
        for n1 in adj.get(seed_id, set()):
            for n2 in adj.get(n1, set()):
                if n2 == seed_id or n2 in adj.get(seed_id, set()):
                    continue
                propagated[n2] = propagated.get(n2, 0) + w * 4

    rows = conn.execute(
        "SELECT e.id, e.canonical_name, e.notes, "
        "COUNT(DISTINCT m.report_id) AS report_count "
        "FROM entities e LEFT JOIN mentions m ON m.entity_id = e.id "
        "GROUP BY e.id"
    ).fetchall()
    count = 0
    for r in rows:
        notes = r["notes"] or ""
        role = notes.split(" — ")[0].replace("role:", "").strip()
        role_w = role_weights.get(role, 0)
        eid = r["id"]
        # Always include seeds + propagated even if role_w is 0/missing
        seed_w = seed_weights.get(eid, 0)
        prop = propagated.get(eid, 0)
        if role_w == 0 and seed_w == 0 and prop == 0:
            continue
        report_count = r["report_count"] or 0
        degree = conn.execute(
            "SELECT COUNT(*) AS n FROM typed_relationships "
            "WHERE (src_entity_id = ? OR dst_entity_id = ?) "
            "AND COALESCE(status,'active') = 'active'",
            (eid, eid),
        ).fetchone()["n"]
        base = role_w * 10 + report_count * 5 + degree * 1
        prior = seed_w * 30
        score = base + prior + prop
        conn.execute(
            "INSERT OR REPLACE INTO entity_scores "
            "(entity_id, threat_score, degree, report_count) VALUES (?, ?, ?, ?)",
            (eid, float(score), degree, report_count),
        )
        count += 1
    conn.commit()
    return count


PIVOT_TEMPLATES = {
    "ip": [
        ("Shodan", "https://www.shodan.io/host/{value}"),
        ("AbuseIPDB", "https://www.abuseipdb.com/check/{value}"),
        ("Censys", "https://search.censys.io/hosts/{value}"),
        ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{value}"),
    ],
    "domain": [
        ("urlscan.io", "https://urlscan.io/domain/{value}"),
        ("VirusTotal", "https://www.virustotal.com/gui/domain/{value}"),
        ("DNSdumpster", "https://dnsdumpster.com/?domain={value}"),
    ],
    "url": [
        ("urlscan.io", "https://urlscan.io/search/#{value}"),
    ],
    "telegram_channel": [
        ("Open in Telegram", "https://{value}" if "{value}".startswith("http") else "https://t.me/{value_strip}"),
        ("TGStat", "https://tgstat.com/channel/@{value_strip}"),
    ],
    "handle": [
        ("Sherlock search", "https://www.google.com/search?q=%22{value}%22"),
        ("X/Twitter", "https://x.com/search?q={value_strip}"),
    ],
    "email": [
        ("Have I Been Pwned", "https://haveibeenpwned.com/account/{value}"),
        ("Hunter.io", "https://hunter.io/email-verifier/{value}"),
    ],
    "phone": [
        ("Truecaller", "https://www.truecaller.com/search/in/{value}"),
        ("Google search", "https://www.google.com/search?q=%22{value}%22"),
    ],
    "crypto_wallet": [
        ("Etherscan", "https://etherscan.io/address/{value}"),
        ("Chainabuse", "https://www.chainabuse.com/address/{value}"),
        ("Blockchair (multi-chain)", "https://blockchair.com/search?q={value}"),
        ("Arkham", "https://platform.arkhamintelligence.com/explorer/address/{value}"),
    ],
    # Web/ad-tech fingerprints — the pivots that enumerate an operator's full
    # deployment from a single shared identifier.
    "tracking_tag": [
        ("PublicWWW (sites using this tag)", "https://publicwww.com/websites/%22{value}%22/"),
        ("DNSlytics reverse analytics", "https://dnslytics.com/reverse-analytics/{value}"),
        ("BuiltWith relationships", "https://builtwith.com/relationships/tag/{value}"),
    ],
    "walletconnect_id": [
        ("WalletConnect Cloud (owner)", "https://cloud.walletconnect.com/"),
        ("PublicWWW (dApps using this id)", "https://publicwww.com/websites/%22{value}%22/"),
    ],
    "saas_service_account": [
        ("PublicWWW (sites with this id)", "https://publicwww.com/websites/%22{value}%22/"),
    ],
    "nameserver": [
        ("Domains on this nameserver", "https://securitytrails.com/list/ns/{value}"),
        ("HackerTarget reverse NS", "https://hackertarget.com/find-dns-records/?q={value}"),
    ],
    "registrar": [
        ("ICANN registrar lookup", "https://lookup.icann.org/en/lookup"),
    ],
    "hash_sha256": [
        ("VirusTotal", "https://www.virustotal.com/gui/file/{value}"),
    ],
    "hash_md5": [
        ("VirusTotal", "https://www.virustotal.com/gui/file/{value}"),
    ],
}


def populate_enrichment_links(conn) -> int:
    conn.execute("DELETE FROM enrichment_links")
    entities = conn.execute(
        "SELECT id, canonical_name, entity_type FROM entities"
    ).fetchall()
    count = 0
    for e in entities:
        templates = PIVOT_TEMPLATES.get(e["entity_type"])
        if not templates:
            continue
        value = e["canonical_name"]
        value_strip = value.lstrip("@").replace("https://", "").replace("http://", "")
        for label, url_tpl in templates:
            url = url_tpl.format(value=value, value_strip=value_strip)
            conn.execute(
                "INSERT INTO enrichment_links (entity_id, label, url) VALUES (?, ?, ?)",
                (e["id"], label, url),
            )
            count += 1
    conn.commit()
    return count


def run(conn, vault_dir: Path, schema: dict | None = None,
        case: str | None = None) -> dict:
    llm_output = extract_typed_relationships(conn, vault_dir, schema, case=case)
    print("Applying typed relationships + clusters to DB…")
    applied = apply_to_db(conn, llm_output, allow_free_rel_types=bool(schema))
    print(f"  typed relationships added: {applied['typed_relationships_added']}")
    print(f"  clusters added: {applied['clusters_added']}")

    print("Computing threat scores…")
    scored = compute_threat_scores(conn)
    print(f"  scored {scored} entities")

    print("Populating enrichment pivot links…")
    links = populate_enrichment_links(conn)
    print(f"  added {links} pivot links")

    return {
        "typed_relationships": applied["typed_relationships_added"],
        "clusters": applied["clusters_added"],
        "scored": scored,
        "enrichment_links": links,
    }
