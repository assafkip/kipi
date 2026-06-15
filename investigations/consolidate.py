"""LLM-driven entity consolidation.

Walks the DB's entities and asks Claude to:
  1. Merge duplicates that surface differently (t.me/example_channel + https://t.me/example_channel)
  2. Drop noise entities (extracted header fragments, parser glitches)
  3. Re-classify each entity by INVESTIGATION ROLE:
       operator   — a human actor / persona / handle
       channel    — a communication channel (telegram channel, forum, etc)
       ioc        — indicator of compromise (IP, hash, wallet, domain used in attack)
       source     — a reference source (news article URL, research paper)
       infra      — infrastructure (IP, domain, server used to host)
       noise      — drop from analysis
  4. For role=operator: assign a sub_role that captures network FUNCTION
     (leadership, facilitator, recruiter, infra_provider, propagandist, ...).
     Data-driven; LLM may invent new sub_roles when evidence supports them.

Writes back to DB:
  - entities.notes gets the role
  - entities.sub_role + sub_role_reason for operators
  - aliases get added for merged entities
  - noise entities get a 'role: noise' tag (kept for audit, hidden in exports)
"""
import json
import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from investigations import verify
from investigations import store
from investigations.llm import client as llm

# 80 (not 40): since ~90% of a CLI call is fixed boot overhead, fewer/larger batches
# pay that tax half as often. Output stays well within limits (≈80 compact cluster
# objects). Override with CONSOLIDATE_BATCH_SIZE.
BATCH_SIZE = max(1, int(os.environ.get("CONSOLIDATE_BATCH_SIZE", "80")))
# How many classify batches run at once. Measured the hard way: the FIRST parallel
# attempt collapsed (1 batch done in 5 min) — but that was the MCP fork-bomb, not a
# rate limit: each `claude -p` was booting the project's 4 MCP servers, so 5 at once
# thrashed. With tools=False (--strict-mcp-config, no MCP boot), 5 real batches in
# parallel run clean — measured 3.5x over serial (106s vs 366s). So: pre-pass shrinks
# the batch count, concurrency runs the survivors wide. Override with CONSOLIDATE_CONCURRENCY.
CONSOLIDATE_CONCURRENCY = max(1, int(os.environ.get("CONSOLIDATE_CONCURRENCY", "5")))

SYSTEM = """You are an intelligence analyst's assistant doing entity consolidation.
You receive a list of entities extracted from intel reports by regex. Your job:
1. MERGE duplicates that point to the same thing (different surface forms of the same actor/channel/IoC).
2. CLASSIFY each surviving entity into a role from this list:
   - operator   — human actor, persona, or threat-actor handle
   - channel    — communication channel (telegram channel, forum, irc, etc)
   - ioc        — indicator of compromise (attacker-controlled IP, hash, wallet, attack domain)
   - source     — reference / citation (news article, research paper, official report)
   - infra      — passive infrastructure (CDN IP, DNS, normal hosting)
   - noise      — parser glitch, OCR artifact, or text fragment misread as an entity
3. For role=operator: ALSO assign a sub_role that reflects the entity's FUNCTION in the network.
   This shows network structure (who leads, who recruits, who runs infra, who is muscle).
   Use these as starting categories but invent NEW sub_roles when the evidence supports it:
     - leadership      (declared crew leader, founder, head admin)
     - facilitator     (intermediary, coordinator across crews/cells)
     - recruiter       (publicly recruits members / runs onboarding)
     - propagandist    (publishes propaganda, claims-of-responsibility, brand)
     - developer       (builds tools, malware, infra, dev work)
     - defacer         (carries out website defacements)
     - spokesperson    (public-facing voice / press contact)
     - infra_provider  (provides hosting, VPN, bulletproof services to others)
     - member          (regular participant, no special role identified)
     - unknown         (operator but role unclear from evidence)
   Sub_role is REQUIRED for operator entities. Use "unknown" if evidence is thin.
   Sub_role MUST be empty string for non-operator entities.
4. Be RUTHLESS about noise — fragments of sentences, broken URLs, OCR errors should be marked noise.

Output strict JSON only. No prose."""


DEFAULT_ROLE_NAMES = ["operator", "channel", "ioc", "source", "infra", "noise"]
DEFAULT_ACTOR_ROLES = {"operator"}


def _build_system(schema: dict | None) -> str:
    """SYSTEM prompt. Default (hardcoded) when no approved schema; otherwise built
    from the case's own roles/sub_roles/noise rules so classification fits THIS
    case's domain instead of the generic threat template."""
    if not schema:
        return SYSTEM
    role_lines, actor_names = [], []
    for r in schema.get("roles", []):
        tag = " (ACTOR — assign a sub_role)" if r.get("actor") else ""
        role_lines.append(f"   - {r['name']}{tag} — {r.get('description','')}")
        if r.get("actor"):
            actor_names.append(r["name"])
    sub_lines = [f"     - {s['name']} — {s.get('description','')}"
                 for s in schema.get("sub_roles", [])]
    domain = schema.get("domain", "")
    summary = schema.get("summary", "")
    noise = schema.get("noise_notes", "Fragments, broken URLs, and OCR errors are noise.")
    actor_str = ", ".join(actor_names) or "(none)"
    return (
        "You are an intelligence analyst's assistant doing entity consolidation "
        f"for a specific case.\n\nCASE DOMAIN: {domain}\n{summary}\n\n"
        "You receive entities extracted from this case's reports by regex. Your job:\n"
        "1. MERGE duplicates that point to the same thing (different surface forms).\n"
        "2. CLASSIFY each surviving entity into EXACTLY ONE of this case's roles:\n"
        + "\n".join(role_lines) + "\n"
        f"3. For ACTOR roles ({actor_str}): ALSO assign a sub_role capturing the "
        "entity's FUNCTION in the network. Use these categories, and invent new "
        "ones when the evidence supports it:\n" + "\n".join(sub_lines) + "\n"
        "   sub_role is REQUIRED for actor roles (use 'unknown' if unclear), and "
        "MUST be empty string for non-actor roles.\n"
        f"4. NOISE for this case: {noise} Be ruthless about marking noise.\n\n"
        "Output strict JSON only. No prose."
    )


def _build_prompt(entities_batch: list[dict],
                  role_names: list[str] | None = None) -> str:
    role_names = role_names or DEFAULT_ROLE_NAMES
    role_options = "|".join(role_names)
    actor_hint = role_names[0]
    items = []
    for e in entities_batch:
        items.append({
            "id": e["id"],
            "name": e["canonical_name"],
            "type": e["entity_type"],
            "mention_count": e["mention_count"],
            "sample_context": (e["sample_context"] or "")[:200],
        })
    payload = json.dumps(items, indent=2, ensure_ascii=False)
    return (
        f"Entities to consolidate (batch of {len(entities_batch)}):\n\n{payload}\n\n"
        "Return JSON with this exact shape:\n"
        "{\n"
        '  "clusters": [\n'
        '    {\n'
        '      "canonical_id": <int — id of the entity to keep>,\n'
        '      "canonical_name": "<str — clean canonical form>",\n'
        f'      "role": "{role_options}",\n'
        '      "sub_role": "<str — function in the network, REQUIRED for ACTOR roles, empty string otherwise>",\n'
        '      "sub_role_reason": "<one short line of evidence for the sub_role>",\n'
        '      "merge_ids": [<int>, ...],   // OTHER ids that mean the same thing (will be merged into canonical_id)\n'
        '      "reason": "<one line why these are the same / why this role>"\n'
        '    }\n'
        '  ]\n'
        "}\n\n"
        "Rules:\n"
        "- Every input id must appear in EXACTLY ONE cluster (either as canonical_id or in merge_ids).\n"
        "- A single-entity cluster has empty merge_ids: [].\n"
        "- Strongly prefer merging URL forms with bare channel forms (https://t.me/X → t.me/X).\n"
        "- Mark fragments / OCR garbage / header text as noise.\n"
        f"- sub_role is mandatory for actor roles (e.g. {actor_hint}); use 'unknown' if unclear; empty string otherwise."
    )


def _candidate_entities(conn, only_new: bool = False,
                        case: str | None = None) -> list[dict]:
    clauses, params = [], []
    if only_new:
        clauses.append("e.notes IS NULL")
    if case:
        # Case-scoped classify: only entities mentioned in THIS case's reports.
        # Lets a per-case schema apply without touching other cases' entities.
        clauses.append(
            "e.id IN (SELECT m2.entity_id FROM mentions m2 "
            "JOIN reports r2 ON r2.id = m2.report_id WHERE r2.investigation = ?)")
        params.append(case)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"SELECT e.id, e.canonical_name, e.entity_type, "
        f"COUNT(m.id) AS mention_count, "
        f"(SELECT m2.context FROM mentions m2 WHERE m2.entity_id = e.id LIMIT 1) AS sample_context "
        f"FROM entities e LEFT JOIN mentions m ON m.entity_id = e.id "
        f"{where} "
        f"GROUP BY e.id "
        f"ORDER BY e.entity_type, e.canonical_name",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def _verify_role_evidence(conn, entity_ids: list[int], reason_text: str) -> set[str]:
    """Hard facts (date/IP/email/wallet) the LLM cited as ROLE evidence that do NOT appear
    in the entity's actual mentions — a fabricated evidentiary detail (replay D5, applied to
    consolidate). Empty set = the reason is soft (nothing hard to check) or every cited fact
    is grounded. Soft mis-classification (no hard token) is out of scope here — verifying
    that needs NLI, which we deliberately don't add (keeps this an auditable string check)."""
    if not verify.hard_tokens(reason_text):
        return set()
    ids = [i for i in entity_ids if isinstance(i, int)]
    if not ids:
        return verify.unbacked_tokens(reason_text, "")
    rows = conn.execute(
        "SELECT surface_form, context FROM mentions WHERE entity_id IN (%s)"
        % ",".join("?" * len(ids)), ids).fetchall()
    src = " ".join(f"{r['surface_form'] or ''} {r['context'] or ''}" for r in rows)
    return verify.unbacked_tokens(reason_text, src)


def _apply_cluster(conn, cluster: dict, actor_roles: set[str] | None = None) -> dict:
    actor_roles = actor_roles or DEFAULT_ACTOR_ROLES
    canonical_id = cluster["canonical_id"]
    canonical_name = cluster["canonical_name"]
    role = cluster["role"]
    sub_role = (cluster.get("sub_role") or "").strip().lower()
    sub_role_reason = (cluster.get("sub_role_reason") or "")[:300]
    merge_ids = cluster.get("merge_ids", []) or []
    reason = cluster.get("reason", "")

    if role not in actor_roles:
        sub_role = ""
        sub_role_reason = ""
    elif not sub_role:
        sub_role = "unknown"

    # Role-evidence check (replay D5): if the actor role's stated reason cites a HARD fact
    # (date/IP/email/wallet) that isn't in this entity's mentions, the evidence is fabricated.
    # Mark it so the analyst doesn't trust the reason — don't destructively demote the role
    # (the classification may still be right; only its cited evidence is suspect).
    if role in actor_roles and sub_role_reason:
        unbacked = _verify_role_evidence(
            conn, [canonical_id, *merge_ids], f"{sub_role_reason} {reason}")
        if unbacked:
            sub_role_reason = (sub_role_reason +
                f" {{{{UNVERIFIED: cites {', '.join(sorted(unbacked))} not in this "
                "entity's sources}}}}")[:300]

    canonical = conn.execute(
        "SELECT * FROM entities WHERE id = ?", (canonical_id,)
    ).fetchone()
    if not canonical:
        return {"skipped": canonical_id}

    notes = f"role:{role}"
    if reason:
        notes += f" — {reason[:200]}"

    existing = conn.execute(
        "SELECT id FROM entities WHERE canonical_name = ? AND id != ?",
        (canonical_name, canonical_id),
    ).fetchone()
    if existing:
        merge_ids = list(merge_ids) + [canonical_id]
        canonical_id = existing["id"]
        store.apply_mutation(conn, store.entity_merged(
            None, canonical_id, merge_ids, actor="pipeline:consolidate",
            fields={"notes": notes, "sub_role": sub_role or None,
                    "sub_role_reason": sub_role_reason or None}))
    else:
        store.apply_mutation(conn, store.entity_merged(
            None, canonical_id, merge_ids, actor="pipeline:consolidate",
            fields={"canonical_name": canonical_name, "notes": notes,
                    "sub_role": sub_role or None,
                    "sub_role_reason": sub_role_reason or None}))

    merged = 0
    for mid in merge_ids:
        if _absorb(conn, mid, canonical_id):
            merged += 1

    return {"canonical_id": canonical_id, "role": role, "merged": merged}


def _absorb(conn, mid: int, canonical_id: int) -> bool:
    """Fold entity `mid` into `canonical_id`: re-point every mention/alias/relationship
    and FK reference, then delete the duplicate. Returns True if a merge happened.
    Shared by the LLM apply path and the deterministic exact-dup pre-pass."""
    if mid == canonical_id:
        return False
    mrow = conn.execute("SELECT canonical_name FROM entities WHERE id = ?",
                        (mid,)).fetchone()
    if not mrow:
        return False
    conn.execute(
        "INSERT OR IGNORE INTO aliases (entity_id, alias) VALUES (?, ?)",
        (canonical_id, mrow["canonical_name"]),
    )
    conn.execute("UPDATE mentions SET entity_id = ? WHERE entity_id = ?",
                 (canonical_id, mid))
    conn.execute(
        "UPDATE OR IGNORE relationships SET src_entity_id = ? WHERE src_entity_id = ?",
        (canonical_id, mid),
    )
    conn.execute("DELETE FROM relationships WHERE src_entity_id = ?", (mid,))
    conn.execute(
        "UPDATE OR IGNORE relationships SET dst_entity_id = ? WHERE dst_entity_id = ?",
        (canonical_id, mid),
    )
    conn.execute("DELETE FROM relationships WHERE dst_entity_id = ?", (mid,))
    conn.execute("UPDATE OR IGNORE aliases SET entity_id = ? WHERE entity_id = ?",
                 (canonical_id, mid))
    conn.execute("DELETE FROM aliases WHERE entity_id = ?", (mid,))
    conn.execute("DELETE FROM relationships WHERE src_entity_id = dst_entity_id")
    # Re-point/clean every other table that FK-references the merged entity,
    # BEFORE deleting it: preserve analyst work + known-bad priors, drop
    # regenerable derived rows. Without this the DELETE hits a FK constraint
    # (foreign_keys=ON) and corrupts the half-merged batch.
    _merge_entity_refs(conn, mid, canonical_id)
    store.apply_mutation(conn, store.entity_merged(
        None, canonical_id, [mid], actor="pipeline:consolidate",
        delete_merged=True))
    return True


def _table_exists(conn, name: str) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (name,)).fetchone())


def _merge_entity_refs(conn, mid: int, canonical_id: int) -> None:
    # Analyst annotations: PRESERVE (the regen-safe promise). Fold into canonical.
    if _table_exists(conn, "entity_annotations"):
        canon = conn.execute(
            "SELECT 1 FROM entity_annotations WHERE entity_id = ?", (canonical_id,)).fetchone()
        if canon:
            dup = conn.execute(
                "SELECT notes FROM entity_annotations WHERE entity_id = ?", (mid,)).fetchone()
            if dup and dup["notes"]:
                conn.execute(
                    "UPDATE entity_annotations SET notes = TRIM(COALESCE(notes,'') || ? || ?) "
                    "WHERE entity_id = ?", ("\n\n", dup["notes"], canonical_id))
            conn.execute("DELETE FROM entity_annotations WHERE entity_id = ?", (mid,))
        else:
            conn.execute("UPDATE entity_annotations SET entity_id = ? WHERE entity_id = ?",
                         (canonical_id, mid))
    # Known-bad priors: PRESERVE by re-pointing to the survivor.
    if _table_exists(conn, "seeds"):
        conn.execute("UPDATE OR IGNORE seeds SET entity_id = ? WHERE entity_id = ?",
                     (canonical_id, mid))
        conn.execute("DELETE FROM seeds WHERE entity_id = ?", (mid,))
    # Derived / regenerable — drop the merged id's rows (rebuilt by analyze/backfill).
    for tbl, cols in (("claims", ("entity_id", "object_entity_id")),
                      ("entity_scores", ("entity_id",)),
                      ("cluster_members", ("entity_id",)),
                      ("typed_relationships", ("src_entity_id", "dst_entity_id")),
                      ("enrichment_links", ("entity_id",))):
        if _table_exists(conn, tbl):
            where = " OR ".join(f"{c} = ?" for c in cols)
            conn.execute(f"DELETE FROM {tbl} WHERE {where}", tuple([mid] * len(cols)))
    # Node properties / alerts / evidence: PRESERVE by re-pointing to the survivor
    # (UNIQUE constraints make the survivor's row win on collision; the duplicate's
    # leftover is dropped). node_properties + alerts have NO delete-cascade, so missing
    # them here fails the final DELETE with a FK error (escape-twin merge, 2026-06-11).
    for tbl in ("node_properties", "alerts", "evidence_artifacts"):
        if _table_exists(conn, tbl):
            conn.execute(f"UPDATE OR IGNORE {tbl} SET entity_id = ? WHERE entity_id = ?",
                         (canonical_id, mid))
            conn.execute(f"DELETE FROM {tbl} WHERE entity_id = ?", (mid,))
    # Enrichment history references entities by nullable cols — null them, keep history.
    if _table_exists(conn, "enrichment_runs"):
        conn.execute("UPDATE enrichment_runs SET entity_id = NULL WHERE entity_id = ?", (mid,))
    if _table_exists(conn, "enrichment_results"):
        conn.execute("UPDATE enrichment_results SET extracted_entity_id = NULL "
                     "WHERE extracted_entity_id = ?", (mid,))


# ---------------------------------------------------------------------------
# Deterministic pre-pass — do the string work in CODE, not the LLM.
#
# ~70% of a scraped case's entity pool is self-labeled platform/tracking IDs
# ("Shopify shop ID 65536098", "Facebook Ad ID …") + extractor garbage (dates
# parsed as phones, registrar privacy-proxy numbers, CSS fragments). The role of
# those is deterministic: a platform ID is a fingerprint, garbage is noise. Code
# types them instantly and more reliably than the model hand-sorting 40 at a time.
# Only the genuine unknowns (handles needing context judgment) reach the LLM.
# ---------------------------------------------------------------------------

# Self-labeled platform / tracking artifacts → fingerprint (a pivot, never an actor).
_PLATFORM_ID_RE = re.compile(
    r"\b(shop|store|listing|goods|item|product|theme|ad|ads|conversion|pixel|"
    r"tracking|seller|catalog|account|merchant|order|sku|app|page|business)\s+id\b",
    re.I)
_PLATFORM_NAME_ID_RE = re.compile(
    r"\b(shopify|etsy|ebay|shein|tiktok|facebook|instagram|google\s*ads?|amazon|"
    r"walletconnect|judge\.me|pinterest|youtube)\b.*\bid\b", re.I)

# Extractor garbage, schema-independent. These phrases come from the extractor's own
# descriptive labels, so matching them is reliable noise detection (low false-positive).
_NOISE_PHRASES = (
    "report date", "registrar privacy", "privacy-proxy", "privacy proxy",
    "whois privacy", "mis-parsed", "misparsed", "parser glitch", "ocr artifact",
)
_CSS_AT_RE = re.compile(
    r"^@(media|import|keyframes|font-face|charset|supports|namespace|page)\b", re.I)

# A platform ID should be routed to the case's fingerprint-style role. These are the
# role names that mean "indicator / infra / fingerprint" across the schema taxonomies.
_FINGERPRINT_ROLE_NAMES = {
    "fingerprint", "ioc", "infra", "infrastructure", "indicator", "artifact",
    "platform_artifact_id",
}


def _fingerprint_role(schema: dict | None) -> str | None:
    """The case role that platform/tracking IDs belong to. None → let the LLM decide
    (safe fallback; only happens when there's no schema, which Process always has)."""
    if not schema:
        return None
    for r in schema.get("roles", []):
        n = (r.get("name") or "").strip().lower()
        if n in _FINGERPRINT_ROLE_NAMES or "fingerprint" in n or "indicator" in n:
            return r["name"]
    return None


def _norm_key(name: str) -> str:
    """Normalized identity key for exact-duplicate detection. Case-fold + strip the
    URL scheme/www + trailing slash. Conservative on purpose: it does NOT strip '@',
    so a handle never collapses into a same-named domain/wallet — those ambiguous
    merges stay the LLM's call."""
    s = (name or "").strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"^www\.", "", s)
    return s.rstrip("/")


def _pretype(name: str, fp_role: str | None) -> str | None:
    """Deterministic role for an entity, or None if it needs the LLM's judgment."""
    s = (name or "").strip()
    low = s.lower()
    if _CSS_AT_RE.match(s) or len(s) <= 2:
        return "noise"
    if any(p in low for p in _NOISE_PHRASES):
        return "noise"
    # Pure-numeric values: the regex extractor dumped platform/tracking IDs (Shopify
    # shop, Facebook Ad, Etsy listing…) into the 'phone' bucket as bare numbers. A
    # context-free number is never an actor. A date-shaped 8-digit value (20260424)
    # is a mis-parsed date = noise; anything else is a fingerprint pivot. Anything
    # with letters (e.g. "TikTok burner user491…") is left for the LLM — it may be a
    # real actor, not an artifact.
    digits = re.sub(r"[\s().+\-]", "", s)
    if digits.isdigit() and len(digits) >= 6:
        if re.fullmatch(r"(19|20)\d{6}", digits):
            return "noise"
        return fp_role or "noise"
    if fp_role and (_PLATFORM_ID_RE.search(s) or _PLATFORM_NAME_ID_RE.search(s)):
        return fp_role
    return None


# Types that name the SAME kind of artifact under different surface forms — the only
# buckets where a cross-type alias merge is safe. A handle must never collapse into a
# same-named domain/wallet/person (the reason _norm_key keeps '@').
_ALIAS_BUCKETS = {
    "actor-handle": {"handle", "telegram_channel"},
}
_TG_PREFIX_RE = re.compile(r"^(t\.me/|telegram\.me/)")


def _alias_key(name: str, entity_type: str | None) -> tuple[str, str] | None:
    """Bucket-scoped identity key: '@kambala_boss' (handle) and 't.me/kambala_boss'
    (telegram_channel) are the same actor by construction. The bench corpus proved
    the LLM batch misses exactly this merge — known-shape identity is code's job."""
    et = (entity_type or "").strip().lower()
    for bucket, types in _ALIAS_BUCKETS.items():
        if et in types:
            s = _norm_key(name)
            s = _TG_PREFIX_RE.sub("", s)
            s = s.lstrip("@").rstrip("/")
            return (bucket, s) if s else None
    return None


def _merge_groups(conn, groups: dict, survivors: list[dict]) -> int:
    """Absorb each group into its richest member; append survivors. Returns merges."""
    merged = 0
    for group in groups.values():
        if len(group) == 1:
            survivors.append(group[0])
            continue
        group.sort(key=lambda x: x.get("mention_count", 0), reverse=True)
        keep = group[0]
        for other in group[1:]:
            if _absorb(conn, other["id"], keep["id"]):
                merged += 1
        survivors.append(keep)
    return merged


def _dedup_exact(conn, entities: list[dict]) -> tuple[list[dict], int]:
    """Merge entities whose names are identical after case/URL normalization, then
    merge bucket-scoped alias forms (t.me/x ↔ @x) — pure string work the LLM was
    being asked to do (and demonstrably missed). Keeps the richest (most-mentioned)
    entity as canonical. Returns (survivors, merged_count)."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in entities:
        groups[_norm_key(e["canonical_name"])].append(e)
    survivors: list[dict] = []
    merged = _merge_groups(conn, groups, survivors)
    # Second pass over the survivors: cross-type alias forms within a safe bucket.
    alias_groups: dict[tuple, list[dict]] = defaultdict(list)
    rest: list[dict] = []
    for e in survivors:
        key = _alias_key(e["canonical_name"], e.get("entity_type"))
        if key:
            alias_groups[key].append(e)
        else:
            rest.append(e)
    survivors = rest
    merged += _merge_groups(conn, alias_groups, survivors)
    return survivors, merged


def run(conn, dry_run: bool = False, only_new: bool = False,
        schema: dict | None = None, case: str | None = None,
        on_progress=None) -> dict:
    """Classify + de-dup entities.

    schema : a per-case ontology (from the analyst-approved Understand step). When
             given, roles/sub_roles/noise rules come from it; otherwise the
             hardcoded generic taxonomy is used.
    case   : restrict classification to this case's entities (global pool stays
             untouched for other cases). Pair with a per-case schema.
    on_progress(done, total, label) : optional callback fired as each LLM batch
             completes, so a caller can render a live sub-step progress bar.
    """
    entities = _candidate_entities(conn, only_new=only_new, case=case)
    total = len(entities)
    scope = "new (unclassified)" if only_new else "all"
    if case:
        scope += f" in case '{case}'"

    # Schema-driven prompt + actor-role set, or the hardcoded defaults.
    system_prompt = _build_system(schema)
    if schema:
        from investigations import understand
        names = understand.role_names(schema)
        actors = understand.actor_roles(schema)
        fp_role = _fingerprint_role(schema)
        print(f"Consolidating {total} {scope} entities with the '{schema.get('domain','case')}' "
              f"schema ({len(names)} roles)…")
    else:
        names, actors, fp_role = DEFAULT_ROLE_NAMES, DEFAULT_ACTOR_ROLES, None
        print(f"Consolidating {total} {scope} entities…")

    stats = {"clusters": 0, "merged": 0, "noise": 0,
             "roles": defaultdict(int), "sub_roles": defaultdict(int)}

    def _tally_cluster(c: dict, merged_count: int) -> None:
        stats["clusters"] += 1
        stats["merged"] += merged_count
        stats["roles"][c.get("role", "?")] += 1
        if c.get("role") in actors:
            sr = (c.get("sub_role") or "unknown").strip().lower() or "unknown"
            stats["sub_roles"][sr] += 1
        if c.get("role") == "noise":
            stats["noise"] += 1

    # --- Deterministic pre-pass: merge exact dups + type self-labeled entities by
    # rule, so only the genuine unknowns reach the (slow) LLM. ---
    if not dry_run:
        entities, dup_merged = _dedup_exact(conn, entities)
        stats["merged"] += dup_merged
        if dup_merged:
            conn.commit()
            print(f"  pre-pass: merged {dup_merged} exact duplicates by rule (no LLM)")

    llm_entities, pretyped = [], 0
    for e in entities:
        role = _pretype(e["canonical_name"], fp_role)
        if role is None:
            llm_entities.append(e)
            continue
        if not dry_run:
            store.apply_mutation(conn, store.entities_retyped_batch(
                None, [{"entity_id": e["id"], "fields": {"notes": f"role:{role}"}}],
                actor="pipeline:consolidate"))
        stats["clusters"] += 1
        stats["roles"][role] += 1
        if role == "noise":
            stats["noise"] += 1
        pretyped += 1
    if not dry_run and pretyped:
        conn.commit()
    if pretyped:
        print(f"  pre-pass: typed {pretyped} self-labeled entities by rule (no LLM) — "
              f"{len(llm_entities)} genuine unknowns left for the model")

    # --- LLM pass on the remainder, in PARALLEL. The slow part is the per-batch
    # `claude` call; those run concurrently. DB writes stay on this (main) thread as
    # each batch returns, so there is exactly one writer = no lock contention. ---
    batches = [llm_entities[i:i + BATCH_SIZE]
               for i in range(0, len(llm_entities), BATCH_SIZE)]
    nb = len(batches)
    if nb:
        print(f"Classifying {len(llm_entities)} entities the rules couldn't resolve, "
              f"in {nb} batches of {BATCH_SIZE} ({CONSOLIDATE_CONCURRENCY} at a time)…")

    def _classify(idx_batch):
        idx, batch = idx_batch
        prompt = _build_prompt(batch, role_names=names)
        try:
            # tools=False: pure-text classification, skip the MCP boot per call.
            # model=CLASSIFY_MODEL (Haiku): this is mechanical classification, not judgment.
            resp = llm.ask_json(prompt, system=system_prompt, timeout=240,
                                tools=False, model=llm.CLASSIFY_MODEL)
            return idx, resp.get("clusters", []), None
        except llm.LLMError as exc:
            return idx, [], str(exc)

    done = 0
    if nb:
        with ThreadPoolExecutor(max_workers=CONSOLIDATE_CONCURRENCY) as pool:
            futures = [pool.submit(_classify, (i, b)) for i, b in enumerate(batches)]
            for fut in as_completed(futures):
                idx, clusters, err = fut.result()
                done += 1
                if err:
                    print(f"  batch {idx + 1}/{nb} LLM ERROR: {err}")
                else:
                    for c in clusters:
                        try:
                            result = _apply_cluster(conn, c, actor_roles=actors) if not dry_run else {
                                "merged": len(c.get("merge_ids", [])),
                            }
                            _tally_cluster(c, result.get("merged", 0))
                        except Exception as exc:
                            print(f"  apply error on cluster {c.get('canonical_id')}: {exc}")
                    if not dry_run:
                        conn.commit()
                    print(f"  batch {idx + 1}/{nb} ({len(batches[idx])} entities)… "
                          f"{len(clusters)} clusters returned")
                if on_progress:
                    try:
                        on_progress(done, nb, "classify batches")
                    except Exception:
                        pass

    if not dry_run:
        conn.commit()

    stats["roles"] = dict(stats["roles"])
    stats["sub_roles"] = dict(stats["sub_roles"])
    return stats
