"""Per-case ontology discovery — the "Understand" step.

Every case has a different shape. A hacktivist crew needs operator / channel /
ioc roles. A crypto rug-pull needs promoter / developer / wallet / contract. A
disinfo network needs persona / amplifier / outlet. Hardcoding one taxonomy
mis-buckets every case that isn't the one it was built for.

So before classification runs, the agent READS the case (report text + the raw
regex-extracted entities) and PROPOSES a schema fit to this case's domain:
  - entity_types : the kinds of things that matter here (wallet, contract, org…)
  - roles        : the investigation buckets each entity gets sorted into
  - sub_roles    : the FUNCTION categories for actor-type roles (who leads, who
                   builds, who promotes…)
  - noise_notes  : what counts as noise FOR THIS CASE

The analyst then approves or edits the proposal (control model: "propose, you
approve first"). Only an APPROVED schema drives consolidate.

Storage: one row per case in `case_schemas` (status 'proposed'|'approved').
"""
import json

from investigations.llm import client as llm

# Corpus bounds for the discovery prompt — enough to read the case, not so much
# the CLI times out. ~60k chars of report text ≈ 15k tokens.
CORPUS_CHAR_BUDGET = 60_000
SAMPLES_PER_TYPE = 6


# The current hand-built taxonomy, expressed as a schema. Used as the fallback
# when a case has no approved schema (back-compat) and as the seed the analyst
# sees on the schema page before running Understand.
DEFAULT_SCHEMA = {
    "domain": "generic threat / hacktivist network",
    "summary": "Default taxonomy. Run Understand to fit it to this case.",
    "entity_types": [
        {"name": "operator", "description": "a human actor, persona, or handle"},
        {"name": "channel", "description": "a telegram channel, forum, or comms surface"},
        {"name": "indicator", "description": "IP, hash, wallet, or domain used in an attack"},
        {"name": "source", "description": "a news article, report, or citation"},
        {"name": "infrastructure", "description": "hosting, DNS, or servers"},
    ],
    "roles": [
        {"name": "operator", "description": "human actor, persona, or threat-actor handle", "actor": True, "weight": 5},
        {"name": "channel", "description": "communication channel (telegram, forum, irc)", "actor": False, "weight": 3},
        {"name": "ioc", "description": "indicator of compromise (attacker IP, hash, wallet, attack domain)", "actor": False, "weight": 4},
        {"name": "source", "description": "reference / citation (news, research, official report)", "actor": False, "weight": 0},
        {"name": "infra", "description": "passive infrastructure (CDN, DNS, normal hosting)", "actor": False, "weight": 1},
        {"name": "noise", "description": "parser glitch, OCR artifact, or text fragment", "actor": False, "weight": 0},
    ],
    "sub_roles": [
        {"name": "leadership", "description": "declared crew leader, founder, head admin"},
        {"name": "facilitator", "description": "intermediary, coordinator across crews/cells"},
        {"name": "recruiter", "description": "publicly recruits members / runs onboarding"},
        {"name": "propagandist", "description": "publishes propaganda, claims-of-responsibility"},
        {"name": "developer", "description": "builds tools, malware, infra"},
        {"name": "defacer", "description": "carries out website defacements"},
        {"name": "spokesperson", "description": "public-facing voice / press contact"},
        {"name": "infra_provider", "description": "provides hosting, VPN, bulletproof services"},
        {"name": "member", "description": "regular participant, no special role"},
        {"name": "unknown", "description": "actor but function unclear from evidence"},
    ],
    "noise_notes": "Sentence fragments, broken URLs, OCR errors, and header text are noise.",
}


SYSTEM = """You are a senior intelligence analyst designing the data model for a
NEW investigation. You are handed: (1) the raw text of the case's reports, and
(2) the entities a regex extractor pulled out, grouped by its crude type with
counts and sample values.

Your job: propose the ENTITY TYPES, ROLES, SUB-ROLES, and NOISE rules that fit
THIS case's domain. Do not force a generic threat-network template. A crypto
rug-pull is not a hacktivist crew is not a disinfo network — each needs its own
buckets. Read what the case is actually about and model THAT.

Definitions:
- entity_types : the kinds of things that matter in this case (e.g. wallet,
  smart_contract, exchange, token, persona, outlet, org). Map loosely to what
  the regex found, but ADD types it missed and DROP types that don't apply.
- roles : the investigation buckets every surviving entity gets sorted into.
  Keep it small (4-8). Always include a 'noise' role. Mark a role actor=true
  when it describes a human/persona/account that has a FUNCTION in the network
  (those get a sub_role); mark actor=false for things (indicators, infra,
  channels, sources, assets). Give each role a weight 0-5 = how central it is to
  the investigation (the prime actors = 5, indicators ~4, infra ~1, sources and
  noise = 0). Weight drives the threat-score ranking.
- sub_roles : the FUNCTION categories for the actor roles — who leads, who
  builds, who promotes, who launders, who recruits. Invent the set that fits
  this case's domain.
- noise_notes : one or two sentences on what to treat as noise here.

MODELING DISCIPLINE for fraud / web / financial cases — propose entity types
across these LAYERS instead of one coarse "infrastructure" bucket, because each
identifier is a different investigative pivot:
- Identifiers / pivots: split out the SHARED FINGERPRINTS — analytics/tracking
  tags (GA/GTM), SaaS widget/service-account IDs (JivoSite, Intercom),
  WalletConnect/project IDs, registrant emails, registrars, nameservers, hosting
  /ASN. Each reverse-looks-up differently; do NOT lump them as one type.
- Money / assets: wallet addresses (note the chain), smart contracts, tokens,
  exchange/deposit accounts (the KYC pivot), mixers/laundering services.
- Deception: impersonated brands/identities, deepfake/synthetic media,
  tech-stack/kit fingerprints, lure templates.
- Traffic / malware: hijacked channels/accounts, stealer/malware families,
  paid-promotion/ad accounts.
- Actors: SPLIT a court-/document-confirmed natural person from an unconfirmed
  operator persona / WHOIS alias / handle — they carry different confidence.
Only include the layers the case actually contains. Don't invent empty ones.

Output strict JSON only. No prose."""


def _case_corpus(conn, case: str) -> dict:
    """Gather what the agent reads to understand the case: bounded report text +
    the regex-extracted entity histogram with samples."""
    reports = conn.execute(
        "SELECT id, title, raw_text FROM reports WHERE investigation = ? ORDER BY ingested_at",
        (case,),
    ).fetchall()

    text_parts, used = [], 0
    for r in reports:
        body = (r["raw_text"] or "").strip()
        if not body:
            continue
        header = f"\n\n===== REPORT: {r['title'] or r['id']} =====\n"
        room = CORPUS_CHAR_BUDGET - used
        if room <= len(header):
            break
        chunk = body[: room - len(header)]
        text_parts.append(header + chunk)
        used += len(header) + len(chunk)
        if used >= CORPUS_CHAR_BUDGET:
            break

    # Entity histogram, scoped to the case (entities mentioned in its reports).
    rows = conn.execute(
        "SELECT e.entity_type, e.canonical_name, COUNT(m.id) AS mentions "
        "FROM entities e JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation = ? "
        "GROUP BY e.id ORDER BY e.entity_type, mentions DESC",
        (case,),
    ).fetchall()

    by_type: dict[str, dict] = {}
    for row in rows:
        t = row["entity_type"] or "unknown"
        bucket = by_type.setdefault(t, {"count": 0, "samples": []})
        bucket["count"] += 1
        if len(bucket["samples"]) < SAMPLES_PER_TYPE:
            bucket["samples"].append(row["canonical_name"])

    # The analyst's objective (the scope anchor) — the schema must be fit to answer
    # it, not just describe the corpus. Empty string when none set.
    from investigations.storage import db as _db
    objective = _db.get_objective(conn, case)

    return {"report_text": "".join(text_parts), "entity_types": by_type,
            "report_count": len(reports), "objective": objective}


def _build_prompt(corpus: dict) -> str:
    hist_lines = []
    for t, b in sorted(corpus["entity_types"].items(), key=lambda kv: -kv[1]["count"]):
        samples = ", ".join(b["samples"][:SAMPLES_PER_TYPE])
        hist_lines.append(f"  {t}: {b['count']} entities — e.g. {samples}")
    histogram = "\n".join(hist_lines) or "  (no entities extracted yet)"

    objective = (corpus.get("objective") or "").strip()
    objective_block = (
        f"ANALYST OBJECTIVE — the schema must be scoped to answer THIS. "
        f"Bias the entity types, roles, and weights toward what this objective "
        f"needs to confirm or refute:\n  {objective}\n\n"
        if objective else "")

    return (
        objective_block
        + f"CASE REPORT TEXT ({corpus['report_count']} report(s)):\n"
        f"{corpus['report_text'][:CORPUS_CHAR_BUDGET]}\n\n"
        f"REGEX-EXTRACTED ENTITIES (crude type → count → samples):\n"
        f"{histogram}\n\n"
        "Propose the schema for THIS case. Return JSON with this exact shape:\n"
        "{\n"
        '  "domain": "<short label, e.g. crypto rug-pull network>",\n'
        '  "summary": "<1-2 lines: what this case is about>",\n'
        '  "entity_types": [{"name": "<str>", "description": "<str>"}],\n'
        '  "roles": [{"name": "<str>", "description": "<str>", "actor": <true|false>, "weight": <0-5>}],\n'
        '  "sub_roles": [{"name": "<str>", "description": "<str>"}],\n'
        '  "noise_notes": "<str>"\n'
        "}\n\n"
        "Rules:\n"
        "- 4-8 roles. ALWAYS include a role named 'noise' with actor=false.\n"
        "- At least one role must have actor=true (the human/persona buckets).\n"
        "- sub_roles describe FUNCTION for the actor roles; fit them to this domain.\n"
        "- Model what the case is ACTUALLY about; don't copy a generic template."
    )


def _clamp_weight(raw, is_actor: bool, name: str) -> int:
    """Coerce a role weight to 0-5. Defaults sensibly when missing: actors are
    prime (5), noise/source are 0, everything else mid (2)."""
    try:
        w = int(round(float(raw)))
        return max(0, min(5, w))
    except (TypeError, ValueError):
        if name in ("noise", "source", "context"):
            return 0
        return 5 if is_actor else 2


def _validate(schema: dict) -> dict:
    """Coerce an LLM/analyst schema into a usable shape. Guarantees a 'noise'
    role and at least one actor role so consolidate never gets a broken model."""
    out = {
        "domain": (schema.get("domain") or "").strip() or "uncharacterized case",
        "summary": (schema.get("summary") or "").strip(),
        "entity_types": [], "roles": [], "sub_roles": [],
        "noise_notes": (schema.get("noise_notes") or "").strip(),
    }
    for t in schema.get("entity_types") or []:
        name = (t.get("name") or "").strip()
        if name:
            out["entity_types"].append({"name": name, "description": (t.get("description") or "").strip()})
    seen_roles = set()
    for r in schema.get("roles") or []:
        name = (r.get("name") or "").strip().lower()
        if not name or name in seen_roles:
            continue
        seen_roles.add(name)
        is_actor = bool(r.get("actor"))
        out["roles"].append({"name": name, "description": (r.get("description") or "").strip(),
                             "actor": is_actor,
                             "weight": _clamp_weight(r.get("weight"), is_actor, name)})
    for s in schema.get("sub_roles") or []:
        name = (s.get("name") or "").strip().lower()
        if name:
            out["sub_roles"].append({"name": name, "description": (s.get("description") or "").strip()})
    # Guarantees.
    if "noise" not in seen_roles:
        out["roles"].append({"name": "noise", "description": "parser glitch / fragment / not a real entity", "actor": False, "weight": 0})
    if not any(r["actor"] for r in out["roles"]):
        # Nothing marked actor — promote the first non-noise role so sub_roles work.
        for r in out["roles"]:
            if r["name"] != "noise":
                r["actor"] = True
                r["weight"] = max(r.get("weight", 0), 5)
                break
    if not out["sub_roles"]:
        out["sub_roles"] = [{"name": "unknown", "description": "function unclear from evidence"}]
    return out


def actor_roles(schema: dict) -> set[str]:
    """The role names that get a sub_role (human/persona buckets)."""
    return {r["name"] for r in schema.get("roles", []) if r.get("actor")}


def role_names(schema: dict) -> list[str]:
    return [r["name"] for r in schema.get("roles", [])]


def role_weights(schema: dict) -> dict[str, int]:
    """role name → weight (0-5). Drives the threat-score ranking in analyze."""
    return {r["name"]: _clamp_weight(r.get("weight"), r.get("actor"), r["name"])
            for r in schema.get("roles", [])}


def entity_type_names(schema: dict) -> list[str]:
    return [t["name"] for t in schema.get("entity_types", [])]


def discover_schema(conn, case: str) -> dict:
    """Read the case, ask the LLM to propose a fit schema, store it as 'proposed'.
    Returns the proposed schema dict. Raises llm.LLMError on a failed LLM call.

    Seeded by the detected investigation type (if any): the schema discovery
    starts warm with a domain-appropriate role hint instead of cold."""
    seed_hint = ""
    try:
        from investigations.intake import types as types_mod
        tinfo = types_mod.get_type(conn, case)
        if tinfo:
            roles = types_mod.seed_roles_for(tinfo["type"])
            seed_hint = (f"\n\nDETECTED INVESTIGATION TYPE: {tinfo['type']} "
                         f"(confidence {tinfo.get('confidence')}). "
                         + (f"Typical roles for this type: {roles}. " if roles else "")
                         + "Use this as a STARTING POINT and adapt it to what this "
                         "case actually shows — don't force it if the evidence differs.")
    except Exception:
        seed_hint = ""
    corpus = _case_corpus(conn, case)
    raw = llm.ask_json(_build_prompt(corpus) + seed_hint, system=SYSTEM, timeout=300)
    schema = _validate(raw)
    save_schema(conn, case, schema, status="proposed")
    return schema


def save_schema(conn, case: str, schema: dict, status: str = "proposed",
                analyst: str | None = None) -> None:
    """Upsert a case's schema. status='approved' stamps approver + time."""
    schema = _validate(schema)
    payload = json.dumps(schema, ensure_ascii=False)
    existing = conn.execute(
        "SELECT case_slug FROM case_schemas WHERE case_slug = ?", (case,)).fetchone()
    if existing:
        if status == "approved":
            conn.execute(
                "UPDATE case_schemas SET schema_json = ?, status = 'approved', "
                "approved_at = CURRENT_TIMESTAMP, approved_by = ? WHERE case_slug = ?",
                (payload, analyst, case))
        else:
            conn.execute(
                "UPDATE case_schemas SET schema_json = ?, status = ?, "
                "proposed_at = CURRENT_TIMESTAMP WHERE case_slug = ?",
                (payload, status, case))
    else:
        conn.execute(
            "INSERT INTO case_schemas (case_slug, schema_json, status, proposed_at, "
            "approved_at, approved_by) VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)",
            (case, payload, status,
             "CURRENT_TIMESTAMP" if status == "approved" else None,
             analyst if status == "approved" else None))
        if status == "approved":
            conn.execute(
                "UPDATE case_schemas SET approved_at = CURRENT_TIMESTAMP WHERE case_slug = ?",
                (case,))
    conn.commit()


def get_schema(conn, case: str) -> dict | None:
    """The stored schema row for a case, or None. Shape:
    {schema: {...}, status: 'proposed'|'approved', approved_by, ...}.
    Tolerates a DB that predates the case_schemas table (read-only page path
    connects with migrate=False)."""
    import sqlite3
    try:
        row = conn.execute(
            "SELECT schema_json, status, proposed_at, approved_at, approved_by "
            "FROM case_schemas WHERE case_slug = ?", (case,)).fetchone()
    except sqlite3.OperationalError:
        return None
    if not row:
        return None
    try:
        schema = json.loads(row["schema_json"])
    except (json.JSONDecodeError, TypeError):
        return None
    return {"schema": schema, "status": row["status"], "proposed_at": row["proposed_at"],
            "approved_at": row["approved_at"], "approved_by": row["approved_by"]}


def approved_schema(conn, case: str) -> dict | None:
    """The schema ONLY if the analyst approved it — what consolidate is allowed
    to use. Returns the inner schema dict, or None when nothing is approved yet."""
    row = get_schema(conn, case)
    if row and row["status"] == "approved":
        return row["schema"]
    return None
