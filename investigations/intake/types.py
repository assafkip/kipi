"""Investigation-type detection — deterministic-first, LLM only on a tie.

The Understand step proposes a per-case SCHEMA (the fine model). This is the
coarse layer above it: a stable TYPE label (crypto-fraud, disinfo, hacktivist…)
identified the moment evidence lands, from signals already in the case — keyword
hits in the report text + the histogram of regex-extracted entity types. The
label drives the /cases badge and SEEDS the schema discovery so Understand starts
warm instead of cold.

Hybrid taxonomy: a fixed seed list for stable labels, with an `other:<freeform>`
escape hatch when nothing fits (so the per-case philosophy still holds). The LLM
is consulted ONLY when the deterministic signal is thin or two types tie.
"""
import json

from investigations.llm import client as llm

# Fixed seed taxonomy. Each type: keyword signals (substring → weight) + entity
# affinities (regex entity_type → weight, applied to the case's histogram).
TAXONOMY = {
    "crypto-fraud": {
        "keywords": {"wallet": 3, "token": 2, "rug": 3, "rugpull": 3, "drainer": 3,
                     "drain": 2, "blockchain": 2, "ethereum": 2, "solana": 2, "crypto": 2,
                     "defi": 2, "airdrop": 2, "metamask": 3, "walletconnect": 3, "mint": 1,
                     "usdt": 2, "binance": 1, "etherscan": 2, "smart contract": 2, "giveaway": 2,
                     "presale": 2, "doubler": 3, "advance-fee": 2, "seed phrase": 3, "tron": 2,
                     "xrp": 1, "phantom": 2, "tornado": 2, "mixer": 2, "streamjack": 3,
                     "hijacked": 1, "stealer": 2, "deepfake": 2, "googletagmanager": 2, "gtag": 2},
        "entities": {"crypto_wallet": 6, "tracking_tag": 5, "walletconnect_id": 6,
                     "tech_stack": 2, "domain": 1},
        "seed_roles": "promoter/shiller, developer, wallet, scam_domain, drainer_kit, exchange, victim, noise",
    },
    "disinfo": {
        "keywords": {"disinformation": 3, "propaganda": 3, "narrative": 2, "influence operation": 3,
                     "amplif": 2, "sockpuppet": 3, "troll": 2, "coordinated inauthentic": 3,
                     "bot network": 3, "fake news": 2, "astroturf": 3, "persona": 1},
        "entities": {"handle": 2, "url": 1},
        "seed_roles": "persona, amplifier, outlet, narrative, bot_account, source, noise",
    },
    "hacktivist": {
        "keywords": {"deface": 3, "ddos": 3, "hacktivist": 3, "opisrael": 2, "anonymous": 1,
                     "claim of responsibility": 2, "crew": 2, "breach": 1, "leak": 1,
                     "telegram channel": 2, "defacement": 3, "cyber army": 2},
        "entities": {"telegram_channel": 4, "handle": 2},
        "seed_roles": "operator, channel, ioc, infra, source, noise",
    },
    "financial-fraud": {
        "keywords": {"money launder": 3, "shell company": 3, "wire transfer": 2, "ponzi": 3,
                     "pig butchering": 3, "romance scam": 3, "invoice": 1, "bank account": 2,
                     "fraud": 2, "mule": 2, "kyc": 1, "remittance": 2},
        "entities": {"email": 1, "phone": 2},
        "seed_roles": "operator, facilitator, mule, shell_entity, account, victim, source, noise",
    },
    "intrusion-apt": {
        "keywords": {"malware": 3, "c2": 3, "command and control": 3, "payload": 2, "exploit": 2,
                     "cve": 2, "backdoor": 3, "threat actor": 2, "implant": 3, "ttp": 2,
                     "phishing": 2, "ransomware": 3, "apt": 3},
        "entities": {"ip": 3, "hash_sha256": 3, "hash_md5": 2, "domain": 2},
        "seed_roles": "threat_actor, malware, c2_infra, victim, ioc, source, noise",
    },
    "person-of-interest": {
        "keywords": {"person of interest": 3, "background check": 2, "dossier": 2, "skip trace": 3,
                     "alias": 1, "date of birth": 2, "residence": 1, "employer": 1,
                     "next of kin": 2, "locate": 1, "subject": 1},
        "entities": {"person": 3, "phone": 2, "email": 1},
        "seed_roles": "subject, associate, address, account, employer, source, noise",
    },
}

FLOOR = 4.0          # below this, deterministic signal is too thin → ask the LLM
MARGIN = 1.25        # winner must beat runner-up by this ratio, else → LLM tiebreak


def score_signals(text: str, histogram: dict[str, int]) -> dict[str, float]:
    """Deterministic per-type score from keyword hits + the entity histogram."""
    low = (text or "").lower()
    scores: dict[str, float] = {}
    for tname, sig in TAXONOMY.items():
        s = 0.0
        for kw, w in sig["keywords"].items():
            hits = low.count(kw)
            if hits:
                s += w * min(hits, 4)        # cap so one spammy word can't dominate
        for etype, w in sig["entities"].items():
            s += w * min(histogram.get(etype, 0), 20)
        scores[tname] = round(s, 2)
    return scores


def _case_signals(conn, case: str) -> tuple[str, dict[str, int]]:
    rows = conn.execute(
        "SELECT raw_text FROM reports WHERE investigation = ? ORDER BY ingested_at LIMIT 50",
        (case,)).fetchall()
    text = "\n".join((r["raw_text"] or "")[:20000] for r in rows)[:120000]
    hist = {}
    for r in conn.execute(
        "SELECT e.entity_type AS t, COUNT(*) AS n FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id JOIN reports rp ON rp.id = m.report_id "
        "WHERE rp.investigation = ? GROUP BY e.entity_type", (case,)):
        hist[r["t"]] = r["n"]
    return text, hist


def _llm_tiebreak(text: str, scores: dict) -> str:
    """Consulted only when deterministic signal is thin/ambiguous. May return a
    fixed type name OR 'other:<freeform label>' (the hybrid escape hatch)."""
    options = ", ".join(TAXONOMY.keys())
    try:
        resp = llm.ask_json(
            f"Investigation evidence (excerpt):\n{text[:8000]}\n\n"
            f"Deterministic signal scores: {json.dumps(scores)}\n\n"
            f"What kind of investigation is this? Choose ONE of these types: {options}. "
            "If none fits, answer 'other:<2-4 word label>'. "
            'Return JSON: {"type": "<type or other:label>", "why": "<one line>"}',
            timeout=120, model=llm.CLASSIFY_MODEL)  # type detection is classification (PRD-02)
        t = (resp.get("type") or "").strip()
        if t in TAXONOMY or t.startswith("other:"):
            return t
    except llm.LLMError:
        pass
    # Fall back to the deterministic winner (or 'general' if truly empty).
    return max(scores, key=scores.get) if any(scores.values()) else "general"


def detect(conn, case: str, use_llm: bool = True) -> dict:
    """Identify the investigation type for a case and store it (status 'proposed'
    unless already approved). Deterministic winner unless thin/tied → LLM."""
    text, hist = _case_signals(conn, case)
    scores = score_signals(text, hist)
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    top, top_score = ranked[0]
    runner = ranked[1][1] if len(ranked) > 1 else 0.0
    thin = top_score < FLOOR
    tied = runner > 0 and (top_score / max(runner, 0.01)) < MARGIN

    method = "deterministic"
    if (thin or tied) and use_llm:
        top = _llm_tiebreak(text, scores)
        method = "llm-tiebreak"
    elif thin:
        top = "general"

    total = sum(scores.values()) or 1.0
    base = scores.get(top, 0.0) if top in scores else top_score
    confidence = round(min(0.95, max(0.2, base / total)), 2)

    # Don't clobber an analyst-approved type.
    cur = conn.execute(
        "SELECT type_status FROM investigations WHERE slug = ?", (case,)).fetchone()
    if cur and cur["type_status"] == "approved":
        return {"case": case, "type": conn.execute(
            "SELECT investigation_type FROM investigations WHERE slug=?", (case,)).fetchone()[0],
            "status": "approved", "unchanged": True}

    conn.execute(
        "UPDATE investigations SET investigation_type = ?, type_confidence = ?, "
        "type_scores = ?, type_status = 'proposed' WHERE slug = ?",
        (top, confidence, json.dumps(dict(ranked)), case))
    conn.commit()
    return {"case": case, "type": top, "confidence": confidence,
            "method": method, "scores": dict(ranked), "status": "proposed"}


def seed_roles_for(type_name: str) -> str:
    """A one-line role hint to seed schema discovery for a known type."""
    base = (type_name or "").split(":")[0]
    sig = TAXONOMY.get(base)
    return sig["seed_roles"] if sig else ""


def get_type(conn, case: str) -> dict | None:
    row = conn.execute(
        "SELECT investigation_type, type_confidence, type_status, type_scores "
        "FROM investigations WHERE slug = ?", (case,)).fetchone()
    if not row or not row["investigation_type"]:
        return None
    try:
        scores = json.loads(row["type_scores"]) if row["type_scores"] else {}
    except (TypeError, json.JSONDecodeError):
        scores = {}
    return {"type": row["investigation_type"], "confidence": row["type_confidence"],
            "status": row["type_status"], "scores": scores}


def set_type(conn, case: str, type_name: str, status: str = "approved") -> None:
    conn.execute(
        "UPDATE investigations SET investigation_type = ?, type_status = ? WHERE slug = ?",
        (type_name.strip(), status, case))
    conn.commit()
