"""Promote an OSINT enrichment result into a graph node.

The new entity joins the GLOBAL entity pool (deduped by canonical_name), so if it
matches an actor already present in another investigation it becomes the SAME
node — an automatic cross-case bridge. It is:
  - linked to the source actor via an 'enriched' typed_relationship (a graph edge),
  - scoped into the case through a synthetic per-case 'OSINT Enrichment' report
    (entity visibility requires a mention in a report of the case),
  - added to the source actor's cluster(s) so in-cluster graph views include it,
  - seeded with a starter dossier (its own brief) from the enrichment evidence.

Promotion is analyst-driven (one call per result) — the analyst decides what
becomes a node, consistent with the analyst-as-top-authority model.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from investigations.storage import db
from investigations.ingest import extractor as _ex
from investigations import annotations as annotations_mod

# Multi-chain address shapes for _classify (PRD-2). Tron = T + 33 base58 (34 total);
# Solana = 32-44 base58. base58 excludes 0/O/I/l and has no separators, so neither
# collides with a domain (has '.') or an @handle (has '@'). Tron is matched BEFORE
# Solana because a Tron address is itself valid 34-char base58.
_TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
# TON user-friendly address (PRD-3): EQ.../UQ... = 48 base64url chars. PRD-3 owns this
# branch (PRD-2 never added TON), so a TON counterparty promotes to crypto_wallet, not
# a dead 'indicator'. 48 chars > Solana's 44 max, so it can't collide with _SOL_RE.
_TON_RE = re.compile(r"^[EU]Q[A-Za-z0-9_-]{46}$")
# ASN (PRD-5): a bare "AS15169" promotes to the `asn` type (it had a recipe but no
# producer until the asn adapter). Requires the AS prefix so a bare number isn't swept.
_ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)


class CaseDeletedError(RuntimeError):
    """A promotion targeted a case whose investigations row no longer exists.

    Raised by the promote choke point so a run that finishes after its case was
    deleted can't scope an orphan node/report into the dead slug (which the
    investigations backfill would then resurrect into a phantom case + graph).
    """


def _host(url: str) -> str:
    try:
        net = urlparse(url if "://" in url else "//" + url).netloc.lower()
    except Exception:
        return ""
    return net[4:] if net.startswith("www.") else net


def _candidate_name(result: dict) -> str:
    """The node name to promote. For a URL result we pull the meaningful pivot:
    a Telegram channel keeps its handle (t.me/<chan>), everything else collapses
    to the host (the domain/IP). No URL -> the result title."""
    url = (result.get("url") or "").strip()
    if url:
        tg = _ex.TELEGRAM_RE.search(url)
        if tg:
            return f"t.me/{tg.group(1).lower()}"
        return _host(url) or url[:120]
    return (result.get("title") or "").strip()[:120]


def _classify(name: str) -> str:
    """Precise entity type, using the SAME patterns the ingest pipeline uses, so
    an enrichment node reads as ip / domain / email / hash / telegram_channel —
    not a vague 'indicator'."""
    n = (name or "").strip()
    if not n:
        return "indicator"
    if n.lower().startswith(("t.me/", "telegram.me/")):
        return "telegram_channel"
    if _ASN_RE.fullmatch(n):           # AS15169 -> asn (PRD-5, closes the asn-orphan)
        return "asn"
    if _ex.IPV4_RE.fullmatch(n):
        return "ip"
    if _ex.SHA256_RE.fullmatch(n):
        return "hash_sha256"
    if _ex.MD5_RE.fullmatch(n):
        return "hash_md5"
    if _ex.WALLET_RE.fullmatch(n):
        return "crypto_wallet"
    if _TRON_RE.fullmatch(n):          # Tron T-address (before Solana: also 34-char base58)
        return "crypto_wallet"
    if _TON_RE.fullmatch(n):           # TON EQ.../UQ... (48 base64url) — PRD-3
        return "crypto_wallet"
    if _ex.EMAIL_RE.fullmatch(n):
        return "email"
    if n.lower().startswith(("http://", "https://")):
        return "url"
    if _SOL_RE.fullmatch(n):           # Solana base58 32-44; after email/url, before handle/domain
        return "crypto_wallet"
    if _ex.HANDLE_RE.fullmatch(n):
        return "handle"
    if _ex.DOMAIN_RE.fullmatch(n) or (" " not in n and "/" not in n and "." in n):
        return "domain"
    return "indicator"


# An adapter may pin the type for a child row whose type _classify can't derive from the
# bare string (OpenCorporates officer -> person, company -> org; dns_deep mail provider ->
# org). promote_result honors this hint (PRD-6 / audit O-7 / correction #4).
_PROMOTE_AS_ALLOWED = {"person", "org", "email", "domain", "ip", "handle",
                       "crypto_wallet", "asn", "phone", "indicator"}


def _promote_as_hint(raw_json) -> str | None:
    """An adapter's explicit entity-type pin for a child row, if present and allowed."""
    if isinstance(raw_json, str):
        try:
            raw_json = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError):
            return None
    if not isinstance(raw_json, dict):
        return None
    pa = (raw_json.get("promote_as") or "").strip().lower()
    return pa if pa in _PROMOTE_AS_ALLOWED else None


def _synthetic_report(conn, case: str | None, kind: str = "enrichment") -> int:
    """Get-or-create the synthetic per-case report that scopes analyst-added nodes
    into the case (mentions need a report; this is that report). kind is the
    report source_type: 'enrichment' (promoted from a lookup) or 'manual'
    (analyst typed it in)."""
    # A specific case that no longer exists must never be written into — an orphan
    # report under a deleted slug is what the investigations backfill resurrects.
    # (case=None is the legitimate unscoped/global pool, so it is exempt.)
    if case and not conn.execute(
            "SELECT 1 FROM investigations WHERE slug = ?", (case,)).fetchone():
        raise CaseDeletedError(case)
    slug = case or "global"
    src_hash = f"{kind}::{slug}"
    label = "OSINT Enrichment" if kind == "enrichment" else "Analyst-added nodes"
    row = conn.execute("SELECT id FROM reports WHERE source_hash = ?", (src_hash,)).fetchone()
    if row:
        return row["id"]
    return db.insert_report(
        conn, source_path=f"<{kind}:{slug}>", source_hash=src_hash,
        source_type=kind, title=f"{label} — {slug}", investigation=case, raw_text="")


def _enrichment_report(conn, case: str | None) -> int:
    return _synthetic_report(conn, case, kind="enrichment")


def add_manual_node(conn, name: str, entity_type: str, *, analyst: str = "anonymous",
                    thumbnail: str | None = None, link_to: int | None = None,
                    case: str | None = None) -> dict:
    """Analyst-created node: pick the name + type + optional thumbnail, optionally
    linked to an existing node. Joins the global entity pool (so it bridges cases
    by name) and is scoped into the case via the synthetic 'manual' report."""
    name = (name or "").strip()
    if not name:
        return {"error": "name is required"}
    etype = (entity_type or "indicator").strip() or "indicator"
    if not case and link_to:
        case = _primary_case(conn, link_to)
    rep_id = _synthetic_report(conn, case, kind="manual")

    from investigations import store
    # store.entity_upserted preserves the exact prior semantics: existing node
    # by canonical_name returns its id with first-stamp-wins provenance
    # backfill; a new node is created with provenance=analyst. The analyst
    # actor keeps the top-authority admission bypass this path always had.
    eid = store.apply_mutation(conn, store.entity_upserted(
        case, name, etype, rep_id, actor=f"analyst:{analyst}",
        provenance="analyst"))["entity_id"]
    db.add_mention(conn, eid, rep_id, name, "analyst-added node")
    if thumbnail and thumbnail.strip():
        store.apply_mutation(conn, store.analyst_annotated(
            case, eid, {"thumbnail": thumbnail.strip()[:2000]},
            actor=f"analyst:{analyst}"))
    if link_to and link_to != eid:
        # Controlled vocabulary: 'linked' is not a REL_VOCAB term — normalize the
        # analyst-link label so a manual node can't write a free-form edge (issue
        # rel-vocab-validator). 'linked' -> 'linked_to'.
        from investigations.enrich.rel_vocab import normalize_rel
        manual_rel = normalize_rel("linked") or "linked_to"
        store.apply_mutation(conn, store.edge_upserted(
            case, link_to, eid, manual_rel, actor=f"analyst:{analyst}",
            confidence="high", evidence="analyst-added", provenance="analyst"))
        for row in conn.execute(
            "SELECT cluster_id FROM cluster_members WHERE entity_id = ?", (link_to,)).fetchall():
            conn.execute("INSERT OR IGNORE INTO cluster_members (cluster_id, entity_id) "
                         "VALUES (?, ?)", (row["cluster_id"], eid))
    conn.commit()
    try:
        from investigations import analyze
        analyze.compute_threat_scores(conn)
    except Exception:
        pass
    return {"ok": True, "entity_id": eid, "name": name, "type": etype,
            "thumbnail": (thumbnail.strip() if thumbnail else None),
            "case": case, "linked_to": link_to if (link_to and link_to != eid) else None,
            "cross_case": _other_cases(conn, eid, case)}


def _primary_case(conn, entity_id: int) -> str | None:
    row = conn.execute(
        "SELECT r.investigation FROM mentions m JOIN reports r ON r.id = m.report_id "
        "WHERE m.entity_id = ? AND r.investigation IS NOT NULL "
        "GROUP BY r.investigation ORDER BY COUNT(*) DESC LIMIT 1", (entity_id,)).fetchone()
    return row["investigation"] if row else None


def _other_cases(conn, entity_id: int, case: str | None) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT r.investigation FROM mentions m JOIN reports r ON r.id = m.report_id "
        "WHERE m.entity_id = ? AND r.investigation IS NOT NULL AND r.investigation != ?",
        (entity_id, case or "")).fetchall()
    return sorted({r[0] for r in rows if r[0]})


def _enrich_rel_type(provider: str, mode: str = "", hint: str = "") -> str:
    """A meaningful edge label for what an enrichment actually FOUND — never the generic
    'enriched', which tells an investigator nothing. The result summary rides along as the
    edge's evidence (shown when the edge is opened), so the label says WHAT and the
    evidence says the detail. The candidate label is passed through the controlled
    vocabulary (normalize_rel) so an enrichment edge can never write a free-form label
    outside REL_VOCAB (issue rel-vocab-validator)."""
    from investigations.enrich.rel_vocab import normalize_rel
    return normalize_rel(_enrich_rel_candidate(provider, mode, hint), hint) or "linked_to"


def _enrich_rel_candidate(provider: str, mode: str = "", hint: str = "") -> str:
    """The raw provider→label heuristic (pre-normalization)."""
    p = (provider or "").lower()
    m = (mode or "").lower()
    h = (hint or "").lower()
    if p == "crtsh":
        return "shares_cert"
    if p == "infra":
        if m == "dns" or "resolves" in h or h.startswith(("a ", "aaaa ", "ns ", "mx ", "cname")):
            return "resolves_to"
        if m == "reverse":
            return "reverse_dns"
        return "registered_by"
    if p == "whoisxml":
        if m == "dns_history":
            return "prior_resolution"
        # Shared NS is infrastructure co-location, NOT registrant identity —
        # same_registrant here would launder a weak pivot into attribution.
        if m == "reverse_ns":
            return "uses_nameserver"
        return "same_registrant"
    if p == "ipgeo":
        return "geolocated"
    if p in ("virustotal", "abusech"):
        return "flagged_ioc"
    if p in ("shodan", "censys"):
        return "exposed_service"
    if p == "gravatar":
        return "linked_account"
    if p == "breach":
        return "breach_exposure"
    if p == "wallet":
        return "transacts_with"
    if p == "username":
        return "account_found"
    if p in ("perplexity", "tavily", "exa", "jina", "apify", "social", "reddit"):
        return "linked_via_search"
    if p == "agent":
        # The agent's own claim text says what the relationship IS — use it, don't fall
        # back to a meaningless 'discovered_with'.
        if "backend" in h or "api domain" in h: return "backend_api"
        if "payment" in h: return "payment_endpoint"
        if "slots" in h or "api endpoint" in h or "/api/" in h: return "api_endpoint"
        if "sister domain" in h or "same registrant" in h: return "same_registrant"
        if "cdn" in h: return "cdn_host"
        if "operate" in h or "operator" in h: return "operated_by"
        if "registr" in h: return "registered_by"
        return "linked_to"
    return ("found_via_" + p) if p else "related"


def promote_result(conn, result_id: int, *, analyst: str = "anonymous") -> dict:
    """Turn one enrichment result into a node connected to the source actor."""
    r = conn.execute(
        "SELECT er.id, er.title, er.summary, er.url, er.raw_json, er.decision, "
        "run.entity_id AS src_entity_id, "
        "run.provider_slug, run.mode, run.investigation "
        "FROM enrichment_results er JOIN enrichment_runs run ON run.id = er.run_id "
        "WHERE er.id = ?", (result_id,)).fetchone()
    if not r:
        return {"error": "result not found"}
    # Refuse to promote a finding the analyst already REJECTED (Codex gtl-2
    # adversarial): a stale button / retry / direct call must not resurrect a
    # rejected finding into the graph and flip its audit decision to accepted.
    if r["decision"] == "rejected":
        return {"error": "finding was rejected — clear the rejection before promoting",
                "result_id": result_id}
    result = dict(r)
    name = _candidate_name(result)
    if not name:
        return {"error": "nothing promotable in this result (no url or title)"}

    # A result must not become a node named after the TOOL that produced it (crt.sh,
    # whois, dns…). "crt.sh" classifies as a domain so it slips past the summary guard —
    # block it explicitly. The finding belongs in the dossier, not as a fake entity.
    _TOOL_NAMES = {"crt.sh", "crtsh", "whois", "dns", "rdap", "virustotal", "abuse.ch",
                   "abusech", "shodan", "censys", "ipgeo", "gravatar", "perplexity",
                   "tavily", "exa", "jina", "whoisxml", "reverse-whois"}
    if name.lower().strip() in _TOOL_NAMES:
        return {"error": f"'{name}' is the lookup tool, not a finding — nothing to promote"}

    # Don't promote a summary/answer into a node — only real indicators. A result
    # with no source link whose name isn't a recognizable indicator (it's the
    # provider's prose answer, e.g. 'Perplexity sonar') is rejected.
    etype = _classify(name)
    # Honor an adapter's explicit type pin (officer -> person, company/provider -> org).
    _hint = _promote_as_hint(result.get("raw_json"))
    if _hint:
        etype = _hint
    if not (result.get("url") or "").strip() and etype in ("indicator", "person", "person_candidate"):
        return {"error": "That's a summary, not an indicator — promote a result that has a source link "
                         "(domain / IP / URL), or open the actor's dossier to add it as a note."}

    src_id = result["src_entity_id"]
    case = result["investigation"] or (_primary_case(conn, src_id) if src_id else None)
    rep_id = _enrichment_report(conn, case)
    provider = result["provider_slug"]

    from investigations import store
    # Analyst actor: promote IS the analyst accepting a gated finding — the
    # finding already cleared its gate at landing; promotion never re-gated.
    eid = store.apply_mutation(conn, store.entity_upserted(
        case, name, etype, rep_id, actor=f"analyst:{analyst}",
        provenance=f"enrich:{provider}"))["entity_id"]
    db.add_mention(conn, eid, rep_id, name, f"via {provider} enrichment")

    # Typed properties from the result's raw_json land on the promoted node, so its facts
    # are queryable fields, not just dossier prose. (issue node-properties-table)
    import json as _json
    from investigations.enrich import properties as _props
    try:
        _raw = _json.loads(result["raw_json"]) if result.get("raw_json") else None
    except (TypeError, _json.JSONDecodeError):
        _raw = None
    if _raw:
        _props.extract_and_upsert(conn, eid, provider, _raw)

    linked = False
    if src_id and src_id != eid:
        ev = (result.get("summary") or result.get("title") or "")[:200]
        # A label that says what the lookup FOUND (resolves_to / same_registrant / shares_cert
        # / flagged_ioc …) instead of the useless 'enriched'. Evidence carries the detail.
        rel = _enrich_rel_type(provider, result.get("mode"),
                               result.get("summary") or result.get("title"))
        db.add_relationship(conn, src_id, eid, rel, rep_id, evidence=ev, confidence=0.6)
        store.apply_mutation(conn, store.edge_upserted(
            case, src_id, eid, rel, actor=f"analyst:{analyst}",
            evidence=ev, provenance=f"enrich:{provider}"))
        # Carry the new node into the source actor's cluster(s) so in-cluster graph
        # views surface it next to the actor it came from.
        for row in conn.execute(
            "SELECT cluster_id FROM cluster_members WHERE entity_id = ?", (src_id,)).fetchall():
            conn.execute("INSERT OR IGNORE INTO cluster_members (cluster_id, entity_id) "
                         "VALUES (?, ?)", (row["cluster_id"], eid))
        linked = True

    conn.execute("UPDATE enrichment_results SET extracted_entity_id = ? WHERE id = ?",
                 (eid, result_id))

    # Seed a starter brief (its own dossier) from the enrichment evidence.
    ann = annotations_mod.get(conn, eid)
    if not ann.get("dossier_override"):
        brief = f"**Source:** {provider} enrichment\n\n" + (
            result.get("summary") or result.get("title") or "").strip()
        if result.get("url"):
            brief += f"\n\n[source]({result['url']})"
        annotations_mod.set_dossier_override(conn, eid, brief.strip(),
                                             author=f"{provider} (enrichment)")
    conn.commit()

    # Capture the result's raw response as point-in-time evidence on the PROMOTED
    # node (ea-1) — promotion can target a DIFFERENT entity than the run's source,
    # so this is the only hook that grounds the promoted node's proof. Covers manual
    # promote AND the agent path (land_findings calls promote_result). Wrapped: an
    # evidence-capture failure must never unwind the promotion.
    try:
        if result.get("raw_json"):
            from investigations import evidence as _evidence
            _evidence.capture_artifact(
                conn, eid, kind=f"promote:{provider}",
                content=result["raw_json"], run_id=None, source_url=result.get("url"))
            conn.commit()
    except Exception:
        conn.rollback()

    # Record the analyst's ACCEPT decision (gtl-2): the decision column + a manual
    # claim on the claims spine, so "analyst vouched for this node" is queryable
    # audit, not just an implicit side effect of promotion. Wrapped: a decision-write
    # failure must NEVER unwind the promotion the analyst already asked for.
    try:
        _set_decision(conn, result_id, "accepted")
        _record_decision_claim(conn, eid, "accepted", analyst, evidence=name)
        conn.commit()
    except Exception:
        conn.rollback()

    try:
        from investigations import analyze
        analyze.compute_threat_scores(conn)
    except Exception:
        pass

    return {"ok": True, "entity_id": eid, "name": name, "type": etype,
            "case": case, "linked_to": src_id if linked else None,
            "cross_case": _other_cases(conn, eid, case)}


def _record_decision_claim(conn, entity_id: int, decision: str, analyst: str,
                           evidence: str | None = None) -> None:
    """Append an analyst promotion/rejection decision as a manual claim on the
    claims spine. Lightweight by design — it does NOT reproject the graph or
    rescore (a decision audit fact maps to no role/edge); it only records that the
    analyst made this call, attributed + timestamped. Idempotent via the claims
    UNIQUE constraint (report_id NULL)."""
    if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='claims'").fetchone():
        return
    # Explicit existence check, NOT INSERT OR IGNORE: report_id and object_entity_id
    # are NULL here, and SQLite treats NULLs as DISTINCT in a UNIQUE constraint, so
    # the constraint would never fire and retries/double-submits would duplicate the
    # claim (Codex gtl-2 finding). Check-then-insert is the idempotency guard.
    exists = conn.execute(
        "SELECT 1 FROM claims WHERE entity_id = ? AND predicate = 'promotion_decision' "
        "AND value = ? AND source = 'manual'", (entity_id, decision)).fetchone()
    if exists:
        return
    conn.execute(
        "INSERT INTO claims (entity_id, report_id, claim_type, predicate, "
        " value, object_entity_id, confidence, evidence, status, source, author) "
        "VALUES (?, NULL, 'attribute', 'promotion_decision', ?, NULL, 'analyst', ?, "
        " 'active', 'manual', ?)",
        (entity_id, decision, evidence or "", analyst))


def reject_result(conn, result_id: int, *, analyst: str = "anonymous",
                  reason: str | None = None) -> dict:
    """Analyst REJECTS an enrichment finding (gtl-2): record decision='rejected' +
    a rejection claim on the source actor entity, so a discarded finding leaves an
    audit trail (today only volume 'revert' existed, with no analyst attribution).
    Never promotes a node. Idempotent — re-rejecting is a no-op."""
    r = conn.execute(
        "SELECT er.id, er.title, run.entity_id AS src_entity_id "
        "FROM enrichment_results er JOIN enrichment_runs run ON run.id = er.run_id "
        "WHERE er.id = ?", (result_id,)).fetchone()
    if not r:
        return {"error": "result not found"}
    prior = conn.execute("SELECT decision, extracted_entity_id FROM enrichment_results "
                         "WHERE id = ?", (result_id,)).fetchone()
    if prior and prior["decision"] == "rejected":
        return {"ok": True, "already": "rejected", "result_id": result_id}
    # Guard against rejecting an already-PROMOTED finding (Codex gtl-2 finding):
    # the graph node/edge would survive while the audit said 'rejected'. The analyst
    # must revert the promotion first; rejection is for un-promoted findings only.
    if prior and (prior["decision"] == "accepted" or prior["extracted_entity_id"]):
        return {"error": "finding already promoted — revert the promotion before rejecting",
                "result_id": result_id}
    _set_decision(conn, result_id, "rejected")
    # The rejection claim attaches to the SOURCE actor (the entity whose run produced
    # the finding) when there is one — a rejected finding never gets its own node.
    if r["src_entity_id"]:
        ev = (reason or r["title"] or "").strip()
        _record_decision_claim(conn, r["src_entity_id"], "rejected", analyst, evidence=ev)
    conn.commit()
    return {"ok": True, "rejected": True, "result_id": result_id,
            "source_entity_id": r["src_entity_id"]}


# ----------------------------------------------------------------------------------
# Volume decision: an adapter can flag a large result `needs_decision` (the FULL set is
# captured in raw_json, nothing dropped). The analyst then chooses what to do with it —
# we never cap evidence. Actions: revert / open in a new cluster / pick a subset / reason.
# ----------------------------------------------------------------------------------

# raw_json keys an adapter may use for its captured list (priority order).
_LIST_KEYS = ("counterparties", "domains", "hostnames", "found", "items", "accounts")


def _materializable_items(raw: dict) -> list[str]:
    """The full captured list out of a result's raw_json, as bare strings (addresses /
    domains / urls). Tries known keys, then the first list-of-strings value. Lossless —
    this is the evidence the analyst chose NOT to auto-spray."""
    if not isinstance(raw, dict):
        return []
    candidates = [raw.get(k) for k in _LIST_KEYS]
    candidates += [v for v in raw.values() if isinstance(v, list)]
    for v in candidates:
        if not isinstance(v, list) or not v:
            continue
        out = []
        for it in v:
            if isinstance(it, str) and it.strip():
                out.append(it.strip())
            elif isinstance(it, dict):
                s = (it.get("url") or it.get("address") or it.get("domain")
                     or it.get("name") or "").strip()
                if s:
                    out.append(s)
        if out:
            return out
    return []


def _unique_cluster_name(conn, base: str) -> str:
    name = base[:120]
    if not conn.execute("SELECT 1 FROM clusters WHERE name = ?", (name,)).fetchone():
        return name
    i = 2
    while conn.execute("SELECT 1 FROM clusters WHERE name = ?",
                       (f"{name} ({i})",)).fetchone():
        i += 1
    return f"{name} ({i})"


def _result_with_run(conn, result_id: int):
    return conn.execute(
        "SELECT er.id, er.raw_json, er.run_id, run.entity_id AS src_entity_id, "
        "run.provider_slug, run.investigation "
        "FROM enrichment_results er JOIN enrichment_runs run ON run.id = er.run_id "
        "WHERE er.id = ?", (result_id,)).fetchone()


def _set_decision(conn, result_id: int, decision: str) -> None:
    """Record the analyst's volume decision on the result (idempotent column add)."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(enrichment_results)")}
    if "decision" not in cols:
        conn.execute("ALTER TABLE enrichment_results ADD COLUMN decision TEXT")
    conn.execute("UPDATE enrichment_results SET decision = ? WHERE id = ?",
                 (decision, result_id))


def materialize_to_cluster(conn, result_id: int, *, subset=None, label: str | None = None,
                           analyst: str = "anonymous") -> dict:
    """'Open in a new cluster' — materialize a large result's captured items (or a
    chosen subset) into a NEW collapsible cluster in the case. Each item becomes a node
    linked to the source actor; all join one cluster. subset: a list of item strings,
    or an int N (take the first N). None = the whole set."""
    import json as _json
    r = _result_with_run(conn, result_id)
    if not r:
        return {"error": "result not found"}
    # Idempotency: a result already decided must not build a SECOND cluster (a double-click
    # or a retry after a slow response would otherwise duplicate the whole set).
    prior = conn.execute("SELECT decision FROM enrichment_results WHERE id = ?",
                         (result_id,)).fetchone()
    if prior and prior["decision"]:
        return {"error": f"already decided ({prior['decision']}) — revert it first to redo"}
    try:
        raw = _json.loads(r["raw_json"]) if r["raw_json"] else {}
    except (TypeError, _json.JSONDecodeError):
        raw = {}
    items = _materializable_items(raw)
    if not items:
        return {"error": "nothing to materialize (no captured list in this result)"}
    if subset is not None:
        if isinstance(subset, int):
            items = items[:max(0, subset)]
        else:
            keep = set(subset)
            items = [it for it in items if it in keep]
        if not items:
            return {"error": "subset matched none of the captured items"}

    src_id = r["src_entity_id"]
    case = r["investigation"] or (_primary_case(conn, src_id) if src_id else None)
    rep_id = _enrichment_report(conn, case)
    provider = r["provider_slug"]
    src_name = ""
    if src_id:
        row = conn.execute("SELECT canonical_name FROM entities WHERE id = ?",
                           (src_id,)).fetchone()
        src_name = row["canonical_name"] if row else ""

    base = label or ((f"{src_name} · {provider}" if src_name else provider) + " cluster")
    cname = _unique_cluster_name(conn, base)
    cur = conn.execute(
        "INSERT INTO clusters (name, kind, description) VALUES (?, 'enrichment', ?)",
        (cname, f"Materialized from {provider} result #{result_id} "
                f"({len(items)} items{', subset' if subset is not None else ''})."))
    cluster_id = cur.lastrowid
    if src_id:
        conn.execute("INSERT OR IGNORE INTO cluster_members (cluster_id, entity_id) "
                     "VALUES (?, ?)", (cluster_id, src_id))

    added = 0
    from investigations import store
    for it in items:
        etype = _classify(it)
        eid = store.apply_mutation(conn, store.entity_upserted(
            case, it, etype, rep_id, actor=f"analyst:{analyst}",
            provenance=f"enrich:{provider}"))["entity_id"]
        db.add_mention(conn, eid, rep_id, it, f"via {provider} enrichment (materialized)")
        conn.execute("INSERT OR IGNORE INTO cluster_members (cluster_id, entity_id) "
                     "VALUES (?, ?)", (cluster_id, eid))
        if src_id and src_id != eid:
            rel = _enrich_rel_type(provider)
            db.add_relationship(conn, src_id, eid, rel, rep_id,
                                evidence=f"materialized from {provider}", confidence=0.6)
            store.apply_mutation(conn, store.edge_upserted(
                case, src_id, eid, rel, actor=f"analyst:{analyst}",
                evidence=f"from {provider}: {', '.join(items[:6])}"[:200],
                provenance=f"enrich:{provider}"))
        added += 1

    _set_decision(conn, result_id, f"cluster:{cluster_id}")
    conn.commit()
    try:
        from investigations import analyze
        analyze.compute_threat_scores(conn)
    except Exception:
        pass
    return {"ok": True, "cluster_id": cluster_id, "cluster_name": cname,
            "added": added, "case": case, "subset": subset is not None}


def revert_result(conn, result_id: int) -> dict:
    """'Revert' — discard a result flagged for decision. Nothing was materialized, so
    deleting the result row (and the run if it was the only one) is clean."""
    r = conn.execute("SELECT run_id FROM enrichment_results WHERE id = ?",
                     (result_id,)).fetchone()
    if not r:
        return {"error": "result not found"}
    run_id = r["run_id"]
    conn.execute("DELETE FROM enrichment_results WHERE id = ?", (result_id,))
    remaining = conn.execute(
        "SELECT COUNT(*) AS n FROM enrichment_results WHERE run_id = ?",
        (run_id,)).fetchone()["n"]
    if remaining == 0:
        conn.execute("DELETE FROM enrichment_runs WHERE id = ?", (run_id,))
    conn.commit()
    return {"ok": True, "reverted": True, "run_deleted": remaining == 0}


def mark_reasoned(conn, result_id: int) -> dict:
    """'Reason on it' — keep the full set in raw_json as evidence, materialize nothing.
    Clears the pending-decision state so the warning stops nagging; the data stays
    queryable by the case Q&A / analysis."""
    if not conn.execute("SELECT 1 FROM enrichment_results WHERE id = ?",
                        (result_id,)).fetchone():
        return {"error": "result not found"}
    _set_decision(conn, result_id, "reason")
    conn.commit()
    return {"ok": True, "reasoned": True}
