"""Runner — bridge between OSINT adapters and SQLite persistence.

Inserts an enrichment_runs row, calls the adapter, persists results, updates
the run status + cost. Used by both the CLI and the webapp.
"""
from __future__ import annotations

import json
import sqlite3
import time
import traceback
from datetime import datetime

from investigations.enrich.base import (
    EnrichmentError, EnrichmentResult, NotConfiguredError,
)
from investigations.enrich.registry import get_adapter


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def start_run(conn, provider_slug: str, query: str, *,
              entity_id: int | None = None, mode: str | None = None,
              investigation: str | None = None) -> int:
    try:
        cur = conn.execute(
            "INSERT INTO enrichment_runs "
            "(entity_id, provider_slug, query, mode, status, investigation) "
            "VALUES (?, ?, ?, ?, 'queued', ?)",
            (entity_id, provider_slug, query, mode, investigation),
        )
    except sqlite3.IntegrityError as exc:
        # This INSERT carries two FKs: provider_slug -> osint_providers(slug)
        # and entity_id -> entities(id). Disambiguate before labeling. An
        # unregistered provider is the catalog gap this guards: it used to
        # bubble out of api_enrich_run as an unhandled 500, which the graph
        # rendered as the misleading "Could not reach the server." Convert it
        # to a typed EnrichmentError so run_and_persist can fail soft. A bad
        # entity_id (or any other constraint) is a DIFFERENT bug and must NOT
        # be mislabeled as a provider-catalog miss, so re-raise it untouched.
        #
        # Do NOT conn.rollback() here: a constraint violation already undoes
        # just the offending INSERT (SQLite statement-level rollback), and the
        # connection stays usable. A full rollback would discard the caller's
        # other uncommitted work AND hide a provider inserted earlier in the
        # same transaction, which would mislabel a same-tx provider + bad
        # entity_id as "unregistered." Querying without the rollback sees the
        # true post-statement state. db.connect() rolls back on exit if the
        # error propagates (commit is skipped), so no partial row is committed.
        known = conn.execute(
            "SELECT 1 FROM osint_providers WHERE slug = ?", (provider_slug,)
        ).fetchone()
        if not known:
            raise EnrichmentError(
                f"provider '{provider_slug}' is not in the provider catalog "
                f"(osint_providers) - cannot start a run"
            ) from exc
        raise
    conn.commit()
    return cur.lastrowid


def execute_run(conn, run_id: int, timeout: int = 90) -> dict:
    """Pull the run row, call the adapter, persist results."""
    row = conn.execute(
        "SELECT * FROM enrichment_runs WHERE id = ?", (run_id,),
    ).fetchone()
    if not row:
        raise ValueError(f"run {run_id} not found")
    provider_slug = row["provider_slug"]
    query = row["query"]
    mode = row["mode"]

    # Typed-transform gate AT THE DISPATCH CHOKE-POINT (codex adversarial
    # blocker: gating only run_and_persist left start_run+execute_run,
    # /api/enrich/run, and any queued row ungated). Every persisted run with
    # an entity derives the node's type from its row; an adapter that does
    # not watch that type refuses HERE. Entity-less runs (ad-hoc bare-query
    # lookups) have no node to validate — out of the gate's domain, like
    # direct adapter.run() reads that persist nothing.
    if row["entity_id"]:
        _gate_entity_type(conn, run_id, provider_slug, row["entity_id"])

    # Mark running
    conn.execute(
        "UPDATE enrichment_runs SET status='running' WHERE id = ?", (run_id,),
    )
    conn.commit()

    started = time.time()
    try:
        adapter = get_adapter(provider_slug)
        results: list[EnrichmentResult] = adapter.run(query, mode=mode, timeout=timeout)
    except NotConfiguredError as exc:
        conn.execute(
            "UPDATE enrichment_runs SET status='error', error_message=?, "
            "finished_at=? WHERE id = ?",
            (str(exc), _now(), run_id),
        )
        conn.commit()
        return {"run_id": run_id, "status": "error", "error": str(exc)}
    except EnrichmentError as exc:
        conn.execute(
            "UPDATE enrichment_runs SET status='error', error_message=?, "
            "finished_at=? WHERE id = ?",
            (str(exc), _now(), run_id),
        )
        conn.commit()
        return {"run_id": run_id, "status": "error", "error": str(exc)}
    except Exception as exc:
        tb = traceback.format_exc()
        conn.execute(
            "UPDATE enrichment_runs SET status='error', error_message=?, "
            "finished_at=? WHERE id = ?",
            (f"{exc}\n{tb[:1000]}", _now(), run_id),
        )
        conn.commit()
        return {"run_id": run_id, "status": "error", "error": str(exc)}

    # Persist each result + extract typed properties onto the enriched node (the run's
    # entity_id), so registrar / A-record / ASN become queryable fields, not freetext.
    # (issue node-properties-table)
    from investigations.enrich import properties as _props
    from investigations import evidence as _evidence
    src_entity_id = row["entity_id"]
    for r in results:
        conn.execute(
            "INSERT INTO enrichment_results "
            "(run_id, result_type, title, summary, url, raw_json, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, r.result_type, r.title, r.summary, r.url,
             json.dumps(r.raw_json) if r.raw_json else None, r.confidence),
        )
        if src_entity_id and r.raw_json:
            _props.extract_and_upsert(conn, src_entity_id, provider_slug, r.raw_json)
            # Capture the FULL raw provider response as point-in-time evidence
            # (ea-1) — the proof behind this node survives the live source dying.
            # Wrapped: a capture failure must never fail the enrichment.
            try:
                _evidence.capture_artifact(
                    conn, src_entity_id, kind=f"enrich:{provider_slug}",
                    content=r.raw_json, run_id=run_id, source_url=r.url)
            except Exception:
                pass

    # Cost (rough — provider's published estimate; real billing is per provider)
    adapter = get_adapter(provider_slug)
    cost = adapter.cost_per_call_usd or 0.0
    conn.execute(
        "UPDATE enrichment_runs SET status='success', finished_at=?, cost_usd=? "
        "WHERE id = ?",
        (_now(), cost, run_id),
    )
    conn.commit()

    return {
        "run_id": run_id,
        "status": "success",
        "result_count": len(results),
        "cost_usd": cost,
        "elapsed_seconds": round(time.time() - started, 2),
    }


def _gate_entity_type(conn, run_id: int, provider_slug: str, entity_id: int) -> None:
    """Refuse a transform whose adapter does not watch the node's type. An
    unknown/blank type is not refused (untyped nodes keep legacy behavior);
    the check is an input-contract fact (wallet-tx on a domain is nonsense),
    not a noise judgment — it applies to every actor."""
    from investigations.enrich.registry import TRANSFORM_TYPES
    row = conn.execute("SELECT entity_type FROM entities WHERE id = ?",
                       (entity_id,)).fetchone()
    et = ((row["entity_type"] if row else "") or "").lower()
    if not et or et not in TRANSFORM_TYPES:
        return
    # The module-level get_adapter reference (tests monkeypatch it; a local
    # import here bypassed the patch and broke the stub-provider tests).
    adapter = get_adapter(provider_slug)
    watched = getattr(adapter, "watched_types", None)
    if watched is None:
        # A stub/legacy adapter object without the contract attr is ungated
        # here — REAL registered adapters can't reach this state (the
        # registry validates declarations at every lookup).
        return
    if et not in watched:
        message = (f"{provider_slug} does not apply to a {et} node (it watches "
                   f"{', '.join(adapter.watched_types)}) — typed-transform gate")
        conn.execute(
            "UPDATE enrichment_runs SET status='error', error_message=?, "
            "finished_at=? WHERE id = ?", (message, _now(), run_id))
        conn.commit()
        raise EnrichmentError(message)


def run_and_persist(conn, provider_slug: str, query: str, *,
                    entity_id: int | None = None, mode: str | None = None,
                    investigation: str | None = None,
                    entity_type: str | None = None,
                    timeout: int = 90) -> dict:
    """Convenience: start a run + execute it synchronously.

    The typed-transform gate lives in execute_run (the dispatch choke-point,
    keyed off the queued row's entity). entity_type= remains as an EARLY
    pre-queue refusal for callers that know the type (saves a dead run row);
    the authoritative check still happens at dispatch."""
    from investigations.enrich.registry import TRANSFORM_TYPES, get_adapter
    et = (entity_type or "").lower()
    if et and et in TRANSFORM_TYPES:
        adapter = get_adapter(provider_slug)
        if et not in adapter.watched_types:
            raise EnrichmentError(
                f"{provider_slug} does not apply to a {et} node (it watches "
                f"{', '.join(adapter.watched_types)}) — typed-transform gate")
    try:
        run_id = start_run(conn, provider_slug, query,
                           entity_id=entity_id, mode=mode, investigation=investigation)
    except EnrichmentError as exc:
        # Fail soft on an unregistered provider (the catalog gap start_run
        # raises): return the SAME structured contract execute_run already
        # uses, so api_enrich_run responds 200 with a real message instead of
        # bubbling a 500. The frontend's existing run.error / status==='error'
        # path renders it. No run row exists yet, so run_id is None.
        return {"run_id": None, "status": "error", "error": str(exc)}
    return execute_run(conn, run_id, timeout=timeout)
