"""Runner — bridge between OSINT adapters and SQLite persistence.

Inserts an enrichment_runs row, calls the adapter, persists results, updates
the run status + cost. Used by both the CLI and the webapp.
"""
from __future__ import annotations

import json
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
    cur = conn.execute(
        "INSERT INTO enrichment_runs "
        "(entity_id, provider_slug, query, mode, status, investigation) "
        "VALUES (?, ?, ?, ?, 'queued', ?)",
        (entity_id, provider_slug, query, mode, investigation),
    )
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


def run_and_persist(conn, provider_slug: str, query: str, *,
                    entity_id: int | None = None, mode: str | None = None,
                    investigation: str | None = None,
                    timeout: int = 90) -> dict:
    """Convenience: start a run + execute it synchronously."""
    run_id = start_run(conn, provider_slug, query,
                       entity_id=entity_id, mode=mode, investigation=investigation)
    return execute_run(conn, run_id, timeout=timeout)
