"""Fail-soft on an unregistered provider slug (issue enrich-run-failsoft).

start_run's INSERT into enrichment_runs carries two FKs: provider_slug ->
osint_providers(slug) and entity_id -> entities(id). An unregistered provider
used to throw sqlite3.IntegrityError straight out of api_enrich_run as an
unhandled 500, which the graph rendered as the misleading "Could not reach the
server." This test pins the fix:

  1. start_run on an unregistered slug raises a typed EnrichmentError naming the
     provider catalog (not a raw IntegrityError).
  2. run_and_persist fails SOFT for that case: returns {status:'error', error}
     instead of raising, so api_enrich_run answers 200 with a real message.
  3. A bad entity_id with a VALID provider is NOT mislabeled as a catalog miss
     - start_run re-raises the original IntegrityError untouched.

Run: .venv/bin/python -m investigations.tests.test_enrich_run_failsoft
"""
import sqlite3
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.enrich import runner
from investigations.enrich.base import EnrichmentError


def main():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)

        # 1) Unregistered slug -> start_run raises a typed, catalog-named error.
        with db.connect(path) as conn:
            raised = None
            try:
                runner.start_run(conn, "definitely_not_a_provider", "q")
            except EnrichmentError as exc:
                raised = exc
            assert raised is not None, "start_run did not raise on an unregistered slug"
            assert "provider catalog" in str(raised), (
                f"error must name the provider catalog, got: {raised!r}")
            print("  ok  start_run(unregistered) raises EnrichmentError naming the catalog")

        # 2) run_and_persist fails SOFT: structured error, never raises. This is
        # the API path (no entity_type passed, so the typed gate is skipped).
        with db.connect(path) as conn:
            result = runner.run_and_persist(conn, "definitely_not_a_provider", "q")
            assert isinstance(result, dict), f"expected a dict, got {type(result)}"
            assert result.get("status") == "error", f"expected status=error, got {result!r}"
            assert "provider catalog" in (result.get("error") or ""), (
                f"structured error must name the catalog, got: {result!r}")
            assert result.get("run_id") is None, "no run row should exist for an unregistered slug"
            print("  ok  run_and_persist(unregistered) returns structured error, no raise")

        # 3) Disambiguation: a VALID provider with a bad entity_id must NOT be
        # mislabeled as a catalog miss. start_run re-raises the original
        # IntegrityError (entity_id FK), not the EnrichmentError. 'phone' is a
        # registered, seeded provider (would have been one of the 18 that 500d
        # before the seed fix); 999999999 is not a real entities.id.
        with db.connect(path) as conn:
            assert conn.execute(
                "SELECT 1 FROM osint_providers WHERE slug='phone'").fetchone(), \
                "precondition: 'phone' must be seeded"
            mislabeled = None
            integrity = None
            try:
                runner.start_run(conn, "phone", "+14155552671", entity_id=999999999)
            except EnrichmentError as exc:
                mislabeled = exc          # WRONG: would mean entity_id was blamed on the catalog
            except sqlite3.IntegrityError as exc:
                integrity = exc           # RIGHT: the real constraint surfaces
            assert mislabeled is None, (
                f"bad entity_id was mislabeled as a provider-catalog error: {mislabeled!r}")
            assert integrity is not None, (
                "bad entity_id should raise the original IntegrityError, not be swallowed")
            print("  ok  bad entity_id raises the real IntegrityError (not mislabeled)")

        # 4) Disambiguation must hold WITHOUT rolling back the caller's
        # transaction: a provider inserted earlier in the SAME (uncommitted)
        # transaction, plus a bad entity_id, must NOT be mislabeled as
        # unregistered. start_run avoids conn.rollback() precisely so this
        # same-tx provider stays visible to the catalog lookup.
        with db.connect(path) as conn:
            conn.execute(
                "INSERT INTO osint_providers (slug, display_name, category) "
                "VALUES ('zzz_same_tx', 'Same-tx provider', 'test')")  # uncommitted
            mislabeled = None
            integrity = None
            try:
                runner.start_run(conn, "zzz_same_tx", "q", entity_id=999999999)
            except EnrichmentError as exc:
                mislabeled = exc
            except sqlite3.IntegrityError as exc:
                integrity = exc
            assert mislabeled is None, (
                "a same-transaction provider + bad entity_id was mislabeled as "
                f"unregistered (rollback hid the uncommitted provider): {mislabeled!r}")
            assert integrity is not None, "expected the entity_id IntegrityError to surface"
            conn.rollback()  # drop the throwaway provider; don't pollute the temp DB
            print("  ok  same-tx provider + bad entity_id is not mislabeled (no rollback)")

    print("\nPASS: test_enrich_run_failsoft")


if __name__ == "__main__":
    main()
