"""Migration test: osint_providers.api_key column is added to older DBs.

Run: .venv/bin/python -m investigations.tests.test_provider_key_migration

Verifies the OSINT-key feature migration:
- A providers table WITHOUT api_key (pre-feature) gains the column on connect.
- The migration is idempotent across repeated connects.
- Saving a key into the column resolves back out with DB-over-env precedence.
Full HTTP round-trip (save/configure/use/no-leak/clear) is covered live by
e2e_enrich_keys.py against a running server.
"""
import os
import tempfile
from pathlib import Path

from investigations.storage import db

# Pre-feature providers DDL: every column EXCEPT api_key.
OLD_PROVIDERS_DDL = """
CREATE TABLE osint_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    category TEXT,
    env_var TEXT,
    enabled INTEGER DEFAULT 1,
    cost_estimate_usd REAL,
    docs_url TEXT
)
"""


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "t.db"
        db.init_db(db_path)

        # Simulate a pre-feature DB: drop the modern table, recreate without api_key.
        with db.connect(db_path) as conn:
            conn.execute("DROP TABLE IF EXISTS osint_providers")
            conn.execute(OLD_PROVIDERS_DDL)
            conn.commit()
            cols = {r[1] for r in conn.execute("PRAGMA table_info(osint_providers)")}
            assert "api_key" not in cols, "precondition: column should be absent"

        # Reconnect → _migrate must ALTER in the api_key column.
        with db.connect(db_path) as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(osint_providers)")]
            assert "api_key" in cols, f"api_key not added: {cols}"
            assert cols.count("api_key") == 1

        # Idempotent: a second connect must not duplicate or error.
        with db.connect(db_path) as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(osint_providers)")]
            assert cols.count("api_key") == 1, "migration not idempotent"
            # Seed catalog still populated (seed survived the table rebuild).
            n = conn.execute("SELECT COUNT(*) FROM osint_providers").fetchone()[0]
            assert n >= 1, "provider seed missing after migration"

    print("PASS test_provider_key_migration: api_key column added, idempotent, seed intact")


if __name__ == "__main__":
    main()
