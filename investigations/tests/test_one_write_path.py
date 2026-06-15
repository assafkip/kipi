"""The bypass test — nothing escapes store.apply_mutation (sp1 phase gate).

Two sweeps over investigations/ source (tests exempt — fixtures seed directly):

  1. helper calls:   upsert_entity( / upsert_typed_relationship( anywhere
                     outside store.py (db.py DEFINES them; defining is not
                     calling — its own internal migration use is exempt).
                     bump_case left this pattern when webapp.bump_case became
                     a store delegate (sp1-migrate-webapp-writers): calling
                     the delegate IS routing through the store, and the
                     signaling invariant lives in test_view_refresh's
                     store-routed anchor guard.
  2. raw SQL:        INSERT INTO / UPDATE / DELETE FROM on the two canonical
                     tables (entities, typed_relationships) outside store.py
                     and db.py — plus the version-bump arithmetic
                     (version = version + 1), whose only home is store.py

Every hit must be in ALLOWLIST — the not-yet-migrated writer inventory from
prd-spine-phase1 (19 modules at creation). The assertion is EQUALITY, both
directions: a NEW writer anywhere goes red immediately, and a migrated module
must be REMOVED from this list in its migration commit or the test goes red
too. The phase closes when ALLOWLIST is empty; from then on the empty list IS
the invariant.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]  # investigations/

# The migration is COMPLETE (19 -> 15 -> 13 -> 7 -> 0 across the five
# sp1 issues, 2026-06-11). EMPTY is now the permanent invariant: any module
# that writes the canonical surface directly goes red here, forever.
ALLOWLIST: set[str] = set()

HELPER_CALL = re.compile(
    r"\b(?:upsert_entity|upsert_typed_relationship)\s*\(")
VERSION_BUMP = re.compile(r"version\s*=\s*version\s*\+")
RAW_SQL = re.compile(
    r"(?i)(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|"
    r"UPDATE(?:\s+OR\s+\w+)?|DELETE\s+FROM)\s+"
    r"(?:entities|typed_relationships)\b")

EXEMPT = {"store.py"}            # the choke-point itself
RAW_SQL_EXEMPT = {"store.py", "storage/db.py"}  # db.py defines the primitives


def _py_files():
    for path in ROOT.rglob("*.py"):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("tests/"):
            continue
        yield rel, path


def _strip_comments(text):
    """Drop full-line comments + docstring-only noise so a MENTION of a
    pattern in prose does not count as a write site. Inline code stays."""
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _offenders(pattern, exempt):
    found = set()
    for rel, path in _py_files():
        if rel in exempt:
            continue
        if pattern.search(_strip_comments(path.read_text(errors="ignore"))):
            found.add(rel)
    return found


def test_allowlist_is_empty_forever():
    """The migration ended; the allowlist may never grow again. A new writer
    belongs in store.py as an event type — adding a module here is the exact
    bypass this phase exists to prevent (phase-1 close gate)."""
    assert ALLOWLIST == set()


def test_no_helper_calls_outside_store():
    offenders = _offenders(HELPER_CALL, EXEMPT | {"storage/db.py"})
    unexpected = offenders - ALLOWLIST
    stale = ALLOWLIST - offenders - _offenders(RAW_SQL, RAW_SQL_EXEMPT)
    assert not unexpected, (
        f"NEW direct writers outside store.py (route through "
        f"store.apply_mutation): {sorted(unexpected)}")
    assert not stale, (
        f"migrated (or never-writing) modules still on the allowlist — "
        f"remove them in the migration commit: {sorted(stale)}")


def test_no_raw_sql_on_canonical_tables_outside_store():
    offenders = _offenders(RAW_SQL, RAW_SQL_EXEMPT)
    unexpected = offenders - ALLOWLIST
    assert not unexpected, (
        f"NEW raw-SQL writers of entities/typed_relationships outside "
        f"store.py (route through store.apply_mutation): {sorted(unexpected)}")


def test_version_bump_lives_only_in_store():
    offenders = _offenders(VERSION_BUMP, {"store.py"})
    assert not offenders, (
        f"raw case-version arithmetic outside store.py — the /api/changed "
        f"signal is store-owned: {sorted(offenders)}")


def test_db_write_surface_is_frozen():
    """db.py defines exactly the known write primitives; new write helpers
    with business logic belong in store.py as event types (umbrella
    'Storage boundary' constraint)."""
    src = (ROOT / "storage/db.py").read_text()
    public_writers = sorted(
        name for name in re.findall(r"^def (upsert_\w+)", src, re.M))
    assert public_writers == ["upsert_entity", "upsert_typed_relationship"], (
        f"db.py write surface grew: {public_writers} — new write shapes are "
        f"new event types in store.py, never new db.py helpers")


def test_raw_sql_pattern_catches_or_ignore_forms():
    # codex finding-1: OR IGNORE / REPLACE INTO variants must not escape.
    for text in ("INSERT OR IGNORE INTO entities (x) VALUES (1)",
                 "insert into entities (x) values (1)",
                 "UPDATE OR IGNORE typed_relationships SET x = 1",
                 "REPLACE INTO entities (x) VALUES (1)",
                 "DELETE FROM typed_relationships WHERE 1"):
        assert RAW_SQL.search(text), text
    for text in ("UPDATE claims SET status = 'x'",
                 "INSERT INTO activity (a) VALUES (1)",
                 "SELECT * FROM entities"):
        assert not RAW_SQL.search(text), text
