"""Wiring tests for the huntkit-ported enrich adapters (no network calls).

Covers: registry membership, slug/env/category contract, keyless detection,
VirusTotal indicator-type detection, and provider-catalog seeding.

Run: .venv/bin/python -m investigations.tests.test_enrich_adapters
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.enrich.registry import get_adapter, all_adapters, _REGISTRY
from investigations.enrich import virustotal, infra, runner

NEW = ["virustotal", "abusech", "crtsh", "infra"]
KEYLESS = ["crtsh", "infra"]
KEYED = {"virustotal": "VIRUSTOTAL_API_KEY", "abusech": "ABUSECH_AUTH_KEY"}


def _check(label, got, want):
    assert got == want, f"{label}: got {got!r}, want {want!r}"
    print(f"  ok  {label} == {want!r}")


def main():
    # 1) All five are registered and report their own slug.
    slugs = {a.slug for a in all_adapters()}
    for s in NEW:
        assert s in slugs, f"{s} not registered"
        _check(f"{s} slug roundtrip", get_adapter(s).slug, s)

    # 2) Keyed adapters carry the right env var; keyless ones report configured.
    for slug, env in KEYED.items():
        _check(f"{slug} env_var", get_adapter(slug).env_var, env)
    for slug in KEYLESS:
        a = get_adapter(slug)
        _check(f"{slug} env_var is None", a.env_var, None)
        _check(f"{slug} keyless is_configured", a.is_configured(), True)

    # 3) Every adapter advertises at least one mode.
    for s in NEW:
        assert get_adapter(s).modes(), f"{s} has no modes"
    print("  ok  all adapters advertise modes")

    # 4) VirusTotal indicator-type detection.
    _check("vt detect ip", virustotal._detect("8.8.8.8"), "ip")
    _check("vt detect url", virustotal._detect("https://x.com/a"), "url")
    _check("vt detect hash", virustotal._detect("d41d8cd98f00b204e9800998ecf8427e"), "hash")
    _check("vt detect domain", virustotal._detect("evil-domain.com"), "domain")
    _check("infra is_ip true", infra._is_ip("1.2.3.4"), True)
    _check("infra is_ip false", infra._is_ip("example.com"), False)

    # 5) Provider catalog is seeded on a fresh DB.
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        db.init_db(path)
        with db.connect(path) as conn:
            rows = {r["slug"]: r for r in conn.execute(
                "SELECT slug, env_var, category FROM osint_providers")}
        for s in NEW:
            assert s in rows, f"{s} not seeded into osint_providers"
        _check("virustotal seed env", rows["virustotal"]["env_var"], "VIRUSTOTAL_API_KEY")
        _check("crtsh seed keyless", rows["crtsh"]["env_var"], None)
        # Wayback / archive.org removed (doesn't work via the agent's fetch path).
        assert "wayback" not in rows, "wayback must not be seeded after removal"
        print("  ok  wayback not seeded (removed)")

    # 6) FULL coverage guard (issue enrich-seed-from-registry). The catalog is
    # seeded FROM the registry, so EVERY registry adapter must have a row. This
    # is the choke-point the old hand-list lacked: it seeded 21 of 39 adapters,
    # so `phone` (and 17 others) FK-failed in start_run -> a 500 -> the graph's
    # "Could not reach the server." If a future adapter is added to the registry
    # without a seed row, this assertion goes red.
    def _unseeded(conn):
        seeded = {r["slug"] for r in conn.execute("SELECT slug FROM osint_providers")}
        return set(_REGISTRY) - seeded

    # (b) key == adapter.slug invariant. The seed keys osint_providers by the
    # registry KEY; dispatch (start_run / recipes) keys off the same key. If a
    # key ever diverged from its adapter.slug the FK gap could reopen, so lock
    # the invariant the seed depends on.
    mismatched = {k: a.slug for k, a in _REGISTRY.items() if k != a.slug}
    assert not mismatched, f"registry key != adapter.slug: {mismatched}"
    print("  ok  registry key == adapter.slug for all adapters")

    # (a) every registry adapter is seeded on a fresh DB, and (d) a runner-level
    # check that a previously-missing slug no longer raises the FK IntegrityError.
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "cov.db"
        db.init_db(path)
        with db.connect(path) as conn:
            missing = _unseeded(conn)
            assert not missing, f"registry adapters missing an osint_providers row: {sorted(missing)}"
            print(f"  ok  all {len(_REGISTRY)} registry adapters seeded (no FK gap)")
            rid = runner.start_run(conn, "phone", "+14155552671")
            assert isinstance(rid, int) and rid > 0, "start_run('phone') did not return a run id"
            print("  ok  start_run('phone') succeeds (no FOREIGN KEY IntegrityError)")

    # (c) negative self-test: prove the coverage guard has teeth. On a fresh DB,
    # delete one seeded provider and assert _unseeded() reports exactly that gap.
    # If a deleted seed is NOT detected, the guard is asleep and the test must
    # fail. (Fresh DB / no enrichment_runs row, so the DELETE is FK-clean.)
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "neg.db"
        db.init_db(path)
        with db.connect(path) as conn:
            assert not _unseeded(conn), "precondition: fresh DB must be fully seeded"
            conn.execute("DELETE FROM osint_providers WHERE slug='phone'")
            conn.commit()
            assert _unseeded(conn) == {"phone"}, (
                "negative self-test FAILED: deleting the 'phone' seed was not "
                "detected by the coverage check - the guard has no teeth")
        print("  ok  negative self-test: coverage guard detects a deleted seed")

    print("\nPASS: test_enrich_adapters")


if __name__ == "__main__":
    main()
