"""UI-set API keys reach the agent's child process (incl. external MCP servers).

Run: .venv/bin/python -m investigations.tests.test_agent_key_injection

The external apify/perplexity MCP servers read ENV vars, not the kipi DB. This proves
the agent run injects DB-stored (UI-entered) keys into the subprocess env, mapped to
the right names — so a key set ONLY in the UI is visible to every tool path.
"""
import tempfile
from pathlib import Path

from investigations.storage import db
from investigations.agent import investigator
from investigations.enrich import base as enrich_base


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def _point_db_at(mp, dbp):
    # resolve_key() does `from investigations.storage import db; db.connect(migrate=False)`
    # against the DEFAULT path — repoint that default at the temp DB.
    orig = db.connect
    mp.setattr(db, "connect", lambda migrate=True, db_path=dbp: orig(db_path=db_path, migrate=migrate))


def test_db_only_key_maps_to_env(mp):
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("UPDATE osint_providers SET api_key=? WHERE slug='perplexity'",
                         ("sk-db-only-pplx",))
            conn.commit()
        _point_db_at(mp, dbp)
        env_keys = investigator._agent_key_env()
        _check("DB-only perplexity key mapped to its env var",
               env_keys.get("PERPLEXITY_API_KEY") == "sk-db-only-pplx")
        _check("no key for a provider left unset",
               "TAVILY_API_KEY" not in env_keys)


def test_apify_name_alias(mp):
    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("UPDATE osint_providers SET api_key=? WHERE slug='apify'",
                         ("apify-secret",))
            conn.commit()
        _point_db_at(mp, dbp)
        env_keys = investigator._agent_key_env()
        # The kipi adapter wants APIFY_API_TOKEN; the .mcp.json apify server wants
        # APIFY_TOKEN. One UI key must satisfy BOTH.
        _check("APIFY_API_TOKEN set from the one key", env_keys.get("APIFY_API_TOKEN") == "apify-secret")
        _check("APIFY_TOKEN aliased to the same key", env_keys.get("APIFY_TOKEN") == "apify-secret")


def test_run_agent_passes_injected_env(mp):
    # Prove _run_agent actually hands the merged env to the subprocess.
    captured = {}

    class _Stop(Exception):
        pass

    def fake_popen(cmd, **kw):
        captured["env"] = kw.get("env")
        raise _Stop()  # short-circuit: we only need the env it would have launched with

    with tempfile.TemporaryDirectory() as d:
        dbp = Path(d) / "t.db"; db.init_db(dbp)
        with db.connect(dbp) as conn:
            conn.execute("UPDATE osint_providers SET api_key=? WHERE slug='perplexity'",
                         ("sk-injected",))
            conn.commit()
        _point_db_at(mp, dbp)
        mp.setattr(investigator.subprocess, "Popen", fake_popen)
        res = investigator._run_agent("task", use_mcp=False)
        _check("launch short-circuited cleanly (env captured)", res.get("ok") is False)
        env = captured.get("env") or {}
        _check("subprocess env carries the DB-only key",
               env.get("PERPLEXITY_API_KEY") == "sk-injected")
        _check("subprocess env still inherits the parent environment", "PATH" in env)


def main():
    for fn in (test_db_only_key_maps_to_env, test_apify_name_alias,
               test_run_agent_passes_injected_env):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_agent_key_injection")


if __name__ == "__main__":
    main()
