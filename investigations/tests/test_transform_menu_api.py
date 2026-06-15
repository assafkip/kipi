"""GET /api/transforms — the type-filtered transform menu (sp2)."""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from investigations.storage import db
from investigations.webapp import app as app_module


def _client(tmp, mp):
    dbp = Path(tmp) / "t.db"
    db.init_db(dbp)
    orig = db.connect
    mp.setattr(app_module.db, "connect",
               lambda migrate=True, db_path=dbp: orig(db_path=db_path,
                                                      migrate=migrate))
    return TestClient(app_module.app)


def test_domain_menu_is_type_filtered_and_ordered(mp):
    with tempfile.TemporaryDirectory() as tmp:
        d = _client(tmp, mp).get("/api/transforms?type=domain").json()
        assert d["type"] == "domain"
        slugs = [t["slug"] for t in d["transforms"]]
        # typosquat (keyless lookalike-domain gen, PRD-7) joins the deterministic tier after crtsh.
        assert slugs[:4] == ["crtsh", "typosquat", "infra", "infra"]  # deterministic tier first
        assert "wallet" not in slugs                      # not a domain transform
        assert "gravatar" not in slugs                    # email-only


def test_schema_and_configured_flag(mp):
    with tempfile.TemporaryDirectory() as tmp:
        d = _client(tmp, mp).get("/api/transforms?type=email").json()
        for item in d["transforms"]:
            assert set(item) == {"slug", "mode", "display", "configured",
                                 "deterministic", "group", "ran"}
        by_slug = {t["slug"]: t for t in d["transforms"]}
        assert by_slug["gravatar"]["configured"] is True      # keyless
        assert by_slug["gravatar"]["deterministic"] is False  # not belt tier
        assert isinstance(by_slug["breach"]["configured"], bool)


def test_unknown_or_missing_type_is_empty_not_refused(mp):
    with tempfile.TemporaryDirectory() as tmp:
        c = _client(tmp, mp)
        assert c.get("/api/transforms?type=nonsense").json()["transforms"] == []
        r = c.get("/api/transforms")
        assert r.status_code == 200
        assert r.json()["transforms"] == []


def test_mode_items_are_distinct_menu_entries(mp):
    with tempfile.TemporaryDirectory() as tmp:
        d = _client(tmp, mp).get("/api/transforms?type=domain").json()
        infra = [t for t in d["transforms"] if t["slug"] == "infra"]
        assert [t["mode"] for t in infra] == ["whois", "dns"]
        assert all("(" in t["display"] for t in infra)  # mode-suffixed labels


def test_configured_resolution_is_bounded(mp):
    # codex adversarial: keyed adapters resolve configuration via SQLite —
    # one resolution per unique slug per menu call, never per recipe row.
    from investigations.enrich import base as enrich_base
    calls = []
    mp.setattr(enrich_base, "resolve_key",
               lambda slug, env: calls.append(slug) or "")
    from investigations.enrich.registry import transforms_for_type
    items = transforms_for_type("domain")
    assert len(items) >= 10
    assert len(calls) == len(set(calls)), f"slug resolved twice: {calls}"
