"""Per-discovered-asset rollup: where each URL came from, checked-live?, pivoted?

Run: .venv/bin/python -m investigations.tests.test_asset_rollup
"""
from investigations.webapp import app


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_rollup():
    results = [
        {"title": "trump-2026.io", "entity_type": "domain", "step_tool": "dns_lookup",
         "step_ref": 13, "provenance": "dns_lookup: 'No DNS records found'",
         "summary": "[domain] no dns records, currently down", "extracted_entity_id": 1},
        {"title": "trump-2026.io", "entity_type": "domain", "step_tool": "whois_lookup",
         "step_ref": 2, "provenance": "whois: Registrar PDR Ltd",
         "summary": "[domain] registrar PDR Ltd, name server ns1.ezydomain.com", "extracted_entity_id": 1},
        {"title": "trump2026.org", "entity_type": "domain", "step_tool": None, "step_ref": 20,
         "provenance": "whois (infra): Registrar PDR Ltd", "summary": "[domain] sibling, registrar PDR Ltd",
         "extracted_entity_id": None},
        {"title": "weird-site.com", "entity_type": "domain", "step_tool": None, "step_ref": 7,
         "provenance": "web_search/perplexity: mentioned once", "summary": "[domain] named in an article",
         "extracted_entity_id": None},
    ]
    by = {a["asset"]: a for a in app._asset_rollup(results)}

    t = by["trump-2026.io"]
    _check("captured both checks (dns + whois)", set(t["checks"]) >= {"dns", "whois"})
    _check("found-via step recorded", t["found_step"] in (2, 13))
    _check("flagged DEAD (no dns records)", t["live"] == "dead")
    _check("flagged chased (multiple checks)", t["pivoted"] is True)
    _check("promoted to graph", t["promoted"] is True)

    o = by["trump2026.org"]
    _check("sibling found via step 20", o["found_step"] == 20)
    _check("sibling whois → live/registered", o["live"] in ("live", "checked"))
    _check("sibling counts as chased (a liveness check ran)", o["pivoted"] is True)

    w = by["weird-site.com"]
    _check("mention-only: liveness NOT checked", w["live"] == "not checked")
    _check("mention-only: flagged surfaced-only (not chased)", w["pivoted"] is False)

    _check("domains sorted before other types", app._asset_rollup(results)[0]["type"] == "domain")


def main():
    test_rollup()
    print("\nPASS: test_asset_rollup")


if __name__ == "__main__":
    main()
