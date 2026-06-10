"""End-to-end test for the OSINT provider API-key feature.

Run against a live server:
  .venv/bin/python -m investigations.tests.e2e_enrich_keys <base_url>

Verifies:
  1. Providers list never leaks the raw api_key column.
  2. Saving a key flips the provider to configured, key_source='db'.
  3. The saved key is never echoed in any API response.
  4. A run gets PAST the 'not configured' gate (the key reaches the adapter).
  5. Clearing the key returns the provider to unconfigured.
Cleans up the test key from the DB at the end (uses a clearly-fake value).
"""
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8771"
TESTKEY = "ZZZ-fake-test-key-DO-NOT-USE-9c3f1a"
PROV = "tavily"  # unconfigured by default (no TAVILY_API_KEY in env)


def api(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def _provider(slug):
    _, d = api("/api/enrich/providers")
    assert all("api_key" not in p for p in d["providers"]), "raw api_key leaked in providers list!"
    return next(p for p in d["providers"] if p["slug"] == slug), d


def main():
    fails = []

    # 1. baseline
    prov, _ = _provider(PROV)
    print(f"[1] baseline {PROV}: configured={prov['configured']} key_source={prov['key_source']}")

    # 2. save a key
    st, d = api(f"/api/enrich/providers/{PROV}/key", "POST", {"api_key": TESTKEY})
    ok = st == 200 and d.get("configured") and d.get("key_source") == "db" and "api_key" not in d
    print(f"[2] save key -> status={st} configured={d.get('configured')} key_source={d.get('key_source')} (echoes key: {'api_key' in d})")
    if not ok:
        fails.append(f"save did not configure provider or leaked key: {d}")

    # 3. providers reflects configured + NO key leak anywhere
    prov, full = _provider(PROV)
    if not (prov["configured"] and prov["key_source"] == "db"):
        fails.append(f"providers list not updated: {prov}")
    if TESTKEY in json.dumps(full):
        fails.append("THE SAVED KEY LEAKED in /api/enrich/providers response")
    print(f"[3] after save: configured={prov['configured']} key_source={prov['key_source']} key_leaked={TESTKEY in json.dumps(full)}")

    # 4. run must get PAST the 'not configured' gate (key reached the adapter)
    mode = (prov.get("modes") or [None])[0]
    st, d = api("/api/enrich/run", "POST",
                {"provider": PROV, "query": "kipi keytest", "mode": mode, "timeout": 15})
    err = (d.get("error") or "").lower()
    past_gate = "not configured" not in err
    print(f"[4] run -> status={d.get('status')} error={(d.get('error') or '')[:80]!r} past_not_configured_gate={past_gate}")
    if not past_gate:
        fails.append(f"key not picked up by adapter (still 'not configured'): {d}")
    if TESTKEY in json.dumps(d):
        fails.append("THE SAVED KEY LEAKED in /api/enrich/run response")

    # 5. clear the key (also cleanup)
    st, d = api(f"/api/enrich/providers/{PROV}/key", "POST", {"api_key": ""})
    cleared = d.get("cleared") and not d.get("configured")
    print(f"[5] clear key -> cleared={d.get('cleared')} configured={d.get('configured')}")
    if not cleared:
        fails.append(f"clear did not unconfigure provider: {d}")

    print()
    if fails:
        for f in fails:
            print("FAIL:", f)
        sys.exit(1)
    print("PASS: key save/configure/use/no-leak/clear all verified")
    sys.exit(0)


if __name__ == "__main__":
    main()
