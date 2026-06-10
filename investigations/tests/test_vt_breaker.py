"""VirusTotal rate-limit circuit breaker: 3 strikes, then skip cleanly.

Run: .venv/bin/python -m investigations.tests.test_vt_breaker

No network: urlopen is stubbed to raise HTTP 429. Proves the first 2 rate-limit
hits still raise (agent sees them), the 3rd trips the breaker and returns a
SKIPPED result, and every later call short-circuits with NO HTTP call until a
clean call resets it.
"""
import os
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from investigations.enrich import virustotal
from investigations.enrich.base import EnrichmentError


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


class _Counter:
    def __init__(self): self.calls = 0


def _run_one(adapter):
    return adapter.run("evil-domain.com", mode="domain", timeout=5)


def main():
    tmp = Path(tempfile.mkdtemp())
    # Isolate breaker + throttle state to this test; no real 16s sleeps.
    virustotal._BREAKER_FILE = str(tmp / "breaker")
    virustotal._THROTTLE_FILE = str(tmp / "throttle")
    virustotal._throttle = lambda: None
    os.environ["VIRUSTOTAL_API_KEY"] = "test-key"

    counter = _Counter()

    def fake_429(req, timeout=30):
        counter.calls += 1
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)

    virustotal.urllib.request.urlopen = fake_429
    adapter = virustotal.VirusTotalAdapter()

    # Strikes 1 + 2: still raise (the agent should see the rate limit).
    for n in (1, 2):
        raised = False
        try:
            _run_one(adapter)
        except EnrichmentError:
            raised = True
        _check(f"strike {n} raises EnrichmentError", raised)
    _check("breaker not tripped after 2 strikes", not virustotal._breaker_tripped())

    # Strike 3: trips the breaker, returns a SKIPPED result instead of raising.
    res = _run_one(adapter)
    _check("strike 3 returns a result (no raise)", isinstance(res, list) and len(res) == 1)
    _check("strike 3 result is SKIPPED", "[SKIPPED]" in res[0].title)
    _check("breaker now tripped", virustotal._breaker_tripped())

    # replay D3: a transient blip must NOT lock VT out for 10 minutes. Cooldown shrunk
    # 600s -> short, so the breaker reopens quickly (4_points has no lockout at all).
    import time as _t
    until = virustotal._breaker_read().get("until", 0)
    _check("breaker cooldown shrunk to <= 120s (was 600 — no 10-min run-wide lockout)",
           virustotal._BREAKER_COOLDOWN <= 120)
    _check("cooldown still clears the 60s 4/min window", virustotal._BREAKER_COOLDOWN >= 60)
    _check("tripped breaker reopens within ~cooldown, not 600s",
           0 < (until - _t.time()) <= virustotal._BREAKER_COOLDOWN + 5)

    calls_after_trip = counter.calls
    # Call 4+: short-circuits — no HTTP call at all.
    res4 = _run_one(adapter)
    _check("post-trip call returns SKIPPED", "[SKIPPED]" in res4[0].title)
    _check("post-trip call made NO http call", counter.calls == calls_after_trip)

    # A clean call (404 = VT responding) resets the breaker for the next run.
    def fake_404(req, timeout=30):
        counter.calls += 1
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    # Manually clear the trip to simulate cooldown elapsing, then a clean 404.
    virustotal._breaker_write({})
    virustotal.urllib.request.urlopen = fake_404
    res404 = _run_one(adapter)
    _check("404 returns UNKNOWN", "[UNKNOWN]" in res404[0].title)
    _check("breaker reset after clean call", not virustotal._breaker_tripped()
           and virustotal._breaker_read() == {})

    print("\nPASS: test_vt_breaker")


if __name__ == "__main__":
    main()
