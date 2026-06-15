"""VirusTotal adapter — domain / IP / file-hash / URL reputation.

Ported from huntkit's threat-intel MCP (vt_lookup), VirusTotal API v3. Free tier:
4 requests/min, 500/day. A 404 means VT has no record (returned as an UNKNOWN
result, not an error); rate-limit / auth failures raise.
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
import tempfile
import time
import urllib.request
import urllib.parse
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

VT_BASE = "https://www.virustotal.com/api/v3"
_GUI = {"domain": "domain", "ip": "ip-address", "hash": "file"}

# Cross-process throttle: VT free tier is 4/min. Each `./invctl osint-tool virustotal`
# is a fresh process, and the swarm runs several in parallel — so the pacing state lives
# in a lock-guarded timestamp file. The adapter sleeps internally to stay under the cap
# (that's fine — only the AGENT's Bash `sleep` is harness-blocked, not the subprocess).
_THROTTLE_FILE = os.path.join(tempfile.gettempdir(), "kipi_vt_throttle")
_MIN_INTERVAL = 16.0  # 4/min = 15s; pad to 16


def _throttle() -> None:
    try:
        fd = os.open(_THROTTLE_FILE, os.O_RDWR | os.O_CREAT, 0o644)
    except OSError:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            next_allowed = float((os.read(fd, 64) or b"0").decode().strip() or "0")
        except (ValueError, OSError):
            next_allowed = 0.0
        now = time.time()
        if next_allowed > now:
            time.sleep(min(next_allowed - now, _MIN_INTERVAL * 4))  # cap pathological waits
            now = time.time()
        new_next = max(now, next_allowed) + _MIN_INTERVAL
        os.lseek(fd, 0, 0)
        os.ftruncate(fd, 0)
        os.write(fd, str(new_next).encode())
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# --- Rate-limit circuit breaker -------------------------------------------------
# The throttle paces the 4/min cap, but it can't help once the 500/DAY cap is gone:
# every call 429s and the run drowns in slow rate-limit errors. The breaker stops that:
# after N consecutive 429s it TRIPS and later calls short-circuit to a clean "skipped"
# result (no HTTP, no 16s wait) until the cooldown passes. Cross-process (lock-guarded
# file) so it holds across the swarm's parallel subprocesses. A success/404 resets strikes.
#
# COOLDOWN is SHORT (replay D3): 4_points has no breaker and never self-harms because it
# calls VT one-at-a-time (natural pacing). kipi's throttle already prevents most 4/min
# bursts; a 600s lockout turned a transient blip that slipped through into a 10-MINUTE
# run-wide VT outage. 90s comfortably clears the 60s rolling 4/min window, so a blip pauses
# VT briefly instead of nuking the run. If it's the genuine 500/day cap, the breaker simply
# re-trips after 90s (one cheap doomed call), never a 10-minute hole.
_BREAKER_FILE = os.path.join(tempfile.gettempdir(), "kipi_vt_breaker")
_BREAKER_STRIKES = int(os.environ.get("KIPI_VT_STRIKES", "3"))   # trip after this many 429s
_BREAKER_COOLDOWN = float(os.environ.get("KIPI_VT_COOLDOWN", "90"))  # seconds to stay tripped (was 600)


def _breaker_read() -> dict:
    try:
        with open(_BREAKER_FILE, "r") as f:
            return json.loads(f.read() or "{}")
    except (OSError, ValueError):
        return {}


def _breaker_write(state: dict) -> None:
    try:
        fd = os.open(_BREAKER_FILE, os.O_RDWR | os.O_CREAT, 0o644)
    except OSError:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, 0)
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps(state).encode())
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _breaker_tripped() -> bool:
    """True while the breaker is tripped and still inside its cooldown."""
    return _breaker_read().get("until", 0) > time.time()


def _breaker_record_429() -> bool:
    """Count a rate-limit hit. Returns True once the strike count trips the breaker
    (so the caller can stop raising and start skipping)."""
    fd = os.open(_BREAKER_FILE, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            state = json.loads((os.read(fd, 256) or b"{}").decode() or "{}")
        except ValueError:
            state = {}
        now = time.time()
        if state.get("until", 0) > now:
            return True   # already tripped
        state["strikes"] = int(state.get("strikes", 0)) + 1
        tripped = state["strikes"] >= _BREAKER_STRIKES
        if tripped:
            state["until"] = now + _BREAKER_COOLDOWN
        os.lseek(fd, 0, 0)
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps(state).encode())
        return tripped
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _breaker_reset() -> None:
    """A clean call (success / 404) clears the strike count so transient blips don't
    accumulate toward a trip across an otherwise-healthy run."""
    if _breaker_read():
        _breaker_write({})


def _skipped_result(indicator: str) -> "EnrichmentResult":
    return EnrichmentResult(
        result_type="profile",
        title=f"VirusTotal: {indicator} [SKIPPED]",
        summary="VirusTotal skipped — rate limit hit 3×, pausing VT briefly (~90s) before "
                "it retries. Free-tier burst (4/min) or daily cap (500/day) was hit.",
        confidence="low",
    )


def _detect(indicator: str) -> str:
    if indicator.startswith(("http://", "https://")):
        return "url"
    if all(c in "0123456789abcdefABCDEF" for c in indicator) and len(indicator) in (32, 40, 64):
        return "hash"
    if indicator.replace(".", "").isdigit() or ":" in indicator:
        return "ip"
    return "domain"


class VirusTotalAdapter(Adapter):
    slug = "virustotal"
    watched_types = ('domain', 'subdomain', 'url', 'ip', 'hash_sha256', 'hash_md5', 'indicator')
    display_name = "VirusTotal (domain / IP / hash / URL)"
    env_var = "VIRUSTOTAL_API_KEY"
    category = "reputation"
    cost_per_call_usd = 0.0  # free tier

    def modes(self) -> list[str]:
        return ["auto", "domain", "ip", "hash", "url"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        key = self.get_key()
        indicator = (query or "").strip()
        if not indicator:
            raise EnrichmentError("VirusTotal: empty indicator")
        itype = (mode or "auto").lower()
        if itype in ("auto", "default", ""):
            itype = _detect(indicator)

        if itype == "domain":
            path = "/domains/" + urllib.parse.quote(indicator, safe="")
        elif itype == "ip":
            path = "/ip_addresses/" + urllib.parse.quote(indicator, safe="")
        elif itype == "hash":
            path = "/files/" + urllib.parse.quote(indicator, safe="")
        elif itype == "url":
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            path = "/urls/" + url_id
        else:
            raise EnrichmentError(f"VirusTotal: unknown type '{itype}'")

        # Breaker already open from earlier 429s this run → skip instantly. No HTTP,
        # no 16s throttle wait. Stops the rate-limit storm from drowning the run.
        if _breaker_tripped():
            return [_skipped_result(indicator)]

        headers = {"x-apikey": key, "Accept": "application/json"}
        req = urllib.request.Request(VT_BASE + path, headers=headers)
        _throttle()  # pace under the 4/min cap before spending a call
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                _breaker_reset()  # a clean answer — VT is responding, not rate-limited
                return [EnrichmentResult(
                    result_type="profile",
                    title=f"VirusTotal: {indicator} [UNKNOWN]",
                    summary="No VirusTotal record for this indicator.",
                    confidence="low",
                )]
            if exc.code == 429:
                # 3rd strike trips the breaker: stop raising, start skipping cleanly.
                if _breaker_record_429():
                    return [_skipped_result(indicator)]
                raise EnrichmentError("VirusTotal rate limit (4/min, 500/day) — wait and retry")
            if exc.code in (401, 403):
                raise EnrichmentError("VirusTotal auth failed — check the API key")
            raise EnrichmentError(f"VirusTotal HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise EnrichmentError(f"VirusTotal network error: {exc}")

        _breaker_reset()  # successful call — clear any accumulated strikes

        attrs = (data.get("data") or {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        undet = stats.get("undetected", 0)
        total = mal + susp + harm + undet
        verdict = ("MALICIOUS" if mal > 2
                   else "SUSPICIOUS" if (mal > 0 or susp > 2) else "CLEAN")

        lines = [
            f"Verdict: {verdict}",
            f"Detections: {mal} malicious / {susp} suspicious of {total} engines",
            f"Reputation score: {attrs.get('reputation', 'N/A')}",
        ]
        extra: dict = {"stats": stats, "reputation": attrs.get("reputation")}
        if itype == "domain":
            extra["registrar"] = attrs.get("registrar")
            extra["categories"] = attrs.get("categories")
            lines.append(f"Registrar: {attrs.get('registrar', 'unknown')}")
        elif itype == "ip":
            extra.update(country=attrs.get("country"), as_owner=attrs.get("as_owner"),
                         asn=attrs.get("asn"))
            lines.append(f"Network: {attrs.get('as_owner', '?')} "
                         f"(ASN {attrs.get('asn', '?')}), {attrs.get('country', '?')}")
        elif itype == "hash":
            name = attrs.get("meaningful_name") or (attrs.get("names") or ["unknown"])[0]
            extra.update(file_name=name, file_type=attrs.get("type_description"),
                         size=attrs.get("size"))
            lines.append(f"File: {name} ({attrs.get('type_description', '?')})")

        conf = "high" if verdict == "MALICIOUS" else "medium" if verdict == "SUSPICIOUS" else "low"
        gui = (f"https://www.virustotal.com/gui/{_GUI[itype]}/{urllib.parse.quote(indicator, safe='')}"
               if itype in _GUI else None)
        return [EnrichmentResult(
            result_type="profile",
            title=f"VirusTotal: {indicator} [{verdict}]",
            summary="\n".join(lines),
            url=gui,
            raw_json=extra,
            confidence=conf,
        )]
