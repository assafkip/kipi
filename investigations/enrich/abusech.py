"""abuse.ch adapter — URLhaus (malware URLs) + ThreatFox (IOCs).

Ported from huntkit's threat-intel MCP (urlhaus_lookup, threatfox_lookup). Both
services are abuse.ch and share one Auth-Key. Modes:
  - urlhaus   : is this host/URL a known malware distribution point?
  - threatfox : is this indicator a known IOC (and tied to what malware)?
Default auto-picks urlhaus for a host/URL, threatfox for anything else.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.parse
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


class AbuseChAdapter(Adapter):
    slug = "abusech"
    watched_types = ('domain', 'subdomain', 'url', 'ip', 'hash_sha256', 'hash_md5', 'indicator')
    display_name = "abuse.ch — URLhaus + ThreatFox"
    env_var = "ABUSECH_AUTH_KEY"
    category = "reputation"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["urlhaus", "threatfox"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        key = self.get_key()
        indicator = (query or "").strip()
        if not indicator:
            raise EnrichmentError("abuse.ch: empty indicator")
        m = (mode or "").lower()
        if m in ("", "auto", "default"):
            m = "urlhaus" if (indicator.startswith(("http://", "https://"))
                              or "." in indicator) else "threatfox"
        headers = {"Auth-Key": key}
        if m == "urlhaus":
            return self._urlhaus(indicator, headers, timeout)
        if m == "threatfox":
            return self._threatfox(indicator, headers, timeout)
        raise EnrichmentError(f"abuse.ch: unknown mode '{m}'")

    def _post(self, url, data, headers, timeout, is_json=False):
        if is_json:
            body = json.dumps(data).encode()
            headers = {**headers, "Content-Type": "application/json"}
        else:
            body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise EnrichmentError("abuse.ch auth failed — check ABUSECH_AUTH_KEY")
            raise EnrichmentError(f"abuse.ch HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise EnrichmentError(f"abuse.ch network error: {exc}")

    def _urlhaus(self, indicator, headers, timeout):
        is_url = indicator.startswith(("http://", "https://"))
        endpoint, field = (f"{URLHAUS_BASE}/url/", "url") if is_url else (f"{URLHAUS_BASE}/host/", "host")
        data = self._post(endpoint, {field: indicator}, headers, timeout)
        status = data.get("query_status", "unknown")
        if status == "no_results":
            return [EnrichmentResult(
                result_type="profile", title=f"URLhaus: {indicator} [NOT FOUND]",
                summary="No URLhaus records for this indicator.", confidence="low")]
        if is_url:
            verdict = "MALICIOUS" if data.get("threat") else "UNKNOWN"
            summary = (f"Verdict: {verdict}\nThreat: {data.get('threat', '?')}\n"
                       f"Status: {data.get('url_status', '?')}\n"
                       f"Added: {data.get('date_added', '?')}\n"
                       f"Tags: {', '.join(data.get('tags') or []) or '—'}")
            return [EnrichmentResult(
                result_type="profile", title=f"URLhaus: {indicator} [{verdict}]",
                summary=summary, url=indicator, raw_json=data,
                confidence="high" if data.get("threat") else "medium")]
        online = data.get("urls_online", 0)
        urls = data.get("urls", []) or []
        verdict = "MALICIOUS" if online > 0 else "PREVIOUSLY FLAGGED" if urls else "CLEAN"
        recent = "\n".join(f"  - {u.get('url', '')[:90]} [{u.get('url_status', '')}]"
                           for u in urls[:5])
        summary = (f"Verdict: {verdict}\n{online} URLs online, "
                   f"{len(urls)} tracked total\n{recent}".rstrip())
        return [EnrichmentResult(
            result_type="profile", title=f"URLhaus: {indicator} [{verdict}]",
            summary=summary, raw_json=data,
            confidence="high" if online else "medium" if urls else "low")]

    def _threatfox(self, indicator, headers, timeout):
        data = self._post(THREATFOX_URL, {"query": "search_ioc", "search_term": indicator},
                          headers, timeout, is_json=True)
        if data.get("query_status") == "no_result":
            return [EnrichmentResult(
                result_type="profile", title=f"ThreatFox: {indicator} [NOT FOUND]",
                summary="No ThreatFox records.", confidence="low")]
        iocs = data.get("data", []) or []
        lines = [f"{len(iocs)} match(es):"]
        for i in iocs[:8]:
            lines.append(f"  - {i.get('ioc', '')} | {i.get('threat_type', '')} | "
                         f"{i.get('malware_printable', '')} (conf {i.get('confidence_level', '?')})")
        return [EnrichmentResult(
            result_type="profile", title=f"ThreatFox: {indicator} [MALICIOUS]",
            summary="\n".join(lines), raw_json=data, confidence="high")]
