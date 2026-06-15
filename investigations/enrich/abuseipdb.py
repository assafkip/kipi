"""AbuseIPDB adapter — crowdsourced IP reputation: abuse-confidence score, total
reports, usage type, ISP, country, and any reported domain/hostnames for an IP.

The IP-reputation pivot kipi lacked (abuse.ch is malware-feed IOCs; VirusTotal is a
multiscanner). Keyed: AbuseIPDB's v2 /check authenticates with a `Key` header; the free
tier allows 1,000 checks/day. Without a key the adapter reports not-configured.

Emits a header document (score / reports / ISP / usage) plus a promotable node per
reported domain/hostname, so the IP's named infrastructure lands on the graph.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentError, EnrichmentResult

_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
_MAX_HOSTNAMES = 25


def _get(url: str, key: str, timeout: int) -> dict:
    """GET a JSON URL with the AbuseIPDB `Key` header; normalize errors."""
    req = urllib.request.Request(url, headers={
        "Key": key, "Accept": "application/json",
        "User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise EnrichmentError("AbuseIPDB auth failed — check ABUSEIPDB_API_KEY")
        if exc.code == 422:
            raise EnrichmentError("AbuseIPDB: not a valid public IP")
        if exc.code == 429:
            raise EnrichmentError("AbuseIPDB rate limit (free tier 1k/day) — wait and retry")
        raise EnrichmentError(f"AbuseIPDB HTTP {exc.code}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"AbuseIPDB unreachable: {exc.reason}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise EnrichmentError(f"AbuseIPDB: bad response ({exc})")


class AbuseIPDBAdapter(Adapter):
    slug = "abuseipdb"
    watched_types = ('ip',)
    display_name = "AbuseIPDB (IP reputation / abuse reports)"
    env_var = "ABUSEIPDB_API_KEY"
    category = "infra"
    cost_per_call_usd = 0.0  # free tier: 1,000 checks/day

    def modes(self) -> list[str]:
        return ["check"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        ip = (query or "").strip()
        if not ip:
            raise EnrichmentError("AbuseIPDB: empty query")
        key = self.get_key()  # raises NotConfiguredError without a key
        q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""})
        data = (_get(f"{_CHECK_URL}?{q}", key, timeout) or {}).get("data") or {}
        score = data.get("abuseConfidenceScore") or 0   # explicit null -> 0 (avoids None >= 75)
        reports = data.get("totalReports") or 0
        usage = data.get("usageType") or "unknown"
        isp = data.get("isp") or "unknown ISP"
        country = data.get("countryCode") or ""
        domain = (data.get("domain") or "").strip().lower()
        hostnames = [h.strip().lower() for h in (data.get("hostnames") or []) if h]
        tor = bool(data.get("isTor"))
        last = data.get("lastReportedAt") or ""
        conf = "high" if score >= 75 else "medium" if score >= 25 else "low"
        summary = (f"abuse confidence: {score}/100 · {reports} report(s)"
                   + (f" · last {last[:10]}" if last else "")
                   + f"\n{isp}" + (f" · {country}" if country else "")
                   + f" · usage: {usage}" + (" · TOR exit" if tor else "")
                   + (f"\nreported domain: {domain}" if domain else ""))
        header = EnrichmentResult(
            result_type="document", title=f"AbuseIPDB: {ip}", summary=summary,
            raw_json={"ip": ip, "score": score, "reports": reports, "usage": usage,
                      "isp": isp, "country": country, "domain": domain,
                      "hostnames": hostnames, "is_tor": tor},
            confidence=conf)
        nodes, seen = [], set()
        for host in ([domain] if domain else []) + hostnames:
            if host and host not in seen:
                seen.add(host)
                nodes.append(EnrichmentResult(
                    result_type="url", title=host,
                    summary=f"Domain/hostname reported on {ip} (AbuseIPDB).",
                    url=f"http://{host}", confidence="medium"))
        return [header] + nodes[:_MAX_HOSTNAMES]
