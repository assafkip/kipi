"""urlscan.io adapter — passive SEARCH of existing scans for a domain/host/IP, surfacing
the related infrastructure (the domains + IPs urlscan has already observed for that target).

A strong infra-pivot source kipi lacked. The public SEARCH API works KEYLESS (rate-limited);
a `URLSCAN_API_KEY` raises the quota, so `is_configured()` is always True (like Shodan's
keyless InternetDB). This adapter does NOT submit new scans — submission is an active, logged,
target-leaking action, intentionally out of scope (a later opt-in mode).

Emits a header document (how many scans, the most recent) plus one promotable node per
DISTINCT related page.domain / page.ip observed across the results.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentError, EnrichmentResult, resolve_key

_SEARCH_URL = "https://urlscan.io/api/v1/search/"
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SIZE = 100
_MAX_NODES = 50


def _build_query(target: str) -> str:
    """Scope the urlscan search by target shape: extract the host FIRST (so an IP inside a
    URL, or a host:port, still resolves to the host), then an IPv4/IPv6 host -> ip:, anything
    else -> its host under domain: (matches the page domain + its subdomains)."""
    t = target.strip().lower()
    # strip scheme + path + userinfo down to the host[:port] (or [ipv6]:port)
    host = t.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
    if host.startswith("["):                       # [2001:db8::1]:443 -> 2001:db8::1
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:                      # host:port / 1.2.3.4:8080 -> strip port
        host = host.split(":", 1)[0]
    host = host.strip().strip(".")
    if _IP_RE.match(host) or ":" in host:           # IPv4 or (bare) IPv6
        return f"ip:{host}"
    return f"domain:{host or t}"


def _get(url: str, key: str, timeout: int) -> dict:
    headers = {"Accept": "application/json", "User-Agent": "kipi-investigations"}
    if key:
        headers["API-Key"] = key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise EnrichmentError("urlscan auth/quota — check URLSCAN_API_KEY or rate limit")
        if exc.code == 429:
            raise EnrichmentError("urlscan rate limit (keyless quota) — add URLSCAN_API_KEY")
        raise EnrichmentError(f"urlscan HTTP {exc.code}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"urlscan unreachable: {exc.reason}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise EnrichmentError(f"urlscan: bad response ({exc})")


class UrlscanAdapter(Adapter):
    slug = "urlscan"
    watched_types = ('domain', 'subdomain', 'url', 'ip')
    display_name = "urlscan.io (scan search — related infra)"
    env_var = "URLSCAN_API_KEY"
    category = "infra"
    cost_per_call_usd = 0.0  # keyless search; key only raises the quota

    def is_configured(self) -> bool:
        return True  # the public search works without a key (rate-limited)

    def modes(self) -> list[str]:
        return ["search"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        target = (query or "").strip()
        if not target:
            raise EnrichmentError("urlscan: empty query")
        key = resolve_key(self.slug, self.env_var)
        q = urllib.parse.urlencode({"q": _build_query(target), "size": _SIZE})
        data = _get(f"{_SEARCH_URL}?{q}", key, timeout)
        results = data.get("results") or []
        total = data.get("total", len(results))
        domains, ips = {}, {}
        recent_url, recent_time = "", ""
        for r in results:
            page = r.get("page") or {}
            task = r.get("task") or {}
            d = (page.get("domain") or "").strip().lower()
            ip = (page.get("ip") or "").strip()
            if d:
                domains.setdefault(d, page.get("server") or "")
            if ip:
                ips.setdefault(ip, page.get("asnname") or page.get("asn") or "")
            if not recent_time and task.get("time"):
                recent_time, recent_url = task.get("time") or "", task.get("url") or page.get("url") or ""
        summary = (f"{total} scan(s) on urlscan for {_build_query(target)}"
                   + (f"\nmost recent: {recent_time[:10]} {recent_url}" if recent_url else "")
                   + (f"\nrelated domains: {len(domains)} · related IPs: {len(ips)}"))
        header = EnrichmentResult(
            result_type="document", title=f"urlscan: {target}", summary=summary,
            raw_json={"query": _build_query(target), "total": total,
                      "domains": sorted(domains), "ips": sorted(ips)},
            confidence="medium")
        nodes = []
        for d in sorted(domains):
            nodes.append(EnrichmentResult(
                result_type="url", title=d,
                summary=f"Domain observed in urlscan scans related to {target}"
                        + (f" (server: {domains[d]})" if domains[d] else "") + ".",
                url=f"http://{d}", confidence="medium"))
        for ip in sorted(ips):
            nodes.append(EnrichmentResult(
                result_type="url", title=ip,
                summary=f"IP serving urlscan-observed pages related to {target}"
                        + (f" (AS: {ips[ip]})" if ips[ip] else "") + ".",
                confidence="medium"))
        return [header] + nodes[:_MAX_NODES]
