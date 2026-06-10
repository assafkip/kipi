"""IP geolocation + ASN adapter — IP (or domain) -> geo + ISP/org + autonomous system.

Keyless via ip-api.com (free tier: HTTP only, ~45 req/min). Fills the IP -> org / ASN
mapping kipi didn't have: shodan/censys give ports/services, this gives WHERE an IP
lives and WHO owns the netblock (ASN + org). A domain is resolved to its A-record first.

  http://ip-api.com/json/<ip>?fields=...   (free, no key, HTTP only)
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

# HTTP (not HTTPS) — the free ip-api tier is HTTP only; HTTPS requires a paid key.
_API = ("http://ip-api.com/json/{q}"
        "?fields=status,message,query,country,countryCode,regionName,city,zip,"
        "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting")


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return ":" in s  # crude IPv6 check


def _resolve(host: str) -> str:
    """Resolve a domain to its A-record IP; pass an IP through unchanged."""
    if _is_ip(host):
        return host
    try:
        return socket.gethostbyname(host)
    except OSError as exc:
        raise EnrichmentError(f"ipgeo: could not resolve {host!r}: {exc}")


def _fetch(ip: str, timeout: int) -> dict:
    req = urllib.request.Request(_API.format(q=ip),
                                 headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"ip-api HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"ip-api network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("ip-api returned non-JSON (rate limited or down)")


class IpGeoAdapter(Adapter):
    slug = "ipgeo"
    display_name = "IP geolocation + ASN (ip-api)"
    env_var = None  # keyless
    category = "infra"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["default"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        target = (query or "").strip().replace("https://", "").replace("http://", "").split("/")[0]
        if not target:
            raise EnrichmentError("ipgeo: empty target")
        ip = _resolve(target)
        data = _fetch(ip, timeout)
        if data.get("status") != "success":
            return [EnrichmentResult(
                result_type="document",
                title=f"IP geo: {ip} [no data]",
                summary=f"ip-api: {data.get('message') or 'no geolocation data'}.",
                confidence="low")]

        loc = ", ".join(p for p in (data.get("city"), data.get("regionName"),
                                    data.get("country")) if p)
        asn = data.get("as") or ""           # e.g. "AS15169 Google LLC"
        flags = [k for k in ("mobile", "proxy", "hosting") if data.get(k)]
        lines = [
            f"location: {loc}" if loc else "",
            f"coords: {data.get('lat')}, {data.get('lon')}" if data.get("lat") else "",
            f"ISP: {data.get('isp')}" if data.get("isp") else "",
            f"org: {data.get('org')}" if data.get("org") else "",
            f"ASN: {asn}" if asn else "",
            f"reverse DNS: {data.get('reverse')}" if data.get("reverse") else "",
            f"flags: {', '.join(flags)}" if flags else "",
        ]
        resolved_note = f" (resolved from {target})" if target != ip else ""
        return [EnrichmentResult(
            result_type="document",
            title=f"IP geo + ASN: {ip}{resolved_note} — {asn or loc or 'located'}",
            summary="\n".join(s for s in lines if s) or "Located.",
            url=f"https://ip-api.com/#{ip}",
            raw_json=data,
            confidence="medium")]
