"""Shodan adapter — host intelligence: open ports, running services, banners,
hostnames, and known CVEs for an IP (or a domain, resolved to its IP first).

Two modes, picked automatically by whether a key is present:
  - KEYED  (SHODAN_API_KEY): full host record via https://api.shodan.io/shodan/host/{ip}
           — service banners, products/versions, org/ISP/ASN, hostnames, vulns.
  - KEYLESS (no key): https://internetdb.shodan.io/{ip} — ports, CPEs, hostnames,
           tags, vulns (no banners). Free, no signup. So Shodan returns SOMETHING
           even before the analyst adds a key (is_configured stays True).

Emits ONE promotable result per discovered hostname (each becomes a graph node) plus
a header document summarizing the host (ports / services / vulns).
"""
from __future__ import annotations

import json
import re
import socket
import urllib.parse
import urllib.request
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError, resolve_key

_HOST_URL = "https://api.shodan.io/shodan/host/"
_RESOLVE_URL = "https://api.shodan.io/dns/resolve"
_INTERNETDB_URL = "https://internetdb.shodan.io/"

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAX_HOSTNAMES = 50


def _get(url: str, timeout: int) -> dict:
    """GET a JSON URL, normalize errors to EnrichmentError."""
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise EnrichmentError("Shodan auth failed — check SHODAN_API_KEY")
        if exc.code == 404:
            raise EnrichmentError("Shodan: no information for that host (404)")
        if exc.code == 429:
            raise EnrichmentError("Shodan rate limit — wait and retry")
        raise EnrichmentError(f"Shodan HTTP {exc.code}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"Shodan unreachable: {exc.reason}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise EnrichmentError(f"Shodan: bad response ({exc})")


def _resolve_to_ip(target: str, key: str, timeout: int) -> str:
    """A domain -> its IP. Uses Shodan's resolver when keyed, else local DNS."""
    if _IP_RE.match(target):
        return target
    if key:
        try:
            q = urllib.parse.urlencode({"hostnames": target, "key": key})
            data = _get(f"{_RESOLVE_URL}?{q}", timeout)
            ip = data.get(target)
            if ip:
                return str(ip)
        except EnrichmentError:
            pass  # fall through to local resolution
    try:
        return socket.gethostbyname(target)
    except OSError:
        raise EnrichmentError(f"Shodan: could not resolve '{target}' to an IP")


class ShodanAdapter(Adapter):
    slug = "shodan"
    display_name = "Shodan (host ports / services / CVEs)"
    env_var = "SHODAN_API_KEY"
    category = "infra"
    cost_per_call_usd = 0.0  # keyless InternetDB free; keyed host lookup = 1 query credit

    def is_configured(self) -> bool:
        # Keyless InternetDB always works, so Shodan is usable even with no key.
        return True

    def modes(self) -> list[str]:
        return ["host"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        target = (query or "").strip().lower()
        if not target:
            raise EnrichmentError("Shodan: empty query")
        key = resolve_key(self.slug, self.env_var)
        ip = _resolve_to_ip(target, key, timeout)
        if key:
            return self._host_keyed(key, ip, target, timeout)
        return self._host_keyless(ip, target, timeout)

    # --- full host record (keyed) ------------------------------------------------
    def _host_keyed(self, key: str, ip: str, target: str, timeout: int) -> list[EnrichmentResult]:
        q = urllib.parse.urlencode({"key": key})
        data = _get(f"{_HOST_URL}{urllib.parse.quote(ip)}?{q}", timeout)
        org = data.get("org") or data.get("isp") or "unknown org"
        asn = data.get("asn") or ""
        country = data.get("country_name") or ""
        ports = data.get("ports") or []
        vulns = list(data.get("vulns") or [])
        hostnames = [h.strip().lower() for h in (data.get("hostnames") or []) if h]
        svc_lines = []
        for s in (data.get("data") or [])[:25]:
            prod = " ".join(x for x in (str(s.get("product") or ""), str(s.get("version") or "")) if x)
            svc_lines.append(f"{s.get('port')}/{s.get('transport') or 'tcp'}"
                             + (f" {prod}" if prod.strip() else ""))
        summary = (f"{org}" + (f" · ASN{asn}" if asn else "") + (f" · {country}" if country else "")
                   + f"\nopen ports: {', '.join(str(p) for p in ports) or 'none'}"
                   + (f"\nservices: {'; '.join(svc_lines)}" if svc_lines else "")
                   + (f"\nCVEs: {', '.join(sorted(vulns)[:20])}" if vulns else ""))
        header = EnrichmentResult(
            result_type="document", title=f"Shodan: {ip} [{target}]" if target != ip else f"Shodan: {ip}",
            summary=summary,
            raw_json={"ip": ip, "org": org, "asn": asn, "country": country,
                      "ports": ports, "hostnames": hostnames, "vulns": vulns},
            confidence="high")
        return [header] + self._hostname_results(hostnames, ip)

    # --- keyless InternetDB ------------------------------------------------------
    def _host_keyless(self, ip: str, target: str, timeout: int) -> list[EnrichmentResult]:
        data = _get(f"{_INTERNETDB_URL}{urllib.parse.quote(ip)}", timeout)
        ports = data.get("ports") or []
        vulns = list(data.get("vulns") or [])
        hostnames = [h.strip().lower() for h in (data.get("hostnames") or []) if h]
        cpes = data.get("cpes") or []
        summary = (f"(keyless InternetDB — add SHODAN_API_KEY for banners/org)\n"
                   f"open ports: {', '.join(str(p) for p in ports) or 'none'}"
                   + (f"\nsoftware (CPE): {', '.join(cpes[:12])}" if cpes else "")
                   + (f"\nCVEs: {', '.join(sorted(vulns)[:20])}" if vulns else ""))
        header = EnrichmentResult(
            result_type="document", title=f"Shodan: {ip} [{target}]" if target != ip else f"Shodan: {ip}",
            summary=summary,
            raw_json={"ip": ip, "ports": ports, "hostnames": hostnames, "vulns": vulns, "cpes": cpes},
            confidence="medium")
        return [header] + self._hostname_results(hostnames, ip)

    def _hostname_results(self, hostnames: list[str], ip: str) -> list[EnrichmentResult]:
        """One promotable node per hostname pointing at this IP."""
        return [EnrichmentResult(
            result_type="url", title=h,
            summary=f"Hostname resolving on {ip} (Shodan host record).",
            url=f"http://{h}", confidence="medium") for h in hostnames[:_MAX_HOSTNAMES]]
