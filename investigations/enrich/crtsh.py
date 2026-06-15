"""crt.sh adapter — certificate transparency lookup (subdomain discovery).

Ported from huntkit's threat-intel MCP (crt_lookup). Keyless. Surfaces every
hostname that has ever had a cert issued for a domain — a fast, free way to
enumerate subdomains and related infrastructure for pivoting.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.parse
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError


class CrtShAdapter(Adapter):
    slug = "crtsh"
    watched_types = ('domain', 'subdomain')
    display_name = "crt.sh certificate transparency"
    env_var = None  # keyless
    category = "infra"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["default"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 40) -> list[EnrichmentResult]:
        domain = (query or "").strip().replace("https://", "").replace("http://", "").split("/")[0]
        if not domain:
            raise EnrichmentError("crt.sh: empty domain")
        params = urllib.parse.urlencode({"q": domain, "output": "json"})
        req = urllib.request.Request(f"https://crt.sh/?{params}",
                                     headers={"User-Agent": "kipi-investigations"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise EnrichmentError(f"crt.sh HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise EnrichmentError(f"crt.sh network error: {exc}")
        try:
            data = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            raise EnrichmentError("crt.sh returned non-JSON (rate limited or down)")

        if not data:
            return [EnrichmentResult(
                result_type="document", title=f"crt.sh: {domain} [no certs]",
                summary="No certificate transparency records found.", confidence="low")]

        # Dedup certs by serial; collect every hostname seen across name_value/common_name.
        seen_serial, hostnames, issuers = set(), set(), set()
        for cert in data:
            serial = cert.get("serial_number", "")
            if serial in seen_serial:
                continue
            seen_serial.add(serial)
            issuers.add(cert.get("issuer_name", ""))
            for nm in (cert.get("name_value", "") or "").splitlines():
                nm = nm.strip().lower()
                if nm and "*" not in nm:
                    hostnames.add(nm)
            cn = (cert.get("common_name", "") or "").strip().lower()
            if cn and "*" not in cn:
                hostnames.add(cn)

        hosts_sorted = sorted(hostnames)
        shown = hosts_sorted[:40]
        summary = (
            f"{len(seen_serial)} unique certs, {len(hostnames)} distinct hostnames, "
            f"{len(issuers)} issuer(s).\n\nHostnames (subdomain pivots):\n"
            + "\n".join(f"  - {h}" for h in shown)
            + (f"\n  …and {len(hosts_sorted) - len(shown)} more" if len(hosts_sorted) > len(shown) else "")
        )
        return [EnrichmentResult(
            result_type="document",
            title=f"crt.sh: {domain} — {len(hostnames)} hostnames",
            summary=summary,
            url=f"https://crt.sh/?q={urllib.parse.quote(domain)}",
            raw_json={"hostnames": hosts_sorted, "issuers": sorted(issuers),
                      "unique_certs": len(seen_serial)},
            confidence="medium",
        )]
