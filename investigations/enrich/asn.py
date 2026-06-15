"""ASN adapter — IP -> ASN -> netblock owner (keyless, Team Cymru DNS).

Closes a live orphan: the `asn` entity type existed in TRANSFORM_TYPES with NO producer.
This gives it both a producer (ip -> AS<n> child node) and a consumer (asn -> org). The
ASN/org owner of a netblock is the shared/bulletproof-hosting pivot for intrusion-apt and
crypto-fraud infra mapping.

Keyless via Team Cymru's DNS-TXT origin service (no key, no rate friction; dnspython is
already a dependency). Real lookup failures raise EnrichmentError.
"""
from __future__ import annotations

import re

import dns.resolver

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ASN_RE = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)


def _cymru_txt(name: str, timeout: int = 10) -> str | None:
    """Resolve one Team Cymru TXT record to its unquoted string. None if empty."""
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=timeout)
    except Exception as exc:  # NXDOMAIN / timeout / no-answer
        raise EnrichmentError(f"Cymru DNS {name}: {exc}")
    for r in ans:
        return r.to_text().strip('"')
    return None


def _asn_name(asn_num: str, timeout: int) -> str:
    """AS<n>.asn.cymru.com -> the org/name (last pipe field). '' if unknown."""
    txt = _cymru_txt(f"AS{asn_num}.asn.cymru.com", timeout)
    if not txt:
        return ""
    return txt.split("|")[-1].strip()


class AsnAdapter(Adapter):
    slug = "asn"
    watched_types = ("ip", "asn")
    display_name = "ASN / netblock owner (Team Cymru)"
    env_var = None  # keyless DNS
    category = "infra"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 20) -> list[EnrichmentResult]:
        q = (query or "").strip()
        if _IPV4_RE.match(q):
            return self._from_ip(q, timeout)
        m = _ASN_RE.match(q)
        if m:
            return self._from_asn(m.group(1), timeout)
        raise EnrichmentError(f"asn: '{query}' is not an IPv4 address or AS number")

    def _from_ip(self, ip: str, timeout: int) -> list[EnrichmentResult]:
        rev = ".".join(reversed(ip.split(".")))
        txt = _cymru_txt(f"{rev}.origin.asn.cymru.com", timeout)
        if not txt:
            return [EnrichmentResult(
                result_type="document", title=f"ASN: {ip} — no origin",
                summary="No BGP origin found for this IP.",
                raw_json={"ip": ip}, confidence="low")]
        # Format: "ASN | BGP prefix | CC | registry | date"
        fields = [f.strip() for f in txt.split("|")]
        asn_num = fields[0].split()[0] if fields else ""
        prefix = fields[1] if len(fields) > 1 else ""
        cc = fields[2] if len(fields) > 2 else ""
        org = _asn_name(asn_num, timeout) if asn_num else ""
        header = EnrichmentResult(
            result_type="document",
            title=f"ASN: {ip} -> AS{asn_num} ({org or 'unknown'})",
            summary=f"AS{asn_num} | prefix {prefix} | {cc} | owner: {org or 'unknown'}",
            raw_json={"ip": ip, "asn": f"AS{asn_num}", "as": asn_num, "prefix": prefix,
                      "country": cc, "as_owner": org},
            confidence="high")
        rows = [EnrichmentResult(
            result_type="profile", title=f"AS{asn_num}",
            summary=f"BGP origin AS for {ip} ({org or 'unknown'}).",
            raw_json={"asn": f"AS{asn_num}", "as_owner": org}, confidence="high")]
        if org:
            rows.append(EnrichmentResult(
                result_type="profile", title=org,
                summary=f"Netblock owner / org behind AS{asn_num}.",
                confidence="high"))
        return [header] + rows

    def _from_asn(self, asn_num: str, timeout: int) -> list[EnrichmentResult]:
        org = _asn_name(asn_num, timeout)
        header = EnrichmentResult(
            result_type="document",
            title=f"AS{asn_num} -> {org or 'unknown'}",
            summary=f"AS{asn_num} owner: {org or 'unknown'}",
            raw_json={"asn": f"AS{asn_num}", "as": asn_num, "as_owner": org},
            confidence="high")
        rows = [EnrichmentResult(
            result_type="profile", title=org,
            summary=f"Org behind AS{asn_num}.", confidence="high")] if org else []
        return [header] + rows
