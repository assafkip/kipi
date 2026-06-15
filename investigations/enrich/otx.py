"""AlienVault OTX adapter — threat-pulse context + passive DNS for an indicator.

The campaign-context source kipi lacked: is this domain/IP/hash in any known OTX pulse
(campaign), with what tags + malware families, and what infrastructure is passively
associated with it.

OTX paths are /api/v1/indicators/{TYPE}/{indicator}/{section} (Codex maj-1). The TYPE is
auto-detected from the value (VirusTotal-style): IPv4/IPv6, url, file (md5/sha256), else
hostname/domain. Keyed (`X-OTX-API-KEY`). Two section calls:
  - `general`  : pulse_info (count + names + tags) + related malware → a header DOCUMENT
                 (document-only; a pulse/tag/malware name is not a graph entity).
  - `passive_dns` (IPv4/IPv6/domain/hostname only): related domains/IPs → promotable nodes,
                 each a REAL domain/IP value passed through the existing admission gate.
Hashes (`file`) get `general` only — no infra pivots.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentError, EnrichmentResult

_BASE = "https://otx.alienvault.com/api/v1/indicators"
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX32_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_HEX64_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DNS_TYPES = {"IPv4", "IPv6", "domain", "hostname"}   # support a passive_dns section
_MAX_NODES = 40


def _detect_type(value: str) -> str:
    """The OTX indicator TYPE slug for a raw value."""
    v = value.strip()
    if "://" in v:
        return "url"
    if _IPV4_RE.match(v):
        return "IPv4"
    if _HEX64_RE.match(v) or _HEX32_RE.match(v):
        return "file"
    if ":" in v and re.match(r"^[0-9a-fA-F:]+$", v):
        return "IPv6"
    # a host with 3+ labels is a hostname; a registrable 2-label name is a domain
    return "hostname" if v.strip(".").count(".") >= 2 else "domain"


def _get(otype: str, indicator: str, section: str, key: str, timeout: int) -> dict:
    url = f"{_BASE}/{otype}/{urllib.parse.quote(indicator, safe='')}/{section}"
    req = urllib.request.Request(url, headers={
        "X-OTX-API-KEY": key, "Accept": "application/json",
        "User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise EnrichmentError("OTX auth failed — check OTX_API_KEY")
        if exc.code == 404:
            return {}  # indicator not in OTX for this section — not an error, just empty
        if exc.code == 429:
            raise EnrichmentError("OTX rate limit — wait and retry")
        raise EnrichmentError(f"OTX HTTP {exc.code}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"OTX unreachable: {exc.reason}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise EnrichmentError(f"OTX: bad response ({exc})")


class OTXAdapter(Adapter):
    slug = "otx"
    watched_types = ('domain', 'subdomain', 'ip', 'url', 'indicator',
                     'hash_sha256', 'hash_md5')
    display_name = "AlienVault OTX (threat pulses + passive DNS)"
    env_var = "OTX_API_KEY"
    category = "threat"
    cost_per_call_usd = 0.0  # free with an API key

    def modes(self) -> list[str]:
        return ["general"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        indicator = (query or "").strip()
        if not indicator:
            raise EnrichmentError("OTX: empty query")
        key = self.get_key()  # raises NotConfiguredError without a key
        otype = _detect_type(indicator)
        out = [self._general(key, otype, indicator, timeout)]
        if otype in _DNS_TYPES:
            out.extend(self._passive_dns(key, otype, indicator, timeout))
        return out

    def _general(self, key, otype, indicator, timeout) -> EnrichmentResult:
        data = _get(otype, indicator, "general", key, timeout) or {}
        pinfo = data.get("pulse_info") or {}
        pulses = pinfo.get("pulses") or []
        count = pinfo.get("count")
        if not isinstance(count, int):                   # missing OR explicit null
            count = len(pulses)
        names = [p.get("name") for p in pulses[:8] if p.get("name")]
        tags = sorted({t for p in pulses for t in (p.get("tags") or [])})[:15]
        # Each nested level is optional and may be explicit null — guard every hop.
        related = pinfo.get("related") or {}
        alienvault = (related.get("alienvault") or {}) if isinstance(related, dict) else {}
        families = (alienvault.get("malware_families") or []) if isinstance(alienvault, dict) else []
        malware = sorted({m.get("display_name") or m.get("id")
                          for m in families if isinstance(m, dict)})
        conf = "high" if count >= 3 else "medium" if count >= 1 else "low"
        summary = (f"{count} OTX pulse(s) [{otype}]"
                   + (f"\npulses: {', '.join(names)}" if names else "")
                   + (f"\ntags: {', '.join(tags)}" if tags else "")
                   + (f"\nmalware: {', '.join(m for m in malware if m)}" if malware else "")
                   + ("" if count else "\n(not currently in any OTX pulse)"))
        return EnrichmentResult(
            result_type="document", title=f"OTX: {indicator}", summary=summary,
            raw_json={"type": otype, "pulse_count": count, "pulses": names, "tags": tags},
            confidence=conf)

    def _passive_dns(self, key, otype, indicator, timeout) -> list[EnrichmentResult]:
        data = _get(otype, indicator, "passive_dns", key, timeout) or {}
        rows = data.get("passive_dns") or []
        nodes, seen = [], set()
        for row in rows:
            # IP indicators return hostnames; domain/hostname indicators return addresses.
            val = (row.get("hostname") or row.get("address") or "").strip().lower()
            if not val or val in seen:
                continue
            seen.add(val)
            is_ip = bool(_IPV4_RE.match(val)) or (":" in val)
            nodes.append(EnrichmentResult(
                result_type="url", title=val,
                summary=f"Passive-DNS associated with {indicator} (OTX"
                        + (f", {row.get('record_type')}" if row.get("record_type") else "") + ").",
                url=None if is_ip else f"http://{val}", confidence="medium"))
            if len(nodes) >= _MAX_NODES:
                break
        return nodes
