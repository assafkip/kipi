"""Censys adapter — host intelligence (services, ports, certs, ASN, DNS names) for
an IP, or a domain resolved to its IP first.

Supports BOTH Censys auth schemes (auto-detected from the stored credential):

  - Platform (current): a Personal Access Token + an Organization ID.
      GET https://api.platform.censys.io/v3/global/asset/host/{ip}?organization_id={org}
      Authorization: Bearer {PAT}
    Enter the credential as "PAT:ORGID", or set CENSYS_PLATFORM_TOKEN + CENSYS_ORG_ID.

  - Legacy (Search v2): an API ID + API secret (HTTP Basic auth).
      GET https://search.censys.io/api/v2/hosts/{ip}
    Enter the credential as "ID:SECRET", or set CENSYS_API_ID + CENSYS_API_SECRET.

A "X:Y" credential is tried as a Platform token first (Bearer), then as legacy Basic
auth, so either format works in the one Enrich-page field. A single bare token is a
Platform PAT and needs the Org ID (CENSYS_ORG_ID) — without it the adapter says so.

Emits a header document (AS / location / services) + one promotable result per DNS name.
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import urllib.parse
import urllib.request
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError, resolve_key

_PLATFORM_URL = "https://api.platform.censys.io/v3/global/asset/host/"
_LEGACY_URL = "https://search.censys.io/api/v2/hosts/"
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAX_NAMES = 50


def _stored(slug: str) -> str:
    return resolve_key(slug, None) or ""


def _platform_creds(slug: str) -> tuple[str, str]:
    """(pat, org_id) for the Platform API, or ('','') if not available."""
    raw = _stored(slug)
    if raw and ":" in raw:
        pat, _, org = raw.partition(":")
        if pat.strip() and org.strip():
            return pat.strip(), org.strip()
    pat = (raw.strip() if raw and ":" not in raw else "") or os.environ.get("CENSYS_PLATFORM_TOKEN", "").strip()
    org = os.environ.get("CENSYS_ORG_ID", "").strip()
    return (pat, org) if pat and org else ("", "")


def _legacy_creds(slug: str) -> tuple[str, str]:
    """(api_id, api_secret) for the legacy Search v2 API, or ('','')."""
    raw = _stored(slug)
    if raw and ":" in raw:
        cid, _, sec = raw.partition(":")
        if cid.strip() and sec.strip():
            return cid.strip(), sec.strip()
    cid = os.environ.get("CENSYS_API_ID", "").strip()
    sec = os.environ.get("CENSYS_API_SECRET", "").strip()
    return (cid, sec) if cid and sec else ("", "")


def _get(url: str, headers: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise EnrichmentError(f"auth {exc.code}")
        if exc.code == 404:
            raise EnrichmentError("Censys: no host record for that IP (404)")
        if exc.code == 429:
            raise EnrichmentError("Censys rate limit — wait and retry")
        raise EnrichmentError(f"Censys HTTP {exc.code}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"Censys unreachable: {exc.reason}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise EnrichmentError(f"Censys: bad response ({exc})")


class CensysAdapter(Adapter):
    slug = "censys"
    watched_types = ('ip', 'domain', 'subdomain')
    display_name = "Censys (host services / ports / certs)"
    env_var = "CENSYS_PLATFORM_TOKEN"  # surfaced in the UI; Org ID / legacy pair via env or 'X:Y'
    category = "infra"
    cost_per_call_usd = 0.0

    def is_configured(self) -> bool:
        # True only when a COMPLETE credential exists (Platform PAT+Org, or legacy ID+secret).
        # A bare PAT with no Org ID is NOT usable → reported unconfigured so the agent drops
        # it instead of burning a turn on a 'needs Org ID' error.
        return bool(_platform_creds(self.slug)[0] or _legacy_creds(self.slug)[0])

    def modes(self) -> list[str]:
        return ["host"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        target = (query or "").strip().lower()
        if not target:
            raise EnrichmentError("Censys: empty query")
        ip = target if _IP_RE.match(target) else self._resolve(target)

        pat, org = _platform_creds(self.slug)
        cid, sec = _legacy_creds(self.slug)
        # A bare PAT with no Org ID: tell the analyst exactly what's missing.
        if _stored(self.slug) and ":" not in _stored(self.slug) and not org:
            raise EnrichmentError("Censys Platform PAT needs an Org ID — enter the "
                                  "credential as 'PAT:ORGID' (find Org ID in the Censys "
                                  "console URL after org=) or set CENSYS_ORG_ID")
        if not (pat or cid):
            raise EnrichmentError("Censys not configured — add 'PAT:ORGID' (Platform) or "
                                  "'ID:SECRET' (legacy) on the Enrich page")

        errors = []
        # Platform first (the current API).
        if pat and org:
            try:
                q = urllib.parse.urlencode({"organization_id": org})
                data = _get(f"{_PLATFORM_URL}{urllib.parse.quote(ip)}?{q}",
                            {"Authorization": f"Bearer {pat}",
                             "Accept": "application/vnd.censys.api.v3.host.v1+json"}, timeout)
                return self._format(data, ip, target)
            except EnrichmentError as exc:
                if "auth" not in str(exc):
                    raise
                errors.append(f"platform {exc}")
        # Legacy Basic auth fallback.
        if cid and sec:
            try:
                token = base64.b64encode(f"{cid}:{sec}".encode()).decode()
                data = _get(f"{_LEGACY_URL}{urllib.parse.quote(ip)}",
                            {"Authorization": f"Basic {token}", "Accept": "application/json"}, timeout)
                return self._format(data, ip, target)
            except EnrichmentError as exc:
                if "auth" not in str(exc):
                    raise
                errors.append(f"legacy {exc}")
        raise EnrichmentError("Censys auth failed — check the credential ("
                              + "; ".join(errors) + ")")

    # --- defensive parse: the Censys host model is consistent across v2/v3 -------
    def _format(self, data: dict, ip: str, target: str) -> list[EnrichmentResult]:
        res = data.get("result") or data
        asys = res.get("autonomous_system") or {}
        loc = res.get("location") or {}
        services = res.get("services") or []
        names = [n.strip().lower() for n in (res.get("dns") or {}).get("names", []) if n]
        svc_lines = []
        for s in services[:30]:
            name = (s.get("service_name") or s.get("protocol")
                    or s.get("extended_service_name") or "")
            transport = s.get("transport_protocol") or s.get("transport") or "TCP"
            svc_lines.append(f"{s.get('port')}/{transport}" + (f" {name}" if name else ""))
        summary = ((f"{asys.get('name')} · ASN{asys.get('asn')}" if asys.get("asn") else "")
                   + (f" · {loc.get('country')}" if loc.get("country") else "")
                   + (f"\nservices: {'; '.join(svc_lines)}" if svc_lines else "\nno services reported"))
        header = EnrichmentResult(
            result_type="document",
            title=f"Censys: {ip} [{target}]" if target != ip else f"Censys: {ip}",
            summary=summary.strip(),
            raw_json={"ip": ip, "asn": asys.get("asn"), "as_name": asys.get("name"),
                      "country": loc.get("country"), "ports": [s.get("port") for s in services],
                      "services": svc_lines, "dns_names": names},
            confidence="high")
        items = [EnrichmentResult(
            result_type="url", title=n,
            summary=f"DNS name on {ip} (Censys host record).",
            url=f"http://{n}", confidence="medium") for n in names[:_MAX_NAMES]]
        return [header] + items

    def _resolve(self, target: str) -> str:
        try:
            return socket.gethostbyname(target)
        except OSError:
            raise EnrichmentError(f"Censys: could not resolve '{target}' to an IP")
