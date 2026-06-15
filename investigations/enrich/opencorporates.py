"""OpenCorporates adapter — company registry: officers / filings / jurisdiction (T1).

kipi extracts `org` and `person` but couldn't resolve a company to its officers,
jurisdiction, or filing record. For financial-fraud shell-company attribution that
government registry data is T1. An org query -> the company; a person query -> officer
positions across companies.

Freemium: works keyless but rate-limited; an OPENCORPORATES_API_KEY raises the cap. With
no key it tries the keyless call and self-guards to a [needs key] doc if that fails.

ORPHAN-TRAP NOTE (audit O-7 / correction #4): promote._classify can't derive org/person
from a bare name, so the officer/company child rows carry an explicit
raw_json={"promote_as": "person"|"org"} hint that promote_result honors. Each child also
carries the OpenCorporates URL so the promotion guard accepts it.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError, resolve_key

_API = "https://api.opencorporates.com/v0.4"


def _get(path: str, params: dict, timeout: int) -> dict:
    url = f"{_API}/{path}?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"OpenCorporates HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"OpenCorporates network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("OpenCorporates returned non-JSON (rate limited or down)")


class OpenCorporatesAdapter(Adapter):
    slug = "opencorporates"
    watched_types = ("org", "person")
    display_name = "OpenCorporates (company registry)"
    env_var = "OPENCORPORATES_API_KEY"
    category = "registry"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["auto", "company", "officer"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        q = (query or "").strip()
        if not q:
            raise EnrichmentError("opencorporates: empty query")
        key = resolve_key(self.slug, self.env_var)
        params = {"q": q, "per_page": 20}
        if key:
            params["api_token"] = key
        is_officer = (mode == "officer")
        path = "officers/search" if is_officer else "companies/search"
        try:
            body = _get(path, params, timeout)
        except EnrichmentError as exc:
            if not key:
                return [EnrichmentResult(
                    result_type="document",
                    title=f"OpenCorporates: {q} [needs key]",
                    summary=f"Keyless call failed ({exc}); add an OPENCORPORATES_API_KEY "
                            "(free tier at opencorporates.com/api_accounts/new) and retry.",
                    confidence="low")]
            raise
        results = (body.get("results") or {})
        if is_officer:
            return self._officers(q, results.get("officers") or [])
        return self._companies(q, results.get("companies") or [])

    def _companies(self, q: str, companies: list) -> list[EnrichmentResult]:
        rows = [c.get("company", {}) for c in companies]
        header = EnrichmentResult(
            result_type="document",
            title=f"OpenCorporates: {q} — {len(rows)} compan{'y' if len(rows) == 1 else 'ies'}",
            summary="\n".join(
                f"- {c.get('name')} | {c.get('jurisdiction_code')} | "
                f"#{c.get('company_number')} | {c.get('current_status', '')}"
                for c in rows[:20]) or "No companies matched.",
            url=f"https://opencorporates.com/companies?q={urllib.parse.quote(q)}",
            raw_json={"query": q, "companies": rows}, confidence="high")
        children = [EnrichmentResult(
            result_type="profile", title=c.get("name", ""),
            summary=f"Company {c.get('company_number')} ({c.get('jurisdiction_code')}), "
                    f"status {c.get('current_status', 'unknown')}.",
            url=c.get("opencorporates_url"),
            raw_json={"promote_as": "org", "company_number": c.get("company_number"),
                      "jurisdiction": c.get("jurisdiction_code")},
            confidence="high") for c in rows[:20] if c.get("name")]
        return [header] + children

    def _officers(self, q: str, officers: list) -> list[EnrichmentResult]:
        rows = [o.get("officer", {}) for o in officers]
        header = EnrichmentResult(
            result_type="document",
            title=f"OpenCorporates officers: {q} — {len(rows)} match(es)",
            summary="\n".join(
                f"- {o.get('name')} | {o.get('position', '')} @ "
                f"{(o.get('company') or {}).get('name', '')} ({o.get('jurisdiction_code')})"
                for o in rows[:20]) or "No officers matched.",
            url=f"https://opencorporates.com/officers?q={urllib.parse.quote(q)}",
            raw_json={"query": q, "officers": rows}, confidence="high")
        children = [EnrichmentResult(
            result_type="profile", title=o.get("name", ""),
            summary=f"{o.get('position', 'officer')} of "
                    f"{(o.get('company') or {}).get('name', 'a company')}.",
            url=o.get("opencorporates_url"),
            raw_json={"promote_as": "person", "position": o.get("position"),
                      "jurisdiction": o.get("jurisdiction_code")},
            confidence="high") for o in rows[:20] if o.get("name")]
        return [header] + children
