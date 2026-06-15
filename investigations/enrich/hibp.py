"""Have I Been Pwned adapter — breach exposure, complementing the HudsonRock infostealer
adapter (HIBP = account breaches; HudsonRock = infostealer creds — different data).

Two modes, picked by whether the value is an email (Codex maj-2):
  - email  : /api/v3/breachedaccount/{acct} — which breaches the account appears in.
             KEYED (`hibp-api-key` + a `user-agent` header are both required); raises
             NotConfiguredError without HIBP_API_KEY.
  - domain : /api/v3/breaches?Domain={d} — the public breach CATALOG filtered to breaches
             recorded AGAINST that website. This is keyless and is site-breach CONTEXT, NOT
             a list of exposed accounts at the domain (that endpoint needs verified control).

Document-only: a breach name is not a graph entity, so no promotable nodes. `is_configured()`
gates on the key (the email pivot is the headline capability), so the UI menu greys HIBP out
until a key is set — but the keyless domain mode stays reachable by the agent (MCP `hibp`) and
a direct `run()`; it just isn't surfaced as a UI button without a key. Intended (Codex review).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentError, EnrichmentResult

_BASE = "https://haveibeenpwned.com/api/v3"
_UA = "kipi-investigations"


def _get(url: str, headers: dict, timeout: int) -> object:
    req = urllib.request.Request(url, headers={**headers, "Accept": "application/json",
                                               "User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []  # HIBP returns 404 for "no breaches found" — clean, not an error
        if exc.code == 401:
            raise EnrichmentError("HIBP auth failed — check HIBP_API_KEY")
        if exc.code == 429:
            raise EnrichmentError("HIBP rate limit — wait and retry")
        raise EnrichmentError(f"HIBP HTTP {exc.code}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"HIBP unreachable: {exc.reason}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise EnrichmentError(f"HIBP: bad response ({exc})")


class HIBPAdapter(Adapter):
    slug = "hibp"
    watched_types = ('email', 'domain')
    display_name = "Have I Been Pwned (breach exposure)"
    env_var = "HIBP_API_KEY"
    category = "breach"
    cost_per_call_usd = 0.0  # subscription key (~$3.95/mo); per-call free

    def modes(self) -> list[str]:
        return ["account", "domain"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        value = (query or "").strip()
        if not value:
            raise EnrichmentError("HIBP: empty query")
        if "@" in value:
            return self._account(value, timeout)
        return self._domain(value, timeout)

    def _account(self, account: str, timeout: int) -> list[EnrichmentResult]:
        key = self.get_key()  # raises NotConfiguredError without a key
        url = f"{_BASE}/breachedaccount/{urllib.parse.quote(account, safe='')}?truncateResponse=false"
        breaches = _get(url, {"hibp-api-key": key}, timeout) or []
        if not breaches:
            return [EnrichmentResult(
                result_type="document", title=f"HIBP: {account}",
                summary="No breaches found for this account.", confidence="medium")]
        lines = [f"- {b.get('Name')} ({(b.get('BreachDate') or '')[:10]}"
                 f", {b.get('PwnCount', '?')} accounts)" for b in breaches]
        return [EnrichmentResult(
            result_type="document", title=f"HIBP: {account} — {len(breaches)} breach(es)",
            summary="\n".join(lines[:40]),
            raw_json={"account": account, "breaches": [b.get("Name") for b in breaches]},
            confidence="high")]

    def _domain(self, domain: str, timeout: int) -> list[EnrichmentResult]:
        # Public breach CATALOG filtered to this site — keyless, site-breach context.
        q = urllib.parse.urlencode({"Domain": domain})
        breaches = _get(f"{_BASE}/breaches?{q}", {}, timeout) or []
        if not breaches:
            return [EnrichmentResult(
                result_type="document", title=f"HIBP: {domain}",
                summary="No breaches recorded against this site in the HIBP catalog.",
                confidence="medium")]
        lines = [f"- {b.get('Name')} ({(b.get('BreachDate') or '')[:10]}"
                 f", {b.get('PwnCount', '?')} accounts)" for b in breaches]
        return [EnrichmentResult(
            result_type="document",
            title=f"HIBP: {domain} — {len(breaches)} breach(es) recorded against this site",
            summary="(public breach catalog — site context, not exposed-account data)\n"
                    + "\n".join(lines[:40]),
            raw_json={"domain": domain, "breaches": [b.get("Name") for b in breaches]},
            confidence="medium")]
