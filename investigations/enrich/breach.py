"""Breach-intel adapter — HudsonRock Cavalier (infostealer exposure).

The 4_points Level-1.5 tier: check breach / infostealer exposure BEFORE paid scraping —
often the highest-signal early pivot (G-BREACH). Query by domain (employees/users
infected by infostealers) or by email/login (stealer records).

Keyed: HudsonRock's Cavalier v3 API authenticates with an `api-key` header and takes a
POST JSON body (the old keyless GET path was removed — verified 2026-06-03, it 404s).
So this adapter declares `HUDSONROCK_API_KEY`; without it the tool reports 'not
configured' (honest) instead of advertising a keyless tool that fails at runtime.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.parse
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_BASE = "https://cavalier.hudsonrock.com/api/json/v3"


def _detect(indicator: str) -> str:
    return "email" if "@" in indicator else "domain"


def _post(url: str, payload: dict, key: str, timeout: int) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json", "api-key": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        if exc.code in (401, 403):
            raise EnrichmentError("HudsonRock auth failed — check HUDSONROCK_API_KEY")
        if exc.code == 429:
            raise EnrichmentError("HudsonRock rate limit — wait and retry")
        raise EnrichmentError(f"HudsonRock HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"HudsonRock network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("HudsonRock returned non-JSON (rate limited or down)")


class BreachAdapter(Adapter):
    slug = "breach"
    display_name = "Breach intel (HudsonRock Cavalier — infostealer exposure)"
    env_var = "HUDSONROCK_API_KEY"
    category = "breach"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["auto", "domain", "email"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 40) -> list[EnrichmentResult]:
        key = self.get_key()
        ind = (query or "").strip()
        if not ind:
            raise EnrichmentError("breach: empty indicator")
        m = (mode or "auto").lower()
        if m in ("auto", "default", ""):
            m = _detect(ind)

        if m == "domain":
            data = _post(f"{_BASE}/search-by-domain", {"domains": [ind]}, key, timeout)
            rec = data.get(ind) if isinstance(data.get(ind), dict) else data
            total = (rec.get("total") or rec.get("totalStealers")
                     or len(rec.get("stealers") or rec.get("data") or []))
            employees = rec.get("employees") or rec.get("employeesCount")
            users = rec.get("users") or rec.get("usersCount")
            if not rec or not (total or employees or users):
                return [EnrichmentResult(
                    result_type="document", title=f"Breach: {ind} [none]",
                    summary="No HudsonRock infostealer exposure found for this domain.",
                    confidence="low")]
            summary = (f"HudsonRock infostealer exposure for {ind}:\n"
                       f"  employees compromised: {employees}\n"
                       f"  users compromised: {users}\n"
                       f"  total stealer records: {total}")
            return [EnrichmentResult(
                result_type="profile", title=f"Breach: {ind} — infostealer exposure",
                summary=summary,
                raw_json={"employees": employees, "users": users, "total": total},
                confidence="high" if (employees or total) else "medium")]

        # email / login
        data = _post(f"{_BASE}/search-by-login/emails", {"logins": [ind]}, key, timeout)
        rec = data.get(ind) if isinstance(data.get(ind), dict) else data
        stealers = rec.get("stealers") or rec.get("data") or []
        if not stealers:
            return [EnrichmentResult(
                result_type="document", title=f"Breach: {ind} [none]",
                summary="No HudsonRock infostealer record for this email/login.",
                confidence="low")]
        lines = [f"{len(stealers)} infostealer record(s) for {ind}:"]
        for s in stealers[:5]:
            when = s.get("date_compromised") or s.get("date") or "?"
            family = s.get("stealer_family") or s.get("malware") or "?"
            lines.append(f"  - {family}, compromised {when}")
        return [EnrichmentResult(
            result_type="profile", title=f"Breach: {ind} — {len(stealers)} stealer hit(s)",
            summary="\n".join(lines), raw_json={"stealers": stealers[:20]},
            confidence="high")]
