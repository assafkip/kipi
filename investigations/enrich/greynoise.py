"""GreyNoise adapter — is this IP internet-background-noise or targeted? (T2).

On an intrusion-apt case, GreyNoise tells the analyst whether a probing IP is a benign
mass-scanner / known-good service (RIOT) / malicious background noise / or UNSEEN (more
likely targeted at you). That triage saves tool budget and doesn't overlap VT/AbuseIPDB.

Community tier needs a free key (GREYNOISE_API_KEY). Self-guards to a [needs key] result
when unset (never raises), mirroring the wallet ETH path. Document-only (the IP is the
seed; no pivotable child entity), mirroring hibp.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError, resolve_key

_API = "https://api.greynoise.io/v3/community/"


def _get(ip: str, key: str, timeout: int) -> dict:
    req = urllib.request.Request(
        _API + ip, headers={"key": key, "Accept": "application/json",
                            "User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"ip": ip, "noise": False, "riot": False, "classification": "unseen",
                    "message": "IP not observed by GreyNoise"}
        raise EnrichmentError(f"GreyNoise HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"GreyNoise network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("GreyNoise returned non-JSON (rate limited or down)")


class GreyNoiseAdapter(Adapter):
    slug = "greynoise"
    watched_types = ("ip",)
    display_name = "GreyNoise (scanner classification)"
    env_var = "GREYNOISE_API_KEY"
    category = "reputation"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        ip = (query or "").strip()
        if not ip:
            raise EnrichmentError("greynoise: empty IP")
        key = resolve_key(self.slug, self.env_var)
        if not key:
            return [EnrichmentResult(
                result_type="document",
                title=f"GreyNoise: {ip} [needs key]",
                summary="GreyNoise community tier needs a free key (greynoise.io). Add it on "
                        "the Enrich page (greynoise) or set $GREYNOISE_API_KEY, then retry.",
                confidence="low")]
        data = _get(ip, key, timeout)
        classification = data.get("classification", "unknown")
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        name = data.get("name", "")
        return [EnrichmentResult(
            result_type="document",
            title=f"GreyNoise: {ip} — {classification}",
            summary=(f"classification: {classification}\n"
                     f"mass-scanner noise: {noise}\nknown-good service (RIOT): {riot}\n"
                     f"actor/name: {name or '(none)'}\n"
                     + ("UNSEEN by GreyNoise — more likely targeted at you than background."
                        if classification == "unseen" else
                        "Background internet noise — likely not specifically targeting you."
                        if noise else "")),
            url=f"https://viz.greynoise.io/ip/{ip}",
            raw_json=data, confidence="high")]
