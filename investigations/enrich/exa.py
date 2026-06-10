"""Exa adapter — semantic search + company / people endpoints."""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError


EXA_SEARCH_URL = "https://api.exa.ai/search"
EXA_FIND_SIMILAR_URL = "https://api.exa.ai/findSimilar"
EXA_CONTENTS_URL = "https://api.exa.ai/contents"


class ExaAdapter(Adapter):
    slug = "exa"
    display_name = "Exa AI semantic search"
    env_var = "EXA_API_KEY"
    category = "search"
    cost_per_call_usd = 0.005

    def modes(self) -> list[str]:
        return ["search", "company", "people", "crawl"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        key = self.get_key()
        m = (mode or "search").lower()
        if m == "crawl":
            return self._crawl(key, query, timeout)
        # search, company, people all use the search endpoint with category param
        payload = {
            "query": query,
            "numResults": 10,
            "contents": {"text": {"maxCharacters": 500}},
        }
        if m == "company":
            payload["category"] = "company"
        elif m == "people":
            payload["category"] = "personal site"
        data = self._post(EXA_SEARCH_URL, payload, key, timeout)
        results = []
        for r in data.get("results", []):
            results.append(EnrichmentResult(
                result_type="url" if m == "search" else "profile",
                title=(r.get("title") or "")[:200],
                summary=(r.get("text") or "")[:600],
                url=r.get("url"),
                raw_json=r,
                confidence="medium",
            ))
        return results

    def _crawl(self, key: str, url: str, timeout: int) -> list[EnrichmentResult]:
        payload = {"ids": [url], "text": {"maxCharacters": 4000}}
        data = self._post(EXA_CONTENTS_URL, payload, key, timeout)
        results = []
        for r in data.get("results", []):
            results.append(EnrichmentResult(
                result_type="document",
                title=(r.get("title") or "")[:200],
                summary=(r.get("text") or "")[:2000],
                url=r.get("url"),
                raw_json=r,
                confidence="high",
            ))
        return results

    def _post(self, url: str, payload: dict, key: str, timeout: int) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "x-api-key": key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise EnrichmentError(f"Exa HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:300]}")
        except urllib.error.URLError as exc:
            raise EnrichmentError(f"Exa network error: {exc}")
