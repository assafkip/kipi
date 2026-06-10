"""Tavily adapter — search + extract."""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError


TAVILY_SEARCH_URL = "https://api.tavily.com/search"
TAVILY_EXTRACT_URL = "https://api.tavily.com/extract"


class TavilyAdapter(Adapter):
    slug = "tavily"
    display_name = "Tavily Search + Extract"
    env_var = "TAVILY_API_KEY"
    category = "search"
    cost_per_call_usd = 0.005

    def modes(self) -> list[str]:
        return ["search", "deep", "extract"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        key = self.get_key()
        m = (mode or "search").lower()
        if m == "extract":
            return self._extract(key, query, timeout)
        depth = "advanced" if m == "deep" else "basic"
        payload = {
            "api_key": key,
            "query": query,
            "search_depth": depth,
            "max_results": 10,
            "include_answer": True,
        }
        data = self._post(TAVILY_SEARCH_URL, payload, timeout)
        results = []
        if data.get("answer"):
            results.append(EnrichmentResult(
                result_type="answer",
                title=f"Tavily {m}",
                summary=data["answer"][:2000],
                raw_json=data,
                confidence="medium",
            ))
        for r in data.get("results", []):
            results.append(EnrichmentResult(
                result_type="url",
                title=(r.get("title") or "")[:200],
                summary=(r.get("content") or "")[:500],
                url=r.get("url"),
                confidence="medium",
            ))
        return results

    def _extract(self, key: str, url: str, timeout: int) -> list[EnrichmentResult]:
        payload = {"api_key": key, "urls": [url], "extract_depth": "basic"}
        data = self._post(TAVILY_EXTRACT_URL, payload, timeout)
        results = []
        for r in data.get("results", []):
            results.append(EnrichmentResult(
                result_type="document",
                title=r.get("url") or url,
                summary=(r.get("raw_content") or "")[:2000],
                url=r.get("url"),
                raw_json=r,
                confidence="high",
            ))
        return results

    def _post(self, url: str, payload: dict, timeout: int) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise EnrichmentError(f"Tavily HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:300]}")
        except urllib.error.URLError as exc:
            raise EnrichmentError(f"Tavily network error: {exc}")
