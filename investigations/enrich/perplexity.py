"""Perplexity adapter — Sonar / Deep / Reasoning modes."""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError


PERPLEXITY_URL = "https://api.perplexity.ai/chat/completions"


MODEL_BY_MODE = {
    "sonar": "sonar",                           # cheap, fast, AI answer w/ citations
    "search": "sonar",                          # alias
    "deep": "sonar-deep-research",              # long-form research
    "reasoning": "sonar-reasoning-pro",         # compare leads, reconcile contradictions
    "reason": "sonar-reasoning-pro",            # alias
}


class PerplexityAdapter(Adapter):
    slug = "perplexity"
    display_name = "Perplexity Sonar / Deep / Reasoning"
    env_var = "PERPLEXITY_API_KEY"
    category = "search"
    cost_per_call_usd = 0.005

    def modes(self) -> list[str]:
        return ["sonar", "deep", "reasoning"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 90) -> list[EnrichmentResult]:
        key = self.get_key()
        m = (mode or "sonar").lower()
        model = MODEL_BY_MODE.get(m, "sonar")
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are an OSINT analyst. Be concise. Cite sources."},
                {"role": "user", "content": query},
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            PERPLEXITY_URL,
            data=body,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:500]
            raise EnrichmentError(f"Perplexity HTTP {exc.code}: {err_body}")
        except urllib.error.URLError as exc:
            raise EnrichmentError(f"Perplexity network error: {exc}")
        except Exception as exc:
            raise EnrichmentError(f"Perplexity unexpected error: {exc}")

        results = []
        # The model's text answer
        choices = data.get("choices") or []
        if choices:
            answer = choices[0].get("message", {}).get("content", "").strip()
            if answer:
                results.append(EnrichmentResult(
                    result_type="answer",
                    title=f"Perplexity {m}",
                    summary=answer,
                    raw_json=data,
                    confidence="high" if m in ("deep", "reasoning") else "medium",
                ))
        # Citations from search_results / citations
        citations = data.get("search_results") or data.get("citations") or []
        for c in citations[:15]:
            if isinstance(c, str):
                url = c
                title = c
                snippet = ""
            else:
                url = c.get("url") or ""
                title = c.get("title") or url
                snippet = c.get("snippet") or ""
            if not url:
                continue
            results.append(EnrichmentResult(
                result_type="url",
                title=title[:200],
                summary=snippet[:500],
                url=url,
                confidence="medium",
            ))
        return results
