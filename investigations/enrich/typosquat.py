"""Typosquat adapter — lookalike-domain candidates via dnstwist (keyless).

crt.sh confirms certs that already exist; it can't GENERATE the lookalike phishing
domains a crypto-fraud / brand-impersonation operator might register. dnstwist produces
homoglyph / typo / TLD-swap / bitsquat candidates locally; each is then liveness-checked
against DNS.

T3 -> T1 gate: a raw candidate is T3 (generated, unconfirmed) and is listed in the header
summary ONLY. A candidate that RESOLVES (live A record) is a real hostname (T1) and is the
only kind emitted as a promotable child node — so unverified lookalikes never enter the
findings file (q-investigation evidence-tier rule).

Keyless. dnstwist is a pure-Python pip dep. Generation is local + fast; liveness checks are
capped to avoid hammering DNS.
"""
from __future__ import annotations

import dnstwist
import dns.resolver

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_MAX_CHECK = 25  # cap liveness checks (generation can yield thousands of candidates)


def _generate(domain: str) -> list[tuple[str, str]]:
    """(candidate_domain, fuzzer_kind) pairs from dnstwist, excluding the original."""
    fuzzer = dnstwist.Fuzzer(domain)
    fuzzer.generate()
    out: list[tuple[str, str]] = []
    for perm in fuzzer.domains:
        dom = perm["domain"]
        if dom and dom != domain:
            out.append((dom, perm.get("fuzzer", "")))
    return out


def _is_live(domain: str, timeout: int = 3) -> bool:
    """True iff the candidate resolves an A record (the T3->T1 promotion gate)."""
    try:
        dns.resolver.resolve(domain, "A", lifetime=timeout)
        return True
    except Exception:
        return False


class TyposquatAdapter(Adapter):
    slug = "typosquat"
    watched_types = ("domain",)
    display_name = "dnstwist typosquat candidates"
    env_var = None  # keyless
    category = "infra"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        domain = (query or "").strip().lower()
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        if not domain or "." not in domain:
            return [EnrichmentResult(
                result_type="document", title=f"typosquat: '{query}' — not a domain",
                summary="Pass a bare domain (e.g. binance.com).", confidence="low")]
        try:
            candidates = _generate(domain)
        except Exception as exc:
            raise EnrichmentError(f"typosquat: dnstwist generation failed: {exc}")
        to_check = candidates[:_MAX_CHECK]
        live: list[tuple[str, str]] = []
        unconfirmed: list[str] = []
        for dom, fz in to_check:
            (live.append((dom, fz)) if _is_live(dom, min(timeout, 4))
             else unconfirmed.append(dom))
        header = EnrichmentResult(
            result_type="document",
            title=f"typosquat: {domain} — {len(candidates)} candidates, "
                  f"{len(live)} live (of {len(to_check)} checked)",
            summary=("LIVE lookalikes (promoted as domain nodes):\n"
                     + ("\n".join(f"- {d} [{fz}]" for d, fz in live) or "  (none live)")
                     + "\n\nUNCONFIRMED candidates (T3, header-only, NOT promoted):\n"
                     + (", ".join(unconfirmed[:40]) or "  (none)")),
            url=f"https://dnstwist.it/?domain={domain}",
            raw_json={"domain": domain, "total_candidates": len(candidates),
                      "checked": len(to_check), "live": [d for d, _ in live],
                      "unconfirmed": unconfirmed}, confidence="high" if live else "low")
        # Only LIVE candidates promote (a resolving hostname is T1). Unconfirmed stay leads.
        rows = [EnrichmentResult(
            result_type="url", title=dom,
            summary=f"Live lookalike of {domain} ({fz}) — confirmed by DNS A record.",
            url=f"http://{dom}", confidence="medium") for dom, fz in live]
        return [header] + rows
