"""Crypto-scam blocklist adapter — flag a known-bad wallet or scam domain (T3 lead).

The crypto-layer mirror of kipi's infra abuse feeds (abuse.ch / AbuseIPDB). Checks a
wallet address or domain against the Scam Sniffer public blocklists. A match is a
strong signal but still T3 (an automated feed flag, not a non-fakeable record): the
flagged entity is emitted as a LOW-confidence lead so the deterministic promotion gate
keeps it a hypothesis, never a written finding, until corroborated.

Keyless. Real HTTP/JSON failures raise EnrichmentError (so a moved feed reads as a
clean tool error the agent can pivot on, not a crash).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

# Scam Sniffer public blocklists (GitHub-hosted JSON arrays).
_DOMAINS_FEED = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json"
_ADDRESS_FEED = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"


def _load_feed(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"ScamSniffer feed HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"ScamSniffer feed network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("ScamSniffer feed returned non-JSON (moved or down)")


class CryptoAbuseAdapter(Adapter):
    slug = "crypto_abuse"
    watched_types = ("crypto_wallet", "wallet", "domain")
    display_name = "Crypto scam blocklists (Scam Sniffer)"
    env_var = None  # keyless
    category = "reputation"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        q = (query or "").strip()
        if not q:
            raise EnrichmentError("crypto_abuse: empty query")
        # A wallet address has no dot/slash; a domain does. Simple, keyless split.
        is_wallet = "." not in q and "/" not in q
        feed = _load_feed(_ADDRESS_FEED if is_wallet else _DOMAINS_FEED, timeout)
        items = feed if isinstance(feed, list) else []
        ql = q.lower()
        matched = [x for x in items if isinstance(x, str) and x.lower() == ql]
        kind = "wallet" if is_wallet else "domain"
        if not matched:
            return [EnrichmentResult(
                result_type="document",
                title=f"crypto_abuse: {q} [CLEAN]",
                summary=f"Not on the Scam Sniffer {kind} blocklist.",
                raw_json={"query": q, "kind": kind, "hit": False, "tier": "T3"},
                confidence="low")]
        header = EnrichmentResult(
            result_type="document",
            title=f"crypto_abuse: {q} [HIT]",
            summary=(f"T3 LEAD — {q} is on the Scam Sniffer {kind} blocklist. A flag, not a "
                     f"finding; corroborate before citing."),
            url="https://github.com/scamsniffer/scam-database",
            raw_json={"query": q, "kind": kind, "hit": True, "matched": matched,
                      "tier": "T3", "lead": True},
            confidence="medium")
        # The flagged entity as a LOW-confidence lead row (gate holds it as a hypothesis).
        lead = EnrichmentResult(
            result_type="profile", title=q,
            summary=f"Flagged scam {kind} (Scam Sniffer blocklist, T3 lead — unverified).",
            confidence="low")
        return [header, lead]
