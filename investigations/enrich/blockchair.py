"""Blockchair multi-chain adapter — BTC / LTC / BCH / DOGE balance + activity.

Generalizes kipi's on-chain reach beyond BTC/ETH. One free-tier REST covers the
UTXO chains a crypto-fraud case scatters across (Litecoin, Bitcoin Cash, Dogecoin,
Bitcoin). Returns a T1 balance/activity header; counterparty rows are emitted when
the response carries transaction detail (free-tier dashboards return tx hashes only,
so counterparty tracing degrades gracefully to header-only — per-tx expansion is a v2).

Keyless free tier. An optional BLOCKCHAIR_API_KEY lifts rate limits; missing it never
raises (self-guard). Real HTTP/JSON failures raise EnrichmentError.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError
from investigations.enrich.wallet import _volume_warning

_API = "https://api.blockchair.com"


def _get_json(url: str, timeout: int, label: str):
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"{label} HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"{label} network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError(f"{label} returned non-JSON (rate limited or down)")


def detect_chain(addr: str) -> str | None:
    """Map an address prefix to a Blockchair chain slug ('bitcoin', 'litecoin', …)."""
    a = (addr or "").strip()
    if a.startswith("ltc1") or a[:1] in ("L", "M"):
        return "litecoin"
    if a.startswith("bitcoincash:") or a[:1] in ("q", "p"):
        return "bitcoin-cash"
    if a[:1] == "D":
        return "dogecoin"
    if a.startswith("bc1") or a[:1] in ("1", "3"):
        return "bitcoin"
    return None


def _counterparties(addr_block: dict, self_addr: str) -> list[str]:
    """Best-effort counterparty addresses from a dashboard block. Free-tier dashboards
    return tx HASHES (strings) -> no counterparties. When transaction_details are present
    (dict entries with addresses) we surface them. Defensive, never assumes a shape."""
    out: list[str] = []
    seen = set()
    for tx in addr_block.get("transactions") or []:
        if not isinstance(tx, dict):
            continue
        for key in ("recipient", "sender", "address"):
            a = (tx.get(key) or "").strip()
            if a and a != self_addr and a not in seen:
                seen.add(a)
                out.append(a)
    return out


class BlockchairAdapter(Adapter):
    slug = "blockchair"
    watched_types = ("crypto_wallet", "wallet")
    display_name = "Blockchair multi-chain (BTC/LTC/BCH/DOGE, keyless free tier)"
    env_var = None  # free tier keyless; optional key lifts limits (self-guard)
    category = "chain"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        addr = (query or "").strip()
        chain = detect_chain(addr)
        if not chain:
            raise EnrichmentError(
                f"blockchair: '{query}' is not a recognized BTC/LTC/BCH/DOGE address")
        url = (f"{_API}/{chain}/dashboards/address/"
               f"{urllib.parse.quote(addr)}?limit=50")
        body = _get_json(url, timeout, "Blockchair")
        data = (body.get("data") if isinstance(body, dict) else None) or {}
        block = data.get(addr) or next(iter(data.values()), {}) or {}
        info = block.get("address") or {}
        balance = info.get("balance", 0)
        tx_count = info.get("transaction_count", 0)
        received = info.get("received", 0)
        spent = info.get("spent", 0)
        counterparties = _counterparties(block, addr)

        warning = _volume_warning(len(counterparties), "counterparties")
        header = EnrichmentResult(
            result_type="document",
            title=f"{chain} wallet: {addr} — balance {balance}, {tx_count} txs",
            summary=(f"chain: {chain}\nbalance: {balance}\nreceived: {received}\n"
                     f"spent: {spent}\ntx count: {tx_count}\n"
                     f"distinct counterparties: {len(counterparties)}"
                     + ("" if counterparties else
                        "\n(counterparty tracing needs per-tx expansion on the free tier)")
                     + (f"\n\n{warning}" if warning else "")),
            url=f"https://blockchair.com/{chain}/address/{addr}",
            raw_json={"address": addr, "chain": chain, "balance": balance,
                      "tx_count": tx_count, "counterparties": counterparties,
                      "counterparty_count": len(counterparties),
                      "needs_decision": warning is not None},
            confidence="high")
        rows = [] if warning else [EnrichmentResult(
            result_type="profile", title=a,
            summary=f"{chain} counterparty of {addr}.",
            confidence="medium") for a in counterparties]
        return [header] + rows
