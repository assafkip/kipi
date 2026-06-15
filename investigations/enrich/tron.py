"""Tron wallet adapter — TRC-20 transfers + counterparties (keyless).

Tron is the dominant USDT pig-butchering / scam-payout rail and was kipi's single
biggest on-chain blind spot. This pulls TRC-20 transfers for a `T…` address from
the keyless TronGrid public endpoint; each distinct counterparty is a promotable
`crypto_wallet` node (promote._classify learned the Tron `T…` shape in PRD-2), with
the token symbol on the edge.

Keyless (TronGrid public tier). If TronGrid ever starts requiring a key, flip to the
wallet._eth self-guard pattern (return a `[needs key]` result, set env_var) rather
than raising. Real failures raise EnrichmentError so the agent sees them and pivots.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError
from investigations.enrich.wallet import _volume_warning

_TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_TRONGRID = "https://api.trongrid.io"


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


class TronAdapter(Adapter):
    slug = "tron"
    watched_types = ("crypto_wallet", "wallet")
    display_name = "Tron wallet (TRC-20 transfers, keyless)"
    env_var = None  # TronGrid public tier is keyless
    category = "chain"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 40) -> list[EnrichmentResult]:
        addr = (query or "").strip()
        if not _TRON_RE.match(addr):
            raise EnrichmentError(
                f"tron: '{query}' is not a Tron T-address (T + 33 base58)")
        url = (f"{_TRONGRID}/v1/accounts/{urllib.parse.quote(addr)}"
               f"/transactions/trc20?limit=50")
        body = _get_json(url, timeout, "TronGrid")
        if isinstance(body, dict) and body.get("success") is False:
            raise EnrichmentError(f"TronGrid error: {body.get('error') or 'request failed'}")
        data = body.get("data") if isinstance(body, dict) else None
        rows = data if isinstance(data, list) else []

        seen: set[str] = set()
        counterparties: list[tuple[str, str]] = []  # (address, tokenSymbol)
        symbols: set[str] = set()
        for tx in rows:
            sym = ((tx.get("token_info") or {}).get("symbol") or "?").strip()
            symbols.add(sym)
            for side in ("from", "to"):
                a = (tx.get(side) or "").strip()
                if a and a != addr and a not in seen and _TRON_RE.match(a):
                    seen.add(a)
                    counterparties.append((a, sym))

        warning = _volume_warning(len(counterparties), "TRC-20 counterparties")
        header = EnrichmentResult(
            result_type="document",
            title=f"Tron wallet: {addr} — {len(rows)} TRC-20 transfers, {len(symbols)} token(s)",
            summary=(f"TRC-20 transfers examined: {len(rows)}\n"
                     f"tokens seen: {', '.join(sorted(symbols)) or 'none'}\n"
                     f"distinct counterparties: {len(counterparties)}"
                     + (f"\n\n{warning}" if warning else "")),
            url=f"https://tronscan.org/#/address/{addr}",
            raw_json={"address": addr, "chain": "tron", "tokens": sorted(symbols),
                      "counterparties": [a for a, _ in counterparties],
                      "counterparty_count": len(counterparties),
                      "needs_decision": warning is not None},
            confidence="high" if rows else "medium")
        rows_out = [] if warning else [EnrichmentResult(
            result_type="profile", title=a,
            summary=f"{sym} counterparty of {addr} (TRC-20 transfer).",
            confidence="medium") for a, sym in counterparties]
        return [header] + rows_out
