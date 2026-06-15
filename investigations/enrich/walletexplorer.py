"""WalletExplorer adapter — BTC exchange-cluster guess (T3 lead).

Cheap first-pass "which exchange clusters this BTC address" = where to send the
subpoena. WalletExplorer's heuristic clustering is a LEAD, never a finding: the
output is routed as low-confidence (the deterministic promotion gate holds it as a
hypothesis, never a graphed/cited finding, per the q-investigation evidence-tier rule).

BTC only, keyless. The exchange label is emitted as a low-confidence org profile, NOT
as a wallet address (it is not a pivotable wallet). Real HTTP/JSON failures raise
EnrichmentError.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError
from investigations.enrich.wallet import detect_chain as _detect_btc_eth

_API = "https://www.walletexplorer.com/api/1/address-lookup"


def _get_json(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"WalletExplorer HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"WalletExplorer network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("WalletExplorer returned non-JSON (rate limited or down)")


class WalletExplorerAdapter(Adapter):
    slug = "walletexplorer"
    watched_types = ("crypto_wallet", "wallet")
    display_name = "WalletExplorer BTC exchange-cluster (T3 lead)"
    env_var = None  # keyless
    category = "chain"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        addr = (query or "").strip()
        if _detect_btc_eth(addr) != "btc":
            raise EnrichmentError("walletexplorer: BTC addresses only")
        url = f"{_API}?address={urllib.parse.quote(addr)}"
        body = _get_json(url, timeout)
        label = (body.get("label") or "").strip() if isinstance(body, dict) else ""
        wallet_id = (body.get("wallet_id") or "").strip() if isinstance(body, dict) else ""
        if not label and not wallet_id:
            return [EnrichmentResult(
                result_type="document",
                title=f"WalletExplorer: {addr} — no cluster",
                summary="No exchange/service cluster known for this BTC address.",
                raw_json={"address": addr, "label": None, "tier": "T3"},
                confidence="low")]
        who = label or wallet_id
        header = EnrichmentResult(
            result_type="document",
            title=f"WalletExplorer: {addr} -> {who}",
            summary=(f"T3 LEAD — {addr} likely clustered to '{who}' (heuristic exchange "
                     f"cluster, the subpoena target). NOT a finding; corroborate before citing."),
            url=f"https://www.walletexplorer.com/address/{addr}",
            raw_json={"address": addr, "label": label, "wallet_id": wallet_id,
                      "tier": "T3", "lead": True},
            confidence="low")
        # The exchange is an ORG lead, not a pivotable wallet — low confidence, gated.
        org = EnrichmentResult(
            result_type="profile", title=who,
            summary=f"Exchange/service cluster lead for BTC address {addr} (T3, unverified).",
            confidence="low")
        return [header, org]
