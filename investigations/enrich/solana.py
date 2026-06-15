"""Solana wallet adapter — recent tx signatures + counterparty accounts (keyless).

Solana is the memecoin rug / drainer surface kipi couldn't touch. This pulls recent
transaction signatures for an address over the keyless public JSON-RPC, then reads a
capped page of those transactions and surfaces the distinct other accounts touched.
Each is a promotable `crypto_wallet` node (promote._classify learned the base58 32-44
shape in PRD-2).

Keyless public RPC. The public endpoint is aggressively throttled, so we cap how many
transactions we read and turn a 429 into a clear EnrichmentError (never raise an
uncaught exception to the agent). Counterparty derivation is v1: distinct non-self
account keys touched in the sampled transactions (a real pivot; directional drains_to
edges need balance-delta attribution, a follow-up).
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError
from investigations.enrich.wallet import _volume_warning

_SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_RPC = "https://api.mainnet-beta.solana.com"
_MAX_TXS = 8  # cap getTransaction calls — public RPC is throttled


def _rpc(method: str, params: list, timeout: int):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode("utf-8")
    req = urllib.request.Request(
        _RPC, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise EnrichmentError("Solana RPC rate limited (429) — retry later or use a paid RPC")
        raise EnrichmentError(f"Solana RPC HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"Solana RPC network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("Solana RPC returned non-JSON (rate limited or down)")
    if "error" in body:
        raise EnrichmentError(f"Solana RPC error: {body['error']}")
    return body.get("result")


class SolanaAdapter(Adapter):
    slug = "solana"
    watched_types = ("crypto_wallet", "wallet")
    display_name = "Solana wallet (tx signatures + counterparties, keyless)"
    env_var = None  # public JSON-RPC is keyless
    category = "chain"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 40) -> list[EnrichmentResult]:
        addr = (query or "").strip()
        if _ETH_RE.match(addr) or _TRON_RE.match(addr) or not _SOL_RE.match(addr):
            raise EnrichmentError(
                f"solana: '{query}' is not a Solana base58 address (32-44, not EVM/Tron)")

        sigs = _rpc("getSignaturesForAddress", [addr, {"limit": 25}], timeout)
        sig_list = [s.get("signature") for s in sigs if s.get("signature")] \
            if isinstance(sigs, list) else []

        seen: set[str] = set()
        counterparties: list[str] = []
        for sig in sig_list[:_MAX_TXS]:
            tx = _rpc("getTransaction",
                      [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}],
                      timeout)
            msg = (((tx or {}).get("transaction") or {}).get("message") or {})
            for acct in msg.get("accountKeys") or []:
                a = acct if isinstance(acct, str) else (acct or {}).get("pubkey", "")
                a = (a or "").strip()
                if a and a != addr and a not in seen and _SOL_RE.match(a):
                    seen.add(a)
                    counterparties.append(a)

        warning = _volume_warning(len(counterparties), "Solana counterparties")
        header = EnrichmentResult(
            result_type="document",
            title=f"Solana wallet: {addr} — {len(sig_list)} recent txs, "
                  f"{len(counterparties)} counterparties",
            summary=(f"recent signatures: {len(sig_list)}\n"
                     f"transactions sampled: {min(len(sig_list), _MAX_TXS)}\n"
                     f"distinct counterparty accounts: {len(counterparties)}"
                     + (f"\n\n{warning}" if warning else "")),
            url=f"https://solscan.io/account/{addr}",
            raw_json={"address": addr, "chain": "solana",
                      "signatures": len(sig_list),
                      "counterparties": counterparties,
                      "counterparty_count": len(counterparties),
                      "needs_decision": warning is not None},
            confidence="high" if sig_list else "medium")
        rows_out = [] if warning else [EnrichmentResult(
            result_type="profile", title=a,
            summary=f"Solana counterparty of {addr} (shared transaction).",
            confidence="medium") for a in counterparties]
        return [header] + rows_out
