"""Crypto wallet adapter — address -> balance + transaction counterparties.

You already pivot on wallets surfaced in evidence; this pulls what they DID. The
counterparty addresses are the pivot: each is a promotable `crypto_wallet` node
(promote._classify recognizes BTC + EVM addresses), so "this wallet drains to that
one" becomes a real graph edge instead of a note.

Chains:
  - BTC (bc1.. / 1.. / 3..)  -> mempool.space  (KEYLESS, free)
  - ETH (0x{40 hex})         -> etherscan      (free tier, needs ETHERSCAN_API_KEY)

env_var is None on purpose: BTC works with no key, so the dead-slug filter must NOT
drop the whole adapter. The ETH mode self-guards — with no key it returns a clear
"needs ETHERSCAN_API_KEY" result (not an exception) so the agent sees it and pivots.
Mirrors shodan's keyless-tier pattern.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
# bech32 (bc1…) is case-insensitive per BIP173 (but never mixed-case); base58 (1…/3…)
# IS case-sensitive, so only the bech32 alt is matched case-insensitively.
_BTC_BECH32_RE = re.compile(r"^bc1[ac-hj-np-z02-9]{6,87}$", re.IGNORECASE)
_BTC_BASE58_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")

_MEMPOOL = "https://mempool.space/api"
_ETHERSCAN = "https://api.etherscan.io/api"

# We do NOT cap evidence. The FULL counterparty set is always captured in the header's
# raw_json (lossless, revertible, subsettable). This threshold only governs MATERIALIZATION:
# above it we don't auto-spray thousands of individual rows into the run — instead the
# header carries needs_decision=True + a volume warning, and the analyst/agent chooses what
# to do with the full set (revert / open in new graph / pick a subset / reason on it).
_MATERIALIZE_THRESHOLD = int(os.environ.get("KIPI_MATERIALIZE_THRESHOLD", "50"))


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
    """'eth' | 'btc' | None for an address string. Accepts uppercase bech32 (BC1…)."""
    a = addr.strip()
    if _ETH_RE.match(a):
        return "eth"
    if _BTC_BASE58_RE.match(a) or _BTC_BECH32_RE.match(a):
        return "btc"
    return None


def _normalize_btc(addr: str) -> str:
    """bech32 addresses are case-insensitive; lowercase them so the API query is
    canonical. base58 (1…/3…) is case-sensitive and passes through untouched."""
    a = addr.strip()
    return a.lower() if a.lower().startswith("bc1") else a


def _counterparty_results(addrs: list[str], chain: str, src: str) -> list[EnrichmentResult]:
    """One promotable wallet node per distinct counterparty (title = bare address so
    promote._classify tags it crypto_wallet). NO truncation — the caller decides whether
    to materialize these rows based on volume."""
    return [EnrichmentResult(
        result_type="profile",
        title=a,
        summary=f"{chain.upper()} counterparty of {src} (transacted).",
        confidence="medium") for a in addrs]


def _volume_warning(n: int, what: str) -> str | None:
    """A 'this is going to be huge' note when a result set is over the materialize
    threshold. None when it's small enough to materialize directly."""
    if n <= _MATERIALIZE_THRESHOLD:
        return None
    return (f"LARGE RESULT: {n} {what} (threshold {_MATERIALIZE_THRESHOLD}). The full set "
            f"is captured in raw_json — nothing dropped. Choose how to materialize it: "
            f"revert / open in a new graph / pick a subset / reason on it.")


class WalletAdapter(Adapter):
    slug = "wallet"
    watched_types = ('crypto_wallet', 'wallet')
    display_name = "Crypto wallet (BTC keyless / ETH via Etherscan)"
    env_var = None  # keyless for BTC; ETH self-guards on ETHERSCAN_API_KEY
    category = "chain"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["auto", "btc", "eth", "erc20"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 40) -> list[EnrichmentResult]:
        addr = (query or "").strip()
        if not addr:
            raise EnrichmentError("wallet: empty address")
        m = (mode or "auto").lower()
        # erc20: ERC-20 token flow (USDT/USDC move via tokentx, invisible to txlist).
        if m == "erc20":
            return self._eth_tokens(addr, timeout)
        chain = m if m in ("btc", "eth") else detect_chain(addr)
        if chain == "btc":
            return self._btc(addr, timeout)
        if chain == "eth":
            return self._eth(addr, timeout)
        raise EnrichmentError(
            f"wallet: '{addr}' is not a recognized BTC or ETH address")

    # --- BTC via mempool.space (keyless) -----------------------------------------
    def _btc(self, addr: str, timeout: int) -> list[EnrichmentResult]:
        addr = _normalize_btc(addr)
        info = _get_json(f"{_MEMPOOL}/address/{urllib.parse.quote(addr)}", timeout, "mempool.space")
        if not isinstance(info, dict):
            raise EnrichmentError("mempool.space: unexpected response (not an address object)")
        cs = info.get("chain_stats") or {}
        funded = cs.get("funded_txo_sum", 0)
        spent = cs.get("spent_txo_sum", 0)
        tx_count = cs.get("tx_count", 0)
        balance_btc = (funded - spent) / 1e8

        counterparties: list[str] = []
        try:
            txs = _get_json(f"{_MEMPOOL}/address/{urllib.parse.quote(addr)}/txs", timeout, "mempool.space")
        except EnrichmentError:
            txs = []
        seen = set()
        for tx in txs if isinstance(txs, list) else []:
            for vin in tx.get("vin") or []:
                a = ((vin.get("prevout") or {}).get("scriptpubkey_address") or "").strip()
                if a and a != addr and a not in seen:
                    seen.add(a); counterparties.append(a)
            for vout in tx.get("vout") or []:
                a = (vout.get("scriptpubkey_address") or "").strip()
                if a and a != addr and a not in seen:
                    seen.add(a); counterparties.append(a)

        warning = _volume_warning(len(counterparties), "counterparties")
        header = EnrichmentResult(
            result_type="document",
            title=f"BTC wallet: {addr} — {balance_btc:.8f} BTC, {tx_count} txs",
            summary=(f"balance: {balance_btc:.8f} BTC\n"
                     f"total received: {funded / 1e8:.8f} BTC\n"
                     f"total sent: {spent / 1e8:.8f} BTC\n"
                     f"tx count: {tx_count}\n"
                     f"distinct counterparties (recent): {len(counterparties)}"
                     + (f"\n\n{warning}" if warning else "")),
            url=f"https://mempool.space/address/{addr}",
            # FULL set always here — lossless, revertible, subsettable.
            raw_json={"address": addr, "chain": "btc", "balance_btc": balance_btc,
                      "tx_count": tx_count, "counterparties": counterparties,
                      "counterparty_count": len(counterparties),
                      "needs_decision": warning is not None},
            confidence="high")
        # Over threshold: don't auto-spray rows — hand the analyst the decision.
        rows = [] if warning else _counterparty_results(counterparties, "btc", addr)
        return [header] + rows

    # --- ETH via Etherscan (free tier, needs a key) ------------------------------
    def _eth(self, addr: str, timeout: int) -> list[EnrichmentResult]:
        # Key resolves DB-first (a key saved on the 'wallet' provider row in the Enrich
        # UI) then the env var — same precedence as every other keyed adapter.
        from investigations.enrich.base import resolve_key
        key = resolve_key("wallet", "ETHERSCAN_API_KEY")
        if not key:
            return [EnrichmentResult(
                result_type="document",
                title=f"ETH wallet: {addr} [needs key]",
                summary="ETH enrichment needs an Etherscan key (free tier at "
                        "etherscan.io/apis). BTC addresses work keyless. Add the key on "
                        "the Enrich page (wallet) or set $ETHERSCAN_API_KEY, then retry.",
                confidence="low")]
        bal = _get_json(
            f"{_ETHERSCAN}?module=account&action=balance&address={addr}&tag=latest&apikey={key}",
            timeout, "Etherscan")
        bal_result = bal.get("result")
        # Etherscan signals errors (bad key, rate limit, "NOTOK") as a non-numeric STRING
        # in `result` with status "0". Surface it instead of silently reporting 0 ETH.
        if not (isinstance(bal_result, (int, str)) and str(bal_result).lstrip("-").isdigit()):
            raise EnrichmentError(f"Etherscan: {bal.get('message') or bal_result or 'error'}")
        balance_eth = int(bal_result) / 1e18
        txs = _get_json(
            f"{_ETHERSCAN}?module=account&action=txlist&address={addr}"
            f"&page=1&offset=50&sort=desc&apikey={key}", timeout, "Etherscan")
        tx_result = txs.get("result")
        rows = tx_result if isinstance(tx_result, list) else []
        # The tx call can rate-limit independently (string result). Don't fake an empty
        # history as fact — note it and drop confidence.
        tx_note = "" if isinstance(tx_result, list) else \
            f" (tx history unavailable: {txs.get('message') or tx_result})"
        a_lower = addr.lower()
        seen, counterparties = set(), []
        for tx in rows:
            for side in ("from", "to"):
                a = (tx.get(side) or "").strip()
                if a and a.lower() != a_lower and a.lower() not in seen:
                    seen.add(a.lower()); counterparties.append(a)

        warning = _volume_warning(len(counterparties), "counterparties")
        header = EnrichmentResult(
            result_type="document",
            title=f"ETH wallet: {addr} — {balance_eth:.6f} ETH, {len(rows)} recent txs",
            summary=(f"balance: {balance_eth:.6f} ETH\n"
                     f"recent txs examined: {len(rows)}{tx_note}\n"
                     f"distinct counterparties: {len(counterparties)}"
                     + (f"\n\n{warning}" if warning else "")),
            url=f"https://etherscan.io/address/{addr}",
            raw_json={"address": addr, "chain": "eth", "balance_eth": balance_eth,
                      "counterparties": counterparties,
                      "counterparty_count": len(counterparties),
                      "needs_decision": warning is not None},
            confidence="medium" if tx_note else "high")
        eth_rows = [] if warning else _counterparty_results(counterparties, "eth", addr)
        return [header] + eth_rows

    # --- ERC-20 token flow via Etherscan tokentx (PRD-2) --------------------------
    def _eth_tokens(self, addr: str, timeout: int) -> list[EnrichmentResult]:
        """Token transfers (USDT/USDC/etc) — where fraud money actually moves. The
        native txlist (in _eth) misses these entirely; tokentx surfaces them. Each
        distinct token counterparty is a promotable crypto_wallet node with the token
        symbol on the edge (in the child summary + the header raw_json)."""
        from investigations.enrich.base import resolve_key
        key = resolve_key("wallet", "ETHERSCAN_API_KEY")
        if not key:
            return [EnrichmentResult(
                result_type="document",
                title=f"ERC-20 flow: {addr} [needs key]",
                summary="ERC-20 token flow needs an Etherscan key (free tier at "
                        "etherscan.io/apis). Add it on the Enrich page (wallet) or set "
                        "$ETHERSCAN_API_KEY, then retry.",
                confidence="low")]
        txs = _get_json(
            f"{_ETHERSCAN}?module=account&action=tokentx&address={addr}"
            f"&page=1&offset=50&sort=desc&apikey={key}", timeout, "Etherscan")
        tx_result = txs.get("result")
        if not isinstance(tx_result, list):
            # Etherscan signals errors (bad key / rate limit / NOTOK) as a string.
            raise EnrichmentError(f"Etherscan: {txs.get('message') or tx_result or 'error'}")
        rows = tx_result
        a_lower = addr.lower()
        seen: set[str] = set()
        counterparties: list[tuple[str, str]] = []  # (address, tokenSymbol)
        symbols: set[str] = set()
        for tx in rows:
            sym = (tx.get("tokenSymbol") or "?").strip()
            symbols.add(sym)
            for side in ("from", "to"):
                a = (tx.get(side) or "").strip()
                if a and a.lower() != a_lower and a.lower() not in seen:
                    seen.add(a.lower())
                    counterparties.append((a, sym))
        warning = _volume_warning(len(counterparties), "token counterparties")
        header = EnrichmentResult(
            result_type="document",
            title=f"ERC-20 flow: {addr} — {len(rows)} transfers, {len(symbols)} token(s)",
            summary=(f"token transfers examined: {len(rows)}\n"
                     f"tokens seen: {', '.join(sorted(symbols)) or 'none'}\n"
                     f"distinct token counterparties: {len(counterparties)}"
                     + (f"\n\n{warning}" if warning else "")),
            url=f"https://etherscan.io/address/{addr}",
            raw_json={"address": addr, "chain": "eth", "mode": "erc20",
                      "tokens": sorted(symbols),
                      "counterparties": [a for a, _ in counterparties],
                      "counterparty_count": len(counterparties),
                      "needs_decision": warning is not None},
            confidence="high" if rows else "medium")
        # Over threshold: hand the analyst the decision (no auto-spray), same as _eth.
        rows_out = [] if warning else [EnrichmentResult(
            result_type="profile", title=a,
            summary=f"{sym} counterparty of {addr} (ERC-20 transfer).",
            confidence="medium") for a, sym in counterparties]
        return [header] + rows_out
