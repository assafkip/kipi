"""OFAC sanctions adapter — wallet sanctions oracle + SDN name match.

The single highest-value T1 on-chain signal kipi lacked: is this wallet (or
person / org) on a US Treasury OFAC sanctions list?

Two checks, by entity type:
  - crypto_wallet (0x EVM) -> the Chainalysis sanctions oracle `isSanctioned(addr)`
    via a keyless eth_call. An on-chain contract read = T1.
  - person / org           -> substring match against the cached OFAC SDN name list
    (treasury.gov SDN.CSV). A government record = T1.

Keyless. The Ethereum RPC defaults to a public endpoint; override with
$KIPI_ETH_RPC_URL (still keyless). Failures raise EnrichmentError so the agent
sees them and pivots — never a silent empty result.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

# Chainalysis sanctions oracle (mainnet) + the isSanctioned(address) selector.
_ORACLE = "0x40C57923924B5c5c5455c48D93317139ADDaC8fb"
_IS_SANCTIONED_SELECTOR = "0xdf592f7d"
# Live-verified keyless RPC (the oracle flags Lazarus SANCTIONED, vitalik clean here).
# cloudflare-eth.com returns -32603 on eth_call; publicnode works. Override with $KIPI_ETH_RPC_URL.
_DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"

# Cached SDN name list (treasury.gov). Vendored cache lives next to the adapter.
_SDN_CSV = "https://www.treasury.gov/ofac/downloads/sdn.csv"
_SDN_CACHE = Path(__file__).parent / "data" / "ofac_sdn_names.json"
_SDN_TTL_SECONDS = 24 * 3600


def _rpc_url() -> str:
    return os.environ.get("KIPI_ETH_RPC_URL", "").strip() or _DEFAULT_RPC


def _eth_call_sanctioned(address: str, timeout: int) -> bool:
    """True iff the Chainalysis oracle reports the EVM address as sanctioned."""
    data = _IS_SANCTIONED_SELECTOR + address[2:].lower().rjust(64, "0")
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": _ORACLE, "data": data}, "latest"],
    }).encode("utf-8")
    req = urllib.request.Request(
        _rpc_url(), data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"OFAC oracle RPC HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"OFAC oracle RPC network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("OFAC oracle RPC returned non-JSON (rate limited or down)")
    if "error" in body:
        raise EnrichmentError(f"OFAC oracle RPC error: {body['error']}")
    result = body.get("result") or "0x0"
    return int(result, 16) != 0


def _load_sdn_names(timeout: int) -> list[str]:
    """The OFAC SDN entity names, cached to data/ofac_sdn_names.json (24h TTL)."""
    if _SDN_CACHE.exists():
        age = time.time() - _SDN_CACHE.stat().st_mtime
        if age < _SDN_TTL_SECONDS:
            return json.loads(_SDN_CACHE.read_text())
    req = urllib.request.Request(_SDN_CSV, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("latin-1")
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise EnrichmentError(f"OFAC SDN list fetch failed: {exc}")
    # SDN.CSV is positional, no header: ent_num, SDN_Name, SDN_Type, Program, ...
    import csv
    import io
    names = []
    for row in csv.reader(io.StringIO(raw)):
        if len(row) > 1 and row[1] and row[1] != "-0-":
            names.append(row[1].strip())
    _SDN_CACHE.parent.mkdir(parents=True, exist_ok=True)
    _SDN_CACHE.write_text(json.dumps(names))
    return names


class OfacAdapter(Adapter):
    slug = "ofac"
    watched_types = ("crypto_wallet", "wallet", "person", "org")
    display_name = "OFAC SDN + sanctions oracle"
    env_var = None  # keyless
    category = "compliance"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 40) -> list[EnrichmentResult]:
        q = (query or "").strip()
        if not q:
            raise EnrichmentError("ofac: empty query")
        if _ETH_RE.match(q):
            return self._screen_wallet(q, timeout)
        return self._screen_name(q, timeout)

    def _screen_wallet(self, address: str, timeout: int) -> list[EnrichmentResult]:
        sanctioned = _eth_call_sanctioned(address, timeout)
        if not sanctioned:
            return [EnrichmentResult(
                result_type="document",
                title=f"OFAC: {address} — NOT sanctioned",
                summary="Chainalysis sanctions oracle: address is not on an OFAC list.",
                url=f"https://etherscan.io/address/{address}",
                raw_json={"address": address, "sanctioned": False, "source": "chainalysis-oracle"},
                confidence="high")]
        header = EnrichmentResult(
            result_type="document",
            title=f"OFAC SANCTIONED: {address}",
            summary=(f"Chainalysis sanctions oracle flags {address} as on an OFAC "
                     f"sanctions list (T1, on-chain contract read). Treat as a confirmed "
                     f"compliance finding."),
            url=f"https://etherscan.io/address/{address}",
            raw_json={"address": address, "sanctioned": True, "source": "chainalysis-oracle"},
            confidence="high")
        # Promotable indicator child (title = bare value so promote._classify tags it).
        hit = EnrichmentResult(
            result_type="profile",
            title=address,
            summary=f"OFAC-sanctioned wallet (Chainalysis oracle).",
            confidence="high")
        return [header, hit]

    def _screen_name(self, name: str, timeout: int) -> list[EnrichmentResult]:
        names = _load_sdn_names(timeout)
        needle = name.lower()
        matches = [n for n in names if needle in n.lower()]
        if not matches:
            return [EnrichmentResult(
                result_type="document",
                title=f"OFAC: '{name}' — no SDN match",
                summary="No OFAC SDN entity name contains this string.",
                raw_json={"query": name, "sanctioned": False, "source": "ofac-sdn-list"},
                confidence="high")]
        top = matches[:25]
        header = EnrichmentResult(
            result_type="document",
            title=f"OFAC SDN match: '{name}' ({len(matches)} entr{'y' if len(matches) == 1 else 'ies'})",
            summary=("Matches the OFAC SDN list (T1, government record). Verify the full "
                     "entry before attribution:\n" + "\n".join(f"- {m}" for m in top)
                     + ("" if len(matches) <= 25 else f"\n… +{len(matches) - 25} more")),
            url="https://sanctionssearch.ofac.treas.gov/",
            raw_json={"query": name, "sanctioned": True, "matches": matches,
                      "source": "ofac-sdn-list"},
            confidence="high")
        return [header]
