"""ENS resolution adapter — name <-> address, both directions.

Ties a wallet to a name and back: `vitalik.eth` -> `0xd8dA…6045` and the
reverse. ENS records live on-chain, so a resolved pairing is T1 and feeds the
2-crosslink attribution floor (a `handle <-> crypto_wallet` crosslink).

Resolution goes through the keyless ENSIdeas HTTP resolver
(`api.ensideas.com/ens/resolve/<name-or-address>`) rather than computing the
ENS namehash ourselves: namehash needs Keccak-256, which the Python stdlib does
NOT provide (hashlib.sha3_256 is NIST SHA3, a different padding). Using the
resolver keeps the adapter stdlib-only with no new dependency. Override the
endpoint with $KIPI_ENS_RESOLVER if needed (still keyless).

ORPHAN-TRAP NOTE: a bare `name.eth` string is neither a wallet nor an @handle,
so promote._classify would mis-route it to `domain`. We therefore NEVER emit the
`.eth` name as a standalone promotable child — only the resolved `0x…` address
(which _classify tags `crypto_wallet`) plus the crosslink. The `.eth` name lives
in the header text + raw_json only.
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
_ENS_NAME_RE = re.compile(r"^[a-z0-9-]+\.eth$", re.IGNORECASE)
_DEFAULT_RESOLVER = "https://api.ensideas.com/ens/resolve"


def _resolver_base() -> str:
    return os.environ.get("KIPI_ENS_RESOLVER", "").strip() or _DEFAULT_RESOLVER


def _resolve(term: str, timeout: int) -> dict:
    """GET the ENS resolver for a name or address; returns {address, name, ...}."""
    url = f"{_resolver_base()}/{urllib.parse.quote(term)}"
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"ENS resolver HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"ENS resolver network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("ENS resolver returned non-JSON (rate limited or down)")


class EnsAdapter(Adapter):
    slug = "ens"
    watched_types = ("crypto_wallet", "wallet", "handle")
    display_name = "ENS forward/reverse resolution"
    env_var = None  # keyless
    category = "chain"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        q = (query or "").strip()
        if not q:
            raise EnrichmentError("ens: empty query")
        if _ETH_RE.match(q):
            return self._reverse(q, timeout)
        if _ENS_NAME_RE.match(q):
            return self._forward(q, timeout)
        raise EnrichmentError(
            f"ens: '{q}' is neither a 0x address nor a *.eth name")

    def _forward(self, name: str, timeout: int) -> list[EnrichmentResult]:
        data = _resolve(name, timeout)
        address = (data.get("address") or "").strip()
        if not address or not _ETH_RE.match(address):
            return [EnrichmentResult(
                result_type="document",
                title=f"ENS: {name} — no address",
                summary=f"{name} does not currently resolve to an address.",
                raw_json={"name": name, "address": None},
                confidence="medium")]
        header = EnrichmentResult(
            result_type="document",
            title=f"ENS: {name} -> {address}",
            summary=(f"{name} resolves to {address} (ENS registry, on-chain = T1). "
                     f"Emitted as a handle<->crypto_wallet crosslink."),
            url=f"https://app.ens.domains/{name}",
            raw_json={"name": name, "address": address,
                      "crosslink": {"handle": name, "crypto_wallet": address,
                                    "rel": "resolves_to"}},
            confidence="high")
        # Promote ONLY the resolved address (title = bare 0x so _classify tags it
        # crypto_wallet). The .eth name stays in the header, never a standalone child.
        wallet = EnrichmentResult(
            result_type="profile",
            title=address,
            summary=f"Address behind ENS name {name}.",
            confidence="high")
        return [header, wallet]

    def _reverse(self, address: str, timeout: int) -> list[EnrichmentResult]:
        data = _resolve(address, timeout)
        name = (data.get("name") or "").strip()
        if not name:
            return [EnrichmentResult(
                result_type="document",
                title=f"ENS: {address} — no reverse record",
                summary=f"{address} has no ENS reverse (primary) name set.",
                raw_json={"address": address, "name": None},
                confidence="high")]
        return [EnrichmentResult(
            result_type="document",
            title=f"ENS: {address} -> {name}",
            summary=(f"{address} reverse-resolves to {name} (ENS primary name, "
                     f"on-chain = T1). handle<->crypto_wallet crosslink."),
            url=f"https://app.ens.domains/{name}",
            raw_json={"address": address, "name": name,
                      "crosslink": {"handle": name, "crypto_wallet": address,
                                    "rel": "resolves_to"}},
            confidence="high")]
