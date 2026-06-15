"""Wallet labels adapter — local exchange/mixer/phish tags for an address.

The cheapest attribution layer: look an `0x…` address up in a vendored snapshot
of the public `brianleect/etherscan-labels` dataset and report what it is known
as (an exchange = where to subpoena; a mixer/sanctioned tag = a risk flag).

T3 BY DESIGN: this is an automated community-dataset lookup, so under the
q-investigation evidence-tier rule it is a NODE TAG, never a citable finding. The
adapter emits a single low-confidence `document` carrying the label in raw_json
and NO promotable child row, so the deterministic promotion gate keeps it as
context/hypothesis, not a confirmed finding.

Keyless, no network: reads the vendored JSON only. If the dataset file is absent
it fails soft to a clear EnrichmentError (re-vendor it; never a silent empty).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_DATASET = Path(__file__).parent / "data" / "etherscan_labels.json"

_cache: dict | None = None


def _load_labels() -> dict:
    """Lazily load + memoize the vendored label dataset (lower-cased keys)."""
    global _cache
    if _cache is not None:
        return _cache
    if not _DATASET.exists():
        raise EnrichmentError(
            "wallet_labels: labels dataset not present "
            "(investigations/enrich/data/etherscan_labels.json) — re-vendor it")
    try:
        data = json.loads(_DATASET.read_text())
    except json.JSONDecodeError as exc:
        raise EnrichmentError(f"wallet_labels: dataset is not valid JSON: {exc}")
    _cache = {k.lower(): v for k, v in data.items() if k.startswith("0x")}
    return _cache


class WalletLabelsAdapter(Adapter):
    slug = "wallet_labels"
    watched_types = ("crypto_wallet", "wallet")
    display_name = "Etherscan public labels (exchange/mixer/phish)"
    env_var = None  # keyless, local file
    category = "chain"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 10) -> list[EnrichmentResult]:
        addr = (query or "").strip().lower()
        if not _ETH_RE.match(addr):
            raise EnrichmentError(
                f"wallet_labels: '{query}' is not a 0x EVM address")
        labels = _load_labels()
        entry = labels.get(addr)
        if not entry:
            return [EnrichmentResult(
                result_type="document",
                title=f"Labels: {addr} — none",
                summary="No label for this address in the vendored Etherscan-labels dataset.",
                raw_json={"address": addr, "labels": [], "node_tag": None,
                          "tier": "T3"},
                confidence="low")]
        name = entry.get("name") or ""
        tags = entry.get("labels") or []
        # Single low-confidence tag document. NO promotable child -> stays a node tag,
        # never a finding (T3, per the q-investigation evidence-tier rule).
        return [EnrichmentResult(
            result_type="document",
            title=f"Label: {addr} = {name}" if name else f"Label: {addr}",
            summary=(f"Etherscan public label (T3 TAG, not a finding): {name}"
                     + (f" [{', '.join(tags)}]" if tags else "")
                     + ". Use as triage context; corroborate before any attribution."),
            url=f"https://etherscan.io/address/{addr}",
            raw_json={"address": addr, "name": name, "labels": tags,
                      "node_tag": name or (tags[0] if tags else None), "tier": "T3"},
            confidence="low")]
