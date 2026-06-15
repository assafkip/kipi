"""TON wallet adapter — TONAPI balance + counterparties (keyless).

TON is a growing laundering / scam rail. This pulls an account's balance + recent
transfer counterparties for a user-friendly TON address (`EQ.../UQ...`) from the
keyless TONAPI. Each distinct counterparty is a promotable crypto_wallet node
(promote._classify learned the TON shape in PRD-3).

Keyless. v1 detects the user-friendly address form (`EQ/UQ`, 48 base64url) that
analysts paste; raw `0:hex` form is out of scope. Real HTTP/JSON failures raise
EnrichmentError.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError
from investigations.enrich.wallet import _volume_warning

_TON_RE = re.compile(r"^[EU]Q[A-Za-z0-9_-]{46}$")
_TONAPI = "https://tonapi.io/v2"


def _get_json(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise EnrichmentError(f"TONAPI HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"TONAPI network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("TONAPI returned non-JSON (rate limited or down)")


def _walk_counterparties(events: dict, self_addr: str) -> list[str]:
    """Distinct EQ/UQ counterparty addresses across an /events payload. Defensive: TONAPI
    nests addresses under actions -> {TonTransfer,JettonTransfer} -> sender/recipient."""
    out: list[str] = []
    seen = set()
    for ev in events.get("events") or []:
        for action in ev.get("actions") or []:
            for body in action.values():
                if not isinstance(body, dict):
                    continue
                for party in ("sender", "recipient"):
                    node = body.get(party) or {}
                    a = (node.get("address") or "").strip() if isinstance(node, dict) else ""
                    if a and a != self_addr and a not in seen:
                        seen.add(a)
                        out.append(a)
    return out


class WalletTonAdapter(Adapter):
    slug = "wallet_ton"
    watched_types = ("crypto_wallet", "wallet")
    display_name = "TON wallet (TONAPI, keyless)"
    env_var = None  # keyless
    category = "chain"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 40) -> list[EnrichmentResult]:
        addr = (query or "").strip()
        if not _TON_RE.match(addr):
            raise EnrichmentError("wallet_ton: not a TON address (EQ.../UQ...)")
        acct = _get_json(f"{_TONAPI}/accounts/{urllib.parse.quote(addr)}", timeout)
        balance_nano = acct.get("balance", 0) if isinstance(acct, dict) else 0
        balance_ton = (balance_nano or 0) / 1e9
        events = _get_json(
            f"{_TONAPI}/accounts/{urllib.parse.quote(addr)}/events?limit=100", timeout)
        counterparties = _walk_counterparties(events if isinstance(events, dict) else {}, addr)

        warning = _volume_warning(len(counterparties), "counterparties")
        header = EnrichmentResult(
            result_type="document",
            title=f"TON wallet: {addr} — {balance_ton:.4f} TON",
            summary=(f"balance: {balance_ton:.9f} TON\n"
                     f"distinct counterparties: {len(counterparties)}"
                     + (f"\n\n{warning}" if warning else "")),
            url=f"https://tonviewer.com/{addr}",
            raw_json={"address": addr, "chain": "ton", "balance_ton": balance_ton,
                      "counterparties": counterparties,
                      "counterparty_count": len(counterparties),
                      "needs_decision": warning is not None},
            confidence="high")
        rows = [] if warning else [EnrichmentResult(
            result_type="profile", title=a,
            summary=f"TON counterparty of {addr} (transfer).",
            confidence="medium") for a in counterparties]
        return [header] + rows
