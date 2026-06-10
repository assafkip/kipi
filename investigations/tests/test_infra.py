"""Infra adapter -- RDAP-redacted registrant falls back to raw WHOIS.

Regression guard for D1 (replay-4points-case031): kipi's `infra` adapter was
RDAP-only in practice -- when RDAP returned non-empty infrastructure (domain +
nameservers) but NO registrant (the .us ccTLD case), the raw-whois fallback never
fired and the actor layer was silently lost. The fix: fall back to raw whois when
RDAP has no registrant, not only when RDAP is wholly empty.

Run: .venv/bin/python -m investigations.tests.test_infra
"""
from investigations.enrich import infra
from investigations.enrich.infra import InfraAdapter

# A .us-style RDAP response: real infrastructure, but the registrant is redacted
# (no contact entity). This is what rdap.org returns for trumpstake.us.
RDAP_NO_REGISTRANT = (
    "Domain: TRUMPSTAKE.US\n"
    "registration: 2025-12-22T19:11:37Z\n"
    "status: client transfer prohibited\n"
    "nameservers: cartman.ns.cloudflare.com, evangeline.ns.cloudflare.com"
)

# A .com-style RDAP response that DOES surface a registrant.
RDAP_WITH_REGISTRANT = (
    "Domain: EXAMPLE.COM\n"
    "registrant: Jane Operator\n"
    "nameservers: a.iana-servers.net"
)

# The raw whois the .us registry still discloses.
RAW_WHOIS_REGISTRANT = (
    "Domain Name: trumpstake.us\n"
    "Registrar: NameCheap, Inc.\n"
    "Registrant Name: Markk Bennett\n"
    "Registrant Organization: stakeus\n"
    "Registrant Phone: +1.8075258080\n"
    "Registrant Email: markk.bennett.2025@gmail.com"
)


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def _run_whois(domain, mode="whois"):
    return InfraAdapter().run(domain, mode=mode)[0].summary


def test_redacted_rdap_falls_back_to_whois(mp):
    """RDAP returns infra but no registrant -> adapter pulls the registrant from raw whois."""
    mp.setattr(infra, "_rdap_domain", lambda d, t: RDAP_NO_REGISTRANT)
    mp.setattr(infra, "_run", lambda cmd, t: RAW_WHOIS_REGISTRANT)
    summary = _run_whois("trumpstake.us")
    assert "Markk Bennett" in summary, f"registrant lost; got:\n{summary}"
    assert "NameCheap" in summary, f"registrar lost; got:\n{summary}"
    # the RDAP infra is still present (nameservers preserved)
    assert "cloudflare" in summary.lower(), "RDAP infra dropped on fallback"
    print("  ok  redacted RDAP -> raw whois recovers registrant")


def test_rdap_with_registrant_skips_whois(mp):
    """When RDAP already has a registrant, raw whois must NOT be called (no over-fetch / no hang)."""
    called = {"whois": False}

    def _boom(cmd, t):
        called["whois"] = True
        raise AssertionError("raw whois should not run when RDAP has a registrant")

    mp.setattr(infra, "_rdap_domain", lambda d, t: RDAP_WITH_REGISTRANT)
    mp.setattr(infra, "_run", _boom)
    summary = _run_whois("example.com")
    assert "Jane Operator" in summary
    assert called["whois"] is False
    print("  ok  RDAP with registrant -> no raw-whois over-fetch")


def test_empty_rdap_still_falls_back(mp):
    """Pre-existing behavior preserved: totally-empty RDAP still falls back to raw whois."""
    mp.setattr(infra, "_rdap_domain", lambda d, t: "")
    mp.setattr(infra, "_run", lambda cmd, t: RAW_WHOIS_REGISTRANT)
    summary = _run_whois("trumpstake.us")
    assert "Markk Bennett" in summary
    print("  ok  empty RDAP -> raw whois (unchanged)")


def main():
    for fn in (test_redacted_rdap_falls_back_to_whois,
               test_rdap_with_registrant_skips_whois,
               test_empty_rdap_still_falls_back):
        mp = _MP()
        try:
            fn(mp)
        finally:
            mp.undo()
    print("\nPASS: test_infra")


if __name__ == "__main__":
    main()
