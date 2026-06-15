"""The single entity-admission contract (RCA rca-recurring-graph-noise-2026-06-11).

ONE table of every junk class the founder has hit + the known-good that must always pass.
A new junk variant = a new row here + (if needed) a clause in admission.py. Because every
creation path routes through is_admissible(), a row that passes here is enforced everywhere.

Run: .venv/bin/python3 -m pytest investigations/tests/test_admission.py -q
"""
from investigations.admission import is_admissible

# (entity_type, value, admissible?, label)
CASES = [
    # --- JUNK that must be rejected (each a real past recurrence) ---
    ("phone", "164736471", False, "bare affiliate/tracking id typed phone"),
    ("phone", "1042168184", False, "an IP with the dots stripped, typed phone"),
    ("phone", "20260419", False, "a date typed phone"),
    ("phone", "000000000", False, "all-zeros placeholder phone"),
    ("phone", "165309999", False, "bare 9-digit id typed phone"),
    ("domain", "iana.org", False, "registry boilerplate"),
    ("domain", "whois.verisign-grs.com", False, "WHOIS server boilerplate"),
    ("subdomain", "whois.globaldomaingroup.com", False, "WHOIS server boilerplate"),
    ("domain", "krebsonsecurity.com", False, "journalist / reporting outlet"),
    ("url", "https://krebsonsecurity.com/2025/07/scammers-unleash-flood/", False, "reporting URL"),
    ("domain", "phishdestroy.io", False, "phishing-takedown feed, not target infra"),
    ("domain", "phishtank.com", False, "phishing blocklist, not target infra"),
    ("subdomain", "urlhaus.abuse.ch", False, "abuse.ch blocklist feed"),
    ("url", "https://urlscan.io/result/abc-123/", False, "scanner result page, not target infra"),
    ("domain", "verisign-grs.com", False, "registrar/registry boilerplate"),
    ("domain", "lynn.ns.cloudflare.com", False, "shared Cloudflare nameserver"),
    ("domain", "ns-1234.awsdns-56.org", False, "shared AWS nameserver"),
    ("domain", "globaldomaingroup.com", False, "registrar boilerplate"),
    ("person", "20260610", False, "date masquerading as a person"),
    ("domain", "x", False, "too short"),
    ("handle", "", False, "empty"),
    ("other", "@media (max-width: 600px)", False, "CSS fragment"),
    ("phone", "registrar privacy 12345", False, "mis-parse label"),
    # trump-demo live dig, 2026-06-11: regex over JSON-escaped tool output + whois boilerplate
    ("url", "https://trumpstake.us/global/fbq.js\\nconfidence: high", False,
     "literal \\n escape glued the confidence line onto the URL"),
    ("url", "https://trumpfundus.com/'", False, "trailing quote from a quoted string"),
    ("domain", "isnic.is", False, "ccTLD registry (the .is NIC) — whois boilerplate"),
    ("email", "iana-contact@isnic.is", False, "the registry's own whois contact email"),
    ("phone", "+3545782030", False, "the registry's own whois contact phone (ISNIC)"),
    ("phone", "+1703925", False, "truncated id wearing a '+1' — NANP needs 11 digits"),
    ("url", "https://crt.sh/?q=trumpfundus.com", False, "the agent's own cert-lookup tool"),
    ("domain", "ip-api.com", False, "the agent's own IP-lookup tool"),
    ("domain", "errors.pydantic.dev", False, "traceback artifact, not an entity"),
    ("url", "https://thereallo.dev/blog/mammoth", False, "kit writeup — a source, not infra"),
    # --- KNOWN-GOOD that must always pass (never over-reject real intel) ---
    ("ip", "9.9.9.9", True, "real resolver IP — dot-stripping must not read it as 9999"),
    ("ip", "1.1.1.1", True, "real resolver IP — not an all-same-digit placeholder"),
    ("ip", "8.8.8.8", True, "real resolver IP"),
    ("phone", "+14805058800", True, "real E.164 phone"),
    ("phone", "(480) 505-8800", True, "real formatted phone"),
    ("domain", "trumpfundus.com", True, "real target domain"),
    ("domain", "alertoscan.io", True, "real target domain"),
    ("url", "https://trumpfundus.com/register", True, "real target URL"),
    ("domain", "scammer-twitter-clone.com", True, "a scammer's own domain"),
    ("handle", "@scam_promoter", True, "a real handle"),
    ("ip", "104.21.68.184", True, "a real IP (CDN is an edge concern, not node admission)"),
    ("affiliate_id", "164736471", True, "the SAME number is fine when typed as affiliate_id"),
    ("wallet", "0x1234567890abcdef1234567890abcdef12345678", True, "a real wallet"),
    ("email", "scam@trumpfundus.com", True, "a real email"),
    ("phone", "+17035551234", True, "real 11-digit NANP phone"),
    ("phone", "+3545781000", True, "a real Icelandic number that is NOT the registry's"),
    ("domain", "gambler-partners.is", True, "a real .is target domain (registry gated, TLD not)"),
]


def test_admission_contract_table():
    failures = []
    for etype, value, want_ok, label in CASES:
        ok, reason = is_admissible(etype, value)
        if ok != want_ok:
            failures.append(f"{label}: is_admissible({etype!r},{value!r}) = ({ok}, {reason!r}), "
                            f"wanted admissible={want_ok}")
    assert not failures, "ADMISSION CONTRACT VIOLATIONS:\n  " + "\n  ".join(failures)


def main():
    test_admission_contract_table()
    print(f"PASS test_admission: {len(CASES)} contract rows (junk rejected, real intel kept)")


if __name__ == "__main__":
    main()
