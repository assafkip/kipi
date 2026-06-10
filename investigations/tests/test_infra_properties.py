"""Reproducer + guard: the infra adapter emits structured raw_json so domains get
typed node_properties (registrar / a_record / nameserver), not just a text dossier.

Before the fix infra returned only `summary` text → extract_properties saw no raw_json →
domains had an empty property sheet. These tests pin the parsers (deterministic, no
network) + the end-to-end raw_json -> Property mapping.

Run: .venv/bin/python -m pytest investigations/tests/test_infra_properties.py -q
"""
from investigations.enrich import infra
from investigations.enrich.properties import extract_properties


SAMPLE_WHOIS = """Domain: trumpstake.us
registration: 2025-01-04T00:00:00Z
expiration: 2026-01-04T00:00:00Z
registrar: NameCheap, Inc.
registrant: WhoisGuard Protected
nameservers: dns1.namecheaphosting.com, dns2.namecheaphosting.com
status: clientTransferProhibited
"""

SAMPLE_RAW_WHOIS = """Registrar: Shinjiru Technology Sdn Bhd
Creation Date: 2024-11-02T10:00:00Z
Registry Expiry Date: 2025-11-02T10:00:00Z
Registrant Organization: Privacy Co
Name Server: NS1.SHINJIRU.COM
Name Server: NS2.SHINJIRU.COM
"""

SAMPLE_DNS = """[A]
trumpstake.us.\t300\tIN\tA\t104.21.5.10
[AAAA]
trumpstake.us.\t300\tIN\tAAAA\t2606:4700:3033::1
[MX]
trumpstake.us.\t300\tIN\tMX\t10 mail.trumpstake.us.
[NS]
trumpstake.us.\t300\tIN\tNS\tdns1.namecheaphosting.com."""


def test_whois_parser_pulls_registration_fields():
    rj = infra._whois_raw_json(SAMPLE_WHOIS)
    assert rj.get("registrar") == "NameCheap, Inc."
    assert rj.get("creation_date") == "2025-01-04T00:00:00Z"
    assert rj.get("expiry_date") == "2026-01-04T00:00:00Z"
    assert rj.get("registrant") == "WhoisGuard Protected"
    assert "dns1.namecheaphosting.com" in rj.get("nameservers", [])


def test_whois_parser_handles_raw_whois_format():
    rj = infra._whois_raw_json(SAMPLE_RAW_WHOIS)
    assert rj.get("registrar") == "Shinjiru Technology Sdn Bhd"
    assert rj.get("creation_date") == "2024-11-02T10:00:00Z"
    assert rj.get("registrant_org") == "Privacy Co"
    assert len(rj.get("nameservers", [])) == 2


POLLUTING_WHOIS = """Registrar URL: http://www.namecheap.com
Registrar WHOIS Server: whois.namecheap.com
Registrar Abuse Contact Email: abuse@namecheap.com
Registrar: NameCheap, Inc.
Registrant Country: US
Registrant Email: redacted@example.com
Registrant Name: Real Registrant LLC
"""


def test_exact_key_match_rejects_pollution_fields():
    """Registrar URL / Registrant Country etc. must NOT become the registrar/registrant
    value (Codex review: prefix match + setdefault locked the wrong first value)."""
    rj = infra._whois_raw_json(POLLUTING_WHOIS)
    assert rj.get("registrar") == "NameCheap, Inc.", rj
    assert rj.get("registrant") == "Real Registrant LLC", rj
    # the country/email/url/server lines must not have leaked into any field
    assert "US" not in rj.values()
    assert "http://www.namecheap.com" not in rj.values()


def test_dns_parser_pulls_records_by_type():
    rj = infra._dns_raw_json(SAMPLE_DNS)
    assert rj.get("a") == ["104.21.5.10"]
    assert rj.get("aaaa") == ["2606:4700:3033::1"]
    assert any("mail.trumpstake.us" in m for m in rj.get("mx", []))
    assert any("namecheaphosting.com" in n for n in rj.get("ns", []))


def test_reverse_parser():
    rj = infra._reverse_raw_json("server-104-21-5-10.cloudflare.com.")
    assert rj.get("reverse") == "server-104-21-5-10.cloudflare.com."


def test_whois_raw_json_becomes_typed_properties():
    """End-to-end: the parsed raw_json maps to the typed node_properties the panel reads."""
    rj = infra._whois_raw_json(SAMPLE_WHOIS)
    props = {p.key: p.value for p in extract_properties("infra", rj)}
    assert props.get("registrar") == "NameCheap, Inc."
    assert props.get("created_date") == "2025-01-04T00:00:00Z"
    assert "dns1.namecheaphosting.com" in props.get("nameserver", "")


def test_dns_raw_json_becomes_a_record_property():
    rj = infra._dns_raw_json(SAMPLE_DNS)
    props = {p.key: p.value for p in extract_properties("infra", rj)}
    assert props.get("a_record") == "104.21.5.10"


def main():
    test_whois_parser_pulls_registration_fields()
    test_whois_parser_handles_raw_whois_format()
    test_exact_key_match_rejects_pollution_fields()
    test_dns_parser_pulls_records_by_type()
    test_reverse_parser()
    test_whois_raw_json_becomes_typed_properties()
    test_dns_raw_json_becomes_a_record_property()
    print("\nPASS: test_infra_properties")


if __name__ == "__main__":
    main()
