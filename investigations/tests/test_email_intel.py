"""Email intel belt (issue email-intel-belt, PRD graph-data-model-hardening).

Offline: DNS is monkeypatched (no network in CI); the headers mode is pure
stdlib parsing. Asserts the triage output (MX/SPF/DMARC/provider/disposable),
the header hop chain + origin-IP detection + promotable IP results, and the
end-to-end registration (registry slug, osint_providers seed row FK-safety,
MCP tools present, invctl belt lists it).

Run: .venv/bin/python3 -m pytest investigations/tests/test_email_intel.py -q
"""
import tempfile
from pathlib import Path

import pytest

from investigations.enrich import email_intel
from investigations.enrich.base import EnrichmentError
from investigations.enrich.email_intel import EmailIntelAdapter, parse_received_chain
from investigations.storage import db


_RAW_HEADERS = """\
Return-Path: <scam@evil-sender.biz>
Received: from mx.victim-corp.com (mx.victim-corp.com [93.184.216.34])
\tby inbox.victim-corp.com with ESMTP id abc123
Received: from relay.bulk-mailer.net (relay.bulk-mailer.net [51.15.43.205])
\tby mx.victim-corp.com with ESMTP
Received: from [192.168.1.50] (unknown [185.220.101.42])
\tby relay.bulk-mailer.net with ESMTPA
From: "PayPal Support" <scam@evil-sender.biz>
Authentication-Results: mx.victim-corp.com; spf=fail smtp.mailfrom=evil-sender.biz
Subject: Your account is locked
"""


# ---------- headers mode (pure offline) ----------

def test_received_chain_orders_hops_and_finds_origin():
    chain = parse_received_chain(_RAW_HEADERS)
    assert len(chain["hops"]) == 3
    # Bottom-most hop with a public IP = origin; 192.168.1.50 (private) excluded.
    assert chain["origin_ip"] == "185.220.101.42"
    assert chain["hops"][0]["ips"] == ["93.184.216.34"]
    assert "spf=fail" in chain["auth_results"]


def test_headers_mode_emits_promotable_ip_results():
    out = EmailIntelAdapter().run(_RAW_HEADERS, mode="headers")
    titles = [r.title for r in out]
    assert any("origin 185.220.101.42" in t for t in titles)  # the chain doc
    # Each public IP is a title-only result (promotes as an 'ip' node).
    assert "185.220.101.42" in titles
    assert "93.184.216.34" in titles
    assert "51.15.43.205" in titles
    origin = next(r for r in out if r.title == "185.220.101.42")
    assert origin.confidence == "high" and "ORIGIN" in origin.summary


def test_headers_mode_autodetects_pasted_headers_without_mode_flag():
    out = EmailIntelAdapter().run(_RAW_HEADERS)   # mode omitted
    assert any("hop chain" in r.title for r in out)


def test_headers_mode_rejects_text_without_received():
    with pytest.raises(EnrichmentError):
        EmailIntelAdapter().run("Subject: hi\nFrom: a@b.com\n", mode="headers")


# ---------- triage mode (DNS mocked) ----------

class _FakeResolver:
    """Stands in for dns.resolver.Resolver: canned MX/TXT answers."""
    def __init__(self, mx=None, txt=None):
        self._mx = mx or []
        self._txt = txt or {}

    def resolve(self, name, rtype):
        import dns.resolver as _dr
        if rtype == "MX":
            if not self._mx:
                raise _dr.NoAnswer()
            return [type("R", (), {"preference": p,
                                   "exchange": h + "."})() for p, h in self._mx]
        if rtype == "TXT":
            vals = self._txt.get(name)
            if not vals:
                raise _dr.NXDOMAIN()
            return [type("R", (), {"strings": (v.encode(),)})() for v in vals]
        raise AssertionError(rtype)


def test_triage_identifies_provider_spf_dmarc(mp):
    fake = _FakeResolver(
        mx=[(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")],
        txt={"target-corp.com": ["v=spf1 include:_spf.google.com ~all"],
             "_dmarc.target-corp.com": ["v=DMARC1; p=reject; rua=mailto:d@target-corp.com"]})
    mp.setattr(email_intel, "_resolver", lambda timeout=6.0: fake)
    out = EmailIntelAdapter().run("ceo@target-corp.com")
    head = out[0]
    assert "Google Workspace" in head.title
    assert head.raw_json["dmarc_policy"] == "reject"
    assert head.raw_json["spf"].startswith("v=spf1")
    assert head.raw_json["disposable"] is False
    # MX hosts ride along as pivotable results.
    assert any(r.title == "aspmx.l.google.com" for r in out)


def test_triage_flags_disposable_and_missing_records(mp):
    mp.setattr(email_intel, "_resolver", lambda timeout=6.0: _FakeResolver())
    out = EmailIntelAdapter().run("x@mailinator.com")
    head = out[0]
    assert "[DISPOSABLE]" in head.title
    assert head.raw_json["disposable"] is True
    assert "NONE" in head.summary           # no MX
    assert head.raw_json["spf"] is None


def test_dmarc_falls_back_to_organizational_domain(mp):
    # RFC 7489 discovery: user@mail.target.com inherits _dmarc.target.com.
    fake = _FakeResolver(
        mx=[(1, "mx.mail.target.com")],
        txt={"_dmarc.target.com": ["v=DMARC1; p=reject"]})
    mp.setattr(email_intel, "_resolver", lambda timeout=6.0: fake)
    head = EmailIntelAdapter().run("x@mail.target.com")[0]
    assert head.raw_json["dmarc_policy"] == "reject"
    assert head.raw_json["dmarc_at"] == "target.com"
    assert "inherited from target.com" in head.summary


def test_multiple_spf_records_report_permerror(mp):
    fake = _FakeResolver(
        mx=[(1, "mx.dual-spf.com")],
        txt={"dual-spf.com": ["v=spf1 include:a.com ~all", "v=spf1 include:b.com ~all"]})
    mp.setattr(email_intel, "_resolver", lambda timeout=6.0: fake)
    head = EmailIntelAdapter().run("x@dual-spf.com")[0]
    assert head.raw_json["spf_permerror"] is True
    assert "PERMERROR" in head.summary


def test_headers_mode_caps_input_size():
    with pytest.raises(EnrichmentError):
        EmailIntelAdapter().run("Received: from x\n" + "A: b\n" * 200_000,
                                mode="headers")


def test_headers_mode_drops_pasted_body():
    raw = _RAW_HEADERS + "\n\nDear victim, Received: from fake [8.8.8.8]\n"
    chain = parse_received_chain(raw)
    assert all("8.8.8.8" not in (h["ips"] or []) for h in chain["hops"])


def test_ipv6_received_chain_extracts_origin():
    raw = ("Received: from mail.example.org (mail.example.org "
           "[IPv6:2606:4700:4700::1111])\n\tby mx.victim.com with ESMTP\n"
           "Subject: t\n")
    chain = parse_received_chain(raw)
    assert chain["origin_ip"] == "2606:4700:4700::1111"


def test_provider_longest_suffix_wins():
    from investigations.enrich.email_intel import identify_provider
    assert identify_provider(["x.olc.protection.outlook.com"]) == "Microsoft 365 (consumer)"
    assert identify_provider(["x.protection.outlook.com"]) == "Microsoft 365"


def test_triage_rejects_non_email():
    with pytest.raises(EnrichmentError):
        EmailIntelAdapter().run("not-an-email")


# ---------- end-to-end registration ----------

def test_registered_in_registry_keyless():
    from investigations.enrich.registry import get_adapter
    a = get_adapter("email")
    assert a.env_var is None and a.modes() == ["triage", "headers"]


def test_provider_seed_row_exists_fk_safe():
    # The whoisxml FK lesson: the osint_providers seed row must exist on a fresh
    # DB before any enrichment_runs row references the slug.
    p = Path(tempfile.mkdtemp()) / "seed.db"
    db.init_db(p)
    with db.connect(db_path=p) as conn:
        row = conn.execute(
            "SELECT slug, env_var, cost_estimate_usd FROM osint_providers "
            "WHERE slug='email'").fetchone()
        assert row is not None
        assert row["env_var"] is None and row["cost_estimate_usd"] == 0.0
        # FK check: a run referencing the slug inserts cleanly.
        conn.execute("PRAGMA foreign_keys=ON")
        rep = db.insert_report(conn, source_path="<t>", source_hash="h",
                               source_type="manual", title="t",
                               investigation=None, raw_text="")
        eid = db.upsert_entity(conn, "a@b.com", "email", rep)
        conn.execute(
            "INSERT INTO enrichment_runs (entity_id, provider_slug, query, status) "
            "VALUES (?, 'email', 'a@b.com', 'success')", (eid,))


def test_mcp_tools_registered():
    from investigations.agent import osint_mcp
    src = Path(osint_mcp.__file__).read_text()
    assert "def email_triage(" in src and "def email_headers(" in src
