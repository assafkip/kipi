"""WhoisXML reverse_ns (issue gma-3-whoisxml-reverse-ns, PRD
graph-machinery-activation).

Asserts: reverse_ns(nameserver) is a real adapter mode (HTTP mocked) emitting a
header + one promotable result per domain; input is normalized; the empty case
degrades to a low-confidence document; the missing-key path raises the standard
'not configured' error; dns_history behavior is unchanged; and the agent wiring
is complete — MCP tool registered, investigator allowlist carries it, and the
whoisxml missing-key filter drops it alongside its siblings.
"""
from pathlib import Path
from unittest import mock

import pytest

from investigations.enrich import whoisxml as wx
from investigations.enrich.base import NotConfiguredError
from investigations.enrich.registry import get_adapter


def _adapter():
    a = get_adapter("whoisxml")
    assert a is not None
    return a


def test_reverse_ns_mode_listed_and_routed():
    a = _adapter()
    assert "reverse_ns" in a.modes()


def test_reverse_ns_parses_dict_and_string_items():
    a = _adapter()
    payload = {"size": 3, "result": [
        {"name": "trumpusa.live", "first_seen": 1, "last_visit": 2},
        {"name": "TRUMPPRESENT.TOP"},
        "extra.example.com",
    ]}
    with mock.patch.object(a, "get_key", return_value="k"), \
         mock.patch.object(wx, "_get", return_value=payload) as get:
        out = a.run("ns1.streetplug.me", mode="reverse_ns")
    assert get.call_args[0][0] == wx._REVERSE_NS_URL
    header, items = out[0], out[1:]
    assert "3 domain(s)" in header.title
    names = {i.title for i in items}
    assert names == {"trumpusa.live", "trumppresent.top", "extra.example.com"}
    # Promotable: url results so promote materializes domain nodes.
    assert all(i.result_type == "url" for i in items)


def test_reverse_ns_uses_get_with_query_params():
    """Codex finding-3: the Reverse NS API is GET-only — POST 4xxes live."""
    a = _adapter()
    captured = {}

    def fake_urlopen(req, timeout=0):
        captured["method"] = req.get_method()
        captured["url"] = req.full_url
        raise AssertionError("stop here")

    with mock.patch.object(a, "get_key", return_value="k"), \
         mock.patch.object(wx.urllib.request, "urlopen", side_effect=fake_urlopen):
        try:
            a.run("ns1.streetplug.me", mode="reverse_ns")
        except Exception:
            pass
    assert captured["method"] == "GET"
    assert "ns=ns1.streetplug.me" in captured["url"]
    assert "apiKey=k" in captured["url"]


def test_reverse_ns_normalizes_input():
    a = _adapter()
    with mock.patch.object(a, "get_key", return_value="k"), \
         mock.patch.object(wx, "_get", return_value={"result": []}) as get:
        a.run("https://NS1.Streetplug.me./path", mode="reverse_ns")
    assert get.call_args[0][1]["ns"] == "ns1.streetplug.me"


def test_reverse_ns_empty_returns_low_confidence_document():
    a = _adapter()
    with mock.patch.object(a, "get_key", return_value="k"), \
         mock.patch.object(wx, "_get", return_value={"result": [], "size": 0}):
        out = a.run("ns1.nowhere.example", mode="reverse_ns")
    assert len(out) == 1
    assert out[0].result_type == "document"
    assert out[0].confidence == "low"


def test_missing_key_reports_not_configured(monkeypatch):
    a = _adapter()
    monkeypatch.delenv("WHOISXML_API_KEY", raising=False)
    with mock.patch.object(wx, "resolve_key", return_value=None, create=True), \
         mock.patch("investigations.enrich.base.resolve_key", return_value=None):
        with pytest.raises(NotConfiguredError, match="not configured"):
            a.run("ns1.streetplug.me", mode="reverse_ns")


def test_dns_history_unchanged():
    a = _adapter()
    payload = {"result": {"count": 1, "records": [
        {"date": "2026-01-01", "ips": [{"ip": "1.2.3.4"}]}]}}
    with mock.patch.object(a, "get_key", return_value="k"), \
         mock.patch.object(wx, "_post", return_value=payload) as post:
        out = a.run("dead.example.com", mode="dns_history")
    assert post.call_args[0][0] == wx._DNS_HISTORY_URL
    assert any(i.title == "1.2.3.4" for i in out[1:])


def test_agent_wiring_complete():
    root = Path(__file__).resolve().parents[1]
    mcp_src = (root / "agent" / "osint_mcp.py").read_text()
    assert "def reverse_ns(" in mcp_src, "MCP tool must be registered"

    from investigations.agent import investigator
    assert "mcp__kipi-osint__reverse_ns" in investigator._KIPI_MCP_TOOLS, \
        "investigator allowlist must carry the tool"
    inv_src = (root / "agent" / "investigator.py").read_text()
    assert inv_src.count("mcp__kipi-osint__reverse_ns") >= 3, \
        "tool must be in allowlist + dead-key filter + infra crew tools"
    # Codex finding-1: caged runs must be able to gate the new enumeration pivot.
    assert "reverse_ns" in investigator._SCOPE_MATCHER, \
        "scope guard must match reverse_ns"


def test_promote_maps_reverse_ns_to_nameserver_edge():
    """Codex finding-2: shared NS is infrastructure co-location, not registrant
    identity — promotions must not write same_registrant."""
    from investigations.enrich.promote import _enrich_rel_candidate
    assert _enrich_rel_candidate("whoisxml", "reverse_ns") == "uses_nameserver"
    assert _enrich_rel_candidate("whoisxml", "dns_history") == "prior_resolution"
    assert _enrich_rel_candidate("whoisxml", "reverse_whois") == "same_registrant"
