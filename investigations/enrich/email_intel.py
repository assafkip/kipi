"""Email intel adapter — triage an address, or pivot raw headers to source IPs.

Keyless (dnspython only). Two modes, the MailTrace checklist implemented native
(gap-analysis #4: "skip tool, steal checklist"):

  triage  (default)  user@domain -> MX records, SPF posture, DMARC policy,
                     mail-provider identification, disposable-domain flag.
  headers            paste raw RFC-822 headers -> the Received hop chain +
                     every public source IP as a promotable result feeding the
                     existing dns / RDAP / VT pivots. Origin IP flagged.

DNS lookups carry a hard per-query timeout and the adapter degrades to a clear
EnrichmentError offline — same posture as the other keyless adapters.
"""
from __future__ import annotations

import ipaddress
import re
from email import message_from_string

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_DNS_TIMEOUT = 6.0       # default per-query cap; resolver hangs are the known failure mode
_MAX_HEADER_BYTES = 256_000   # hostile-input cap for pasted headers (a header block is KBs)
_MAX_HOPS = 50                # Received hops beyond this are noise or abuse

# Common disposable / throwaway mail domains (in-repo set, keyless posture —
# a curated core beats a rotting 3000-entry list, same stance as username.py).
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com",
    "10minutemail.com", "temp-mail.org", "tempmail.com", "tempmail.dev",
    "yopmail.com", "trashmail.com", "dispostable.com", "getnada.com",
    "maildrop.cc", "mohmal.com", "mintemail.com", "throwawaymail.com",
    "fakeinbox.com", "spamgourmet.com", "mailnesia.com", "tempinbox.com",
    "emailondeck.com", "burnermail.io", "33mail.com", "anonaddy.me",
}

# MX host suffix -> mail provider. Checked longest-suffix-first.
_MX_PROVIDERS = (
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("google.com", "Google Workspace"),
    ("protection.outlook.com", "Microsoft 365"),
    ("olc.protection.outlook.com", "Microsoft 365 (consumer)"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("protonmail.ch", "Proton Mail"),
    ("proton.me", "Proton Mail"),
    ("yandex.net", "Yandex Mail"),
    ("yandex.ru", "Yandex Mail"),
    ("mail.ru", "Mail.ru"),
    ("icloud.com", "Apple iCloud Mail"),
    ("pphosted.com", "Proofpoint (corporate filter)"),
    ("mimecast.com", "Mimecast (corporate filter)"),
    ("barracudanetworks.com", "Barracuda (corporate filter)"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("secureserver.net", "GoDaddy email"),
    ("emailsrvr.com", "Rackspace email"),
    ("ovh.net", "OVH email"),
)

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# IPv6 candidates (2+ hextet groups with colons); validated via ipaddress before use.
_IP6_RE = re.compile(r"\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]{1,40})\b")


def _resolver(timeout: float = _DNS_TIMEOUT):
    try:
        import dns.resolver
    except ImportError:
        raise EnrichmentError(
            "email: dnspython not installed (pip install dnspython)")
    res = dns.resolver.Resolver()
    res.timeout = min(timeout, _DNS_TIMEOUT)
    res.lifetime = min(timeout, _DNS_TIMEOUT)
    return res


def _txt_records(res, name: str) -> list[str]:
    """All TXT strings for a name; [] on NXDOMAIN/no-answer (absence is intel,
    not an error)."""
    import dns.resolver as _dr
    try:
        answers = res.resolve(name, "TXT")
    except (_dr.NXDOMAIN, _dr.NoAnswer, _dr.NoNameservers):
        return []
    except Exception as exc:
        raise EnrichmentError(f"email: TXT lookup failed for {name}: {exc}")
    out = []
    for r in answers:
        try:
            out.append(b"".join(r.strings).decode("utf-8", "replace"))
        except Exception:
            out.append(str(r))
    return out


def _mx_hosts(res, domain: str) -> list[tuple[int, str]]:
    import dns.resolver as _dr
    try:
        answers = res.resolve(domain, "MX")
    except (_dr.NXDOMAIN, _dr.NoAnswer, _dr.NoNameservers):
        return []
    except Exception as exc:
        raise EnrichmentError(f"email: MX lookup failed for {domain}: {exc}")
    pairs = sorted((r.preference, str(r.exchange).rstrip(".").lower()) for r in answers)
    return [(p, h) for p, h in pairs if h]


def identify_provider(mx_hosts: list[str]) -> str | None:
    """Mail provider from MX host suffixes; None when unrecognized. Longest
    suffix wins regardless of table order (olc.protection.outlook.com must beat
    protection.outlook.com)."""
    by_length = sorted(_MX_PROVIDERS, key=lambda sp: len(sp[0]), reverse=True)
    for host in mx_hosts:
        for suffix, provider in by_length:
            if host == suffix or host.endswith("." + suffix):
                return provider
    return None


def _public_ips(text: str) -> list[str]:
    """Public (non-private, non-reserved) IPv4 + IPv6 in a header line, order kept."""
    out = []
    for ip in _IP_RE.findall(text) + _IP6_RE.findall(text):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_global and str(addr) not in out:
            out.append(str(addr))
    return out


def parse_received_chain(raw_headers: str) -> dict:
    """Received hop chain from raw headers. Hops keep header order (top = nearest,
    bottom = origin). Each hop: its line (trimmed) + its public IPs. The ORIGIN
    is the bottom-most hop that carries a public IP — the sender's exit point."""
    if len(raw_headers) > _MAX_HEADER_BYTES:
        raise EnrichmentError(
            f"email: header block too large (> {_MAX_HEADER_BYTES} bytes) — "
            "paste headers only, not the message body")
    # Headers end at the first blank line — drop any pasted body before parsing.
    raw_headers = raw_headers.split("\n\n", 1)[0].split("\r\n\r\n", 1)[0]
    msg = message_from_string(raw_headers)
    received = (msg.get_all("Received") or [])[:_MAX_HOPS]
    hops = []
    for i, line in enumerate(received):
        flat = " ".join(str(line).split())
        hops.append({"hop": i + 1, "line": flat[:300], "ips": _public_ips(flat)})
    origin_ip = None
    for hop in reversed(hops):
        if hop["ips"]:
            origin_ip = hop["ips"][0]
            break
    auth = " ".join(str(v).split())[:300] if (v := msg.get("Authentication-Results")) else None
    x_orig = None
    if (xo := msg.get("X-Originating-IP")):
        found = _public_ips(str(xo))
        x_orig = found[0] if found else None
    return {"hops": hops, "origin_ip": origin_ip, "x_originating_ip": x_orig,
            "from": msg.get("From"), "return_path": msg.get("Return-Path"),
            "auth_results": auth}


class EmailIntelAdapter(Adapter):
    slug = "email"
    display_name = "Email intel (triage MX/SPF/DMARC + header->IP pivot)"
    env_var = None  # keyless
    category = "infra"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["triage", "headers"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        mode = (mode or "triage").strip().lower()
        # Pasted headers self-identify even when the caller forgot the mode flag.
        if mode == "triage" and "received:" in (query or "").lower():
            mode = "headers"
        if mode == "headers":
            return self._run_headers(query)
        return self._run_triage(query, timeout)

    # ---------- mode: triage ----------

    def _run_triage(self, query: str, timeout: int = 30) -> list[EnrichmentResult]:
        email = (query or "").strip().lower()
        if "@" not in email:
            raise EnrichmentError("email: pass user@domain (or mode=headers with raw headers)")
        domain = email.rsplit("@", 1)[1]
        res = _resolver(timeout)

        mx = _mx_hosts(res, domain)
        mx_hosts = [h for _, h in mx]
        provider = identify_provider(mx_hosts)
        spf = [t for t in _txt_records(res, domain) if t.lower().startswith("v=spf1")]
        # >1 v=spf1 record is a permerror (RFC 7208 §4.5) — receivers treat SPF as
        # broken, which is itself posture intel. Surface it instead of picking one.
        spf_permerror = len(spf) > 1
        # DMARC discovery (RFC 7489 §6.6.3): exact domain first, then fall back
        # toward the organizational domain (approximated as parent labels down to
        # 2 — no public-suffix list in keyless posture; errs toward finding a policy).
        dmarc, dmarc_at = [], None
        labels = domain.split(".")
        for i in range(0, max(1, len(labels) - 1)):
            cand = ".".join(labels[i:])
            if len(cand.split(".")) < 2:
                break
            found = [t for t in _txt_records(res, f"_dmarc.{cand}")
                     if t.lower().startswith("v=dmarc1")]
            if found:
                dmarc, dmarc_at = found, cand
                break
        dmarc_policy = None
        if dmarc:
            m = re.search(r"\bp=([a-z]+)", dmarc[0], re.I)
            dmarc_policy = m.group(1).lower() if m else None
        disposable = domain in DISPOSABLE_DOMAINS

        spf_line = ("PERMERROR — multiple v=spf1 records (SPF is broken for receivers)"
                    if spf_permerror else (spf[0][:120] if spf else "NONE (spoofable)"))
        dmarc_line = (f"{dmarc[0][:120]}"
                      + (f" — policy {dmarc_policy}" if dmarc_policy else "")
                      + (f" (inherited from {dmarc_at})" if dmarc_at and dmarc_at != domain else "")
                      if dmarc else "NONE (no policy)")
        lines = [
            f"domain: {domain}",
            # No MX ≠ undeliverable: SMTP falls back to the A/AAAA record (implicit MX).
            f"MX: {', '.join(mx_hosts) if mx_hosts else 'NONE (no MX — implicit A-record fallback possible)'}",
            f"provider: {provider or 'unrecognized'}",
            f"SPF: {spf_line}",
            f"DMARC: {dmarc_line}",
            f"disposable: {'YES — throwaway domain' if disposable else 'no'}",
        ]
        results = [EnrichmentResult(
            result_type="document",
            title=f"Email triage: {email}"
                  + (" [DISPOSABLE]" if disposable else "")
                  + (f" [{provider}]" if provider else ""),
            summary="\n".join(lines),
            raw_json={"email": email, "domain": domain,
                      "mx": mx_hosts, "provider": provider,
                      "spf": spf[0] if (spf and not spf_permerror) else None,
                      "spf_permerror": spf_permerror,
                      "dmarc": dmarc[0] if dmarc else None,
                      "dmarc_at": dmarc_at,
                      "dmarc_policy": dmarc_policy, "disposable": disposable},
            confidence="high" if mx_hosts else "medium")]
        # Each MX host is a pivotable node (title-only result → promotes as a domain).
        for host in mx_hosts[:5]:
            results.append(EnrichmentResult(
                result_type="document", title=host,
                summary=f"MX host for {domain}"
                        + (f" ({provider})" if provider else ""),
                confidence="medium"))
        return results

    # ---------- mode: headers ----------

    def _run_headers(self, query: str) -> list[EnrichmentResult]:
        raw = (query or "").strip()
        if not raw or ":" not in raw:
            raise EnrichmentError("email: mode=headers needs raw RFC-822 headers pasted as the query")
        chain = parse_received_chain(raw)
        if not chain["hops"]:
            raise EnrichmentError("email: no Received headers found in the pasted text")

        hop_lines = [f"hop {h['hop']}: {h['line'][:160]}"
                     + (f"  [IPs: {', '.join(h['ips'])}]" if h["ips"] else "")
                     for h in chain["hops"]]
        meta = [f"origin IP: {chain['origin_ip'] or 'not found'}",
                f"X-Originating-IP: {chain['x_originating_ip'] or '—'}",
                f"From: {chain['from'] or '—'}",
                f"Return-Path: {chain['return_path'] or '—'}",
                f"Authentication-Results: {chain['auth_results'] or '—'}"]
        results = [EnrichmentResult(
            result_type="document",
            title=f"Header hop chain ({len(chain['hops'])} hops)"
                  + (f" — origin {chain['origin_ip']}" if chain["origin_ip"] else ""),
            summary="\n".join(meta + [""] + hop_lines),
            raw_json=chain,
            confidence="high")]

        seen: set[str] = set()
        for h in chain["hops"]:
            for ip in h["ips"]:
                if ip in seen:
                    continue
                seen.add(ip)
                is_origin = ip == chain["origin_ip"]
                results.append(EnrichmentResult(
                    result_type="document", title=ip,
                    summary=("ORIGIN source IP" if is_origin else "relay source IP")
                            + f" (Received hop {h['hop']}) — pivot: dns/RDAP/VT",
                    confidence="high" if is_origin else "medium"))
        return results
