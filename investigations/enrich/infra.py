"""Infrastructure adapter — WHOIS / DNS / reverse-DNS via local tools.

Ported from huntkit's osint-infra MCP (whois_lookup, dns_lookup, reverse_dns).
Keyless: shells out to the system `whois` and `dig`. Modes:
  - whois   : registration data for a domain
  - dns     : A/AAAA/MX/NS/TXT/CNAME records for a domain
  - reverse : PTR record for an IP
Default auto-picks reverse for an IP, whois for a domain.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def _is_ip(s: str) -> bool:
    return s.replace(".", "").isdigit() or ":" in s


def _rdap_domain(domain: str, timeout: int) -> str:
    """Registration data via RDAP (the modern HTTP/JSON replacement for whois).
    rdap.org follows the IANA bootstrap to the right registry. Fast (~1s) and not subject
    to the per-server whois rate-limits/hangs. Returns '' on any failure so the caller
    can fall back to raw whois."""
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json", "User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError):
        return ""
    lines = []
    if data.get("ldhName"):
        lines.append(f"Domain: {data['ldhName']}")
    for ev in data.get("events", []) or []:
        lines.append(f"{ev.get('eventAction')}: {ev.get('eventDate')}")
    for s in data.get("status", []) or []:
        lines.append(f"status: {s}")
    for ent in data.get("entities", []) or []:
        roles = ",".join(ent.get("roles") or [])
        name = ""
        for item in (ent.get("vcardArray") or [None, []])[1] or []:
            if isinstance(item, list) and item and item[0] == "fn":
                name = item[-1]
        if roles or name:
            lines.append(f"{roles or 'entity'}: {name or ent.get('handle', '')}")
    ns = [n.get("ldhName") for n in (data.get("nameservers") or []) if n.get("ldhName")]
    if ns:
        lines.append("nameservers: " + ", ".join(ns))
    return "\n".join(lines)


def _run(cmd: list[str], timeout: int) -> str:
    if not shutil.which(cmd[0]):
        raise EnrichmentError(f"`{cmd[0]}` is not installed on this host")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise EnrichmentError(f"`{cmd[0]}` timed out after {timeout}s")
    return (out.stdout or "").strip() or (out.stderr or "").strip()


def _rdap_has_registrant(rdap_text: str) -> bool:
    """True if the RDAP block surfaced a registrant contact (not just infra).

    Many ccTLDs (.us) and privacy domains redact the registrant in RDAP, returning
    only the domain + nameservers. The registry's raw whois often still discloses
    it, so the caller uses this to decide whether a whois supplement is needed."""
    for line in rdap_text.splitlines():
        role, _, value = line.partition(":")
        if "registrant" in role.strip().lower() and value.strip():
            return True
    return False


def _safe_whois(domain: str, timeout: int) -> str:
    """Raw whois, or '' if whois is missing / times out (never raises)."""
    try:
        return _run(["whois", domain], timeout)
    except EnrichmentError:
        return ""


_REGISTRANT_PREFIXES = (
    "registrant", "registrar", "creation date", "registry expiry",
    "admin name", "admin email", "admin phone",
)


def _registrant_lines(raw_whois: str) -> str:
    """Pull the registrant / registrar / creation lines out of a raw whois dump,
    dropping the IANA boilerplate and nameserver noise so the supplement stays tight."""
    kept = [line.strip() for line in raw_whois.splitlines()
            if line.strip().lower().startswith(_REGISTRANT_PREFIXES)]
    return "\n".join(kept)


# --- structured-field parsers: turn the rendered text into typed raw_json so the existing
# properties pipeline (properties.PROPERTY_MAP) fills a domain's panel. Keys here match
# PROPERTY_MAP exactly. Pure string parsing, no network. ---

# whois/RDAP "key: value" lines -> the raw_json key the property map expects. EXACT key
# match (not startswith): a prefix match would capture `Registrar URL` / `Registrant
# Country` / `Registrar Abuse Contact Email` and, with setdefault, lock the wrong value
# into registrar/registrant (Codex review).
_WHOIS_KEY_TO_FIELD: dict[str, str] = {
    "registrar": "registrar",
    "registrant": "registrant",
    "registrant name": "registrant",
    "registrant organization": "registrant_org",
    "registrant org": "registrant_org",
    "creation date": "creation_date",
    "created": "creation_date",
    "created date": "creation_date",
    "registration": "creation_date",
    "registration date": "creation_date",
    "registry expiry date": "expiry_date",
    "registrar registration expiration date": "expiry_date",
    "expiry date": "expiry_date",
    "expiration": "expiry_date",
    "expiration date": "expiry_date",
    "expires": "expiry_date",
}
_NAMESERVER_KEYS = frozenset({"name server", "nameserver", "nameservers", "nserver"})


def _whois_raw_json(text: str) -> dict:
    """Pull registrar / registrant / dates / nameservers out of a whois or RDAP-rendered
    block. Exact key match per field; first non-empty value wins; nameservers (which
    repeat in raw whois and comma-join in RDAP) accumulate into a deduped list."""
    out: dict = {}
    nameservers: list[str] = []
    for line in (text or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        k, v = key.strip().lower(), value.strip()
        if not v:
            continue
        if k in _NAMESERVER_KEYS:
            for ns in (p.strip() for p in v.split(",")):
                if ns and ns not in nameservers:
                    nameservers.append(ns)
            continue
        field = _WHOIS_KEY_TO_FIELD.get(k)
        if field:
            out.setdefault(field, v)
    if nameservers:
        out["nameservers"] = nameservers
    return out


def _dns_raw_json(text: str) -> dict:
    """Pull A / AAAA / MX / NS records out of the `dig +noall +answer` blocks. Each answer
    line is `name. TTL IN <TYPE> <value>`; the value is the last whitespace field."""
    by_type: dict[str, list[str]] = {}
    current = None
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("[") and s.endswith("]"):
            current = s[1:-1].strip().upper()
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        rtype = current
        if "IN" in parts:  # dig answer line carries its own type — trust it
            i = parts.index("IN")
            if i + 1 < len(parts):
                rtype = parts[i + 1].upper()
            value = " ".join(parts[i + 2:]).strip()
        else:
            value = parts[-1]
        if not rtype or not value:
            continue
        by_type.setdefault(rtype, []).append(value.rstrip("."))
    out: dict = {}
    mapping = {"A": "a", "AAAA": "aaaa", "MX": "mx", "NS": "ns"}
    for rtype, key in mapping.items():
        if by_type.get(rtype):
            out[key] = by_type[rtype]
    return out


def _reverse_raw_json(text: str) -> dict:
    ptr = (text or "").strip().splitlines()
    return {"reverse": ptr[0].strip()} if ptr and ptr[0].strip() else {}


class InfraAdapter(Adapter):
    slug = "infra"
    display_name = "Infra recon (WHOIS / DNS / reverse-DNS)"
    env_var = None  # keyless — uses local whois + dig
    category = "infra"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["whois", "dns", "reverse"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 20) -> list[EnrichmentResult]:
        target = (query or "").strip()
        if not target:
            raise EnrichmentError("infra: empty target")
        m = (mode or "").lower()
        if m in ("", "auto", "default"):
            m = "reverse" if _is_ip(target) else "whois"

        if m == "whois":
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            # RDAP first (fast, no per-server whois rate-limit/hang). But RDAP redacts
            # the registrant for many ccTLDs (.us) and privacy domains even when it
            # returns infrastructure -- so fall back to raw whois whenever there's no
            # registrant, not only when RDAP is wholly empty. Short whois timeout so a
            # slow server fails fast instead of hanging the run.
            rdap_text = _rdap_domain(domain, min(timeout, 8))
            text, source = rdap_text, "RDAP"
            if not _rdap_has_registrant(rdap_text):
                raw = _safe_whois(domain, min(timeout, 10))
                registrant = _registrant_lines(raw)
                if rdap_text and registrant:
                    text = f"{rdap_text}\n\n[registrant via raw whois]\n{registrant}"
                    source = "RDAP+whois"
                elif not rdap_text and raw:
                    text, source = raw, "whois"
            return [EnrichmentResult(
                result_type="document", title=f"WHOIS/RDAP: {domain}",
                summary=(f"[{source}]\n{text}")[:4000] or "No registration data.",
                raw_json=(_whois_raw_json(text) or None),
                confidence="medium")]

        if m == "reverse":
            text = _run(["dig", "+short", "-x", target], timeout)
            return [EnrichmentResult(
                result_type="document", title=f"Reverse DNS: {target}",
                summary=text or "No PTR record.",
                raw_json=(_reverse_raw_json(text) or None),
                confidence="medium")]

        if m == "dns":
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            blocks = []
            for rt in _DNS_TYPES:
                ans = _run(["dig", "+noall", "+answer", domain, rt], timeout)
                if ans:
                    blocks.append(f"[{rt}]\n{ans}")
            summary = "\n\n".join(blocks) or "No DNS records found."
            return [EnrichmentResult(
                result_type="document", title=f"DNS: {domain}",
                summary=summary[:4000],
                raw_json=(_dns_raw_json(summary) or None),
                confidence="medium")]

        raise EnrichmentError(f"infra: unknown mode '{m}'")
