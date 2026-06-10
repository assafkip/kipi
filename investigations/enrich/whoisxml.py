"""WhoisXML adapter — reverse-WHOIS + historical (passive) DNS.

Fills the two pivots the investigator named but could not call (RCA 2026-06-03):
  - reverse_whois: registrant email/term -> the full domain portfolio
                   (Reverse WHOIS API v2, https://reverse-whois.whoisxmlapi.com/api/v2)
  - dns_history:   a (now-dead) domain's historical A-records / resolution history
                   (DNS Chronicle API v1, https://dns-history.whoisxmlapi.com/api/v1)

One provider, one key (WHOISXML_API_KEY, or set via the Enrich UI per RULE-104).
Free credits on signup; a reverse-WHOIS purchase call costs 1 DRS credit.

Emits ONE result per discovered domain/IP (not a single prose summary) so each is
individually promotable to a graph node via promote.promote_result — that is what
makes the pivots actually reach the graph instead of dying in a summary.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_REVERSE_WHOIS_URL = "https://reverse-whois.whoisxmlapi.com/api/v2"
_DNS_HISTORY_URL = "https://dns-history.whoisxmlapi.com/api/v1"

# Cap per-entity results so a 10k-domain portfolio doesn't flood the run. The header
# result always reports the true total; the analyst/agent promotes selectively.
_MAX_ITEMS = 100


def _post(url: str, payload: dict, timeout: int) -> dict:
    """POST a JSON body to a WhoisXML endpoint, normalize errors to EnrichmentError."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise EnrichmentError("WhoisXML auth failed — check WHOISXML_API_KEY")
        if exc.code == 402:
            raise EnrichmentError("WhoisXML out of credits — top up or use a different key")
        if exc.code == 429:
            raise EnrichmentError("WhoisXML rate limit — wait and retry")
        # Many WhoisXML errors come back 4xx with a JSON {messages|msg} body.
        try:
            detail = json.loads(exc.read().decode("utf-8"))
            msg = detail.get("messages") or detail.get("msg") or detail.get("error") or exc.reason
        except Exception:
            msg = exc.reason
        raise EnrichmentError(f"WhoisXML HTTP {exc.code}: {msg}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"WhoisXML network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("WhoisXML returned non-JSON (rate limited or down)")


class WhoisXMLAdapter(Adapter):
    slug = "whoisxml"
    display_name = "WhoisXML (reverse-WHOIS / historical DNS)"
    env_var = "WHOISXML_API_KEY"
    category = "infra"
    cost_per_call_usd = 0.0  # free credits on signup; reverse-WHOIS purchase = 1 DRS credit

    def modes(self) -> list[str]:
        return ["auto", "reverse_whois", "dns_history"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        key = self.get_key()
        term = (query or "").strip()
        if not term:
            raise EnrichmentError("WhoisXML: empty query")
        m = (mode or "auto").lower()
        if m in ("auto", "default", ""):
            # an email/registrant term -> reverse-WHOIS; a domain -> its DNS history
            m = "reverse_whois" if "@" in term else "dns_history"
        if m == "reverse_whois":
            return self._reverse_whois(key, term, timeout)
        if m == "dns_history":
            return self._dns_history(key, term, timeout)
        raise EnrichmentError(f"WhoisXML: unknown mode '{m}'")

    # --- reverse WHOIS: registrant term -> domains -------------------------------
    def _reverse_whois(self, key: str, term: str, timeout: int) -> list[EnrichmentResult]:
        payload = {
            "apiKey": key,
            "searchType": "historic",   # current + historical WHOIS records
            "mode": "purchase",          # return the actual domain list (1 DRS credit)
            "basicSearchTerms": {"include": [term]},
        }
        data = _post(_REVERSE_WHOIS_URL, payload, timeout)
        raw_list = data.get("domainsList") or []
        total = data.get("domainsCount", len(raw_list))
        # domainsList items are bare strings, or objects when includeAuditDates is set.
        domains = []
        for item in raw_list:
            if isinstance(item, dict):
                d = (item.get("domainName") or "").strip().lower()
            else:
                d = str(item).strip().lower()
            if d:
                domains.append(d)

        if not domains:
            return [EnrichmentResult(
                result_type="document",
                title=f"Reverse-WHOIS: {term} [none]",
                summary=f"No domains found whose WHOIS records contain '{term}'.",
                confidence="low")]

        shown = domains[:_MAX_ITEMS]
        header = EnrichmentResult(
            result_type="document",
            title=f"Reverse-WHOIS: {term} — {total} domains",
            summary=(f"{total} domain(s) share '{term}' in WHOIS"
                     + (f"; showing first {len(shown)}." if total > len(shown) else ".")
                     + " Each domain below is a promotable node."),
            raw_json={"term": term, "domains_count": total, "domains": domains},
            confidence="medium")
        # One promotable result per domain (url so promote._host -> domain node).
        items = [EnrichmentResult(
            result_type="url",
            title=d,
            summary=f"Registered with WHOIS containing '{term}' (reverse-WHOIS pivot).",
            url=f"http://{d}",
            confidence="medium") for d in shown]
        return [header] + items

    # --- DNS Chronicle: domain -> historical A-records ---------------------------
    def _dns_history(self, key: str, domain: str, timeout: int) -> list[EnrichmentResult]:
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
        payload = {"apiKey": key, "searchType": "forward",
                   "recordType": "a", "domainName": domain}
        data = _post(_DNS_HISTORY_URL, payload, timeout)
        # DNS Chronicle shape: {"result": {"count": N, "records": [
        #   {"date": "YYYY-MM-DD", "ips": [{"ip": "1.2.3.4", "wildcard": null}, ...]}, ...]}}
        recs = (data.get("result") or {}).get("records") or []
        # Collapse to distinct IPs, tracking the first/last date each was seen (ISO
        # dates compare lexicographically, so plain string min/max is correct).
        seen: dict[str, dict] = {}
        for rec in recs:
            if not isinstance(rec, dict):
                continue
            date = (rec.get("date") or "").strip()
            for ipobj in rec.get("ips") or []:
                ip = (ipobj.get("ip") if isinstance(ipobj, dict) else str(ipobj) or "").strip()
                if not ip:
                    continue
                cur = seen.setdefault(ip, {"first": date, "last": date})
                if date:
                    if not cur["first"] or date < cur["first"]:
                        cur["first"] = date
                    if not cur["last"] or date > cur["last"]:
                        cur["last"] = date

        if not seen:
            return [EnrichmentResult(
                result_type="document",
                title=f"DNS history: {domain} [none]",
                summary="No historical A-records found (domain may be too new, or never resolved).",
                raw_json={"domain": domain, "raw": data} if data else None,
                confidence="low")]

        ips = list(seen.items())[:_MAX_ITEMS]
        header = EnrichmentResult(
            result_type="document",
            title=f"DNS history: {domain} — {len(seen)} historical IP(s)",
            summary=(f"{domain} resolved to {len(seen)} distinct IP(s) over time. "
                     "Each IP below is a promotable node — pivot it to find co-hosted "
                     "infrastructure (the dead seed's historical IP is the cluster link)."),
            raw_json={"domain": domain, "ips": {ip: w for ip, w in seen.items()}},
            confidence="medium")
        items = [EnrichmentResult(
            result_type="profile",
            title=ip,
            summary=f"{domain} resolved here historically"
                    + (f" ({w['first']} → {w['last']})" if (w['first'] or w['last']) else "")
                    + ".",
            confidence="medium") for ip, w in ips]
        return [header] + items
