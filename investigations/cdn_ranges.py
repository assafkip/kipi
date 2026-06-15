"""Known CDN / anycast IP ranges (issue gtl-3-cdn-tagging, PRD graph-trust-layer).

A CDN edge IP is shared by thousands of unrelated sites, so a shared CDN IP is
NOT evidence of shared operation — two unrelated scam domains both behind
Cloudflare "share" 104.21.x. This module classifies an IP as CDN so the graph can
de-weight it and the cleanup pass can refuse same-operator inference through it.

Data, not logic: the list is a static prefix table. A false-negative (an untagged
CDN IP) degrades to today's behavior, never worse. Update source noted per entry.
IPv4 only for now — the case data is IPv4; IPv6 CDN ranges are a follow-up.
"""
from __future__ import annotations

import ipaddress

# (network, label). Cloudflare's published ranges (cloudflare.com/ips-v4) are the
# bulk; a few other majors cover common anycast edges seen in scam hosting.
_CDN_NETS_RAW = [
    # Cloudflare (https://www.cloudflare.com/ips-v4/, 2026-06)
    ("173.245.48.0/20", "cloudflare"),
    ("103.21.244.0/22", "cloudflare"),
    ("103.22.200.0/22", "cloudflare"),
    ("103.31.4.0/22", "cloudflare"),
    ("141.101.64.0/18", "cloudflare"),
    ("108.162.192.0/18", "cloudflare"),
    ("190.93.240.0/20", "cloudflare"),
    ("188.114.96.0/20", "cloudflare"),
    ("197.234.240.0/22", "cloudflare"),
    ("198.41.128.0/17", "cloudflare"),
    ("162.158.0.0/15", "cloudflare"),
    ("104.16.0.0/13", "cloudflare"),     # covers 104.16.* – 104.23.*
    ("104.24.0.0/14", "cloudflare"),     # covers 104.24.* – 104.27.*
    ("172.64.0.0/13", "cloudflare"),     # covers 172.64.* – 172.71.* (incl. 172.67.*)
    ("131.0.72.0/22", "cloudflare"),
    # Fastly (https://api.fastly.com/public-ip-list, partial)
    ("151.101.0.0/16", "fastly"),
    # Amazon CloudFront (representative edge blocks)
    ("13.32.0.0/15", "cloudfront"),
    ("13.35.0.0/16", "cloudfront"),
    ("99.84.0.0/16", "cloudfront"),
    # Akamai (representative)
    ("23.32.0.0/11", "akamai"),
    ("104.64.0.0/10", "akamai"),
]

_CDN_NETS = [(ipaddress.ip_network(net), label) for net, label in _CDN_NETS_RAW]


def cdn_label(ip: str) -> str | None:
    """Return the CDN label if `ip` falls in a known CDN range, else None.
    Tolerant of junk input (returns None on a non-IP string)."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    for net, label in _CDN_NETS:
        if addr.version == net.version and addr in net:
            return label
    return None


def is_cdn_ip(ip: str) -> bool:
    """True when `ip` is a known CDN / anycast edge address."""
    return cdn_label(ip) is not None
