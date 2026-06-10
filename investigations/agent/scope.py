"""Deterministic investigation-scope gate (RULE-112, "leads first").

The case agent drives its own paths (one context → cross-entity pivots). To keep it
USER-GUIDED instead of an autonomous chaser, this gate bounds WHAT it may investigate:
a tool call against a target ALREADY in the case roster is allowed; a target the agent
just surfaced (not yet in the case) is DENIED — it lands as a LEAD for the analyst to
promote, not an autonomous one-hop-deeper chase. Code, not a prompt: the LLM can try to
chase the 51st domain; the gate says no.

Wired as a PreToolUse hook (cold `claude -p` via --settings) and the SDK `can_use_tool`
callback (warm). Disabled for deep runs (chase freely). Pure + dependency-free so the
hook subprocess can import it.
"""
from __future__ import annotations

import re

# Tools that INVESTIGATE a specific target entity (bounded by the roster). Recall/search
# tools (web_search/perplexity/tavily/exa) are NOT bounded — they're attribution queries,
# not entity enumeration; one search doesn't "chase" a network. Reasoning / ToolSearch /
# internal tools have no target → always allowed.
_TARGETED_MCP = {
    "whois_lookup", "dns_lookup", "reverse_dns", "virustotal", "crtsh_subdomains",
    "abusech", "shodan_host", "censys_host", "breach_intel", "social_scrape",
    "reverse_whois", "dns_history", "browser_navigate", "jina_read",
}
# ./invctl osint-tool <slug> <target> — the entity-investigation slugs. jina (read a page)
# is targeted: reading a research-site result about a new domain IS enumeration.
_TARGETED_BELT = {
    "infra", "whois", "dns", "virustotal", "crtsh", "abusech", "shodan", "censys",
    "breach", "whoisxml", "jina",
}
# Search / recall tools. NOT blanket-allowed (replay: the agent search-mapped the network
# through them). The line 4_points drew (ops-log [058] vs [066]): searching to ATTRIBUTE the
# in-scope targets is autonomous; ENUMERATING the network (a search NAMING a new domain) was
# human-gated. So: deny a search that names an OUT-OF-SCOPE entity; allow in-scope/general.
_SEARCH_MCP = {"web_search", "tavily_search", "exa_search", "perplexity_ask"}
_SEARCH_BELT = {"perplexity", "exa", "tavily", "web_search"}

# Tools that ENUMERATE the network from one entity: reverse-WHOIS turns a registrant into
# EVERY other domain that registrant owns; dns_history turns a domain into its historical
# infra. Their OUTPUT is the network expansion itself — not attribution of one node — so on
# the bounded path they are ALWAYS a lead, even when the input entity is in-roster. 4_points
# gated this behind the analyst (ops-log [066]). These are the two whoisxml-adapter modes.
_ENUMERATION_MCP = {"reverse_whois", "dns_history"}
_ENUMERATION_BELT = {"whoisxml"}
# Mode keywords the whoisxml belt may pass positionally — they are NOT the target.
_BELT_MODE_WORDS = {"reverse_whois", "dns_history"}

_DOMAIN_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)\b", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _norm(value: str) -> str:
    """Normalise an entity value for comparison: lowercase, strip scheme + leading www.,
    drop any path/port. A bare domain/ip/handle survives unchanged."""
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z]+://", "", v)        # scheme
    v = v.split("/")[0].split("?")[0]       # path/query
    v = v.split(":")[0]                      # port
    if v.startswith("www."):
        v = v[4:]
    return v.strip()


def _belt_slug_and_target(command: str) -> tuple[str | None, str | None]:
    """(slug, target) for a `./invctl osint-tool <slug> <target>` (or raw `whois <target>`)
    Bash command, if it's an entity-investigation slug; else (None, None).

    Mode-aware so the whoisxml modes yield the real ENTITY, not the mode word. All three
    forms extract `<email>`:
      osint-tool whoisxml <email> --mode reverse_whois
      osint-tool whoisxml --mode reverse_whois <email>
      osint-tool whoisxml reverse_whois <email>   (mode passed positionally)
    """
    m = re.search(r"osint-tool\s+([a-z0-9_-]+)\s+(.*)", command, re.I)
    if m and m.group(1).lower() in _TARGETED_BELT:
        slug = m.group(1).lower()
        rest = m.group(2)
        rest = re.sub(r"--mode[=\s]+\S+", " ", rest, flags=re.I)  # drop `--mode <m>`
        rest = re.sub(r"--[a-z0-9-]+", " ", rest, flags=re.I)      # drop bare flags (--list)
        tokens = [t for t in re.split(r"[\s\"'|>&;]+", rest)
                  if t and t.lower() not in _BELT_MODE_WORDS]
        return slug, (tokens[0] if tokens else None)
    m = re.search(r"\bwhois\s+([^\s|>&;]+)", command)
    if m:
        return "whois", m.group(1)
    return None, None


def extract_target(tool_name: str, tool_input: dict) -> str | None:
    """The concrete entity a tool call would INVESTIGATE, or None for non-targeted tools
    (search/recall/reasoning). Normalised for roster comparison."""
    name = (tool_name or "").rsplit("__", 1)[-1]  # strip mcp__server__ prefix
    ti = tool_input or {}
    if name == "Bash" or name.lower() == "bash":
        _, t = _belt_slug_and_target(str(ti.get("command", "")))
        return _norm(t) if t else None
    if name in _TARGETED_MCP:
        # Every targeted MCP tool's first-arg key. reverse_dns→ip_address, reverse_whois→
        # registrant were missing, so those slipped the gate (Codex follow-up #2).
        raw = (ti.get("target") or ti.get("url") or ti.get("domain") or ti.get("indicator")
               or ti.get("ip") or ti.get("ip_address") or ti.get("registrant")
               or ti.get("query") or "")
        return _norm(str(raw)) if raw else None
    return None


def is_enumeration(tool_name: str, tool_input: dict) -> bool:
    """True for tools that EXPAND the network from one entity (reverse-WHOIS / dns_history /
    the whoisxml belt). Always a lead on the bounded path — see _ENUMERATION_MCP."""
    name = (tool_name or "").rsplit("__", 1)[-1]
    if name in _ENUMERATION_MCP:
        return True
    if name == "Bash" or name.lower() == "bash":
        slug, _ = _belt_slug_and_target(str((tool_input or {}).get("command", "")))
        return slug in _ENUMERATION_BELT
    return False


def in_scope(target: str, roster: set[str]) -> bool:
    """True if `target` is in the case roster — directly, or as a subdomain of a roster
    domain (www./sub of an in-scope domain is still in scope)."""
    if not target:
        return True
    t = _norm(target)
    if t in roster:
        return True
    # subdomain of a roster domain → in scope (sub.evil.com when evil.com is in the case)
    for r in roster:
        if t.endswith("." + r) and "." in r:
            return True
    return False


def _search_query(tool_name: str, tool_input: dict) -> str | None:
    """The query text of a SEARCH/recall tool call, or None if it isn't one."""
    name = (tool_name or "").rsplit("__", 1)[-1]
    ti = tool_input or {}
    if name == "Bash" or name.lower() == "bash":
        m = re.search(r"osint-tool\s+(?:perplexity|exa|tavily|web_search)\s+(.+)",
                      str(ti.get("command", "")), re.I)
        return m.group(1) if m else None
    if name in _SEARCH_MCP:
        return str(ti.get("query") or ti.get("q") or "")
    return None


def _domains_in(text: str) -> list[str]:
    """Domains + IPv4s named in free text, normalised (for the search-enumeration check)."""
    out = [_norm(m.group(1)) for m in _DOMAIN_RE.finditer(text or "")]
    out += [_norm(m.group(0)) for m in _IPV4_RE.finditer(text or "")]
    return [d for d in out if d]


def _deny(target: str, search: bool = False) -> str:
    verb = "search for" if search else "investigate"
    return (f"out of scope: '{target}' is not in the case roster. Don't {verb} it — it's a "
            "LEAD; surface it in your findings and the analyst promotes it to expand it "
            "(RULE-112, one hop). 4_points gated network enumeration behind the analyst.")


def _deny_enumeration(target: str) -> str:
    return (f"network enumeration: reverse-WHOIS / DNS-history on '{target}' expands the case "
            f"to the operator's OTHER infrastructure. Don't run it — surface '{target}' and "
            "the pivot as a LEAD; the analyst promotes it to expand the network (RULE-112). "
            "4_points gated enumeration behind the analyst (ops-log [066]).")


def gate(tool_name: str, tool_input: dict, roster: set[str]) -> tuple[bool, str]:
    """Deterministic allow/deny.
    1. Entity-investigation tools (whois/dns/browser/jina/belt): their single target must be
       in the roster, else deny (→ lead).
    2. Search/recall (perplexity/exa/tavily/web_search): deny only when the query NAMES an
       OUT-OF-SCOPE entity — that's enumerating the network. Allow searches about in-scope
       entities or general topics (attribution). This is the 4_points line ([058] vs [066]).
    3. Everything else (reasoning / ToolSearch / internal): allow.

    Enumeration tools (reverse_whois / dns_history / whoisxml belt) are denied FIRST — they
    are a lead even on an in-roster entity, because their output is the network expansion."""
    if is_enumeration(tool_name, tool_input):
        return False, _deny_enumeration(extract_target(tool_name, tool_input) or "this entity")
    target = extract_target(tool_name, tool_input)
    if target is not None:
        if in_scope(target, roster):
            return True, ""
        return False, _deny(target)
    q = _search_query(tool_name, tool_input)
    if q is not None:
        outside = [d for d in _domains_in(q) if not in_scope(d, roster)]
        if outside:
            return False, _deny(outside[0], search=True)
        return True, ""
    return True, ""


def normalize_roster(names) -> set[str]:
    """Build the comparison roster from raw entity names."""
    return {_norm(str(n)) for n in (names or []) if n}
