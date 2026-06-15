"""The investigator agent — Claude in tool-using agent mode, driven by kipi.

This is the "investigator LLM powers" layer. It shells out to the `claude` CLI in
AGENT mode (the same binary llm/client.py uses for one-shot judgment, plus the
tool flags) with:
  - a senior-OSINT-analyst system prompt (provenance, mark-unvalidated, no fabrication),
  - a tool belt: kipi's adapters via `./invctl osint-tool` (Bash, read-only) + the
    project .mcp.json MCP servers (perplexity / apify / reddit) + WebFetch,
  - the case/entity context.

The agent investigates, then returns a JSON findings block. Findings land as
enrichment_results under an 'agent' run AND are auto-promoted into graph nodes
(land_findings(auto_promote=True)) — the agent builds the graph itself, no human
gate. promote_result self-filters to real indicators. The analyst is still the
authority: they REVIEW the graph after the fact and prune, rather than gating
every node up front. Caps: max_turns + timeout + a tight allowedTools list.
"""
from __future__ import annotations

import json
import logging
import os
import re as _re
import subprocess
import threading as _threading
from pathlib import Path

from investigations import identity_anchor, verify
from investigations.enrich.rel_vocab import normalize_rel, vocab_prompt_list
from investigations.llm.client import CLAUDE_BIN, ask
from investigations.storage import db

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
# Cost lever (audit 2026-06-03): the agent CLI was UNPINNED → inherited the claude
# default (Opus-tier). 4_points runs its swarm on Sonnet ("5x cheaper than Opus"); match
# it. Override per run/instance with KIPI_AGENT_MODEL (e.g. claude-opus-4-8 for a hard
# case, claude-haiku-4-5 for a cheap sweep).
AGENT_MODEL = os.environ.get("KIPI_AGENT_MODEL", "claude-sonnet-4-6")
# Opus discipline (founder 2026-06-03): never run Opus unless explicitly allowed. A stray
# "opus" model string is downgraded to Sonnet. OSINT doesn't need Opus; Sonnet/Haiku do it.
ALLOW_OPUS = os.environ.get("KIPI_ALLOW_OPUS", "") == "1"
CHEAP_MODEL = os.environ.get("KIPI_CHEAP_MODEL", "claude-haiku-4-5-20251001")


def _safe_model(model: str | None) -> str:
    """Resolve a model with the Opus guard: 'opus' → Sonnet unless KIPI_ALLOW_OPUS=1."""
    m = model or AGENT_MODEL
    if "opus" in m.lower() and not ALLOW_OPUS:
        return "claude-sonnet-4-6"
    return m


# Per-token price table — $ per 1 token (input, output), keyed by model family.
# Sourced via the claude-api skill (cached 2026-05-26), NOT memory: published rates are
# $/1M tokens → divide by 1e6. Used ONLY to ESTIMATE a STOPPED turn's spend (the SDK
# ResultMessage carries the exact cost on a natural finish; a Stop/turn-limit cut means no
# ResultMessage, so we estimate from accumulated token usage instead — never a null bill).
# Keyed by substring so date-suffixed IDs (claude-haiku-4-5-20251001) still match.
_MODEL_PRICES = {
    "fable-5":     (10.00 / 1_000_000, 50.00 / 1_000_000),
    "opus":        (5.00 / 1_000_000, 25.00 / 1_000_000),
    "sonnet-4-6":  (3.00 / 1_000_000, 15.00 / 1_000_000),
    "haiku-4-5":   (1.00 / 1_000_000, 5.00 / 1_000_000),
}
# Default rate when the model string matches nothing (the AGENT_MODEL default is Sonnet).
_DEFAULT_PRICE = _MODEL_PRICES["sonnet-4-6"]


def _price_for(model: str | None) -> tuple[float, float]:
    """(input_rate, output_rate) $/token for a model string, by substring match."""
    m = (model or AGENT_MODEL).lower()
    for key, rate in _MODEL_PRICES.items():
        if key in m:
            return rate
    return _DEFAULT_PRICE


def estimate_cost_usd(input_tokens: int, output_tokens: int,
                      model: str | None = None) -> float:
    """Estimate a turn's $ spend from token usage when the exact SDK cost is unavailable
    (a STOPPED / turn-limit-cut turn emits no ResultMessage). Cache tokens count as input
    at full rate here — a deliberate slight over-estimate so the shown number never
    under-promises the bill."""
    in_rate, out_rate = _price_for(model)
    return round(input_tokens * in_rate + output_tokens * out_rate, 4)


# GLOBAL agent cap (Codex/founder 2026-06-03): the crew fans each target to 4 sub-agents
# and the swarm runs N targets — without one shared limit that's N*4 parallel claude
# subprocesses (fd exhaustion, 429s, OOM). This semaphore bounds TOTAL concurrent agents
# across BOTH pools, so APIs can't be overwhelmed regardless of target count.
MAX_CONCURRENT_AGENTS = int(os.environ.get("KIPI_MAX_AGENTS", "4"))
_AGENT_SEM = _threading.Semaphore(MAX_CONCURRENT_AGENTS)
MCP_CONFIG = ROOT / ".mcp.json"
RUNTIME_MCP = ROOT / "investigations" / "agent" / ".mcp-runtime.json"


def _build_mcp_config() -> Path:
    """Merge the project .mcp.json (apify/perplexity/reddit) with kipi-osint, using
    this instance's ABSOLUTE venv path (a relative MCP command fails to launch).
    Regenerated per run so it's correct in any instance / checkout location."""
    cfg = {"mcpServers": {}}
    if MCP_CONFIG.exists():
        try:
            cfg = json.loads(MCP_CONFIG.read_text())
        except json.JSONDecodeError:
            cfg = {"mcpServers": {}}
    cfg.setdefault("mcpServers", {})
    cfg["mcpServers"]["kipi-osint"] = {
        "command": str(ROOT / ".venv" / "bin" / "python"),
        "args": ["-m", "investigations.agent.osint_mcp"],
        # claude may launch this server from ANY cwd; `-m investigations...` only
        # resolves when ROOT is importable. Pin it on PYTHONPATH + cwd so the server
        # starts (and its tools register) regardless of where claude spawns it.
        # Without this the server crashed with "No module named investigations" and
        # every mcp__kipi-osint__* call errored "No such tool available".
        "cwd": str(ROOT),
        "env": {"PYTHONPATH": str(ROOT)},
    }
    RUNTIME_MCP.write_text(json.dumps(cfg))
    return RUNTIME_MCP

# kipi-osint MCP tools — one per wrappable registry adapter (kept in lockstep with
# the registry by test_investigator_tools). The Bash wildcard below additionally
# covers EVERY provider (incl. apify) via `./invctl osint-tool`, so the full belt is
# reachable even when an MCP tool fails to register.
_KIPI_MCP_TOOLS = [
    "mcp__kipi-osint__enumerate_infra",
    "mcp__kipi-osint__crtsh_subdomains", "mcp__kipi-osint__typosquat",
    "mcp__kipi-osint__whois_lookup",
    "mcp__kipi-osint__dns_lookup", "mcp__kipi-osint__reverse_dns",
    "mcp__kipi-osint__virustotal",
    "mcp__kipi-osint__reverse_whois", "mcp__kipi-osint__dns_history",
    "mcp__kipi-osint__reverse_ns",
    "mcp__kipi-osint__shodan_host", "mcp__kipi-osint__censys_host",
    "mcp__kipi-osint__breach_intel",
    # IP reputation, scan-search, threat pulses, breach (PRD osint-providers-batch).
    "mcp__kipi-osint__abuseipdb", "mcp__kipi-osint__urlscan",
    "mcp__kipi-osint__otx", "mcp__kipi-osint__hibp",
    "mcp__kipi-osint__abusech", "mcp__kipi-osint__web_search",
    "mcp__kipi-osint__tavily_search", "mcp__kipi-osint__exa_search",
    "mcp__kipi-osint__jina_read",
    # Flowsint-inspired enrichers (native): email->profile, IP->geo/ASN, handle->presence,
    # wallet->tx. All keyless (wallet ETH self-guards on a key).
    "mcp__kipi-osint__gravatar", "mcp__kipi-osint__ipgeo",
    "mcp__kipi-osint__username_sweep", "mcp__kipi-osint__wallet_tx",
    # On-chain compliance + identity (PRD-1): sanctions oracle, ENS, wallet labels.
    "mcp__kipi-osint__ofac_screen", "mcp__kipi-osint__ens_resolve",
    "mcp__kipi-osint__wallet_labels",
    # On-chain value flow + multi-chain (PRD-2): ERC-20 token flow, Tron, Solana.
    "mcp__kipi-osint__wallet_tokens", "mcp__kipi-osint__tron_wallet",
    "mcp__kipi-osint__solana_wallet",
    # On-chain breadth + clustering (PRD-3): multi-chain, BTC cluster (T3 lead), TON.
    "mcp__kipi-osint__blockchair_tx", "mcp__kipi-osint__wallet_cluster",
    "mcp__kipi-osint__ton_tx",
    # Crypto + dark-web reputation / leads (PRD-4): T3 lead generators.
    "mcp__kipi-osint__crypto_abuse", "mcp__kipi-osint__darkweb_search",
    # Non-crypto primitives (PRD-5): ASN/netblock owner, phone intel, EXIF metadata.
    "mcp__kipi-osint__asn_lookup", "mcp__kipi-osint__phone_parse",
    "mcp__kipi-osint__exif_extract",
    # Existing-adapter hardening + keyed lookups (PRD-6): scanner, registry, git, holehe, deep-DNS.
    "mcp__kipi-osint__greynoise", "mcp__kipi-osint__opencorporates",
    "mcp__kipi-osint__git_emails", "mcp__kipi-osint__holehe",
    "mcp__kipi-osint__dns_deep",
    # Composite tool (not a 1:1 adapter): content-platform scrape via the apify adapter.
    "mcp__kipi-osint__social_scrape",
]

# Headless-browser tools (playwright MCP, keyless). The investigator NEEDS these for
# JS-rendered scam sites: WebFetch/jina only see the server HTML, but the payout wallet,
# contact, and content are injected by client-side JS (web3.js / walletconnect / NUXT).
# navigate→wait→snapshot/evaluate renders the DOM and pulls what static fetch can't.
# Excludes file_upload + run_code_unsafe (host-code exec) — page interaction only.
_PLAYWRIGHT_TOOLS = [
    "mcp__playwright__browser_navigate", "mcp__playwright__browser_navigate_back",
    "mcp__playwright__browser_snapshot", "mcp__playwright__browser_evaluate",
    "mcp__playwright__browser_take_screenshot", "mcp__playwright__browser_wait_for",
    "mcp__playwright__browser_network_requests", "mcp__playwright__browser_console_messages",
    "mcp__playwright__browser_click", "mcp__playwright__browser_type",
    "mcp__playwright__browser_press_key", "mcp__playwright__browser_hover",
    "mcp__playwright__browser_close",
]

# Read-only tool belt the agent is allowed to use. The Bash entry is scoped to the
# osint-tool subcommand only; no Write/Edit/arbitrary Bash.
ALLOWED_TOOLS = [
    *_KIPI_MCP_TOOLS,
    # The SAME belt via Bash — covers every registry provider reliably (this is the
    # dependable path; the MCP tools are a bonus). Plus page fetch.
    "Bash(./invctl osint-tool:*)",
    "WebFetch",
    *_PLAYWRIGHT_TOOLS,                       # render JS pages (the missing capability)
    # Live social / search MCPs from the project .mcp.json.
    "mcp__perplexity__perplexity_ask",
    # Apify: discover + run any actor, read async run output, and the twitter scraper.
    "mcp__apify__search-actors", "mcp__apify__call-actor", "mcp__apify__fetch-actor-details",
    "mcp__apify__get-actor-output", "mcp__apify__get-actor-run",
    "mcp__apify__curious_coder-slash-twitter-scraper",
    # Reddit (keyless): search + read posts/users/subreddits for a target's presence.
    "mcp__reddit__reddit_search", "mcp__reddit__reddit_get_user",
    "mcp__reddit__reddit_get_user_posts", "mcp__reddit__reddit_get_post",
    "mcp__reddit__reddit_get_subreddit_posts", "mcp__reddit__reddit_search_subreddit",
]


def _live_allowed_tools() -> list[str]:
    """ALLOWED_TOOLS minus the MCP tools whose provider has no key this run — so the
    agent can't even reach a dead tool to waste a turn on it. The Bash belt wildcard
    stays (its own 'not configured' guard is instant), and keyless / keyed-and-set
    providers are untouched. Re-evaluated per run (a freshly-added key re-enables)."""
    dead = _dead_slugs()
    if not dead:
        return list(ALLOWED_TOOLS)
    # social_scrape rides on the apify adapter — drop it too when apify has no key
    # (its name doesn't contain 'apify', so the generic filter would miss it).
    drop = set()
    if "apify" in dead:
        drop.update({"mcp__kipi-osint__social_scrape", "mcp__apify__search-actors",
                     "mcp__apify__call-actor", "mcp__apify__fetch-actor-details"})
    # C7: the whoisxml adapter backs three MCP tools whose names don't contain
    # 'whoisxml' (reverse_whois / dns_history / reverse_ns) — the generic substring
    # filter misses them.
    if "whoisxml" in dead:
        drop.update({"mcp__kipi-osint__reverse_whois", "mcp__kipi-osint__dns_history",
                     "mcp__kipi-osint__reverse_ns"})
    return [t for t in ALLOWED_TOOLS
            if t not in drop and not (t.startswith("mcp__") and any(d in t for d in dead))]


def _dead_slugs() -> set[str]:
    """Providers that need a key and don't have one — calling them only wastes
    agent turns on a 'not configured' error. Computed live (DB + env) per run."""
    from investigations.enrich import registry
    return {a.slug for a in registry.all_adapters()
            if a.env_var and not a.is_configured()}


# Web-RECALL tools (each call surfaces a different "documented" set → non-reproducible).
# Dropped from the infra-FIRST pass so enumeration comes from deterministic infra;
# re-enabled on the later attribution pass (G-INFRA-FIRST).
_WEB_RECALL_MCP = {"mcp__kipi-osint__web_search", "mcp__kipi-osint__tavily_search",
                   "mcp__kipi-osint__exa_search", "mcp__perplexity__perplexity_ask"}
# Infra adapter slugs the pass-0 belt is narrowed to (replaces the `osint-tool:*` wildcard
# so `./invctl osint-tool perplexity` can't run during the infra-only pass — Codex).
_INFRA_BELT_PATTERNS = [f"Bash(./invctl osint-tool {s}:*)" for s in
                        ("crtsh", "typosquat", "whois", "dns", "reverse_dns", "virustotal",
                         "abusech", "whoisxml", "infra", "breach")]
# Pass-0 NON-infra tools to drop: web recall, the full belt wildcard, arbitrary page
# fetch, paid scraping (apify), and reddit/web search.
_NON_INFRA_PASS0 = _WEB_RECALL_MCP | {
    "WebFetch", "Bash(./invctl osint-tool:*)", "mcp__kipi-osint__social_scrape",
    "mcp__apify__search-actors", "mcp__apify__call-actor", "mcp__apify__fetch-actor-details",
    "mcp__apify__get-actor-output", "mcp__apify__get-actor-run",
    "mcp__apify__curious_coder-slash-twitter-scraper",
    "mcp__reddit__reddit_search", "mcp__reddit__reddit_get_user",
    "mcp__reddit__reddit_get_user_posts", "mcp__reddit__reddit_get_post",
    "mcp__reddit__reddit_get_subreddit_posts", "mcp__reddit__reddit_search_subreddit"}


def _infra_first_allowlist(tools: list[str]) -> list[str]:
    """Pass-0 INFRA-ONLY allowlist: drop web-recall + scrape + arbitrary fetch, AND
    replace the full belt wildcard with explicit infra-slug belt patterns, so the agent
    truly cannot web-search (even via `./invctl osint-tool perplexity`) before it has
    enumerated the cluster with deterministic infra. Web/scrape return on later passes."""
    kept = [t for t in tools if t not in _NON_INFRA_PASS0]
    if "Bash(./invctl osint-tool:*)" in tools:
        kept += _INFRA_BELT_PATTERNS
    return kept


def _belt_text() -> str:
    """The provider list the agent is told to use — ONLY the ones that are actually
    live (keyless, or a key is set). Unconfigured providers are omitted so the agent
    never burns turns discovering a missing key by trial. Generated from the registry
    so it tracks the real adapter set, and re-evaluated per run so a freshly-added
    key shows up without a restart."""
    from investigations.enrich import registry
    dead = _dead_slugs()
    lines, skipped = [], []
    for a in registry.all_adapters():
        if a.slug in dead:
            skipped.append(a.slug)
            continue
        keyed = " (keyless)" if not a.env_var else " (key set)"
        lines.append(f"- `./invctl osint-tool {a.slug} <query>` — {a.display_name}{keyed}")
    if skipped:
        # Surface what was dropped (no silent caps) so the agent doesn't try them.
        lines.append(f"\nNOT available this run (no key — do NOT call): {', '.join(skipped)}.")
    return "\n".join(lines)


def _build_persona() -> str:
    return """You are a Senior Staff Investigator in Security, Safety & Fraud at a
FAANG-tier company, running inside an automated pipeline. You investigate ONE target
end-to-end and report evidence-grade findings.

MANDATE — apply the FULL belt. Do NOT stop after one lookup. For the target's type,
run EVERY applicable tool below, then corroborate across at least two independent
sources before calling anything confirmed. A thin investigation that skipped
available tools is a FAILURE, not a result.

PLAYBOOK BY TARGET TYPE (run all that apply):
- domain            -> crtsh (subdomains) + typosquat (lookalike phishing domains; only
                       LIVE/resolving candidates promote, unconfirmed stay header-only leads)
                       + whois + dns (infra)
                       + virustotal + abusech (reputation/IOC) + urlscan (scans urlscan
                       already has: its related domains/IPs) + otx (threat pulses + passive
                       DNS) + hibp (breaches recorded against the site) + web_search/tavily/exa
                       (who runs it) + jina (read its key page). If DNS is DEAD/empty,
                       pull `whoisxml --mode dns_history` for its HISTORICAL IPs — a dead
                       seed still has a past, and its old IP is the link to the cluster.
                       dns_deep (SPF/DMARC posture + mail provider + AXFR attempt) hardens
                       the infra pivot — a shared mail provider / open AXFR is a finding.
- ip                -> reverse_dns + whois (infra) + ipgeo (geo + ASN: who owns the
                       netblock) + abuseipdb (IP reputation / abuse reports) + urlscan
                       (pages served here) + otx (pulses + passive DNS) + virustotal
                       + abusech + web_search.
- url / page        -> jina/WebFetch for a cheap first read + virustotal. But on a
                       SCAM / PAYMENT / JS-heavy page, the BROWSER is a PRIMARY move,
                       NOT a last resort: browser_navigate -> browser_wait_for, then
                       browser_network_requests (the XHR/fetch + script.js calls carry
                       the payout wallet, payment API, and affiliate endpoints — this is
                       the 4_points script.js depth) AND browser_evaluate (pull the
                       JS-injected DOM: wallet, contacts, linked sites). On these pages
                       static fetch alone misses everything that matters — reach for
                       network_requests + evaluate early, don't wait for jina to fail.
- handle / person / org -> web_search + tavily + exa (identity, footprint) + apify
                       (social profiles/posts) + reddit (presence) + opencorporates (officers
                       / filings / jurisdiction — T1 registry for an org/person) + git_emails
                       (commit-author emails from a public repo/handle — corroborates a
                       scraped email; alone a hypothesis) + darkweb_search (Ahmia .onion
                       leads — T3, hypothesis not finding; hacktivist/leak cases).
- content platform (a tiktok / youtube / twitter-x / instagram URL or @handle)
                    -> social_scrape (pulls the profile + recent posts + transcript via
                       the right scraper). Content platforms are the RICHEST source on a
                       creator/operator — pull the actual content, don't just note the link.
- wallet / hash     -> wallet (BTC keyless / ETH key: balance + tx COUNTERPARTIES — each
                       counterparty address is a promotable pivot, "drains_to") +
                       wallet_tokens (ERC-20 token flow: USDT/USDC counterparties, symbol on
                       the edge) + tron_wallet (Tron/TRC-20 — the USDT pig-butchering rail) +
                       solana_wallet (Solana/SPL — rug/drainer surface) +
                       blockchair_tx (LTC/BCH/DOGE + other UTXO chains) +
                       ton_tx (TON EQ/UQ addresses) + wallet_cluster (which exchange owns a
                       BTC address = subpoena target; T3 LEAD only, hypothesis not finding) +
                       ofac_screen (OFAC sanctions oracle, T1 — a hit is a confirmed
                       compliance finding) + ens_resolve (name<->address crosslink, T1) +
                       wallet_labels (exchange/mixer/phish — T3 TAG only, NEVER a finding) +
                       crypto_abuse (scam blocklist — T3 LEAD, hypothesis not finding) +
                       virustotal + abusech (known-bad) + web_search (attribution).
- ip                -> asn_lookup (ASN / netblock owner — a shared ASN/org = shared or
                       bulletproof hosting, the infra pivot) + greynoise (scanner-vs-targeted:
                       benign-scanner / malicious-noise / unseen) + reverse_dns + reputation.
- phone             -> phone_parse (region / carrier / line-type incl. VoIP, a fraud signal).
- image / file      -> exif_extract (GPS coordinates + device make/model/serial from EXIF).
- email             -> gravatar (profile + the owner's LINKED social accounts — pivots) +
                       breach_intel (stealer/breach exposure) + hibp (which account breaches
                       it appears in) + holehe (which of ~120 sites it registered on — T3
                       HYPOTHESIS leads, corroborate before findings) + web_search.
- email (registrant) -> `whoisxml --mode reverse_whois` (EVERY other domain that email
                       registered = the operator's full portfolio) + web_search.
- handle / username -> username (presence sweep: which platforms the handle exists on —
                       each found profile is a pivot) + web_search + apify (read content).

TOOLS — the full belt. Invoke via the `mcp__kipi-osint__*` tool if it's available,
OR the Bash form (the dependable path, covers every provider):
""" + _belt_text() + """
Plus: WebFetch to read a page; the perplexity / apify / reddit MCP tools for live
search + social scraping when available.

RULES (non-negotiable):
- Run the applicable tools BEFORE concluding. Exhaust the belt for the target type.
- Cite the tool + value behind every claim in `provenance`.
- CORROBORATE: a finding is only "confirmed" if 2+ independent tools surfaced it.
  Single-source findings are fine — mark confidence honestly (medium/low). A finding
  no tool's RESULT actually contains will NOT enter the graph, so cite real results.
- Mark anything you did NOT directly observe from a tool as unvalidated=true.
- BUILD THE STORY, not just a fact list. Whenever you find that two entities relate
  (X hosts Y, A operates B, this handle = that email, this wallet pays that one),
  emit it in `relationships` (or `same_as` for one real-world actor behind multiple
  handles). The relationship IS the deliverable — don't leave it implicit in prose.
  `same_as` IS ONLY for aliases of ONE actor — the same human/handle under multiple
  names/emails. NEVER `same_as` a person to an ORG / company / brand (registrant name vs
  registrant org on a WHOIS record are NOT the same entity) — that's `registered_as` /
  `operates`. A person and the company they sign up under are two nodes, not one.
  MATERIALIZE THE SHARED THING AS A NODE — never a vague link between two domains. When
  two+ entities share an attribute, the shared attribute is its OWN entity that each
  connects to, so the analyst can SEE and pivot on it:
    • shared registrant → emit the registrant as an entity; each domain `registered_by` it.
    • shared backend/platform/kit → emit the platform (e.g. "Mammoth Platform") as an
      entity; each site `runs_on` it.
    • shared IP / PoP / host → emit that infra as an entity; each domain `hosted_on` /
      `routes_through` it.
  Do NOT emit a bare `same_campaign` / `same_registrant` / `same_platform` edge between the
  two domains — that hides the pivot. Name the shared entity and connect each to it.
  DON'T GUESS THE CONCLUSION — emit the OBSERVABLE. A shared registration date is
  `registered_same_day`, NOT `same_operator`; shared theme is `same_theme`, not a shared
  actor. Only assert `same_operator`/`operated_by` with HARD evidence (shared registrant
  account, login, wallet, or the operator named in a source). The label is what you SAW.
- A tool failing / 'not configured' / empty is itself a finding — report it, pivot,
  never invent. Never fabricate addresses, names, or links.
- WEIGH DECEPTION: registrant whois, self-reported bios, and shared-CDN IPs are trivially
  faked. Don't treat them as ground truth; corroborate with sources the actor can't edit.
- WEB SEARCH IS FOR ATTRIBUTION, NOT ENUMERATION: perplexity/web_search/tavily/exa tell
  you WHO is behind something and WHETHER it's been reported — they do NOT authoritatively
  list a cluster's domains (they recall a different set each run). A domain/IP you only
  saw in web search is a LEAD: confirm it with an infra tool (crt.sh / DNS / WHOIS /
  reverse-WHOIS / passive-DNS) before treating it as a cluster member. Cluster membership
  comes from SHARED INFRA (same registrant, dedicated IP, cert), not from being named in
  the same article.
- CONSIDER ALTERNATIVES: for each high/medium finding, ask what BENIGN or different
  explanation could fit, and only conclude if the evidence rules it out.
- RECORD NEGATIVES: when you check something and find nothing, say so in `negatives` —
  "cleared" is intel. It stops the next analyst re-running the same dead pivot.
- ALWAYS GUIDE THE ANALYST (non-optional): every run MUST fill `recommended_pivots`
  (the single best next thing to investigate, and why — even if it's "no further leads,
  this target is exhausted") and `assessment.collection_gaps` (what you could NOT confirm
  and what tool/data would close it). The analyst depends on your "look here next" and
  "here's the gap" — never leave these empty.

OUTPUT
When done, output EXACTLY ONE JSON object as the final message and nothing after it:
{
 "findings":[{"entity":"<value>","entity_type":"<domain|ip|subdomain|email|handle|wallet|org|person|other>","claim":"<what you found, one line>","confidence":"high|medium|low","provenance":"<tool: value>","unvalidated":<true|false>}],
 "relationships":[{"src":"<entity value>","dst":"<entity value>","rel_type":"<pick EXACTLY ONE of: __REL_ENUM__ — if none fits use linked_to>","direction":"src_to_dst","confidence":"high|medium|low","provenance":"<tool: value>"}],
 "same_as":[{"entity_a":"<value>","entity_b":"<value>","confidence":"high|medium|low","provenance":"<why they are the same actor>"}],
 "negatives":[{"checked":"<what you looked for>","tool":"<tool used>","result":"no hit / cleared"}],
 "recommended_pivots":[{"entity":"<the single best next target>","why":"<what it would confirm>"}],
 "assessment":{"attributed_actor":"<who/what is behind this, or 'unknown'>","best_judgment":"<one-line bottom line>","overall_confidence":"high|medium|low","collection_gaps":"<what you could not confirm and why>"},
 "summary":"<2-3 line wrap>"
}
""".replace("__REL_ENUM__", vocab_prompt_list())


PERSONA = _build_persona()


def _ensure_agent_provider(conn) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO osint_providers (slug, display_name, category, env_var, "
        "description, cost_estimate_usd) VALUES ('agent','Investigator agent','agent',NULL,"
        "'Autonomous OSINT agent (claude in tool mode)',0.0)")


def _agent_key_env() -> dict:
    """Every provider key the analyst set (DB-first via resolve_key) mapped to its env
    var name, so the agent's child process — including the EXTERNAL apify/perplexity
    MCP servers in .mcp.json, which read env vars and NOT the kipi DB — sees the
    UI-entered keys. Makes the UI the single source of truth for keys. Local only:
    these are injected into the subprocess env, nothing leaves the box."""
    out: dict[str, str] = {}
    try:
        from investigations.enrich.registry import all_adapters
        from investigations.enrich.base import resolve_key
        for a in all_adapters():
            if not a.env_var:
                continue
            key = resolve_key(a.slug, a.env_var)
            if key:
                out[a.env_var] = key
    except Exception:
        pass
    # The apify MCP server (.mcp.json) reads APIFY_TOKEN; the kipi adapter uses
    # APIFY_API_TOKEN. Alias so the one key satisfies both names.
    if out.get("APIFY_API_TOKEN") and "APIFY_TOKEN" not in out:
        out["APIFY_TOKEN"] = out["APIFY_API_TOKEN"]
    elif out.get("APIFY_TOKEN") and "APIFY_API_TOKEN" not in out:
        out["APIFY_API_TOKEN"] = out["APIFY_TOKEN"]
    return out


def warm_run_available() -> bool:
    """Warm-session seam (4pa-01). True when KIPI_WARM_SESSION is on. 4pa-02 wires
    the webapp run loop to dispatch a warm turn (warm_session.run_turn_warm) over a
    per-case ClaudeSDKClient that boots MCP once, instead of the cold _run_agent
    subprocess below. Cold `claude -p` stays the default until the 4pa-05 A/B flip."""
    from investigations.agent.warm_session import warm_session_enabled
    return warm_session_enabled()


def _run_agent_warm(task: str, case: str | None, timeout: int | None = None,
                    cancel=None) -> dict:
    """Warm-path counterpart to _run_agent: run ONE analyst turn over the per-case
    warm ClaudeSDKClient (MCP booted once, 4pa-00/4pa-01) and adapt the result to
    the SAME shape _run_agent returns, so the shared landing pipeline (parse →
    salvage → attribute → build_process → land_findings) is byte-for-byte unchanged.

    Runs on the PERSISTENT warm loop (run_turn_on_warm_loop), never asyncio.run —
    asyncio.run-per-turn would close the loop and orphan the warm client (cold).
    NO wall-clock deadline by default (founder: "no more deadlines" — a timer cut real
    digs; the surviving twin of the removed --max-turns leash). The run is bounded by the
    warm tool BUDGET (KIPI_WARM_TOOL_BUDGET, a PreToolUse circuit-breaker) + the max-turns
    backstop instead. KIPI_WARM_TURN_TIMEOUT can re-impose a wall-clock if set. `cancel`
    (Stop) still interrupts cooperatively. The warm turn streams a step trail and returns it
    (+capped) so investigate_entity salvages partial findings on a cutoff — no work lost."""
    if timeout is None:
        _env_to = os.environ.get("KIPI_WARM_TURN_TIMEOUT", "").strip()
        timeout = int(_env_to) if _env_to else None
    from investigations.agent.warm_session import run_turn_on_warm_loop
    try:
        warm = run_turn_on_warm_loop(case or "default", task,
                                     timeout=timeout, cancel=cancel)
    except TimeoutError:
        return {"ok": False, "error": f"warm turn timeout after {timeout}s"}
    except Exception as exc:
        return {"ok": False, "error": f"warm session failed: {exc}"}
    if not warm.get("ok"):
        return {"ok": False, "error": warm.get("error") or "warm run failed"}
    # A cutoff that produced NOTHING (no text, no steps — e.g. an MCP/model startup
    # stall) is a timeout failure, not a successful empty run — parity with cold
    # (which returns an error when a timeout yields no events). Codex review.
    if warm.get("capped") and not (warm.get("steps") or (warm.get("result_text") or "").strip()):
        return {"ok": False, "error": f"warm turn timeout after {timeout}s (no output)"}
    # Carry the step trail + capped flag so the shared salvage reconstructs findings
    # on a cutoff — parity with the cold path (no work lost). `raw` now mirrors the cold
    # ResultMessage shape (num_turns/total_cost_usd) so _build_process records real cost +
    # turns instead of NULLs — the warm path is no longer cost-blind.
    raw = {"num_turns": warm.get("turns"), "total_cost_usd": warm.get("cost_usd")}
    return {"ok": True, "result_text": warm.get("result_text") or "", "raw": raw,
            "events": [], "steps": warm.get("steps") or [],
            "capped": bool(warm.get("capped")), "cancelled": False,
            "stderr_tail": "", "returncode": 0,
            "started_at": warm.get("started_at"), "finished_at": warm.get("finished_at"),
            "elapsed_s": warm.get("elapsed_s")}


_SCOPE_MATCHER = ("Bash|whois_lookup|dns_lookup|reverse_dns|virustotal|crtsh|typosquat|abusech|"
                  "shodan|censys|breach|browser_navigate|reverse_whois|dns_history|"
                  "reverse_ns|"
                  "jina_read|social_scrape|web_search|exa_search|tavily_search|perplexity_ask")


def _build_guard_settings(roster: list, tool_budget: int | None = None) -> tuple[str, str, str | None]:
    """Write the case roster + a PreToolUse-hook settings file to temp; return
    (settings_path, roster_path, budget_path). Two deterministic guards:
      - scope_hook.py (RULE-112): denies investigating any target not in the roster — matcher
        covers the entity-investigation tools only; recall/reasoning never trigger it.
      - budget_hook.py (RULE-114): charges every tool call against `tool_budget` and denies
        once the cap is exceeded — matcher is `.*` (count EVERY call). Only when tool_budget
        is given; budget_path is None otherwise."""
    import tempfile as _tf
    rfd, roster_path = _tf.mkstemp(prefix="kipi_scope_roster_", suffix=".txt")
    with os.fdopen(rfd, "w") as f:
        f.write("\n".join(str(n) for n in roster if n))
    scope_py = os.path.join(str(ROOT), "investigations", "agent", "scope_hook.py")
    pretooluse = [{"matcher": _SCOPE_MATCHER,
                   "hooks": [{"type": "command", "command": f"python3 {scope_py}"}]}]
    budget_path = None
    if tool_budget and tool_budget > 0:
        from investigations.agent import budget as _budget
        bfd, budget_path = _tf.mkstemp(prefix="kipi_tool_budget_", suffix=".json")
        os.close(bfd)
        _budget.write_budget(budget_path, tool_budget)
        budget_py = os.path.join(str(ROOT), "investigations", "agent", "budget_hook.py")
        pretooluse.append({"matcher": ".*",
                           "hooks": [{"type": "command", "command": f"python3 {budget_py}"}]})
    settings = {"hooks": {"PreToolUse": pretooluse}}
    sfd, settings_path = _tf.mkstemp(prefix="kipi_scope_settings_", suffix=".json")
    with os.fdopen(sfd, "w") as f:
        json.dump(settings, f)
    return settings_path, roster_path, budget_path


def _build_scope_settings(roster: list) -> tuple[str, str]:
    """Back-compat shim (scope hook only). _build_guard_settings is the full builder."""
    settings_path, roster_path, _ = _build_guard_settings(roster, tool_budget=None)
    return settings_path, roster_path


def _build_budget_settings(tool_budget: int) -> tuple[str, str]:
    """Write a settings file wiring ONLY the RULE-114 budget hook (no scope cage), plus the
    budget file it reads. Return (settings_path, budget_path). This is what lets a DEEP /
    unbounded warm run still carry a tool-call circuit-breaker — the warm agent loads no repo
    hooks (setting_sources=[]), so the breaker must be injected through `settings=`."""
    import tempfile as _tf
    from investigations.agent import budget as _budget
    bfd, budget_path = _tf.mkstemp(prefix="kipi_tool_budget_", suffix=".json")
    os.close(bfd)
    _budget.write_budget(budget_path, tool_budget)
    budget_py = os.path.join(str(ROOT), "investigations", "agent", "budget_hook.py")
    settings = {"hooks": {"PreToolUse": [
        {"matcher": ".*", "hooks": [{"type": "command", "command": f"python3 {budget_py}"}]}]}}
    sfd, settings_path = _tf.mkstemp(prefix="kipi_budget_settings_", suffix=".json")
    with os.fdopen(sfd, "w") as f:
        json.dump(settings, f)
    return settings_path, budget_path


def _run_agent(task: str, max_turns: int = 28, timeout: int = 600,
               use_mcp: bool = True, on_event=None, persona: str | None = None,
               cancel=None, allowed_tools: list | None = None,
               model: str | None = None, scope_roster: list | None = None,
               tool_budget: int | None = None) -> dict:
    """Invoke claude in agent mode with STREAM-JSON output so we capture the
    agent's real moves (each tool call + its result), not just the final text.

    Reads the JSONL stream line-by-line as the agent works. When `on_event` is
    given, each move is formatted to a short human line and pushed to it LIVE
    (tool call → result, reasoning) so a UI can show what the agent is doing
    right now instead of a blind spinner.

    Returns {ok, result_text, raw, events, steps, capped, error}."""
    cmd = [CLAUDE_BIN, "-p", task, "--output-format", "stream-json", "--verbose",
           "--model", _safe_model(model),
           # Built fresh per run so the belt reflects which keys are set RIGHT NOW
           # (dead providers omitted → no turns wasted discovering missing keys).
           # persona defaults to the per-target investigator; case runs pass CASE_PERSONA.
           "--append-system-prompt", persona or _build_persona(),
           "--permission-mode", "bypassPermissions",
           # NO turn leash (founder 2026-06-03): a `--max-turns` cap was cutting the agent
           # off BEFORE it wrote its findings → nothing kept. The timeout below is the only
           # safety; the agent runs until it's actually done and emits its findings JSON.
           "--allowedTools", *(allowed_tools if allowed_tools is not None else _live_allowed_tools()),
           "--disallowedTools", "Write", "Edit", "NotebookEdit"]
    if use_mcp:
        # --strict-mcp-config: use ONLY our config (kipi-osint + headless playwright). Do
        # NOT inherit the user's global plugin MCPs — chrome-devtools-mcp launches a
        # VISIBLE Chrome window and dumps huge DOM/network blobs (token cost). This keeps
        # the agent's browser headless and its tool surface deterministic.
        cmd += ["--mcp-config", str(_build_mcp_config()), "--strict-mcp-config"]
    # Inject the analyst's UI-set keys (DB-first) so EVERY tool path the agent uses —
    # the kipi belt, the kipi-osint MCP, AND the external apify/perplexity MCP servers
    # — sees the same keys. The UI is the single source of truth.
    env = {**os.environ, **_agent_key_env()}
    # RULE-112 scope bound (leads-first, deterministic): a PreToolUse hook denies the agent
    # from INVESTIGATING any target not already in the case roster — newly-surfaced entities
    # land as leads for the analyst, not autonomous chases. Only when a roster is given
    # (bounded case runs); deep runs pass scope_roster=None → no bound (chase freely).
    if scope_roster:
        settings_path, roster_path, budget_path = _build_guard_settings(scope_roster, tool_budget=tool_budget)
        cmd += ["--settings", settings_path]
        env["KIPI_SCOPE_ROSTER"] = roster_path
        # RULE-114 in-flight bound: cap THIS run's tool calls (a circuit-breaker for a pass
        # that loops without finishing — the between-pass cost cap can't see inside a pass).
        if budget_path:
            env["KIPI_BUDGET_FILE"] = budget_path
    # Hold a global slot for the lifetime of THIS subprocess. With the crew fanning each
    # target to 4 sub-agents and the swarm running N targets, this is the one place that
    # caps TOTAL concurrent claude processes → APIs can't be flooded (Codex 2026-06-03).
    _AGENT_SEM.acquire()
    _released = {"v": False}

    def _release_slot():
        if not _released["v"]:
            _released["v"] = True
            _AGENT_SEM.release()

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                                bufsize=1, env=env)
    except Exception as exc:
        _release_slot()
        return {"ok": False, "error": f"agent launch failed: {exc}"}
    # Popen has no built-in timeout for streaming reads — a watchdog kills the
    # process after `timeout`s; the read loop then ends as stdout closes.
    timed_out = {"hit": False}

    def _kill_on_timeout():
        timed_out["hit"] = True
        try:
            proc.kill()
        except Exception:
            pass

    watchdog = _threading.Timer(timeout, _kill_on_timeout)
    watchdog.start()
    # Cancel watch: the analyst hit Stop. `cancel` is a threading.Event — when set,
    # kill the agent so we salvage whatever it emitted so far (same path as a cap).
    poll_done = {"v": False}

    def _cancel_watch():
        while not poll_done["v"]:
            if cancel.wait(0.5):   # set → analyst stopped the run
                try:
                    proc.kill()
                except Exception:
                    pass
                return

    if cancel is not None:
        _threading.Thread(target=_cancel_watch, daemon=True).start()
    # stream-json emits one JSON event per line (JSONL): system/init, assistant
    # turns (text + tool_use), user turns (tool_result), and a final 'result'.
    # `pending` joins a live tool_result back to the tool call that produced it.
    events = []
    pending: dict[str, str] = {}
    counter = {"n": 0}
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(evt)
            if on_event:
                for human in _live_lines(evt, pending, counter):
                    try:
                        on_event(human)
                    except Exception:
                        pass
    finally:
        watchdog.cancel()
        poll_done["v"] = True
        _release_slot()   # free the global slot the moment this agent's stream ends
    proc.wait()
    cancelled = cancel is not None and cancel.is_set()
    stderr = proc.stderr.read() if proc.stderr else ""
    if timed_out["hit"] and not events:
        return {"ok": False, "error": f"agent timeout after {timeout}s"}
    if cancelled and not events:
        # Stopped before the agent produced anything usable.
        return {"ok": False, "error": "stopped by analyst", "cancelled": True}
    result_evt = next((e for e in reversed(events)
                       if isinstance(e, dict) and e.get("type") == "result"), {})
    text = result_evt.get("result") or ""
    if not text:
        # Capped at --max-turns / timed out: no final 'result' text. Salvage the
        # last thing the agent said so partial findings still parse.
        text = _last_assistant_text(events)
    steps = _extract_steps(events)
    # claude returns rc=1 when it hits --max-turns; that's fine as long as we got
    # SOMETHING usable (text or at least a step trail). Only fail on a true blank.
    if proc.returncode != 0 and not text.strip() and not steps:
        reason = f"agent timeout after {timeout}s" if timed_out["hit"] else \
                 f"agent rc={proc.returncode}: {(stderr or '')[:400] or 'no output'}"
        return {"ok": False, "error": reason}
    # Cost = the REAL number the agent reports in its final 'result' event (or None if it
    # never finished). No fabricated estimate — the Anthropic console is the source of truth.
    return {"ok": True, "result_text": text, "raw": result_evt, "events": events,
            "steps": steps, "capped": proc.returncode != 0, "cancelled": cancelled,
            # Kept even on a "successful" run so an empty result (no steps) is diagnosable
            # instead of silently swallowed — the agent's stderr is the only clue when it
            # launched but never executed a tool (MCP/tool-server stall, startup kill).
            "stderr_tail": (stderr or "")[-1500:], "returncode": proc.returncode}


def _live_lines(evt: dict, pending: dict, counter: dict) -> list[str]:
    """Format one stream event into short human lines for the live activity feed.
    Mirrors `_extract_steps`: tool_use → '[3] dns_lookup example_channel.com', its result →
    '    ↳ 3 A records', assistant text → '[4] reasoning: …'. Same numbering the
    final step trail uses, so the live feed and the saved trail line up."""
    if not isinstance(evt, dict):
        return []
    out: list[str] = []
    t = evt.get("type")
    content = (evt.get("message") or {}).get("content") or []
    if t == "assistant":
        for c in content:
            if not isinstance(c, dict):
                continue
            if c.get("type") == "text":
                txt = (c.get("text") or "").strip()
                if txt:
                    counter["n"] += 1
                    out.append(f"[{counter['n']}] reasoning: {txt[:140]}")
            elif c.get("type") == "tool_use":
                counter["n"] += 1
                tool = _short_tool(c.get("name"))
                inp = _short_input(c.get("input"))
                out.append(f"[{counter['n']}] {tool} {inp}".rstrip())
                tid = c.get("id")
                if tid:
                    pending[tid] = tool
    elif t == "user":
        for c in content:
            if isinstance(c, dict) and c.get("type") == "tool_result":
                res = _short_result(c.get("content"))
                if res:
                    out.append(f"    ↳ {res[:160]}")
    return out


def _last_assistant_text(events: list) -> str:
    """Concatenate the text blocks from the last assistant turn — the salvage path
    when the run was capped before emitting a final 'result' event."""
    for e in reversed(events):
        if not isinstance(e, dict) or e.get("type") != "assistant":
            continue
        parts = [c.get("text", "") for c in (e.get("message", {}).get("content") or [])
                 if isinstance(c, dict) and c.get("type") == "text"]
        joined = "".join(parts).strip()
        if joined:
            return joined
    return ""


def _short_tool(name: str | None) -> str:
    """'mcp__kipi-osint__dns_lookup' -> 'dns_lookup'; 'WebFetch' -> 'WebFetch'."""
    name = name or ""
    if "__" in name:
        name = name.split("__")[-1]
    return name[:40]


_INPUT_KEYS = ("query", "domain", "ip", "url", "handle", "q", "name", "value", "command")


def _short_input(inp) -> str:
    """A compact one-line label for a tool call's input (the salient value)."""
    if isinstance(inp, dict):
        parts = []
        for k, v in inp.items():
            vs = str(v)
            if len(vs) > 160:
                continue
            parts.append(vs if k in _INPUT_KEYS else f"{k}={vs}")
        joined = " ".join(parts)[:200]
        return joined or json.dumps(inp, ensure_ascii=False)[:200]
    return str(inp)[:200]


def _flatten_result(content) -> str:
    """Flatten a tool_result's content (string or [{type:text,text}]) to one line."""
    txt = ""
    if isinstance(content, str):
        txt = content
    elif isinstance(content, list):
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                txt += c.get("text") or ""
            elif isinstance(c, str):
                txt += c
    else:
        txt = str(content or "")
    return " ".join(txt.split())


# Stored on each tool step for DISPLAY (the run trail). The longer `result_full`
# (used only for corroboration, then dropped before persistence) lives in _extract_steps.
_RESULT_PREVIEW_CHARS = 600       # 600 (not 300): a real 2nd source often mentions the entity past 300
_RESULT_VERIFY_CHARS = 4000       # corroboration sees more — a claimed date/IP often sits past char 600


def _short_result(content) -> str:
    """Short one-line preview of a tool_result for the run trail."""
    return _flatten_result(content)[:_RESULT_PREVIEW_CHARS]


def _extract_steps(events: list) -> list[dict]:
    """The agent's real moves, in order. Each tool_use is a step (tool + input,
    later joined to its result by tool_use_id); each assistant text block is a
    'reasoning' step. This is captured from the stream, not invented."""
    steps: list[dict] = []
    pending: dict[str, dict] = {}
    n = 0
    for e in events:
        if not isinstance(e, dict):
            continue
        t = e.get("type")
        content = (e.get("message") or {}).get("content") or []
        if t == "assistant":
            for c in content:
                if not isinstance(c, dict):
                    continue
                if c.get("type") == "text":
                    txt = (c.get("text") or "").strip()
                    if txt:
                        n += 1
                        steps.append({"n": n, "type": "reasoning", "text": txt[:600]})
                elif c.get("type") == "tool_use":
                    n += 1
                    step = {"n": n, "type": "tool",
                            "tool": _short_tool(c.get("name")),
                            "raw_tool": c.get("name"),
                            "input": _short_input(c.get("input")),
                            "result": None}
                    steps.append(step)
                    tid = c.get("id")
                    if tid:
                        pending[tid] = step
        elif t == "user":
            for c in content:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    step = pending.get(c.get("tool_use_id"))
                    if step is not None:
                        full = _flatten_result(c.get("content"))
                        step["result"] = full[:_RESULT_PREVIEW_CHARS]      # stored (display)
                        # result_full: corroboration sees more of the tool output, so a fact
                        # past char 600 isn't over-gated. Dropped in _attribute_findings before
                        # the steps are persisted — never bloats agent_process.
                        step["result_full"] = full[:_RESULT_VERIFY_CHARS]
    return steps


# Claim-faithfulness primitives live in the shared `verify` module (also used by ask +
# consolidate). `_claim_hard_tokens` is the local name used throughout this file (replay D5:
# a finding claimed "registered 2025-12-22 via whois_lookup" but NO whois result had the
# date — it came from dns_history). Near-zero false-positive: ISO date, IPv4, email, ETH
# wallet. Soft claims ("impersonation") have no hard token → fall back to entity-corroboration.
_claim_hard_tokens = verify.hard_tokens


def _verify_text(step: dict) -> str:
    """Tool-result text used for corroboration: the fuller `result_full` when present (set
    in _extract_steps, dropped before persistence) else the stored short preview. Lets a
    claimed fact past char 600 still be verified instead of over-gated."""
    return str(step.get("result_full") or step.get("result") or "")


def _value_observed_in_steps(val: str, tool_steps: list[dict]) -> bool:
    """True if this value appears in some tool RESULT (a tool actually observed it), not
    merely in the agent's text. <4 chars → can't check safely → True (don't block)."""
    v = (val or "").strip().lower()
    if len(v) < 4:
        return True
    return any(v in _verify_text(s).lower() for s in tool_steps)


def _attribute_findings(parsed: dict, steps: list[dict]) -> None:
    """Link each finding to the real step that produced it (mutates findings,
    setting step_ref + step_tool). The link is the agent's OWN provenance token
    matched to the tool calls it made, preferring the call whose input/result
    mentions the finding's entity. No match -> step_ref stays None (honest).

    ALSO does CLAIM-level corroboration (replay D5): if a finding's claim asserts a hard
    fact (date/IP/email/wallet), that fact must be in a real tool result or the finding is
    flagged `claim_unverified` (graded D, not promoted); when it IS backed, step_ref is
    re-pointed to the step that actually contains it. Relationships + same_as get a
    `corroborated` flag (both endpoints observed in tool results) for the landing gate."""
    tool_steps = [s for s in steps if s.get("type") == "tool"]
    for f in parsed.get("findings", []) or []:
        prov_tok = (f.get("provenance") or "").split(":")[0].strip().lower()
        ent = (f.get("entity") or "").strip().lower()
        # Candidate steps whose tool matches the provenance token (dns ~ dns_lookup).
        cand = [s for s in tool_steps
                if prov_tok and (prov_tok in (s.get("tool") or "").lower()
                                 or (s.get("tool") or "").lower() in prov_tok)]
        chosen = None
        for s in cand:
            blob = (str(s.get("input", "")) + " " + _verify_text(s)).lower()
            if ent and ent in blob:
                chosen = s
                break
        if chosen is None and cand:
            chosen = cand[-1]
        if chosen is None and ent:  # fall back to any step that touched the entity
            for s in tool_steps:
                blob = (str(s.get("input", "")) + " " + _verify_text(s)).lower()
                if ent in blob:
                    chosen = s
                    break
        f["step_ref"] = chosen["n"] if chosen else None
        f["step_tool"] = chosen["tool"] if chosen else None
        # Corroboration: how many DISTINCT tools independently surfaced this finding's
        # ENTITY in their RESULT. >=2 = multi-source. The agent's provenance text is
        # deliberately NOT counted — it's agent-controlled, so a fabricated entity could
        # borrow an unrelated tool's mention of a common word ('iran', 'admin') to fake
        # corroboration. Only the entity value itself, >=4 chars (avoid tiny-string
        # false positives), counts as a real "a tool observed this" signal.
        ent_match = ent if len(ent) >= 4 else None
        srcs, infra_srcs = set(), set()
        if ent_match:
            for s in tool_steps:
                if ent_match in _verify_text(s).lower():
                    # Identity by adapter SLUG, not the raw tool name: every belt call
                    # (`./invctl osint-tool <slug>`) has tool name 'Bash', so dns+whois+
                    # crtsh would otherwise collapse to one source (C1). Use the slug.
                    sid = _step_source_id(s)
                    srcs.add(sid)
                    if _is_infra_source(s):
                        infra_srcs.add(sid)
        f["source_count"] = len(srcs)
        # How many of those sources are AUTHORITATIVE infra tools (crt.sh / DNS / WHOIS /
        # passive-DNS / reputation / the rendered page) vs web-recall (perplexity / search).
        # A domain/IP's cluster membership must be infra-confirmed; web recall is a LEAD —
        # otherwise non-deterministic web results reshuffle the graph every run.
        f["infra_source_count"] = len(infra_srcs)

        # CLAIM-level corroboration (replay D5). The entity check above proves a tool saw
        # the ENTITY; this proves a tool saw the asserted FACT. A claim that asserts a hard
        # token (date/IP/email/wallet) NONE of the tool results contain is an inference or
        # fabrication — flag it (graded D, not promoted). When a tool DID return the fact,
        # re-point step_ref to that step (fixes mis-attribution to the wrong tool call).
        claim_toks = _claim_hard_tokens(f.get("claim") or "")
        f["claim_tokens"] = len(claim_toks)
        backed: set[str] = set()
        backing_step = None
        if claim_toks:
            for s in tool_steps:
                res = _verify_text(s).lower()
                hit = {t for t in claim_toks if t in res}
                if hit:
                    backed |= hit
                    if backing_step is None:
                        backing_step = s
        f["claim_tokens_backed"] = len(backed)
        f["claim_unverified"] = bool(claim_toks) and not backed
        if backing_step is not None:
            f["step_ref"] = backing_step["n"]
            f["step_tool"] = backing_step["tool"]

    # Relationship + identity edges: corroborated only if BOTH endpoints were observed in
    # real tool results (the agent can't draw an edge to an entity no tool ever returned).
    # The landing gate (_land_relationships / _land_same_as) reads this flag; absence means
    # un-attributed path → the gate defaults to allow (never silently drops on those paths).
    for r in parsed.get("relationships", []) or []:
        r["corroborated"] = (_value_observed_in_steps(str(r.get("src", "")), tool_steps)
                             and _value_observed_in_steps(str(r.get("dst", "")), tool_steps))
    for s in parsed.get("same_as", []) or []:
        s["corroborated"] = (_value_observed_in_steps(str(s.get("entity_a", "")), tool_steps)
                            and _value_observed_in_steps(str(s.get("entity_b", "")), tool_steps))

    # Drop the verification-only full result so it never bloats the persisted agent_process
    # (the short `result` preview stays for the trail). Idempotent across re-attribution.
    for s in tool_steps:
        s.pop("result_full", None)


# Tools that AUTHORITATIVELY observe infrastructure (deterministic + reproducible) vs
# web-recall tools (perplexity / search) that surface a DIFFERENT set of "documented"
# domains every call. A domain/IP's cluster membership must come from an infra tool;
# a web-only hit is a LEAD to verify, never a confirmed graph node — otherwise the graph
# reshuffles run-to-run (RCA 2026-06-03: Perplexity-recalled domains drove the cluster).
_INFRA_TOOL_TOKENS = ("crtsh", "dns", "whois", "virustotal", "abusech", "infra",
                      "rdap", "browser_")
_INFRA_BELT_SLUGS = ("crtsh", "whois", "dns", "virustotal", "abusech", "whoisxml", "infra")
_INFRA_ENTITY_TYPES = {"domain", "subdomain", "ip", "ip_address", "url", "netblock", "asn"}
# Person/handle types whose identity attribution is fakeable from name/photo/web alone.
# The tradecraft floor (q-investigation.md) requires a NON-FAKEABLE crosslink to graph one.
# One source of truth, shared with identity_anchor (the reference builder + classifier).
_PERSON_ENTITY_TYPES = identity_anchor.PERSON_ENTITY_TYPES


def _bash_slug(step: dict) -> str | None:
    """The adapter slug from a Bash belt step (`./invctl osint-tool <slug> ...`), or None.
    Anchored on the `osint-tool` token so a query string that merely contains 'dns'/'whois'
    can't be mistaken for the adapter (C2)."""
    # Anchored on `invctl osint-tool` so an arbitrary Bash command that merely contains
    # the phrase 'osint-tool' can't be mis-parsed into a fake adapter slug (Codex).
    m = _re.search(r"invctl\s+osint-tool\s+([a-z0-9_-]+)", str(step.get("input", "")), _re.I)
    return m.group(1).lower() if m else None


def _step_source_id(step: dict) -> str:
    """Stable corroboration identity. The belt runs many adapters but every step's tool
    name is 'Bash' — collapsing distinct adapters to one source (C1). Key Bash steps on
    their slug so dns/whois/crtsh count as distinct sources."""
    tool = (step.get("tool") or "").lower()
    if tool == "bash":
        slug = _bash_slug(step)
        return f"bash:{slug}" if slug else "bash"
    return step.get("tool") or "?"


def _is_infra_source(step: dict) -> bool:
    """True if this tool step is an authoritative infra observation (not web recall).
    The Bash belt counts as infra only when its parsed adapter SLUG is an infra adapter —
    an exact slug match, NOT a substring of the whole command (so `perplexity "whois X"`
    is correctly web, not infra — C2)."""
    tool = (step.get("tool") or "").lower()
    if tool == "bash":
        return _bash_slug(step) in _INFRA_BELT_SLUGS
    return any(t in tool for t in _INFRA_TOOL_TOKENS)


def _asset_confidence(entity_type: str | None, infra: int, srcs: int, conf: str) -> str:
    """Per-asset-type TENTATIVE/FIRM/CONFIRMED (G-ASSET-PERTYPE, 4_points' per-type
    table). Different asset classes are confirmed by different evidence:
      - infra (domain/IP/URL/...): by INFRA tools (DNS/WHOIS/cert/passive-DNS).
      - identifier (email/wallet/hash/handle/telegram): NOT DNS-confirmable, so by
        independent source corroboration.
      - actor/org/person/other: attribution — by independent corroboration.
    """
    etype = (entity_type or "").lower()
    if etype in _INFRA_ENTITY_TYPES:
        return "CONFIRMED" if infra >= 2 else "FIRM" if infra >= 1 else "TENTATIVE"
    if etype in ("email", "crypto_wallet", "wallet", "hash_sha256", "hash_md5",
                 "handle", "telegram_channel"):
        return ("CONFIRMED" if srcs >= 2 else
                "FIRM" if (srcs >= 1 and conf in ("high", "medium")) else "TENTATIVE")
    # actor / org / person / indicator / other: attribution-class
    return ("CONFIRMED" if srcs >= 2 else "FIRM" if (srcs >= 1 and conf == "high")
            else "TENTATIVE")


def _grade_finding(f: dict) -> tuple[str, str]:
    """4_points-style source-reliability grade (A–D) + asset-confidence
    (TENTATIVE/FIRM/CONFIRMED), from how many tools — and how many AUTHORITATIVE infra
    tools — independently surfaced the finding's entity in their RESULT.

    Grade (source reliability): A = 2+ infra confirmations, or 1 infra + agent-high;
    B = 1 infra OR 2+ sources (web counts here); C = single web/inferred source;
    D = unverifiable (no tool result contains it) or agent-marked unvalidated.
    Asset confidence keys off infra confirmations only: CONFIRMED ≥2, FIRM =1, else
    TENTATIVE — so a domain is 'CONFIRMED in the cluster' only on shared infra, never
    on a web co-mention (the reproducibility fix, matching 4_points)."""
    srcs = f.get("source_count") or 0
    infra = f.get("infra_source_count") or 0
    conf = (f.get("confidence") or "medium").lower()
    # claim_unverified (replay D5): the claim asserts a hard fact (date/IP/email/wallet)
    # that NO tool result contains → unverifiable assertion, grade D regardless of how well
    # the ENTITY is corroborated. This is what stops the "high-confidence, fake-sourced" node.
    if f.get("unvalidated") or f.get("claim_unverified") or srcs < 1:
        grade = "D"
    elif infra >= 2 or (infra >= 1 and conf == "high"):
        grade = "A"
    elif infra >= 1 or srcs >= 2:
        grade = "B"
    else:
        grade = "C"
    asset_conf = _asset_confidence(f.get("entity_type"), infra, srcs, conf)
    return grade, asset_conf


def _promotion_gate(f: dict, reference: "identity_anchor.Reference | None" = None) -> tuple[bool, str]:
    """Whether a finding may auto-build the graph, and if not, why — on the 4_points
    A–D reliability model. The agent's self-declared flags are NOT trusted alone:
    the grade is computed from independent tool corroboration (_attribute_findings).
    Grade A/B promote; C/D LAND but stay gated as LEADS in /enrich for the analyst.
    For a domain/IP, cluster membership additionally requires an INFRA confirmation —
    a web co-mention is never enough (keeps the graph reproducible run-to-run).

    `reference` (the case's confirmed-actor identity, PRD prd-identity-anchor) is annotation
    only: it sets f['identity_anchor']='match' on a finding that matches a confirmed actor and
    NEVER changes the promote/deny decision. Default None keeps every legacy caller unchanged."""
    # Scrub any agent-supplied identity annotation up front (Codex adv-4: the finding JSON could
    # carry a forged identity_anchor='match'); it is re-set below only on a deterministic match.
    # Runs even when reference is None, so a forged key never survives into raw_json on any path.
    f.pop("identity_anchor", None)
    grade, asset_conf = _grade_finding(f)
    f["grade"], f["asset_confidence"] = grade, asset_conf
    etype = (f.get("entity_type") or "").lower()
    val = f.get("entity") or ""
    # Annotate (only) a finding that matches a confirmed actor. Placed before the gates so a
    # held-as-lead match is annotated too; the annotation never affects the decision below.
    if reference is not None and identity_anchor.classify(reference, etype, val) == "match":
        f["identity_anchor"] = "match"
    # Entity-admission contract (RCA rca-recurring-graph-noise-2026-06-11): the ONE gate
    # every creation path shares, so junk can't re-enter through this (agent) door after
    # being blocked at another. Keeps boilerplate / reference / mistyped-junk nodes OFF the
    # graph regardless of grade; they still LAND as leads in /enrich.
    from investigations import admission
    ok, why = admission.is_admissible(etype, val)
    if not ok:
        return False, f"not graphed ({why}); lead"
    if f.get("unvalidated"):
        return False, "agent marked unvalidated (grade D)"
    if f.get("claim_unverified"):
        return False, ("claim asserts a hard fact (date/IP/email/wallet) no tool result "
                       "contains — unverified attribution; lead")
    if grade == "D":
        return False, "grade D — no tool result contains this (unverifiable); lead"
    if grade == "C":
        return False, "grade C — single web/inferred source; lead, corroborate before graphing"
    # Grade A/B: a domain/IP joins the cluster only on shared INFRA (crt.sh / DNS /
    # WHOIS / reverse-WHOIS / passive-DNS), not a web co-mention. (etype computed above.)
    if etype in _INFRA_ENTITY_TYPES and (f.get("infra_source_count") or 0) < 1:
        return False, ("web-recall only — no infra tool confirmed this domain/IP; "
                       "lead, verify (crt.sh / DNS / WHOIS / passive-DNS) before graphing")
    # Person/handle identity floor (tradecraft: photo/name-only attribution prohibition,
    # q-investigation.md). A person or handle joins the graph ONLY on a NON-FAKEABLE crosslink
    # (registry / infra / on-chain — i.e. infra_source_count>=1). Name + photo + a web
    # co-mention are all fakeable, so a person/handle with no such crosslink caps at grade C
    # and stays a lead. Mirrors the name+photo inversion fixed in the osint skill (70d23b59),
    # now enforced in the agent's own gate so a warm-chat / run finding can't slip a
    # name-only person into the graph.
    if etype in _PERSON_ENTITY_TYPES and (f.get("infra_source_count") or 0) < 1:
        if grade in ("A", "B"):
            f["grade"] = "C"
        return False, ("person/handle attributed with no non-fakeable crosslink "
                       "(name/photo/web only) — unverified identity; lead, corroborate with "
                       "a registry / infra / on-chain link before graphing")
    return True, ""


_FINDINGS_OPENER = _re.compile(r'\{\s*"findings"')


# Appended to a WARM CHAT turn so the agent both talks AND emits landable findings. The
# conversation comes first (the analyst reads it); the JSON is the last thing and gets
# stripped from the display + landed into the graph. Optional by design: a casual turn
# that established nothing omits the JSON and just replies (issue warm-lands-findings).
CHAT_FINDINGS_CONTRACT = (
    "\n\n---\nIMPORTANT (graph wiring): reply to the analyst conversationally FIRST. THEN, "
    "ONLY IF this turn established new findings / relationships / identity links, append the "
    "findings JSON (the SAME schema a run emits) as the very LAST thing in your message — it "
    "is parsed out and landed into the case graph, so talking to you BUILDS the graph. If "
    "nothing new was established, omit the JSON entirely and just reply normally."
)


def _strip_findings_json(text: str) -> str:
    """Remove the trailing findings JSON object (and an enclosing ```json fence, if any)
    from a warm chat reply, leaving the conversational narration. No findings block →
    returned unchanged. Never raises."""
    if not text:
        return ""
    # Strip from the LAST findings opener (the trailing JSON the contract asks the agent to
    # emit), not the first — so an example/schema findings object earlier in the narration
    # doesn't cause the real narration between it and the trailing object to be deleted.
    matches = list(_FINDINGS_OPENER.finditer(text))
    cut = matches[-1].start() if matches else None
    if cut is None:
        return text
    end = text.rfind("}")
    if end == -1 or end < cut:
        return text
    head = text[:cut]
    # Drop a dangling ```json fence opener just before the object, plus trailing fence after.
    head = _re.sub(r"```(?:json)?\s*$", "", head.rstrip())
    tail = text[end + 1:]
    tail = _re.sub(r"^\s*```", "", tail.strip())
    return (head + (" " + tail if tail.strip() else "")).strip()


def land_warm_chat(conn, case: str | None, message: str, run: dict) -> dict:
    """Land a WARM CHAT turn's findings into the graph via the SAME path the cold/agent
    runs use (parse → salvage → attribute → build_process → land_findings), and return the
    narration with the findings JSON stripped out (the conversational reply). This is what
    makes talking to the investigator BUILD the graph (issue warm-lands-findings).

    A turn whose narration carries no parseable findings lands nothing and returns the
    narration unchanged — casual turns stay clean, malformed/missing JSON never crashes."""
    text = run.get("result_text") or ""
    steps = run.get("steps") or []
    try:
        parsed = _parse_findings(text)
        if run.get("capped") and not parsed.get("findings"):
            rescued = _salvage_from_trail(steps, text)
            if rescued.get("findings"):
                parsed = rescued
    except Exception:
        parsed = {"findings": [], "summary": ""}
    landed: dict = {}
    has_intel = bool(parsed.get("findings") or parsed.get("relationships")
                     or parsed.get("same_as"))
    if has_intel:
        try:
            _attribute_findings(parsed, steps)
            # The chat path's `run` is the raw _collect output (no `raw` dict) — build one
            # from its cost/turns so _build_process records them instead of NULLs.
            raw = run.get("raw") or {"num_turns": run.get("turns"),
                                     "total_cost_usd": run.get("cost_usd")}
            process = _build_process(parsed, text, raw, run.get("capped"), steps)
            landed = land_findings(conn, case, f"CHAT: {message[:60]}", message, parsed,
                                   process=process, started_at=run.get("started_at"),
                                   cost_usd=run.get("cost_usd")) or {}
        except Exception as exc:  # landing must never break the chat reply
            landed = {"error": str(exc)[:200]}
    reply = _strip_findings_json(text).strip() or text.strip()
    # landed_any covers findings AND relationships AND identity links — any of which is a
    # graph change the client must refresh on (Codex: relationship-only turns were missed).
    landed_any = bool(landed and not landed.get("error") and (
        landed.get("results") or landed.get("promoted") or landed.get("relationships")
        or landed.get("same_as")))
    return {"reply": reply, "landed": landed, "landed_any": landed_any,
            "findings": len(parsed.get("findings", []))}


def _parse_findings(text: str) -> dict:
    """Pull the final JSON findings object out of the agent's last message. Robust to
    the real shapes the agent emits: ```json fences, prose before the JSON, and
    whitespace/newlines after the opening brace (`{\\n "findings"`). The old exact-match
    on `{"findings` missed the very common `{ "findings` and silently dropped findings."""
    if not text:
        return {"findings": [], "summary": ""}
    end = text.rfind("}")
    if end == -1:
        return {"findings": [], "summary": text[:400]}
    # Every place a findings object could START — regex openers (whitespace-tolerant)
    # first, then brace fallbacks. Try each; the first that parses + has 'findings' wins.
    starts = [m.start() for m in _FINDINGS_OPENER.finditer(text)]
    starts += [text.find("{"), text.rfind("{")]
    seen = set()
    for s in starts:
        if s is None or s == -1 or s > end or s in seen:
            continue
        seen.add(s)
        try:
            obj = json.loads(text[s:end + 1], strict=False)
            if isinstance(obj, dict) and "findings" in obj:
                return obj
        except json.JSONDecodeError:
            continue
    # Salvage: the whole object didn't parse (often TRUNCATED output). Pull each complete
    # {...} finding object out of the "findings":[ array individually — the finished ones
    # survive even when the array was cut off mid-way.
    salvaged = _salvage_findings(text)
    if salvaged:
        return {"findings": salvaged, "summary": text[:400]}
    return {"findings": [], "summary": text[:400]}


def _salvage_findings(text: str) -> list[dict]:
    """Extract complete finding objects from a (possibly truncated) findings array by
    brace-matching, so a cut-off final object doesn't lose the ones before it."""
    m = _re.search(r'"findings"\s*:\s*\[', text)
    if not m:
        return []
    out, depth, start = [], 0, None
    for j in range(m.end(), len(text)):
        ch = text[j]
        if ch == "{":
            if depth == 0:
                start = j
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    o = json.loads(text[start:j + 1], strict=False)
                    if isinstance(o, dict) and o.get("entity"):
                        out.append(o)
                except json.JSONDecodeError:
                    pass
                start = None
        elif ch == "]" and depth == 0:
            break
    return out


def _salvage_from_trail(steps: list[dict], partial_text: str) -> dict:
    """Cut-off rescue. The agent did real work — tool calls in `steps` — but was killed
    (timeout, --max-turns cap, or analyst Stop) BEFORE it emitted its findings JSON, so
    `_parse_findings` got nothing and the whole investigation would be lost. Reconstruct
    the findings from the agent's OWN tool trail (each call + its result) + its last words.

    Holistic: it doesn't matter WHY the run stopped — whatever it actually collected is
    turned into findings. One bounded LLM pass (no tools, capped tokens) so the salvage
    itself can't hang. Grounded strictly in the trail — provenance must trace to a tool
    result, no invention. Returns {findings, relationships, same_as, summary} or {}."""
    tool_steps = [s for s in steps if s.get("type") == "tool" and s.get("result")]
    if not tool_steps:
        return {}  # no tool evidence to reconstruct from — nothing to salvage
    lines = []
    for s in steps:
        if s.get("type") == "tool":
            lines.append(f"[{s.get('n')}] {s.get('tool')} {s.get('input', '')} "
                         f"-> {(s.get('result') or '')[:300]}")
        elif s.get("type") == "reasoning":
            lines.append(f"[{s.get('n')}] thought: {(s.get('text') or '')[:200]}")
    trail = "\n".join(lines)[-12000:]   # keep the tail — the most-developed picture
    prompt = (
        "An OSINT investigation was CUT OFF before the agent wrote its findings JSON. "
        "Below is the agent's real tool trail (each call and its result) and its last "
        "words. Reconstruct the findings from ONLY what the trail actually shows — every "
        "entity and relationship MUST trace to a tool result in the trail (provenance = "
        "the tool + the value it returned). Do NOT invent or infer beyond the evidence. "
        "If the trail shows nothing concrete, return empty arrays.\n\n"
        "Schema (exact keys):\n"
        '{"findings":[{"entity":"<value>","entity_type":"<domain|ip|subdomain|email|handle|'
        'wallet|org|person|other>","claim":"<one line>","confidence":"high|medium|low",'
        '"provenance":"<tool: value>","unvalidated":false}],"relationships":[{"src":"<value>",'
        '"dst":"<value>","rel_type":"<snake_case>","direction":"src_to_dst","confidence":'
        '"high|medium|low","provenance":"<tool: value>"}],"same_as":[],'
        '"summary":"<2-3 lines on what was established before the cutoff>"}\n\n'
        f"=== TOOL TRAIL ===\n{trail}\n\n=== AGENT'S LAST WORDS ===\n{(partial_text or '')[-1500:]}"
        "\n\nReturn ONLY the JSON object — no prose, no fences.")
    try:
        # Raw text (not ask_json): a rich trail yields a long findings array that can hit
        # the token ceiling and truncate mid-string. `_parse_findings` is truncation-
        # tolerant (brace-matches the complete finding objects out of a cut-off array), so
        # a partial salvage still keeps the finished findings instead of erroring to zero.
        raw = ask(prompt, timeout=180, tools=False, max_tokens=4000)
    except Exception:
        return {}
    out = _parse_findings(raw or "")
    if not out.get("findings"):
        return {}
    # On a truncated salvage, _parse_findings stashes the raw JSON text in `summary`;
    # replace that with a clean, honest label.
    s = (out.get("summary") or "").strip()
    if not s or s.startswith("{"):
        s = (f"reconstructed {len(out['findings'])} finding(s) from the agent's tool "
             "trail after the run was cut off")
    out["summary"] = s
    return out


def _build_process(parsed: dict, result_text: str, raw: dict, capped: bool,
                   steps: list[dict] | None = None) -> dict:
    """The 'how it investigated' record: the agent's REAL step trail (tool calls +
    results), its narration, the tools it actually used, and run stats. Shown as
    the Run trail."""
    steps = steps or []
    # Tools actually used = the real tool calls (fall back to provenance tokens
    # for legacy/no-step runs).
    tools = []
    for s in steps:
        if s.get("type") == "tool" and s.get("tool") and s["tool"] not in tools:
            tools.append(s["tool"])
    if not tools:
        for f in parsed.get("findings", []) or []:
            prov = (f.get("provenance") or "").split(":")[0].strip().lower()
            if prov and prov not in tools:
                tools.append(prov)
    # Narration = the agent's prose, with the final JSON block stripped off. Use the
    # whitespace-tolerant opener + strip a leading ```json fence, so the bottom line
    # shows the agent's actual wrap-up, not a raw truncated JSON dump.
    narration = result_text or ""
    m = _FINDINGS_OPENER.search(narration)
    if m:
        narration = narration[:m.start()]
    narration = _re.sub(r'```(?:json)?\s*$', '', narration.strip()).strip()[:4000]
    return {
        "summary": (parsed.get("summary") or "")[:1000],
        "narration": narration,
        "steps": steps,
        "tools_used": tools,
        "turns": (raw or {}).get("num_turns"),
        "cost_usd": (raw or {}).get("total_cost_usd"),
        "capped": bool(capped),
    }


_REL_CONF = {"high": 0.85, "medium": 0.6, "low": 0.35}


def _looks_like_entity(name: str) -> bool:
    """A name worth creating a brand-new node for: short, not a sentence. Blocks the
    LLM dumping a prose clause ('the actor operates several coordinated accounts') as
    an entity. Existing entities still resolve regardless — this only gates CREATION."""
    if not (1 <= len(name) <= 80):
        return False
    if name.count(" ") > 3:   # handles/domains/wallets have none; allow a few for names
        return False
    return True


def _resolve_entity_id(conn, name, rep_id: int, create_infra: bool = True,
                       case: str | None = None) -> int | None:
    """Find an entity by name; create it only if the agent named a plausible NEW
    indicator (not a prose fragment). A non-string endpoint (LLM emitted a list /
    number) is malformed → return None, never stringify it into a junk node.

    C3 gate: with create_infra=False (relationship / same_as landing), a NEW infra-type
    endpoint (domain / IP / URL) is NOT created — infra nodes must enter through the
    GRADED findings path, so a web-asserted relationship can't mint an ungated cluster
    node. Existing infra nodes still resolve; non-infra endpoints (actor/handle/org)
    still create."""
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name:
        return None
    row = conn.execute("SELECT id FROM entities WHERE canonical_name = ?", (name,)).fetchone()
    if row:
        return row["id"]
    if not _looks_like_entity(name):
        return None
    from investigations.enrich.promote import _classify
    etype = _classify(name) or "other"
    if not create_infra and etype in _INFRA_ENTITY_TYPES:
        return None  # C3: relationships cannot create ungated infra (domain/IP) nodes
    # The store gates agent-actor creations through is_admissible (RCA
    # rca-recurring-graph-noise): a junk endpoint (bare tracking id, reference
    # domain) is rejected, which drops the edge too (caller skips on None).
    from investigations import store
    result = store.apply_mutation(conn, store.entity_upserted(
        case, name, etype, rep_id, actor="agent", provenance="agent"))
    if not result["applied"]:
        return None
    eid = result["entity_id"]
    db.add_mention(conn, eid, rep_id, name, "via agent relationship")
    return eid


# The free-form-label band-aids (_REL_SYNONYMS, _DROP_RELS, _skip_rel, _concrete_rel) were
# replaced by the single controlled-vocabulary validator: investigations/enrich/rel_vocab.py
# (normalize_rel). All three landing paths call it; nothing here maps labels anymore.


def _land_relationships(conn, parsed: dict, rep_id: int, case: str | None = None) -> int:
    """Persist the agent's discovered relationships as TYPED, DIRECTED graph edges
    with the REAL rel_type + the agent's confidence + provenance — instead of the
    old generic 'enriched' link. This is the story the agent built, made queryable.
    Low-confidence edges are skipped (don't write weak claims as graph fact), and a
    prose / non-string endpoint that isn't an existing entity is dropped, not nodified.
    Each item is isolated so one malformed entry can't kill the run after promotion."""
    made = 0
    for r in parsed.get("relationships", []) or []:
        try:
            conf = str(r.get("confidence") or "medium").lower()
            if conf == "low":
                continue
            # Claim-corroboration gate (replay D5): an edge whose endpoints weren't BOTH
            # observed in real tool results is the agent inventing a connection — skip it.
            # `is False` (not falsy): absent flag = un-attributed path → default allow.
            if r.get("corroborated") is False:
                continue
            # C3: relationships connect EXISTING infra nodes; they can't create new
            # ungated domains/IPs (those come through the graded findings path).
            src = _resolve_entity_id(conn, r.get("src"), rep_id, create_infra=False, case=case)
            dst = _resolve_entity_id(conn, r.get("dst"), rep_id, create_infra=False, case=case)
            ev = str(r.get("provenance") or "")[:200]
            # Controlled vocabulary is the binding gate: normalize_rel returns a REL_VOCAB
            # member or None (skip). No free-form label reaches the DB. (issue rel-vocab-validator)
            rel = normalize_rel(r.get("rel_type"), ev)
            if not src or not dst or src == dst or not rel:
                continue
            from investigations import store
            db.add_relationship(conn, src, dst, rel, rep_id, ev, _REL_CONF.get(conf, 0.6))
            store.apply_mutation(conn, store.edge_upserted(
                case, src, dst, rel, actor="agent", confidence=conf,
                evidence=ev, provenance=ev or "agent"))
            # Carry dst into src's cluster(s) so in-cluster graph views show them together.
            for row in conn.execute(
                "SELECT cluster_id FROM cluster_members WHERE entity_id = ?", (src,)).fetchall():
                conn.execute("INSERT OR IGNORE INTO cluster_members (cluster_id, entity_id) "
                             "VALUES (?, ?)", (row["cluster_id"], dst))
            made += 1
        except Exception:
            continue
    return made


def _land_same_as(conn, parsed: dict, rep_id: int, case: str | None = None) -> int:
    """Persist identity merges (one real actor behind multiple handles) as a high-signal
    'same_as' edge. NOT a hard node-merge (destructive — the analyst decides) and NOT a
    cross-alias (that would make a name resolve to two entities and corrupt lookups) —
    just the edge, which makes the identity visible and reversible. Low-confidence
    merges are skipped; each item is isolated against malformed input."""
    made = 0
    for s in parsed.get("same_as", []) or []:
        try:
            conf = str(s.get("confidence") or "medium").lower()
            if conf == "low":
                continue
            # Claim-corroboration gate (replay D5): an identity merge whose two sides weren't
            # both observed in real tool results is invented — skip it (default allow if the
            # flag is absent, i.e. an un-attributed path). Namesake guard still applies below.
            if s.get("corroborated") is False:
                continue
            # C3: identity merges connect EXISTING nodes; no ungated infra creation.
            a = _resolve_entity_id(conn, s.get("entity_a"), rep_id, create_infra=False, case=case)
            b = _resolve_entity_id(conn, s.get("entity_b"), rep_id, create_infra=False, case=case)
            if not a or not b or a == b:
                continue
            # G-NAMECOLLISION: don't conflate two same-named PEOPLE on a weak signal —
            # split (skip the merge) unless it's high-confidence or corroborated.
            if _namesake_collision_risk(conn, a, b, conf):
                continue
            ev = str(s.get("provenance") or "")[:200]
            from investigations import store
            store.apply_mutation(conn, store.edge_upserted(
                case, a, b, "same_as", actor="agent", confidence=conf,
                evidence=ev, provenance=ev or "agent"))
            made += 1
        except Exception:
            continue
    return made


def _namesake_collision_risk(conn, a: int, b: int, conf: str) -> bool:
    """G-NAMECOLLISION (4_points Phase-3 step 4): a same_as merge of two PERSON/HANDLE
    entities is a namesake risk — two different people sharing a common name. Require
    high confidence OR a corroborating shared neighbor before merging; otherwise return
    True so the caller SPLITS (skips the merge) instead of conflating them."""
    rows = conn.execute("SELECT entity_type FROM entities WHERE id IN (?, ?)", (a, b)).fetchall()
    types = {r["entity_type"] for r in rows}
    if not types & {"person", "handle", "person_candidate"}:
        return False  # infra / identifier merges aren't namesake-prone
    if conf == "high":
        return False
    # A corroborating shared neighbor = some entity adjacent to BOTH a and b over ACTIVE
    # edges, in EITHER direction (Codex: prior query missed incoming edges + superseded ones).
    shared = conn.execute(
        "WITH adj(node, nbr) AS ("
        "  SELECT src_entity_id, dst_entity_id FROM typed_relationships WHERE status='active' "
        "  UNION SELECT dst_entity_id, src_entity_id FROM typed_relationships WHERE status='active') "
        "SELECT 1 FROM adj x JOIN adj y ON x.nbr = y.nbr "
        "WHERE x.node = ? AND y.node = ? LIMIT 1", (a, b)).fetchone()
    return shared is None   # risky → split when there's no corroborating shared link


def _land_contradictions(conn, parsed: dict, rep_id: int, case: str | None = None) -> int:
    """G-CONTRADICT (4_points Phase-3 step 3): persist the agent's reported contradictions
    as 'contradicts' edges, keeping BOTH conflicting claims visible — never silently pick
    one. The agent emits `contradictions: [{entity_a, entity_b, note}]` for facts that
    conflict across sources."""
    made = 0
    for c in parsed.get("contradictions", []) or []:
        try:
            a = _resolve_entity_id(conn, c.get("entity_a"), rep_id, create_infra=False, case=case)
            b = _resolve_entity_id(conn, c.get("entity_b"), rep_id, create_infra=False, case=case)
            if not a or not b or a == b:
                continue
            ev = str(c.get("note") or c.get("provenance") or "")[:200]
            from investigations import store
            store.apply_mutation(conn, store.edge_upserted(
                case, a, b, "contradicts", actor="agent",
                evidence=ev, provenance=ev or "agent"))
            made += 1
        except Exception:
            continue
    return made



def _osint_dossier_block(parsed: dict) -> str:
    """A dossier block summarizing this investigation's findings (incl. the prose
    attributions that never reach the graph), each flagged verified vs unverified lead."""
    lines = []
    for f in parsed.get("findings", []) or []:
        claim = (f.get("claim") or "").strip()
        if not claim:
            continue
        conf = (f.get("confidence") or "?")
        unver = bool(f.get("unvalidated")) or ((f.get("source_count") or 0) < 2 and conf != "high")
        tag = f"{conf}, lead" if unver else conf
        prov = (f.get("provenance") or "").strip()
        lines.append(f"- [{tag}] {claim}" + (f"  _( {prov} )_" if prov else ""))
    a = parsed.get("assessment") or {}
    if a.get("attributed_actor") and a["attributed_actor"].lower() != "unknown":
        lines.insert(0, f"- **Attribution:** {a['attributed_actor']}"
                        + (f" — {a.get('best_judgment','')}" if a.get("best_judgment") else ""))
    if not lines:
        return ""
    return "<!--osint-->\n**OSINT investigation findings:**\n" + "\n".join(lines) + "\n<!--/osint-->"


def _attach_osint_dossier(conn, entity_id: int, parsed: dict) -> None:
    """Append/replace the OSINT findings block on an entity's dossier (idempotent — a
    prior block is replaced, an analyst's own notes are preserved)."""
    block = _osint_dossier_block(parsed)
    if not block:
        return
    try:
        from investigations import annotations as _ann
        existing = (_ann.get(conn, entity_id) or {}).get("dossier_override") or ""
        existing = _re.sub(r"<!--osint-->.*?<!--/osint-->", "", existing, flags=_re.S).strip()
        merged = (existing + "\n\n" + block).strip() if existing else block
        _ann.set_dossier_override(conn, entity_id, merged, author="OSINT agent")
    except Exception:
        pass




# Indicator types worth recovering from prose; everything else (phone fragments from
# hashes, proper names) is noise. Common free-mail domains are not real infra indicators.
_PROSE_INDICATOR_TYPES = {"domain", "ip", "crypto_wallet", "email",
                          "telegram_channel", "hash_sha256", "hash_md5", "handle"}
_PROSE_NOISE_DOMAINS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
                        "yahoo.com", "proton.me", "protonmail.com", "icloud.com"}


def _land_prose_indicators(conn, run_id: int, parsed: dict, finding_names: set[str],
                           extra_text: str = "") -> int:
    """RULE-106-safe recovery of indicators named ONLY in the summary prose.

    The agent often NAMES domains/wallets/emails/IPs in its summary that no single
    tool call extracted — so they never became findings or graph nodes (the RCA's
    'vanished ~250 domains' gap). Extract the REAL typed indicators (never prose
    phrases — RULE-106) and land them as source_count=0 GATED results so they surface
    in /enrich for MANUAL promotion. They never auto-promote (no tool backs them)."""
    from investigations.ingest.extractor import extract_all
    a = parsed.get("assessment") or {}
    # Scan the summary + assessment AND the run narration (extra_text). The narration is
    # where a CAPPED run's discoveries live (it never reached the findings JSON), so this
    # is the salvage path — indicators it named there still land as gated /enrich leads.
    text = "\n".join(t for t in (parsed.get("summary") or "",
                                 a.get("best_judgment") or "",
                                 a.get("attributed_actor") or "",
                                 extra_text or "") if t)
    if not text.strip():
        return 0
    # Skip what's already a finding this run or already an entity anywhere (dedup).
    known = {n.lower() for n in finding_names}
    for row in conn.execute("SELECT LOWER(canonical_name) AS n FROM entities").fetchall():
        known.add(row["n"])
    seen, landed = set(), 0
    for e in extract_all(text):
        if e.entity_type not in _PROSE_INDICATOR_TYPES:
            continue
        val = (e.canonical or "").strip()
        low = val.lower()
        if not low or low in seen or low in known:
            continue
        if e.entity_type == "domain" and low in _PROSE_NOISE_DOMAINS:
            continue
        seen.add(low)
        summary = (f"[{e.entity_type}] named in the investigator's summary, NOT "
                   f"tool-confirmed (source_count=0). Promote manually if it matters.")
        conn.execute(
            "INSERT INTO enrichment_results (run_id, result_type, title, summary, url, "
            "raw_json, confidence) VALUES (?, 'finding', ?, ?, ?, ?, 'low')",
            (run_id, val[:200], summary,
             f"http://{val}" if e.entity_type == "domain" else None,
             json.dumps({"entity_type": e.entity_type, "source_count": 0,
                         "from": "summary-prose", "gate_reason": "named in prose only "
                         "— no tool result backs it"}, ensure_ascii=False)))
        landed += 1
    return landed


def land_findings(conn, case: str | None, target: str, task: str, parsed: dict,
                  entity_id: int | None = None, process: dict | None = None,
                  auto_promote: bool = True, started_at: str | None = None,
                  cost_usd: float | None = None) -> dict:
    """Store the agent's findings as enrichment_results under an 'agent' run, plus
    the agent's process trail. With auto_promote (default), the agent builds the
    GRAPH itself — each finding is promoted to a node immediately, no human gate.
    promote_result self-filters: only real indicators (domain/IP/URL) become nodes,
    prose answers are rejected. The analyst stays the authority by REVIEWING the
    graph after the fact (and can prune), not by gating every node up front.

    `started_at` (UTC 'YYYY-MM-DD HH:MM:SS') + `cost_usd` record the run's real
    wall-clock + spend on the enrichment_runs row. When omitted, started_at falls back
    to CURRENT_TIMESTAMP (==finished_at, the old cost-blind behavior) and cost_usd stays
    NULL — so existing callers are unchanged."""
    import json as _json
    from investigations.enrich import promote as promote_mod
    from investigations.enrich.promote import _enrichment_report
    # The analyst may have deleted this case while the run was in flight. Writing
    # findings back would leave orphan rows that the investigations backfill
    # resurrects into a phantom case + graph. Drop the results silently (founder
    # decision 2026-06-08) — a deleted case stays deleted.
    if case and not conn.execute(
            "SELECT 1 FROM investigations WHERE slug = ?", (case,)).fetchone():
        return {"discarded": "case_deleted", "case": case, "run_id": None,
                "results": 0, "promoted": 0, "gated": 0, "relationships": 0,
                "same_as": 0, "prose_indicators": 0, "summary": ""}
    _ensure_agent_provider(conn)
    # Build the case's confirmed-actor reference ONCE (PRD prd-identity-anchor), after the
    # deleted-case early return. The promotion gate uses it to annotate findings that match a
    # confirmed actor (annotation only). Empty (no-op) until the analyst has confirmed an actor.
    reference = identity_anchor.build_reference(conn, case)
    # Carry the agent's verdict + negative findings + next-pivot recommendation onto
    # the run record so the Run trail + brief show "who/what this is, how confident,
    # what was cleared, and what to chase next" — not just a flat fact list.
    extras = {k: parsed[k] for k in ("assessment", "negatives", "recommended_pivots")
              if parsed.get(k)}
    if process is not None and extras:
        process = {**process, **extras}
    # started_at = the run's real start (COALESCE falls back to now when not supplied, so
    # legacy callers keep started_at==finished_at); cost_usd = the run's real spend.
    cur = conn.execute(
        "INSERT INTO enrichment_runs (entity_id, provider_slug, query, mode, status, "
        "investigation, started_at, finished_at, cost_usd, agent_process) "
        "VALUES (?, 'agent', ?, 'investigate', 'success', ?, "
        "COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP, ?, ?)",
        (entity_id, task[:300], case, started_at, cost_usd,
         _json.dumps(process) if process else None))
    run_id = cur.lastrowid
    n = 0
    gated = 0
    result_ids = []
    finding_names: set[str] = set()
    for f in parsed.get("findings", []) or []:
        ent = (f.get("entity") or "").strip()
        if not ent:
            continue
        finding_names.add(ent)
        # The gate decides if this finding may auto-build the graph. Computed BEFORE
        # the insert so the reason is stored on the result for the analyst to see.
        may_promote, gate_reason = _promotion_gate(f, reference)
        if not may_promote:
            f["gate_reason"] = gate_reason
        flag = " {{UNVALIDATED}}" if f.get("unvalidated") else ""
        gate_note = f"\ngated: {gate_reason}" if not may_promote else ""
        # Title is the BARE entity (so promote_result can classify it as a real
        # indicator and auto-build the graph); type goes in the summary + raw_json.
        title = ent
        etype = f.get("entity_type", "?")
        summary = f"[{etype}] {f.get('claim','')}{flag}\nprovenance: {f.get('provenance','')}{gate_note}"
        rcur = conn.execute(
            "INSERT INTO enrichment_results (run_id, result_type, title, summary, url, "
            "raw_json, confidence) VALUES (?, 'finding', ?, ?, ?, ?, ?)",
            (run_id, title[:200], summary[:1000], f.get("url"),
             json.dumps(f, ensure_ascii=False), f.get("confidence", "medium")))
        # Only findings that clear the gate auto-build the graph. The rest LAND (so
        # the analyst sees them in /enrich) but stay un-promoted until reviewed — the
        # agent no longer writes single-source / unbacked claims into the graph as fact.
        if may_promote:
            result_ids.append(rcur.lastrowid)
        else:
            gated += 1
        n += 1
    # The agent creates the graph — promote each validated finding into a node now.
    # Indicators land + link to the source actor; non-indicators are silently skipped.
    promoted = 0
    if auto_promote:
        for rid in result_ids:
            try:
                # promote_result captures the finding's evidence on the promoted node
                # (ea-1) — the capture lives there so manual + agent promotion share
                # one code path.
                if not promote_mod.promote_result(conn, rid, analyst="agent").get("error"):
                    promoted += 1
            except Exception:
                pass
    # Attach what the investigation found to the TARGET entity's dossier — so prose
    # attributions ("real identity: Tristan Anthony Orth") that can't become graph nodes
    # are still visible on the node + entity page, not buried on the Run trail.
    if entity_id:
        _attach_osint_dossier(conn, entity_id, parsed)
    # The agent's discovered STORY: typed/directed edges + identity merges, written
    # with their real rel_type + confidence (the old path only ever made 'enriched').
    rep_id = _enrichment_report(conn, case)
    rels = _land_relationships(conn, parsed, rep_id, case=case)
    same = _land_same_as(conn, parsed, rep_id, case=case)
    contradictions = _land_contradictions(conn, parsed, rep_id, case=case)
    # Recover indicators named only in the summary prose as gated /enrich items
    # (WS3 — the RCA's vanished-prose-domains gap). Never auto-promoted.
    prose_indicators = _land_prose_indicators(
        conn, run_id, parsed, finding_names,
        extra_text=(process or {}).get("narration", "") if isinstance(process, dict) else "")
    conn.commit()
    # Rescore AFTER the late edge writes above (_land_relationships/_land_same_as/
    # _land_contradictions) — promote_result's internal recompute ran before these
    # edges existed, leaving them invisible to the score formula's degree term.
    try:
        from investigations import analyze as _analyze
        rescored = _analyze.compute_threat_scores(conn)
        log.info("land_findings: rescored %d entities after edge writes", rescored)
    except Exception as exc:
        log.warning("land_findings: score recompute failed: %s: %s",
                    type(exc).__name__, exc)
    return {"run_id": run_id, "results": n, "promoted": promoted, "gated": gated,
            "relationships": rels, "same_as": same, "contradictions": contradictions,
            "prose_indicators": prose_indicators,
            "summary": parsed.get("summary", "")}


def _case_thesis(conn, case: str | None) -> str:
    """The case's thesis — what the whole investigation is trying to establish.
    Threaded into each target's task (PRD-09) so the agent digs TOWARD the case
    question, not just the easy lookups. Empty if none.

    The analyst's typed OBJECTIVE wins: it's the explicit scope anchor, so it
    outranks the schema-derived domain+summary. Falls back to the schema."""
    if not case:
        return ""
    try:
        from investigations.storage import db as _db
        objective = _db.get_objective(conn, case)
        if objective:
            return objective
    except Exception:
        pass
    try:
        row = conn.execute("SELECT schema_json FROM case_schemas WHERE case_slug = ?",
                           (case,)).fetchone()
        if not row:
            return ""
        import json as _json
        s = _json.loads(row["schema_json"])
        return f"{(s.get('domain') or '').strip()} — {(s.get('summary') or '').strip()}".strip(" —")
    except Exception:
        return ""


def _entity_context(conn, entity: str, case: str | None) -> str:
    """The agent's briefing on its target. NOT just a bare name — it carries what
    the ingested source (the screenshots/reports) actually says about this entity,
    what the case already found in prior runs, the entity's current graph neighbors,
    and any analyst corrections. So the agent VERIFIES/REFUTES the source instead of
    starting cold, and doesn't re-assert things the analyst already rejected."""
    row = conn.execute(
        "SELECT id, canonical_name, entity_type, notes FROM entities WHERE canonical_name = ?",
        (entity,)).fetchone()
    if not row:
        return (f"Target: {entity}\n(not yet in the case DB — investigate it fresh "
                "with the OSINT tools.)")
    eid = row["id"]
    role = (row["notes"] or "").split(" — ")[0].replace("role:", "").strip()
    parts = [f"Target: {row['canonical_name']} (type={row['entity_type']}, role={role})",
             f"Case: {case or 'n/a'}."]

    # 1) WHAT THE SOURCE SAYS — the OCR'd screenshot / report text where this entity
    # appears. This is the in-image story; treat it as CLAIMS to verify or refute.
    try:
        # Scope to THIS case's reports — entities are a global pool, so without the
        # case filter another case's report text would leak into this briefing.
        case_f = "AND r.investigation = ? " if case else ""
        snips = conn.execute(
            "SELECT m.context, m.surface_form, r.title FROM mentions m "
            "JOIN reports r ON r.id = m.report_id WHERE m.entity_id = ? "
            "AND m.context IS NOT NULL AND TRIM(m.context) != '' " + case_f + "LIMIT 6",
            (eid, *((case,) if case else ()))).fetchall()
        if snips:
            parts.append("\nWHAT THE SOURCE CLAIMS (from the ingested reports — VERIFY or REFUTE, don't assume true):")
            for s in snips:
                ctx = " ".join((s["context"] or "").split())[:300]
                parts.append(f'  - [{(s["title"] or "report")[:40]}] "{ctx}"')
    except Exception:
        pass

    # 2) WHAT THE CASE ALREADY KNOWS — prior agent findings on this entity. So the
    # agent builds on them instead of re-deriving, and doesn't repeat the same run.
    try:
        case_f = "AND run.investigation = ? " if case else ""
        prior = conn.execute(
            "SELECT er.summary FROM enrichment_results er JOIN enrichment_runs run "
            "ON run.id = er.run_id WHERE run.provider_slug = 'agent' "
            "AND (run.entity_id = ? OR er.extracted_entity_id = ?) " + case_f +
            "ORDER BY er.id DESC LIMIT 8",
            (eid, eid, *((case,) if case else ()))).fetchall()
        if prior:
            parts.append("\nALREADY FOUND in prior runs (build on these, don't repeat):")
            for p in prior:
                parts.append(f"  - {' '.join((p['summary'] or '').split())[:200]}")
    except Exception:
        pass

    # 3) GRAPH NEIGHBORS — who this entity is already connected to, and how.
    try:
        nbrs = conn.execute(
            "SELECT tr.rel_type, e2.canonical_name AS name, "
            "  CASE WHEN tr.src_entity_id = ? THEN '->' ELSE '<-' END AS dir "
            "FROM typed_relationships tr "
            "JOIN entities e2 ON e2.id = CASE WHEN tr.src_entity_id = ? "
            "  THEN tr.dst_entity_id ELSE tr.src_entity_id END "
            "WHERE tr.status = 'active' AND (tr.src_entity_id = ? OR tr.dst_entity_id = ?) "
            "LIMIT 12", (eid, eid, eid, eid)).fetchall()
        if nbrs:
            parts.append("\nKNOWN CONNECTIONS (current graph — extend or correct):")
            for nb in nbrs:
                parts.append(f"  {nb['dir']} {nb['rel_type']} {nb['name'][:50]}")
    except Exception:
        pass

    # 4) ANALYST CORRECTIONS — the analyst is the top authority. Honor their dossier
    # override and NEVER re-assert a claim they rejected.
    try:
        from investigations import annotations as _ann
        ov = (_ann.get(conn, eid) or {}).get("dossier_override")
        if ov:
            parts.append(f"\nANALYST NOTE (authoritative): {' '.join(ov.split())[:300]}")
    except Exception:
        pass
    try:
        rej = conn.execute(
            "SELECT predicate, value FROM claims WHERE entity_id = ? AND status = 'rejected' "
            "LIMIT 8", (eid,)).fetchall()
        if rej:
            parts.append("\nDO NOT RE-ASSERT (analyst rejected these):")
            for c in rej:
                parts.append(f"  - {c['predicate']}: {str(c['value'])[:80]}")
    except Exception:
        pass

    parts.append("\nInvestigate this target with the OSINT tools.")
    return "\n".join(parts)


def investigate_entity(conn, entity: str, case: str | None = None,
                       max_turns: int = 28, use_mcp: bool = True, on_event=None,
                       question: str | None = None, cancel=None) -> dict:
    """Run the agent on one entity; land gated findings. Returns a summary.
    `on_event(line)` (optional) streams each agent move live for a progress UI.
    `question` (optional) is the analyst's specific ask — it steers the run instead
    of the generic end-to-end sweep. `cancel` (optional) lets Stop kill the run."""
    ctx = _entity_context(conn, entity, case)
    thesis = _case_thesis(conn, case)
    thesis_line = (f"\n\nCASE THESIS — what this investigation is trying to establish: "
                   f"{thesis}. Dig TOWARD this: follow the paths that confirm or refute "
                   f"it, not just the easy lookups." if thesis else "")
    steer = (f"\n\nANALYST'S SPECIFIC QUESTION (prioritize answering this): {question.strip()}"
             if question and question.strip() else "")
    task = (f"{ctx}{thesis_line}{steer}\n\nInvestigate this target end-to-end with the OSINT "
            "tools. Pivot through infrastructure, corroborate, chase every lead until the "
            "trail goes cold, then output the findings JSON.")
    # Warm path (KIPI_WARM_SESSION): land through the per-case warm session instead
    # of cold-booting a claude -p subprocess. The landing below is identical either
    # way — the warm run is just a different way to produce `run`. Cold is default.
    if warm_run_available():
        run = _run_agent_warm(task, case, cancel=cancel)
    else:
        run = _run_agent(task, max_turns=max_turns, use_mcp=use_mcp, on_event=on_event,
                         cancel=cancel)
    if not run.get("ok"):
        return {"ok": False, "entity": entity, "error": run.get("error")}
    parsed = _parse_findings(run["result_text"])
    steps = run.get("steps") or []
    # Cut-off rescue: the agent ran real tools but was killed before emitting findings JSON,
    # so the parse came back empty. Reconstruct findings from its own tool trail so the work
    # isn't lost — holistic, covers timeout / --max-turns cap / analyst Stop alike.
    salvaged = False
    if run.get("capped") and not parsed.get("findings"):
        rescued = _salvage_from_trail(steps, run.get("result_text") or "")
        if rescued.get("findings"):
            parsed = rescued
            salvaged = True
    # Link each finding to the real step that produced it (mutates parsed findings).
    _attribute_findings(parsed, steps)
    process = _build_process(parsed, run["result_text"], run.get("raw"),
                             run.get("capped"), steps)
    row = conn.execute("SELECT id FROM entities WHERE canonical_name = ?", (entity,)).fetchone()
    landed = land_findings(conn, case, entity, task, parsed,
                           entity_id=row["id"] if row else None, process=process,
                           started_at=run.get("started_at"),
                           cost_usd=process.get("cost_usd"))
    n_findings = len(parsed.get("findings", []))
    result = {"ok": True, "entity": entity, "case": case, "findings": n_findings,
              "cost_usd": process.get("cost_usd") or 0.0, **landed}
    if salvaged:
        # Be transparent: these findings were reconstructed from the trail after a cutoff,
        # not emitted by the agent itself.
        result["salvaged"] = True
        result["note"] = (f"reconstructed {n_findings} finding(s) from the agent's tool "
                          "trail — the run was cut off before it wrote them")
    elif not steps and n_findings == 0:
        # Ran NO tools and found nothing — startup kill, MCP/tool stall. Loud, not silent.
        result["worked"] = False
        result["note"] = ("no-work — the agent ran no tools and found nothing; "
                          "check OSINT tool/MCP startup or a run timeout")
        result["stderr_tail"] = run.get("stderr_tail") or ""
    elif run.get("capped") and n_findings == 0:
        # Ran real tools but was cut off AND the trail had nothing recoverable. Loud.
        result["worked"] = False
        result["note"] = ("cut off before recording findings and nothing was recoverable "
                          "from the trail — raise the run timeout")
        result["stderr_tail"] = run.get("stderr_tail") or ""
    return result


# --- ONE-HOP node investigation (the trimmed "Investigate this node") ----------
# The default node click runs ONE deterministic infra hop (code, no LLM) + a single short
# LLM read. Fast + cheap by design: the founder's "one node investigation should not go
# crazy and run 10 minutes — I just want info about that node." The deep 28-turn end-to-end
# agent (investigate_entity) stays for the whole-case run + explicit analyst questions.
# Plan: q-system/output/plans/deterministic-enumeration-split-2026-06-08.md
QUICK_READ_TIMEOUT = int(os.environ.get("KIPI_QUICK_READ_TIMEOUT", "60"))


def _infra_belt_for_type(entity_type: str | None) -> list[tuple[str, str | None]]:
    """The deterministic infra providers (slug, mode) for a node's type — a
    thin view of the registry's static transform map (registry.BELT_RECIPES,
    sp2-watched-types-registry): one source of "what runs on this type", not
    a hand-rolled copy. Keyless ones (crtsh/infra) always run; keyed ones
    (ipgeo/whoisxml) run only when configured."""
    from investigations.enrich.registry import belt_for_type
    return belt_for_type(entity_type)


def _cancelled(cancel) -> bool:
    """True when the analyst pressed Stop (the per-case cancel Event is set)."""
    return cancel is not None and cancel.is_set()


def _run_infra_belt(conn, entity: str, entity_type: str | None, case: str | None,
                    on_event=None, cancel=None, timeout: int = 30) -> tuple[list[int], list[str]]:
    """Run the type's infra providers in CODE (no LLM). Returns (new result ids, ran slugs).
    Unconfigured keyed providers are skipped and announced — never silently dropped.
    Stop-aware: checks `cancel` between providers, so Stop interrupts the belt (after the
    in-flight lookup returns — a single network call can't be killed mid-flight)."""
    from investigations.enrich import registry
    from investigations.enrich import runner as enrich_runner
    row = conn.execute("SELECT id FROM entities WHERE canonical_name = ?", (entity,)).fetchone()
    eid = row["id"] if row else None
    result_ids: list[int] = []
    ran: list[str] = []
    # crt.sh is the flakiest provider (routine 502s/hangs) and runs first in the belt — a
    # 30s hang there dominated one-hop expand latency. Give it a tight fail-fast timeout so
    # whois/dns aren't held up; the others keep the full timeout. KIPI_CRTSH_TIMEOUT overrides.
    try:
        _crtsh_to = max(3, int(os.environ.get("KIPI_CRTSH_TIMEOUT", "12")))
    except ValueError:
        _crtsh_to = 12
    for slug, mode in _infra_belt_for_type(entity_type):
        if _cancelled(cancel):
            if on_event:
                on_event("stopped — skipping the rest of the belt")
            break
        try:
            adapter = registry.get_adapter(slug)
        except KeyError:
            continue
        if not adapter.is_configured():
            if on_event:
                on_event(f"skip {slug} — not configured (needs a key)")
            continue
        if on_event:
            on_event(f"infra: {slug}{(' ' + mode) if mode else ''} → {entity}")
        slug_timeout = _crtsh_to if slug == "crtsh" else timeout
        out = enrich_runner.run_and_persist(conn, slug, entity, entity_id=eid, mode=mode,
                                            investigation=case, timeout=slug_timeout)
        if out.get("status") != "success":
            continue
        ran.append(slug)
        rows = conn.execute("SELECT id FROM enrichment_results WHERE run_id = ?",
                            (out["run_id"],)).fetchall()
        result_ids.extend(r["id"] for r in rows)
    return result_ids, ran


def _promote_infra_results(conn, result_ids: list[int], analyst: str) -> int:
    """Land each promotable infra result as a node + 'enriched' edge to the source node.
    Non-promotable results (provider prose) are skipped — they stay as enrichment rows."""
    from investigations.enrich import promote as promote_mod
    landed = 0
    for rid in result_ids:
        out = promote_mod.promote_result(conn, rid, analyst=analyst)
        if not out.get("error"):
            landed += 1
    return landed


def _infra_digest(conn, result_ids: list[int]) -> str:
    """The infra results as a compact text block for the read pass."""
    if not result_ids:
        return ""
    placeholders = ",".join("?" * len(result_ids))
    rows = conn.execute(
        "SELECT er.title, er.summary, run.provider_slug AS p "
        "FROM enrichment_results er JOIN enrichment_runs run ON run.id = er.run_id "
        f"WHERE er.id IN ({placeholders})", result_ids).fetchall()
    lines = []
    for r in rows:
        body = (r["summary"] or r["title"] or "").strip()
        if body:
            lines.append(f"[{r['p']}] {body[:400]}")
    return "\n".join(lines)


def _quick_read(entity: str, entity_type: str | None, digest: str, context: str) -> str:
    """ONE short LLM call (no tools, capped): what this node IS + the single best next pivot.
    Reads the already-gathered infra + case context — it does NOT dispatch its own lookups."""
    body = "\n\n".join(p for p in (digest, context) if p.strip())
    if not body.strip():
        return ""
    system = ("You are an OSINT analyst. From the infra results + context for ONE node, "
              "write 2-3 tight lines: what/who this node is, then the single best next "
              "pivot to run. Concrete, no preamble, no fluff.")
    prompt = f"Node: {entity} (type={entity_type or 'unknown'})\n\n{body}\n\nThe read:"
    try:
        return ask(prompt, system=system, tools=False, max_tokens=300,
                   timeout=QUICK_READ_TIMEOUT).strip()
    except Exception:
        return ""


def _suggest_next_hop(entity: str, entity_type: str | None, digest: str) -> str:
    """ONE short LLM call: given what expanding this node JUST surfaced, suggest the single
    best NEXT hop to expand and why. The analyst drives one hop at a time; the agent advises
    the next move (Maltego co-pilot) — e.g. domain→wallet ⇒ 'expand the wallet to find more
    wallets it transacts with, or trace its owner.' No tools, capped, fast."""
    if not (digest or "").strip():
        return ""
    system = ("You are an OSINT analyst guiding a ONE-HOP-AT-A-TIME graph investigation. "
              "Given what expanding ONE node just surfaced, name the single best NEXT hop to "
              "expand and WHY, in ONE concrete line. Name the specific entity or type to "
              "expand next (e.g. 'expand wallet 0xAB… to find more wallets or its owner'; "
              "'pivot on the shared nameserver to find sibling domains'). No preamble, no fluff.")
    prompt = (f"Just expanded: {entity} (type={entity_type or 'unknown'}).\n"
              f"What that one hop surfaced:\n{digest}\n\nBest next hop:")
    try:
        return ask(prompt, system=system, tools=False, max_tokens=160,
                   timeout=QUICK_READ_TIMEOUT).strip()
    except Exception:
        return ""


def _store_node_read(conn, entity_id: int, read: str) -> None:
    """Append the quick read to the node's dossier (same path the promote endpoint uses)."""
    from investigations import annotations as annotations_mod
    ann = annotations_mod.get(conn, entity_id) or {}
    existing = (ann.get("dossier_override") or "").strip()
    if read in existing:
        return
    block = f"**Quick read:** {read}"
    merged = (existing + "\n\n" + block).strip() if existing else block
    annotations_mod.set_dossier_override(conn, entity_id, merged, author="quick investigate")


def investigate_entity_quick(conn, entity: str, case: str | None = None,
                             on_event=None, analyst: str = "anonymous", cancel=None,
                             with_read: bool = True, suggest: bool = False) -> dict:
    """ONE-HOP node investigation: deterministic infra belt (code, no LLM) + a single short
    LLM read. Fast + cheap — "info about this node", not a whole investigation. No 28-turn
    agent, no completeness recursion, no pivoting into the network. Stop-aware: `cancel`
    interrupts the belt between lookups and skips the read.

    `with_read=False` is the Maltego EXPAND: infra belt + promote connected nodes ONLY, no
    LLM brief — pure-deterministic, grows the graph one hop, fast (~tool latency, no model).
    `suggest=True` adds ONE short LLM call after the hop that proposes the best NEXT hop
    (the agent advises; the analyst drives) — returned as `next_hop`."""
    row = conn.execute("SELECT id, entity_type FROM entities WHERE canonical_name = ?",
                       (entity,)).fetchone()
    if not row:
        return {"ok": False, "entity": entity, "error": "node not in the case DB"}
    etype = row["entity_type"]
    result_ids, ran = _run_infra_belt(conn, entity, etype, case, on_event=on_event, cancel=cancel)
    nodes_added = _promote_infra_results(conn, result_ids, analyst)
    # Stop pressed: keep what already landed, skip the LLM read, report stopped.
    if _cancelled(cancel):
        conn.commit()
        return {"ok": True, "entity": entity, "case": case, "quick": True, "stopped": True,
                "providers_run": ran, "nodes_added": nodes_added, "read": "",
                "worked": bool(result_ids)}
    # Maltego EXPAND: stop after the deterministic belt + promote — no LLM brief (the slow
    # part). The graph already grew one hop; optionally let the agent suggest the NEXT hop.
    if not with_read:
        next_hop = ""
        if suggest and result_ids:
            if on_event:
                on_event("thinking about the next hop…")
            next_hop = _suggest_next_hop(entity, etype, _infra_digest(conn, result_ids))
        conn.commit()
        return {"ok": True, "entity": entity, "case": case, "quick": True, "expand": True,
                "providers_run": ran, "nodes_added": nodes_added, "read": "",
                "next_hop": next_hop, "result_ids": result_ids, "worked": bool(result_ids)}
    if on_event:
        on_event("reading what we found…")
    read = _quick_read(entity, etype, _infra_digest(conn, result_ids),
                       _entity_context(conn, entity, case)[:1500])
    if read:
        _store_node_read(conn, row["id"], read)
    conn.commit()
    return {"ok": True, "entity": entity, "case": case, "quick": True,
            "providers_run": ran, "nodes_added": nodes_added, "read": read,
            "worked": bool(result_ids or read)}


def _edge_context(conn, src_id: int, dst_id: int, case: str | None) -> tuple:
    """Briefing for investigating a RELATIONSHIP: the two node names, the current typed
    relationship(s) between them (rel_type + evidence = the claim to confirm/refute), and
    the source context where both appear. Returns (src_name, dst_name, briefing)."""
    def nm(i):
        r = conn.execute("SELECT canonical_name FROM entities WHERE id = ?", (i,)).fetchone()
        return r["canonical_name"] if r else None
    src_name, dst_name = nm(src_id), nm(dst_id)
    if not src_name or not dst_name:
        return src_name, dst_name, ""
    parts = [f"RELATIONSHIP UNDER INVESTIGATION: {src_name}  <->  {dst_name}",
             f"Case: {case or 'n/a'}."]
    rels = conn.execute(
        "SELECT rel_type, confidence, evidence FROM typed_relationships "
        "WHERE status = 'active' AND ((src_entity_id = ? AND dst_entity_id = ?) "
        "OR (src_entity_id = ? AND dst_entity_id = ?))",
        (src_id, dst_id, dst_id, src_id)).fetchall()
    if rels:
        parts.append("\nCURRENT CLAIMS (verify or refute each — do not assume true):")
        for r in rels:
            parts.append(f"- {src_name} -[{r['rel_type']}]-> {dst_name} "
                         f"(confidence={r['confidence']}); evidence: {r['evidence'] or 'none'}")
    snips = conn.execute(
        "SELECT r.title, ms.context FROM mentions ms JOIN reports r ON r.id = ms.report_id "
        "WHERE ms.entity_id = ? AND ms.report_id IN "
        "  (SELECT report_id FROM mentions WHERE entity_id = ?) "
        "AND ms.context IS NOT NULL LIMIT 4", (src_id, dst_id)).fetchall()
    if snips:
        parts.append("\nWHERE BOTH APPEAR (source context):")
        for s in snips:
            parts.append(f"- [{s['title']}] {' '.join((s['context'] or '').split())[:200]}")
    return src_name, dst_name, "\n".join(parts)


def investigate_edge(conn, src_id: int, dst_id: int, case: str | None = None,
                     max_turns: int = 20, use_mcp: bool = True, on_event=None,
                     cancel=None) -> dict:
    """Investigate the RELATIONSHIP between two nodes (not just read it): gather OSINT
    evidence that confirms or refutes the connection, update the typed_relationship's
    evidence with the agent's verdict, and land any new findings through the normal gate.
    Bounded (analyst-driven, one pass) — the analyst chose this edge to expand."""
    src_name, dst_name, ctx = _edge_context(conn, src_id, dst_id, case)
    if not src_name or not dst_name:
        return {"ok": False, "error": "edge endpoints not found in the entity graph"}
    if not case:
        # Recover the slug so the verdict-append event lands in the right
        # case's log + bumps its version (a None case logs unfiled and
        # signals nobody — codex adversarial finding 2026-06-11).
        from investigations.enrich.promote import _primary_case
        case = _primary_case(conn, src_id) or _primary_case(conn, dst_id)
    thesis = _case_thesis(conn, case)
    thesis_line = f"\n\nCASE THESIS — dig toward this: {thesis}." if thesis else ""
    task = (f"{ctx}{thesis_line}\n\nInvestigate whether and HOW these two are connected. "
            f"Use the OSINT tools to find evidence that CONFIRMS or REFUTES the link "
            f"(shared infrastructure / registrant / money flow / same operator / co-mention "
            f"in authoritative sources). Then output the findings JSON — express the verdict "
            f"as a relationship between '{src_name}' and '{dst_name}' with its evidence + "
            f"confidence, and set unvalidated:true on anything not corroborated.")
    run = _run_agent(task, max_turns=max_turns, use_mcp=use_mcp, on_event=on_event,
                     cancel=cancel)
    if not run.get("ok"):
        return {"ok": False, "src": src_name, "dst": dst_name, "error": run.get("error")}
    parsed = _parse_findings(run["result_text"])
    steps = run.get("steps") or []
    _attribute_findings(parsed, steps)
    process = _build_process(parsed, run["result_text"], run.get("raw"),
                             run.get("capped"), steps)
    landed = land_findings(conn, case, f"{src_name} <-> {dst_name}",
                           f"EDGE: {src_name} <-> {dst_name}", parsed,
                           entity_id=src_id, process=process)
    # Append the agent's verdict to the edge's evidence (don't clobber the original).
    verdict = (parsed.get("assessment") or {}).get("best_judgment") or parsed.get("summary") or ""
    if verdict:
        from investigations import store
        store.apply_mutation(conn, store.edge_evidence_appended(
            case, src_id, dst_id, f"\n[agent] {verdict[:300]}", actor="agent"))
        conn.commit()
    return {"ok": True, "src": src_name, "dst": dst_name, "case": case,
            "findings": len(parsed.get("findings", [])), "verdict": verdict[:300],
            "cost_usd": process.get("cost_usd") or 0.0, **landed}


# --- CREW: coordinator + focused parallel sub-agents (boss + crew) -------------
# Each target is split into small FOCUSED sub-agents that run in parallel, each with a
# NARROW tool allowlist, a one-job task, and a CHEAP model (Sonnet, or Haiku for pure
# lookups — never Opus). Each returns a small findings JSON; the coordinator merges them
# deterministically and lands once. Replaces the one-giant-agent-per-target monster.
_CREW_PERSONA = (
    "You are ONE focused OSINT collection sub-agent. Do ONLY the single job you're given "
    "on the single target — do not wander into other jobs. Be fast. Use your tools, never "
    "fabricate (no invented domains/wallets/names). When done, output the findings JSON and "
    "nothing after it. If a tool fails or is rate-limited, switch or stop — don't retry it.")

CREW_TIMEOUT = int(os.environ.get("KIPI_CREW_TIMEOUT", "420"))  # per sub-agent wall-clock

ROLE_AGENTS = [
    {"role": "infra", "model": AGENT_MODEL,
     "tools": ["mcp__kipi-osint__crtsh_subdomains", "mcp__kipi-osint__whois_lookup",
               "mcp__kipi-osint__dns_lookup", "mcp__kipi-osint__reverse_dns",
               "mcp__kipi-osint__reverse_whois", "mcp__kipi-osint__dns_history",
               "mcp__kipi-osint__reverse_ns",
               "mcp__kipi-osint__shodan_host", "mcp__kipi-osint__censys_host",
               "mcp__kipi-osint__asn_lookup", "mcp__kipi-osint__greynoise",
               "mcp__kipi-osint__opencorporates"]
              + [f"Bash(./invctl osint-tool {s}:*)" for s in
                 ("crtsh", "whois", "dns", "reverse_dns", "whoisxml", "infra",
                  "shodan", "censys", "asn", "greynoise", "opencorporates")],
     "job": "Enumerate this target's INFRASTRUCTURE only: crt.sh subdomains, DNS, WHOIS/RDAP, "
            "reverse-WHOIS on the registrant email (pull sibling domains), passive/historical "
            "DNS, and HOST INTEL on any IP (shodan_host / censys_host: open ports, services, "
            "certs, CVEs, co-hosted hostnames). Do NOT web-search. Return findings for "
            "domains/IPs/emails you CONFIRMED with these tools."},
    {"role": "reputation", "model": CHEAP_MODEL,
     "tools": ["mcp__kipi-osint__virustotal", "mcp__kipi-osint__abusech",
               "mcp__kipi-osint__breach_intel"]
              + [f"Bash(./invctl osint-tool {s}:*)" for s in ("virustotal", "abusech", "breach")],
     "job": "Check this target's REPUTATION + BREACH exposure only: VirusTotal, abuse.ch, "
            "breach/infostealer. Return findings on what is flagged malicious or exposed."},
    {"role": "page", "model": AGENT_MODEL,
     "tools": list(_PLAYWRIGHT_TOOLS) + ["WebFetch", "mcp__kipi-osint__jina_read",
               "Bash(./invctl osint-tool jina:*)"],
     "job": "READ the live site: jina_read (clean markdown) / WebFetch for a cheap first "
            "pass to pull crypto WALLET addresses, payout links, affiliate/ref IDs, contact "
            "emails, linked sites. But on a SCAM/PAYMENT/JS-heavy page the BROWSER is a "
            "PRIMARY move, not a last resort: browser_navigate -> browser_wait_for, then "
            "browser_network_requests (XHR/fetch + script.js carry the payout wallet, payment "
            "API, affiliate endpoints — the 4_points script.js depth) AND browser_evaluate "
            "(JS-injected DOM). On these pages static fetch misses what matters — reach for "
            "network_requests + evaluate early. Return findings for the assets you pulled."},
    {"role": "attribution", "model": AGENT_MODEL,
     "tools": ["mcp__kipi-osint__web_search", "mcp__kipi-osint__tavily_search",
               "mcp__kipi-osint__exa_search", "mcp__perplexity__perplexity_ask",
               "mcp__reddit__reddit_search", "mcp__reddit__reddit_get_subreddit_posts"]
              + [f"Bash(./invctl osint-tool {s}:*)" for s in ("perplexity", "tavily", "exa")],
     "job": "ATTRIBUTION only: who is behind this target? Reports, scam trackers, Reddit, "
            "social. Search CHEAP FIRST — use tavily_search / exa_search before perplexity "
            "(perplexity is the costly fallback; reach for it only when tavily/exa come up "
            "empty). These are LEADS — set unvalidated:true on findings unless an "
            "authoritative source confirms them."},
]


def _role_allowlist(tools: list[str]) -> list[str]:
    """A sub-agent's narrow allowlist: keep its Bash-belt patterns + playwright + any of
    its MCP tools that are LIVE this run (dead-provider tools dropped). ToolSearch always
    on so it can load MCP schemas.

    Belt patterns for providers with NO key are dropped too — otherwise the agent keeps
    calling `./invctl osint-tool <unkeyed>` and burns a turn on a 'not configured' error
    (founder 2026-06-03). MCP tools were already key-gated via _live_allowed_tools; this
    closes the same gap on the Bash belt."""
    live = set(_live_allowed_tools())
    dead = _dead_slugs()
    keep = ["ToolSearch"]
    for t in tools:
        if t.startswith("Bash("):
            m = _re.search(r"osint-tool\s+([a-z0-9_-]+)", t)
            if m and m.group(1).lower() in dead:
                continue  # no key for this provider → don't hand the agent its belt
            keep.append(t)
        elif t in _PLAYWRIGHT_TOOLS or t in live or t == "WebFetch":
            keep.append(t)
    return keep


def _merge_crew(parsed_list: list[dict]) -> dict:
    """Deterministically merge the sub-agents' findings (NO LLM — no extra model spend).
    Dedup findings by entity, relationships by (src,dst,type); concatenate the rest."""
    merged = {"findings": [], "relationships": [], "same_as": [], "contradictions": [],
              "recommended_pivots": [], "assessment": {}, "summary": ""}
    seen_r, summaries = set(), []
    # Per entity, keep the BEST-EVIDENCED finding (most infra confirmations, then most
    # sources) — so an infra-confirmed domain is NOT overridden by a perplexity/web
    # version of the same domain that another sub-agent named (anti-contamination).
    best_finding: dict[str, tuple] = {}
    for p in parsed_list:
        for f in p.get("findings") or []:
            k = (f.get("entity") or "").strip().lower()
            if not k:
                continue
            score = ((f.get("infra_source_count") or 0), (f.get("source_count") or 0))
            cur = best_finding.get(k)
            if cur is None or score > cur[0]:
                best_finding[k] = (score, f)
        for r in p.get("relationships") or []:
            k = (str(r.get("src")), str(r.get("dst")), str(r.get("rel_type")))
            if k not in seen_r:
                seen_r.add(k)
                merged["relationships"].append(r)
        merged["same_as"] += p.get("same_as") or []
        merged["contradictions"] += p.get("contradictions") or []
        merged["recommended_pivots"] += p.get("recommended_pivots") or []
        if p.get("summary"):
            summaries.append(p["summary"])
        a = p.get("assessment") or {}
        if a.get("attributed_actor") and not merged["assessment"].get("attributed_actor"):
            merged["assessment"] = a
    # Materialize the best-evidenced finding per entity (infra-confirmed beats web-only).
    merged["findings"] = [f for _score, f in best_finding.values()]
    merged["summary"] = "\n".join(summaries)[:1000]
    return merged


def investigate_entity_crew(conn, entity: str, case: str | None = None,
                            on_event=None, cancel=None) -> dict:
    """Boss + crew: split a target into focused sub-agents that run in PARALLEL (each a
    small bounded job on a cheap model), merge deterministically, land once. No single
    100-step monster, no turn leash needed — each sub-agent finishes its one job fast."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    ctx = _entity_context(conn, entity, case)
    thesis = _case_thesis(conn, case)
    thesis_line = f"\nCASE THESIS — dig toward this: {thesis}" if thesis else ""

    def run_role(spec):
        try:
            task = (f"{ctx}{thesis_line}\n\nYOUR ONE JOB ({spec['role']}): {spec['job']}\n\n"
                    f"Output the findings JSON and nothing else:\n{_OUTPUT_JSON}")
            tagged = (lambda l, r=spec["role"]: on_event(f"[{r}] {l}")) if on_event else None
            if warm_run_available():
                # In-session fan-out (4pa-04): each role is a warm turn on the ONE
                # per-case session — ZERO new claude -p subprocesses (cold spawns 4
                # metered procs per target). The role's narrow job rides in the task.
                run = _run_agent_warm(task, case, timeout=CREW_TIMEOUT, cancel=cancel)
            else:
                run = _run_agent(task, timeout=CREW_TIMEOUT, persona=_CREW_PERSONA,
                                 allowed_tools=_role_allowlist(spec["tools"]),
                                 model=spec["model"], on_event=tagged, cancel=cancel)
            parsed = _parse_findings(run["result_text"]) if run.get("ok") else {}
            if run.get("ok"):
                _attribute_findings(parsed, run.get("steps") or [])
            return {"role": spec["role"], "parsed": parsed,
                    "steps": run.get("steps") or [], "run": run}
        except Exception as exc:
            return {"role": spec["role"], "parsed": {}, "steps": [],
                    "run": {"ok": False, "error": str(exc)[:200]}}

    def _log_role(r):
        if on_event:
            nf = len((r.get("parsed") or {}).get("findings") or [])
            on_event(f"✓ {r['role']}: {nf} finding(s)")

    results = []
    if warm_run_available():
        # Warm roles serialize on the ONE warm client, so run them SEQUENTIALLY — each
        # role gets its OWN full CREW_TIMEOUT. A threadpool here would start every role's
        # timeout clock at once and queued roles could time out before their turn (Codex
        # 4pa-04 P2). The cold path keeps real subprocess parallelism below.
        for spec in ROLE_AGENTS:
            if cancel is not None and cancel.is_set():
                break
            r = run_role(spec)
            results.append(r)
            _log_role(r)
    else:
        with ThreadPoolExecutor(max_workers=len(ROLE_AGENTS)) as pool:
            futs = {pool.submit(run_role, s): s for s in ROLE_AGENTS}
            for fut in as_completed(futs):
                if cancel is not None and cancel.is_set():
                    break
                results.append(fut.result())
                _log_role(results[-1])

    merged = _merge_crew([r["parsed"] for r in results])
    all_steps = [s for r in results for s in r["steps"]]
    total_cost = sum(((r["run"].get("raw") or {}).get("total_cost_usd") or 0.0) for r in results)
    process = _build_process(merged, merged.get("summary", ""),
                             {"total_cost_usd": total_cost or None}, False, all_steps)
    row = conn.execute("SELECT id FROM entities WHERE canonical_name = ?", (entity,)).fetchone()
    landed = land_findings(conn, case, entity, f"CREW: {entity}", merged,
                           entity_id=row["id"] if row else None, process=process)
    if on_event:
        on_event(f"crew merged: {len(merged['findings'])} finding(s), "
                 f"{landed.get('promoted', 0)} node(s)")
    return {"ok": True, "entity": entity, "case": case,
            "findings": len(merged.get("findings") or []), "cost_usd": total_cost,
            "crew": [r["role"] for r in results], **landed}


# --- Persona-driven WHOLE-CASE investigation -----------------------------------
# One agent run owns the case and drives its own paths (the 4_points model). The
# governor is turns + a wall-clock timeout on the single run; the agent self-stops
# via the completeness rubric in CASE_PERSONA. Tune with the envs.
CASE_MAX_TURNS = int(os.environ.get("KIPI_CASE_TURNS", "80"))
CASE_TIMEOUT = int(os.environ.get("KIPI_CASE_TIMEOUT", "1800"))
# RULE-114 in-flight tool-call budget for a BOUNDED pass — a circuit-breaker for a pass that
# loops on tools without finishing (the between-pass cost cap can't see inside one pass, and
# a cut-off pass reports cost_usd=0). Generous: a normal bounded run concludes well under it
# (the live 2-domain validation ran ~29 steps). Deep runs are unbudgeted (chase to completion).
CASE_TOOL_BUDGET = int(os.environ.get("KIPI_TOOL_BUDGET", "150"))
# Stop-guard (WS2 / RULE-103): a single agentic pass can self-declare "plateau" while
# untried entities still sit in the case inventory. Python then RE-SEEDS the remaining
# inventory as context for another pass — it governs WHEN to stop (pass/cost cap), never
# WHERE the agent goes (RULE-101). Bounded by passes + the deep cost cap.
CASE_MAX_PASSES = int(os.environ.get("KIPI_CASE_PASSES", "3"))

# Identical output contract to the per-target persona so _parse_findings + land_findings
# are unchanged.
_OUTPUT_JSON = """{
 "findings":[{"entity":"<value>","entity_type":"<domain|ip|subdomain|email|handle|wallet|affiliate_id|org|person|other>","claim":"<what you found, one line>","confidence":"high|medium|low","provenance":"<tool: value>","unvalidated":<true|false>}],
 "relationships":[{"src":"<entity value>","dst":"<entity value>","rel_type":"<pick EXACTLY ONE of: __REL_ENUM__ — if none fits use linked_to>","direction":"src_to_dst","confidence":"high|medium|low","provenance":"<tool: value>"}],
 "same_as":[{"entity_a":"<value>","entity_b":"<value>","confidence":"high|medium|low","provenance":"<why they are the same actor>"}],
 "negatives":[{"checked":"<what you looked for>","tool":"<tool used>","result":"no hit / cleared"}],
 "recommended_pivots":[{"entity":"<the single best next target>","why":"<what it would confirm>"}],
 "assessment":{"attributed_actor":"<who/what is behind this, or 'unknown'>","best_judgment":"<one-line bottom line>","overall_confidence":"high|medium|low","collection_gaps":"<what you could not confirm and why>"},
 "summary":"<2-3 line wrap>"
}""".replace("__REL_ENUM__", vocab_prompt_list())


# Prepended to the persona on a BOUNDED run so the prompt COOPERATES with the scope hook
# instead of fighting it (revalidation finding: the hook denied every off-case chase, but the
# "chase EVERY asset" prompt made the agent retry through every tool for 7 min instead of
# concluding). The hook is the deterministic enforcer; this makes the agent stop banging on it.
_BOUNDED_DIRECTIVE = """=== BOUNDED RUN — ANALYST-DRIVEN (RULE-112, leads-first) ===
You may ONLY investigate entities ALREADY in the case roster (your task lists them). Any NEW
entity you surface — a sibling or registrant-portfolio domain, a research-site (urlscan /
phishdestroy / domaintools) result, an off-case wallet / pixel / affiliate id — is a LEAD,
NOT a target. RECORD it in your findings (entity + why it matters) and MOVE ON.

Do NOT try to investigate a new entity with ANY tool — not whois / dns / browser /
reverse-whois, and NOT search / perplexity / exa either. The tools WILL refuse an off-case
target; retrying a refused target just burns the run. The analyst promotes a lead to expand
into it (the "do it" step).

Go DEEP on the IN-SCOPE entities (read their pages, pull their infra + assets, enumerate the
kit's variants ON the same domain). Surface everything off-case as leads. CONCLUDE and emit
your findings JSON as soon as the in-scope entities are investigated — do NOT keep trying to
map the wider network. This section OVERRIDES the "follow every new asset / keep investigating
until the network is mapped" guidance below.

"""


def _build_case_persona(bounded: bool = False) -> str:
    """The whole-case investigator persona — it DRIVES its own investigation and
    decides its own paths (replaces the Python plan→volley→re-plan loop). Ported from
    the 4_points phase doctrine, retargeted from person-dossier to scam/infra network,
    with the recursive completeness self-evaluation as the stop/continue engine.
    `bounded` prepends the leads-first directive so the prompt aligns with the scope hook."""
    _base = """You are a Senior Staff Investigator in Security, Safety & Fraud at a
FAANG-tier company. You run a WHOLE investigation end-to-end and you DRIVE IT YOURSELF.
You are NOT handed one target at a time — you read the case, form a theory, and decide
your own paths and your own order.

YOU OWN THE INVESTIGATION. Map the entire network behind this case: every related
domain, subdomain, IP, crypto wallet, affiliate/referral ID, email, and handle, plus
the links between them. You decide what to chase next and when you are done.

PHASE DOCTRINE (run it, loop as needed):
0. TOOLING. The live tools are listed below. If a tool fails, rate-limits, or returns
   'not configured', SWITCH to a fallback source immediately — NEVER retry the same
   failed tool. A rate limit is a reason to use a different tool, not a dead end.
1. SEED — INTERNAL INTEL BEFORE GOING EXTERNAL. Start from the case GOAL and the entity
   ROSTER in the task — these are the internal case-DB entities. EXHAUST them (read what
   the case already knows: every roster entity, every report mention) BEFORE spending on
   external collection. (4_points Phase 1.5: internal intel is graded high; don't skip it.)
   The roster is your entry point, not your boundary.
1b. ESCALATION TIERS — CHEAP-FIRST, escalate only as needed (4_points Levels 1->4):
   - Level 1 (free infra): crt.sh / DNS / WHOIS / RDAP / reverse-WHOIS / passive-DNS — run
     these FIRST to enumerate the cluster deterministically (pass 0 is infra-only).
   - Level 1.5 (free breach intel): check breach exposure before any paid scraping.
   - Level 2 (cheap verify): read the actual pages (jina/WebFetch).
   - Level 3 (paid scrape): apify/social_scrape for content platforms.
   - Level 4 (deep): web_search/perplexity/tavily/exa for ATTRIBUTION (who's behind it) —
     NOT for enumerating the cluster. A domain seen only in web search is a LEAD.
2. PIVOT THE NETWORK — chase links across ALL asset types, not just domains:
   - domain -> crtsh subdomains + whois + dns + reputation (virustotal/abusech)
              + who-runs-it (web_search/tavily/exa) + READ the page (jina/WebFetch),
              and from the page PULL NEW assets: sibling domains, crypto WALLET
              addresses, AFFILIATE/REF IDs in links (?ref=, ?aff=, /r/CODE), contact
              emails, social handles. On a SCAM/PAYMENT/JS-heavy page the BROWSER is a
              PRIMARY move, not a fallback: browser_navigate -> browser_wait_for, then
              browser_network_requests (XHR/fetch + script.js = payout wallet, payment
              API, affiliate endpoints — the 4_points script.js depth) AND
              browser_evaluate (JS-injected wallet/links). Reach for network_requests +
              evaluate early; do NOT report "JS constraint" and stop. If DNS is DEAD
              (no current A record), pull
              `whoisxml --mode dns_history` for the domain's HISTORICAL IPs; the dead
              seed's old IP is the link to the live cluster.
   - ip -> asn_lookup (ASN/netblock owner) + greynoise (scanner-vs-targeted) + reverse_dns +
           whois + reputation + what else it hosts. For a domain, dns_deep (SPF/DMARC + mail
           provider + AXFR attempt).
   - phone -> phone_parse (region / carrier / line-type incl. VoIP).
   - image / file -> exif_extract (GPS + device make/model/serial from EXIF).
   - wallet -> wallet_tokens (ERC-20 token flow) + tron_wallet (Tron/TRC-20) + solana_wallet
               (Solana) + blockchair_tx (LTC/BCH/DOGE) + ton_tx (TON) + wallet_cluster
               (BTC exchange cluster, T3 lead) + ofac_screen (sanctions, T1) + ens_resolve
               (name<->address) + wallet_labels (exchange/mixer tag, T3 only) +
               crypto_abuse (scam blocklist, T3 lead) + reputation +
               web_search attribution + who it pays / who funds it.
   - affiliate/ref id -> web_search the code; the SAME code on other sites = same crew.
   - email / handle -> web_search + social + holehe (email -> ~120 site registrations, T3
                       leads) + opencorporates (org/person -> officers/filings, T1 registry) +
                       git_emails (commit-author emails from a repo/handle) + darkweb_search
                       (Ahmia .onion leads — T3, hypothesis not finding); tie them to the
                       operator. For a REGISTRANT email, `whoisxml --mode reverse_whois`
                       returns its full domain portfolio (the operator's other sites = same crew).
   - content platform (tiktok / youtube / twitter-x / instagram URL or @handle)
              -> social_scrape: pull the profile + recent posts + transcript. A creator/
                 operator's actual content is the richest source — read it, don't just
                 note the link. Pull the bio, linked sites, wallets, and @mentions out
                 of it as NEW assets and chase them.
   Follow EVERY new asset you surface. A sibling domain, shared wallet, reused affiliate
   code, or linked social account is the whole point — chase it, do not just note it.
3. CROSS-REFERENCE + GRADE. Corroborate across 2+ independent tools before calling
   anything confirmed; single-source = medium/low + unvalidated=true. Resolve
   contradictions out loud. Build the STORY: emit every link in `relationships` and
   every same-actor identity in `same_as`.
   CONNECT THE CLUSTERS: if two domains/tiers run the IDENTICAL scam kit, branding, or
   page template but sit on SEPARATE infrastructure (different registrar/host/nameserver/
   wallet), emit a `same_campaign` relationship between them (confidence medium — it's a
   behavioral match, not infrastructural). Do NOT leave two obviously-same-campaign
   clusters disconnected just because they share no infra.
4. RECURSIVE COMPLETENESS — THIS IS HOW YOU DECIDE TO CONTINUE OR STOP. After each
   pass, score your OWN coverage:
     - every roster entity investigated or explicitly cleared?
     - every NEW asset you surfaced (sibling domain, wallet, affiliate id, ip, email,
       handle) chased or cleared?
     - infrastructure links mapped as relationships?
     - the CASE GOAL answered, or the remaining gaps named?
     - contradictions resolved?
   KEEP INVESTIGATING until you can answer yes, OR you have made ~3 full passes, OR a
   pass adds nothing new (plateau). Do NOT stop because a tool was rate-limited —
   switch tools and keep going. Recover silently; the analyst needs the mapped
   network, not a "got stuck" message.

RULES (non-negotiable):
- Cite the tool + value behind every claim in `provenance`. Never fabricate addresses,
  names, or links. A claim no tool RESULT contains will not enter the graph.
- WEIGH DECEPTION: whois registrant, self-reported bios, shared-CDN IPs are trivially
  faked — corroborate with sources the actor cannot edit.
- RECORD NEGATIVES: a cleared pivot is intel — put it in `negatives` so it isn't re-run.
- recommended_pivots + assessment.collection_gaps are mandatory, never empty.

TOOLS — the full belt (your Phase 0 list). Invoke via `mcp__kipi-osint__*` if available,
OR the Bash form (the dependable path):
""" + _belt_text() + """
Plus WebFetch to read a page; the perplexity / apify / reddit MCP tools when available.

OUTPUT — when the network is mapped (or you hit a stopping criterion), output EXACTLY
ONE JSON object as the final message and nothing after it. Report EVERY asset and link
you found across the whole case (not just one target):
""" + _OUTPUT_JSON + """
"""
    return (_BOUNDED_DIRECTIVE + _base) if bounded else _base


CASE_PERSONA = _build_case_persona()
CASE_PERSONA_BOUNDED = _build_case_persona(bounded=True)


def _case_roster_text(conn, case: str | None, cap: int = 40) -> str:
    """The pivotable-entity roster the case agent starts from — its entry points.
    Reuses the swarm's roster query (non-noise, scored, with role + covered flag)."""
    from investigations.agent import swarm
    roster = swarm._case_roster(conn, case, cap=cap)
    if not roster:
        return "(no entities extracted yet — start from the case goal and read the reports)"
    return "\n".join(
        f"- {e['name']}  (type={e['type']}, role={e['role']}"
        + (", already investigated — revisit only with a fresh angle" if e.get("covered") else "")
        + ")" for e in roster)


def _case_bound_roster(conn, case: str | None) -> list:
    """The leads-first roster the scope hook bounds the agent to (RULE-112): every non-noise
    entity in the case. Shared by the cold case path and the warm client so both enforce the
    same bound from one query."""
    if not case:
        return []
    return [r["canonical_name"] for r in conn.execute(
        "SELECT DISTINCT e.canonical_name FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id JOIN reports rp ON rp.id = m.report_id "
        "WHERE rp.investigation = ? AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%')",
        (case,)).fetchall()]


def _case_bound_roster_for_slug(case: str | None) -> list:
    """Open a short read connection and return the case's leads-first roster — the warm
    client factory has only a slug, not a live connection."""
    if not case or case == "default":
        return []
    from investigations.storage import db as _db
    try:
        with _db.connect() as conn:
            return _case_bound_roster(conn, case)
    except Exception:
        return []


def _content_platform_links(conn, case: str | None) -> list[tuple]:
    """Content-platform URLs already in the case (youtube / tiktok / twitter-x /
    instagram). A video/profile link dropped as evidence lands as a `url` entity; this
    hands it to the agent to social_scrape, so it becomes actual content not a dead
    domain. Returns [(url, platform), ...]."""
    if not case:
        return []
    from investigations.enrich import social
    rows = conn.execute(
        "SELECT DISTINCT e.canonical_name AS v FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation = ? AND e.entity_type IN ('url', 'handle')",
        (case,)).fetchall()
    out, seen = [], set()
    for row in rows:
        v = row["v"]
        plat = social.detect_platform(v)
        if plat and v not in seen:
            seen.add(v)
            out.append((v, plat))
    return out[:20]


def enum_wiring_on() -> bool:
    """Stage-1 wiring flag (speed-cost-staged-rollout plan): when on, the case task
    tells the agent to use ONE enumerate_infra call instead of per-entity infra
    dispatch. DEFAULT OFF after the 2026-06-09 A/B: wired runs produced consistently
    smaller graphs (11/13 and 13/28 entities/edges) than unwired runs (19/26, 19/45)
    for ~25% cost saving — bad trade, the depth is the product. The enumerate tool
    stays available to the agent; only the prompt steering is off. KIPI_ENUM_PROMPT=1
    re-enables for future A/Bs."""
    import os
    return os.environ.get("KIPI_ENUM_PROMPT", "0").strip() not in ("0", "false", "no")


def preseed_on() -> bool:
    """Stage-2 flag: deterministic infra pre-seed before the whole-case agent boots.
    Default ON (additive only — nothing is taken from the agent). KIPI_PRESEED=0
    disables, giving the differential gate its control arm."""
    import os
    return os.environ.get("KIPI_PRESEED", "1").strip() not in ("0", "false", "no")


def _enum_prompt_block(case: str | None) -> str:
    if not enum_wiring_on():
        return ""
    return (f"ENUMERATE FIRST, IN ONE CALL: mcp__kipi-osint__enumerate_infra with "
            f'case="{case}" runs the whole deterministic infra sweep (crt.sh, whois/RDAP, '
            f"DNS, reverse-DNS, reverse-whois) over every seed + the tier-2 infra it "
            f"surfaces, and LANDS the nodes/edges for you. Call it once at the start; "
            f"call it again (with seeds=[...]) only when you surface a NEW domain "
            f"cluster. Do NOT run whois_lookup/dns_lookup/crtsh_subdomains entity by "
            f"entity — that's covered. Spend your turns on what only you can do: read "
            f"the content, attribute the operator, weigh deception, judge the links.\n\n")


def _build_case_task(conn, case: str | None) -> str:
    """The whole-case task: goal + thesis + the entity roster + content links + live
    tool status."""
    from investigations.agent import swarm
    from investigations.storage import db as _db
    objective = _db.get_objective(conn, case)
    thesis = _case_thesis(conn, case)
    roster = _case_roster_text(conn, case)
    links = _content_platform_links(conn, case)
    tools = swarm.tool_status()
    live = ", ".join(tools.get("live", [])) or "none configured"
    missing = ", ".join(m["name"] for m in tools.get("missing", [])) or "none"
    goal_line = (f"\n\nCASE GOAL — the investigation must answer this, scope everything to it:\n  {objective}"
                 if objective else "")
    thesis_line = (f"\n\nCASE THESIS (what we're trying to establish): {thesis}" if thesis else "")
    links_block = ""
    if links:
        link_lines = "\n".join(f"  - {u}  ({p})" for u, p in links)
        links_block = ("\n\nCONTENT-PLATFORM LINKS already in this case — call "
                       "social_scrape on EACH to pull the real profile + posts + "
                       f"transcript (don't treat them as bare links):\n{link_lines}")
    return (f"INVESTIGATE THIS WHOLE CASE: {case or '(unscoped)'}."
            f"{goal_line}{thesis_line}\n\n"
            f"ENTITY ROSTER — your entry points (pivot out from these across ALL asset types):\n"
            f"{roster}{links_block}\n\n"
            f"PHASE 0 — TOOLS LIVE THIS RUN: {live}.\n"
            f"NOT available (do not call): {missing}.\n\n"
            f"{_enum_prompt_block(case)}"
            f"Drive the investigation yourself: pivot the network, chase every new asset "
            f"(sibling domains, wallets, affiliate IDs, IPs, emails, handles), score your "
            f"own completeness, and keep going until the network is mapped or you plateau. "
            f"Then output the findings JSON for the WHOLE case.")


def _continuation_task(case: str | None, covered_count: int, uninvestigated: list[str]) -> str:
    """Pass N>0 task: re-seed the STILL-uninvestigated inventory as context. The agent
    still picks its own paths (RULE-101); Python only hands it the untried roster."""
    roster = "\n".join(f"- {t}" for t in uninvestigated[:40])
    return (f"CONTINUE investigating case: {case or '(unscoped)'}.\n"
            f"You have already covered ~{covered_count} entit(ies) in prior passes — do "
            f"NOT repeat those pivots. These pivotable entities are STILL UNINVESTIGATED; "
            + (f'for the domains/IPs/emails among them call mcp__kipi-osint__enumerate_infra '
               f'(case="{case}", seeds=[...]) ONCE instead of per-entity infra lookups, then '
               if enum_wiring_on() else "")
            + f"pivot out from EACH across ALL asset types (sibling domains, wallets, "
            f"affiliate/ref IDs, IPs, emails, handles), chase the new links, corroborate:\n"
            f"{roster}\n\n"
            f"Output the findings JSON for what you find THIS pass (every new asset + link).")


def _land_pass(conn, case: str | None, task: str, run: dict) -> tuple[dict, dict]:
    """Parse → attribute → build process → land one pass's findings. Returns
    (parsed, landed). Best-effort same-campaign cleanup after."""
    parsed = _parse_findings(run["result_text"])
    # Durability: a CAPPED run (timeout / cancel / watchdog kill) usually dies BEFORE the
    # agent emits its findings JSON, so result_text has none and the case path used to land
    # ZERO — a destructive stop. Reconstruct from the agent's OWN tool trail instead, the
    # same salvage investigate_entity + the warm path already use. No termination path
    # should lose work (the timer is a circuit-breaker, not a guillotine).
    if run.get("capped") and not parsed.get("findings"):
        rescued = _salvage_from_trail(run.get("steps") or [], run.get("result_text") or "")
        if rescued.get("findings"):
            parsed = rescued
    _attribute_findings(parsed, run.get("steps") or [])
    process = _build_process(parsed, run["result_text"], run.get("raw"),
                             run.get("capped"), run.get("steps") or [])
    landed = land_findings(conn, case, f"CASE: {case}", task, parsed,
                           entity_id=None, process=process)
    landed["cost_usd"] = process.get("cost_usd") or 0.0
    try:
        from investigations import graph_cleanup
        graph_cleanup.cleanup(conn, case)
    except Exception:
        pass
    return parsed, landed


def _covered_names(parsed: dict, run: dict, seeded: list[str]) -> set[str]:
    """Entities ACTUALLY investigated this pass (C4/C5): names the agent reported
    (findings + relationship/same_as endpoints) PLUS any seeded-roster entity the agent
    actually ran a tool on (it appears in a step input). Seeded entities the agent never
    reached (turn/timeout) are deliberately NOT marked seen, so the next pass re-chases
    them instead of falsely declaring 'exhausted'."""
    names: set[str] = set()
    for f in parsed.get("findings", []) or []:
        e = (f.get("entity") or "").strip().lower()
        if e:
            names.add(e)
    # NOTE: relationship/same_as ENDPOINTS are deliberately NOT marked seen — an edge
    # endpoint is a (possibly brand-new) pivot, not something investigated. Marking it
    # would suppress it from later passes (Codex). Only seeded entities the agent
    # actually ran a tool on count as investigated.
    step_blob = " ".join(str(st.get("input", "")) for st in (run.get("steps") or [])).lower()
    names |= {t for t in seeded if t and t in step_blob}
    return names


def _completeness_score(parsed: dict) -> dict:
    """G-COMPLETENESS (4_points Phase 5): a numeric completeness read of the case —
    a coverage_check (findings? infra-confirmed nodes? relationships? assessment?
    next-pivots?), a source_diversity count (distinct tools that produced findings), and
    a 0..1 depth_score. Surfaced so a run is judged on quality, not just 'inventory empty'."""
    findings = parsed.get("findings", []) or []
    rels = parsed.get("relationships", []) or []
    a = parsed.get("assessment") or {}
    coverage_check = {
        "has_findings": bool(findings),
        "has_infra_confirmed": any((f.get("infra_source_count") or 0) >= 1 for f in findings),
        "has_relationships": bool(rels),
        "has_assessment": bool(a.get("attributed_actor") or a.get("best_judgment")),
        "has_next_pivots": bool(parsed.get("recommended_pivots")),
    }
    source_diversity = len({f.get("step_tool") for f in findings if f.get("step_tool")})
    depth_score = round(sum(1 for v in coverage_check.values() if v) / len(coverage_check), 2)
    return {"coverage_check": coverage_check, "source_diversity": source_diversity,
            "depth_score": depth_score}


def _coverage_met(completeness: dict) -> bool:
    """k4p-02 completeness STOP condition (4_points Phase 5): the case is covered when the
    network is found, attributed, AND its links are mapped — found stuff (has_findings) +
    a who/what assessment (has_assessment) + at least one mapped relationship
    (has_relationships). This is what 4_points concludes on, NOT a budget or hop count."""
    cc = (completeness or {}).get("coverage_check") or {}
    return bool(cc.get("has_findings") and cc.get("has_assessment")
                and cc.get("has_relationships"))


# Attributive edge types that put a NEW entity in-scope (it's tied to an in-case entity by
# a signal the actor can't trivially fake away — not a mere web co-mention).
_ATTRIBUTIVE_RELS = ("registered_by", "hosted_on", "resolves_to", "same_operator",
                     "same_campaign", "operates", "drains_to", "uses_affiliate", "member_of")


def _in_scope(conn, name: str, case: str | None) -> bool:
    """k4p-02 relevance boundary that REPLACES the roster cage. An entity is in-scope to
    pivot on / count as progress if it is (1) already an entity in this case (a seed or a
    derived node), or (2) linked by an ATTRIBUTIVE typed-relationship to an in-case entity
    (shared registrant / dedicated IP / cert / same_campaign). A web-co-mention-only name
    is NOT in-scope — it's recorded as a graded lead, not chased. Pure read; no writes."""
    if not isinstance(name, str) or not name.strip() or not case:
        return False
    name = name.strip()
    row = conn.execute("SELECT id FROM entities WHERE canonical_name = ?", (name,)).fetchone()
    if not row:
        return False
    eid = row["id"]
    # (1) already scoped into this case via a mention.
    in_case = conn.execute(
        "SELECT 1 FROM mentions m JOIN reports r ON r.id = m.report_id "
        "WHERE m.entity_id = ? AND r.investigation = ? LIMIT 1", (eid, case)).fetchone()
    if in_case:
        return True
    # (2) attributive edge to an entity that IS in this case.
    placeholders = ",".join("?" * len(_ATTRIBUTIVE_RELS))
    linked = conn.execute(
        f"SELECT 1 FROM typed_relationships tr "
        f"WHERE tr.rel_type IN ({placeholders}) "
        f"AND (tr.src_entity_id = ? OR tr.dst_entity_id = ?) "
        f"AND (tr.src_entity_id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
        f"       ON r.id = m.report_id WHERE r.investigation = ?) "
        f"  OR tr.dst_entity_id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
        f"       ON r.id = m.report_id WHERE r.investigation = ?)) LIMIT 1",
        (*_ATTRIBUTIVE_RELS, eid, eid, case, case)).fetchone()
    return bool(linked)


def write_case_seeds(conn, case: str | None) -> int:
    """Materialize the case's intake entities as scoring seeds (PRD
    graph-machinery-activation, gma-1): every non-noise entity mentioned in the
    analyst's intake reports (anything that is not enrichment/manual output)
    gets a `seeds` row, so compute_threat_scores' seed prior + propagation light
    up the graph the agent builds outward from those entry points. Idempotent:
    UNIQUE(entity_id, source_file) makes re-runs no-ops. Returns rows added."""
    if not case:
        return 0
    rows = conn.execute(
        "SELECT DISTINCT e.id FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id "
        "WHERE r.investigation = ? "
        "AND r.source_type NOT IN ('enrichment', 'manual') "
        "AND (e.notes IS NULL OR e.notes NOT LIKE 'role:noise%')",
        (case,)).fetchall()
    added = 0
    for r in rows:
        cur = conn.execute(
            "INSERT OR IGNORE INTO seeds (entity_id, label, source_file, weight) "
            "VALUES (?, 'case-intake', ?, 1.0)", (r["id"], f"case:{case}"))
        added += cur.rowcount
    conn.commit()
    return added


def investigate_case_agentic(conn, case: str | None, max_turns: int = CASE_MAX_TURNS,
                             timeout: int = CASE_TIMEOUT, use_mcp: bool = True,
                             on_event=None, cancel=None,
                             max_passes: int = 1, deep: bool = True,
                             caged: bool = False) -> dict:
    """Persona-driven whole-case investigation. Each PASS is one agent run that drives
    its own paths (RULE-101 — no Python plan→volley→re-plan). Between passes a Python
    STOP-GUARD (RULE-103) checks the case's uninvestigated inventory: if untried entities
    remain and the pass/cost budget is not spent, it re-seeds them as context and runs
    another pass — so a single pass's self-declared "plateau" can no longer abandon a
    large untried inventory. Stops on: inventory empty (exhausted), cost cap, pass cap,
    or analyst cancel. Findings land + auto-promote each pass.

    `caged` (k4p-01, default OFF): when True, RULE-112 leads-first is enforced — the
    agent may only INVESTIGATE entities already in the case roster; a newly-surfaced
    one is denied by the PreToolUse hook and lands as a lead. This is the opt-in
    shallow/cheap mode. The DEFAULT (caged=False) is the 4_points shape: the single
    agent pivots freely to every seed and the assets it surfaces (the cage was the
    case-031 operator miss — it forbade the WHOIS-on-the-second-seed pivot)."""
    from investigations.agent import swarm
    from investigations import activity as activity_mod
    # Seed-persistence (k4p-01): materialize a domain node for every url-seed host so
    # EVERY user seed is a first-class node the agent works and edges can link to.
    swarm.ensure_seed_domains(conn, case)
    # Scoring seeds (gma-1): the intake roster becomes `seeds` rows so the score
    # formula's seed prior + propagation cover the graph this run builds.
    seeded = write_case_seeds(conn, case)
    if seeded and on_event:
        on_event(f"registered {seeded} intake entit(y/ies) as scoring seeds")
    # Stage-2 pre-seed (speed-cost-staged-rollout): the deterministic infra sweep runs
    # in CODE before the agent boots — first nodes hit the canvas in seconds instead of
    # at end-of-run, and the agent starts from a built graph. ADDITIVE ONLY: the agent
    # itself is untouched (same prompt, full belt); it just finds the mechanical half
    # already landed. KIPI_PRESEED=0 disables (the gate's control arm).
    if preseed_on():
        import time as _time
        _t0 = _time.monotonic()
        if on_event:
            on_event("pre-seeding: deterministic infra sweep over the seeds (no LLM)…")
        try:
            from investigations.enrich import enumerate as _enum
            pre = _enum.enumerate_infra(conn, case, on_event=on_event, cancel=cancel)
            if on_event:
                on_event(f"pre-seed done in {_time.monotonic() - _t0:.0f}s — "
                         f"{pre['results']} lookup result(s) landed; the agent starts "
                         f"from a built graph")
        except Exception as exc:
            # Pre-seed is an accelerant, never a gate: a belt failure must not block
            # the investigation itself.
            if on_event:
                on_event(f"pre-seed skipped ({exc}) — agent runs from raw seeds")
    # Ground every pass in the case's confirmed actors (PRD prd-identity-anchor). Built ONCE;
    # reference_prompt is '' for an empty reference, so day-one cases are unchanged.
    reference = identity_anchor.build_reference(conn, case)
    cost_cap = swarm.DEEP_COST_CAP_USD
    seen: set[str] = set()
    agg = {"results": 0, "promoted": 0, "gated": 0, "prose_indicators": 0,
           "relationships": 0, "same_as": 0}
    spent, findings_total, last_parsed, summary = 0.0, 0, {}, ""
    last_completeness: dict = {}
    run_id = None
    stopped = False
    stop_reason = "exhausted"
    prev_depth = 0.0  # k4p-02: track coverage improvement to detect a genuinely dry pass
    last_assessment: dict = {}  # k4p-02: cumulative (keep the last non-empty attribution)
    # RULE-112 scope bound (leads-first) — OPT-IN only (caged=True). Decoupled from
    # `deep` (k4p-01): un-caging is the default so one agent works every seed + pivots
    # freely, like 4_points. `caged` re-enables the bound for the shallow/cheap mode.
    bound_roster = None
    if caged and case:
        bound_roster = _case_bound_roster(conn, case)
    pass_no = 0
    while pass_no < max_passes:
        # Don't START a NEW pass once cancelled — but pass 0 always runs so a stop
        # mid-run still salvages + lands what the agent got (never discard pass 0's
        # work). _run_agent itself honors `cancel` and salvages on kill; the post-pass
        # `if stopped` break below ends the loop after landing.
        if pass_no > 0 and cancel is not None and cancel.is_set():
            stopped, stop_reason = True, "cancelled"
            break
        if pass_no == 0:
            if on_event:
                on_event("planning the case — the investigator is driving its own paths…")
            task = _build_case_task(conn, case)
        else:
            # k4p-02: only CHASE in-scope entities (seed / attributively-linked). A bare
            # web-co-mention stays a graded lead, not a continuation target — this wires
            # the _in_scope relevance boundary onto the run path (Codex), replacing the
            # roster cage with relevance instead of a hard deny.
            uninvestigated = [t for t in swarm._uninvestigated_targets(conn, case, seen, 40 + len(seen))
                              if _in_scope(conn, t, case)]
            if not uninvestigated:
                stop_reason = "exhausted"
                break
            if on_event:
                on_event(f"pass {pass_no + 1}: {len(uninvestigated)} entit(ies) still "
                         f"uninvestigated — chasing them [${spent:.2f} of ${cost_cap:.2f}]")
            task = _continuation_task(case, len(seen), uninvestigated)
            seeded = [t.lower() for t in uninvestigated[:40]]

        if pass_no == 0:
            # The roster the first task handed the agent — candidates to mark seen, but
            # only the ones it ACTUALLY investigates (computed after the pass, C4/C5).
            seeded = [t.lower() for t in swarm._targets(conn, case, 40)]
        # C6: best-effort pre-pass budget guard — skip launching a continuation pass when
        # the projected cost (avg-so-far) already exceeds the cap, instead of only the
        # post-pass check (which catches an actual overshoot). The post-pass check below
        # remains the hard backstop for a non-linear/rising next pass.
        if pass_no > 0 and spent + (spent / pass_no) > cost_cap:
            stop_reason = "cost-capped"
            break
        # G-INFRA-FIRST: pass 0 enumerates with infra tools ONLY (no web recall); later
        # passes get the full belt for attribution.
        pass_tools = _infra_first_allowlist(_live_allowed_tools()) if pass_no == 0 else None
        # Append the confirmed-actor grounding to this pass's task ('' when no actor confirmed).
        task = task + identity_anchor.reference_prompt(reference)
        run = _run_agent(task, max_turns=max_turns, timeout=timeout, use_mcp=use_mcp,
                         on_event=on_event,
                         persona=CASE_PERSONA_BOUNDED if bound_roster else CASE_PERSONA,
                         cancel=cancel, allowed_tools=pass_tools, scope_roster=bound_roster,
                         # k4p-02 (Codex): install the per-pass tool budget on EVERY run,
                         # not only caged ones — the un-caged default loops to completeness
                         # and must be bounded per pass, not just by the post-pass $ check.
                         tool_budget=CASE_TOOL_BUDGET)
        stopped = bool(run.get("cancelled"))
        if not run.get("ok"):
            if pass_no == 0:
                return {"ok": stopped, "case": case, "agentic": True, "stopped": stopped,
                        "findings": 0, "error": None if stopped else run.get("error")}
            break  # a later pass failed/cancelled — keep what earlier passes landed

        parsed, landed = _land_pass(conn, case, task, run)
        # C4/C5: mark seen only what this pass ACTUALLY investigated, AFTER it succeeded.
        seen |= _covered_names(parsed, run, seeded)
        last_completeness = _completeness_score(parsed)  # G-COMPLETENESS
        run_id = landed.get("run_id") or run_id
        last_parsed = parsed
        if parsed.get("assessment"):
            last_assessment = parsed["assessment"]  # k4p-02: cumulative attribution
        summary = landed.get("summary") or summary
        for k in agg:
            agg[k] += landed.get(k, 0) or 0
        spent += landed.get("cost_usd", 0.0)
        new_finds = len(parsed.get("findings", []) or [])
        findings_total += new_finds
        if on_event:
            on_event(f"pass {pass_no + 1}: +{new_finds} finding(s), "
                     f"+{landed.get('promoted', 0)} node(s)")
        pass_no += 1

        if stopped:
            stop_reason = "cancelled"
            break
        if spent >= cost_cap:
            stop_reason = "cost-capped"
            break
        # k4p-02 COMPLETENESS-AS-STOP (4_points Phase 5): the run concludes on coverage,
        # not a hop count or a budget. Coverage is CUMULATIVE over the whole case (Codex):
        # every in-scope target worked + the case attributed (assessment) + its links
        # mapped (relationships exist in the case) — NOT just "the last pass had a finding".
        depth = float(last_completeness.get("depth_score") or 0.0)
        all_worked = not swarm._uninvestigated_targets(conn, case, seen, 40 + len(seen))
        case_has_rels = bool(conn.execute(
            "SELECT 1 FROM typed_relationships tr WHERE tr.status='active' AND ("
            " tr.src_entity_id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
            "   ON r.id = m.report_id WHERE r.investigation = ?)"
            " OR tr.dst_entity_id IN (SELECT m.entity_id FROM mentions m JOIN reports r "
            "   ON r.id = m.report_id WHERE r.investigation = ?)) LIMIT 1",
            (case, case)).fetchone()) if case else False
        cumulative = {"coverage_check": {"has_findings": findings_total > 0,
                                         "has_assessment": bool(last_assessment),
                                         "has_relationships": case_has_rels}}
        if all_worked and _coverage_met(cumulative):
            stop_reason = "covered"
            break
        # Genuinely dry: a full pass added no findings AND coverage did not improve.
        if new_finds == 0 and depth <= prev_depth:
            stop_reason = "dry"
            break
        prev_depth = depth
        # STOP-GUARD: every in-scope target worked but the case isn't "covered" (no
        # attribution / no mapped links) — worked-but-thin, stop as exhausted.
        if all_worked:
            stop_reason = "exhausted"
            break
    else:
        stop_reason = "max-passes"  # hard backstop hit with coverage still open

    if on_event:
        verb = "stopped — kept" if stopped else f"✓ case mapped ({stop_reason}):"
        on_event(f"{verb} {findings_total} finding(s), {agg['promoted']} graph node(s) "
                 f"over {pass_no} pass(es)")
    activity_mod.log(conn, "agent-investigator",
                     f"persona-driven case investigation{' (stopped)' if stopped else ''}: "
                     f"{findings_total} findings, {agg['promoted']} graph nodes, "
                     f"{pass_no} pass(es), stop={stop_reason}",
                     investigation=case)
    return {"ok": True, "case": case, "deep": deep, "agentic": True, "stopped": stopped,
            "findings": findings_total, "cost_usd": spent, "passes": pass_no,
            "stop_reason": stop_reason, "run_id": run_id,
            "assessment": last_parsed.get("assessment") or {},
            "recommended_pivots": last_parsed.get("recommended_pivots") or [],
            "summary": summary, "completeness": last_completeness,
            "tools": swarm.tool_status(), **agg}
