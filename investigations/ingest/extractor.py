"""Entity + relationship extraction. Regex-first, LLM optional fallback."""
import re
from dataclasses import dataclass
from typing import Iterable

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
URL_RE = re.compile(r"https?://[^\s<>\")]+")
# A bare scheme://host/ URL (no real path) IS just the domain — DOMAIN_RE already
# extracts the host, so emitting a separate 'url' node only duplicates the domain dot.
_BARE_URL_RE = re.compile(r"^https?://[^/]+/?$")
HANDLE_RE = re.compile(r"(?<![\w@])@[A-Za-z0-9_]{2,32}\b")
TELEGRAM_RE = re.compile(r"\b(?:t\.me|telegram\.me)/(?:joinchat/)?([A-Za-z0-9_-]{3,})", re.IGNORECASE)
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b")
WALLET_RE = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{6,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
# Abuse/fraud domains live on cheap weird TLDs, so DOMAIN_RE captures ANY final label
# and extract_all validates it against DOMAIN_TLDS — broad on the gTLDs abuse favors
# (.xyz/.top/.icu/.cyou/.sbs/.cfd/.shop/.vip/...), Freenom (.tk/.ml/.ga/.cf/.gq), and
# common ccTLDs (incl .us), but deliberately OMITTING ccTLDs that collide with source
# file extensions (.md .py .rs .sh .so .pe) so "README.md" / "main.py" never get typed
# as domains. Widen by adding to the set below — the regex doesn't change.
_TLD_LEGACY = "com net org info biz name pro mobi tel asia cat jobs aero coop museum"
_TLD_GTLD = ("io ai co me tv cc ws app dev cloud tech space world life today news blog "
             "email link click media network agency solutions services group team plus "
             "run now one zone fyi studio photos pics host press website digital center "
             "support online site live shop store work")
_TLD_ABUSE = ("xyz top club icu cyou sbs cfd quest bond beauty hair makeup skin cam wiki "
              "monster buzz lol mom fun vip rest autos boats motorcycles gdn stream "
              "download loan win bid trade date review country kim science party "
              "gq tk ml ga cf pw su")
_TLD_CC = ("us uk ca au nz de fr es it nl be ch at se no fi dk pt pl gr cz hu ro bg ie "
           "ru cn hk tw jp kr sg in br mx ar cl za ng ke eg tr ua by kz ge il sa ae ir "
           "pk id th vn my ph is im li lu ee lv lt si hr sk onion")
DOMAIN_TLDS = frozenset(
    f"{_TLD_LEGACY} {_TLD_GTLD} {_TLD_ABUSE} {_TLD_CC}".split())
DOMAIN_RE = re.compile(r"\b(?!www\.)(?:[a-zA-Z0-9-]+\.)+([a-zA-Z]{2,24})\b")
PERSON_HINT_RE = re.compile(r"\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})")
PROPER_NAME_RE = re.compile(r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3})\b")

# --- Web/ad-tech + crypto fraud fingerprints (the pivot layer) -------------
# Precise patterns (low false-positive) — extracted unconditionally:
TRACKING_TAG_RE = re.compile(r"\b(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{6,8}|AW-\d{9,11})\b")
TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
# Ambiguous patterns (match many strings) — only emitted when a chain/service
# keyword sits in the surrounding context (see _scan_gated). Without the gate
# these flood every case with false entities.
WALLETCONNECT_RE = re.compile(r"\b[0-9a-f]{32}\b")          # collides with md5 → gate
SOL_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")     # base58 → gate
XRP_RE = re.compile(r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b")    # base58 → gate

# Gate keywords (case-insensitive substrings within the context window).
GATE_WALLETCONNECT = ("walletconnect", "projectid", "project id", "web3modal", "wagmi", "reown")
GATE_SOL = ("solana", "sol ", "phantom", "spl", "$sol", "sol/")
GATE_XRP = ("xrp", "ripple", "xrpl", "destinationtag", "destination tag")
# Presence flags for the tech stack of a fraud site (emitted once per match).
TECH_STACK_RE = re.compile(
    r"\b(__NUXT__|ethers\.js|web3\.js|@?walletconnect|window\.ethereum|connect-wallet|next\.js|nuxt)\b",
    re.IGNORECASE)
# Third-party SaaS widget / service-account id: a known vendor + an id label +
# the value. The id label keeps it precise (vs grabbing any word after the vendor).
SAAS_ACCOUNT_RE = re.compile(
    r"(?i)\b(?:jivosite|jivo|intercom|tawk\.to|tawk|crisp|tidio|livechat|zendesk|drift)\b"
    r"[^\n]{0,25}?\b(?:account[ _]?id|widget[ _]?id|app[ _]?id|site[ _]?id|id)\b[:#\s]*"
    r"([A-Za-z0-9]{8,24})\b")
# WHOIS field lines (only present when raw WHOIS text is ingested).
REGISTRAR_RE = re.compile(r"(?im)^\s*Registrar:\s*(.+?)\s*$")
NAMESERVER_RE = re.compile(r"(?im)^\s*Name\s*Server:\s*(.+?)\s*$")

CONTEXT_WINDOW = 120
GATE_WINDOW = 60          # how far around a match a gate keyword may sit


@dataclass
class Extracted:
    surface: str
    entity_type: str
    canonical: str
    context: str
    offset: int


def _ctx(text: str, start: int, end: int) -> str:
    s = max(0, start - CONTEXT_WINDOW)
    e = min(len(text), end + CONTEXT_WINDOW)
    return text[s:e].replace("\n", " ").strip()


def _scan(text: str, pattern: re.Pattern, entity_type: str,
          canonical_fn=None, claimed: set | None = None,
          predicate=None) -> Iterable[Extracted]:
    seen_offsets: set[int] = set()
    for m in pattern.finditer(text):
        if m.start() in seen_offsets:
            continue
        # Cross-type precedence: skip a span already claimed by a more specific
        # scan (e.g. a 32-hex already typed walletconnect_id won't re-type as md5).
        if claimed is not None and m.start() in claimed:
            continue
        # Optional validity gate (e.g. DOMAIN_RE: the captured TLD must be a real one).
        # Rejected matches don't claim their span, so a later scan can still type it.
        if predicate is not None and not predicate(m):
            continue
        seen_offsets.add(m.start())
        if claimed is not None:
            claimed.add(m.start())
        surface = m.group(0)
        canonical = canonical_fn(m) if canonical_fn else surface.lower().strip()
        yield Extracted(
            surface=surface,
            entity_type=entity_type,
            canonical=canonical,
            context=_ctx(text, m.start(), m.end()),
            offset=m.start(),
        )


def _scan_gated(text: str, pattern: re.Pattern, entity_type: str, gates: tuple,
                canonical_fn=None, claimed: set | None = None) -> Iterable[Extracted]:
    """Like _scan, but only emits a match when one of `gates` (lowercase
    substrings) sits within GATE_WINDOW chars of it. For ambiguous patterns
    (base58 addresses, bare 32-hex) that would otherwise match half the document.
    Claims a span ONLY when it passes the gate + is emitted, so a filtered-out
    match doesn't starve a later scan of the same span."""
    low = text.lower()
    seen: set[int] = set()
    for m in pattern.finditer(text):
        if m.start() in seen:
            continue
        if claimed is not None and m.start() in claimed:
            continue
        s = max(0, m.start() - GATE_WINDOW)
        end = min(len(low), m.end() + GATE_WINDOW)
        if not any(g in low[s:end] for g in gates):
            continue
        seen.add(m.start())
        if claimed is not None:
            claimed.add(m.start())
        surface = m.group(0)
        canonical = canonical_fn(m) if canonical_fn else surface.lower().strip()
        yield Extracted(surface=surface, entity_type=entity_type, canonical=canonical,
                        context=_ctx(text, m.start(), m.end()), offset=m.start())


# Phone-specific NOUNS only (word-boundary-anchored so 'tel' doesn't fire on
# 'Hotel'). Deliberately NOT 'call'/'contact' — those are action words that sit
# beside non-phone numbers ('contact id 1234567890', 'call me re ticket 998877').
# A real phone after call/contact carries '+' or formatting, which already pass.
_PHONE_LABEL_RE = re.compile(r"\b(phone|tel|mobile|cell|fax|whatsapp|msisdn)\b",
                             re.IGNORECASE)


def _looks_like_phone(m) -> bool:
    """Accept a '+' prefix, formatting separators, OR a phone/tel/mobile label
    anywhere in the ~24 chars right before the match (the structured-scrape
    bare-digit shape: 'Phone: …', 'tel no: …', 'mobile phone number: …').
    Reject everything else so unlabeled counters/IDs/timestamps don't become
    phone nodes."""
    s = m.group(0)
    if "+" in s or re.search(r"[\s().-]", s):
        return True
    # search() with pos/endpos (not a sliced copy) so \b evaluates against the
    # REAL neighboring chars — a slice would cut 'Hotel' into 'tel' and forge a
    # word boundary the original text doesn't have.
    return bool(_PHONE_LABEL_RE.search(m.string, max(0, m.start() - 24), m.start()))


def _wallet_canonical(m) -> str:
    """Case-normalize a wallet address by family: EVM (0x) + bech32 (bc1)
    lowercase (case-insensitive, so this dedupes); base58 (1.../3...) preserved
    verbatim (case-sensitive — lowercasing corrupts it into an invalid twin)."""
    s = m.group(0)
    low = s.lower()
    return low if (low.startswith("0x") or low.startswith("bc1")) else s


def extract_all(text: str) -> list[Extracted]:
    """Run all regex extractors. Returns deduplicated list."""
    out: list[Extracted] = []
    out.extend(_scan(text, EMAIL_RE, "email"))
    # Skip bare scheme://host URLs — they duplicate the domain (extracted below by DOMAIN_RE).
    out.extend(e for e in _scan(text, URL_RE, "url") if not _BARE_URL_RE.match(e.surface.strip()))
    out.extend(_scan(text, HANDLE_RE, "handle"))
    out.extend(_scan(
        text, TELEGRAM_RE, "telegram_channel",
        canonical_fn=lambda m: f"t.me/{m.group(1).lower()}",
    ))
    # A real phone carries a '+' country prefix, formatting separators
    # (spaces / () / . / -), OR a phone/tel/mobile label just before it (the
    # structured-scrape "Phone: 4155550199" shape). A bare digit run with none of
    # those — 000000000, transaction IDs, counters, timestamps — is NOT a phone
    # and used to flood the graph as a junk node.
    out.extend(_scan(text, PHONE_RE, "phone",
                     predicate=_looks_like_phone,
                     canonical_fn=lambda m: re.sub(r"[\s().-]", "", m.group(0))))

    # Web/crypto fingerprint layer. Shared `claimed` set enforces precedence:
    # most-specific span wins, so a 32-hex isn't typed as BOTH walletconnect_id
    # and md5, and an EVM contract isn't also a bare wallet.
    claimed: set[int] = set()
    out.extend(_scan(text, TRACKING_TAG_RE, "tracking_tag", claimed=claimed))
    out.extend(_scan_gated(text, WALLETCONNECT_RE, "walletconnect_id", GATE_WALLETCONNECT,
                           canonical_fn=lambda m: m.group(0).lower(), claimed=claimed))
    out.extend(_scan(text, SHA256_RE, "hash_sha256",
                     canonical_fn=lambda m: m.group(0).lower(), claimed=claimed))
    out.extend(_scan(text, MD5_RE, "hash_md5",
                     canonical_fn=lambda m: m.group(0).lower(), claimed=claimed))
    # All EVM/BTC/bech32 addresses → crypto_wallet (WALLET_RE). Contract-vs-wallet
    # is NOT decided by regex proximity (it mis-types — "contractAddress" describing
    # one address leaks into the next). The LLM typing pass refines an address to a
    # smart_contract case_type when the case schema has one and context supports it.
    # Preserve case per address family: EVM (0x) hex and bech32 (bc1) are
    # case-insensitive so lowercasing is safe and dedupes nicely, BUT base58
    # (1.../3...) is CASE-SENSITIVE — lowercasing it forges an invalid duplicate
    # address. (Fixes the 1musk… / 1muskDgU… corrupted-twin bug.)
    out.extend(_scan(text, WALLET_RE, "crypto_wallet", claimed=claimed,
                     canonical_fn=_wallet_canonical))
    out.extend(_scan(text, TRON_RE, "crypto_wallet",
                     canonical_fn=lambda m: m.group(0), claimed=claimed))
    out.extend(_scan_gated(text, SOL_RE, "crypto_wallet", GATE_SOL,
                           canonical_fn=lambda m: m.group(0), claimed=claimed))
    out.extend(_scan_gated(text, XRP_RE, "crypto_wallet", GATE_XRP,
                           canonical_fn=lambda m: m.group(0), claimed=claimed))

    out.extend(_scan(text, IPV4_RE, "ip"))
    out.extend(_scan(text, DOMAIN_RE, "domain",
                     canonical_fn=lambda m: m.group(0).lower(),
                     predicate=lambda m: m.group(1).lower() in DOMAIN_TLDS))
    out.extend(_scan(text, TECH_STACK_RE, "tech_stack",
                     canonical_fn=lambda m: m.group(0).lower()))
    out.extend(_scan(text, SAAS_ACCOUNT_RE, "saas_service_account",
                     canonical_fn=lambda m: m.group(1)))
    out.extend(_scan(text, REGISTRAR_RE, "registrar",
                     canonical_fn=lambda m: m.group(1).strip().lower()))
    out.extend(_scan(text, NAMESERVER_RE, "nameserver",
                     canonical_fn=lambda m: m.group(1).strip().lower()))
    out.extend(_scan(text, PERSON_HINT_RE, "person",
                     canonical_fn=lambda m: m.group(1)))
    out.extend(_scan(text, PROPER_NAME_RE, "person_candidate",
                     canonical_fn=lambda m: m.group(1)))

    seen: set[tuple[str, str]] = set()
    deduped: list[Extracted] = []
    for e in out:
        key = (e.canonical, e.entity_type)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)
    return deduped


def infer_relationships(text: str, entities: list[Extracted],
                        proximity_chars: int = 200) -> list[tuple[Extracted, Extracted, str]]:
    """Naive proximity-based co-occurrence relationships."""
    rels: list[tuple[Extracted, Extracted, str]] = []
    by_offset = sorted(entities, key=lambda e: e.offset)
    for i, a in enumerate(by_offset):
        for b in by_offset[i + 1:]:
            if b.offset - a.offset > proximity_chars:
                break
            if a.canonical == b.canonical:
                continue
            rels.append((a, b, "co_mentioned"))
    return rels
