"""SQLite helpers for kipi-investigations."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "investigations" / "data" / "investigations.db"
SCHEMA_PATH = ROOT / "investigations" / "storage" / "schema.sql"


def init_db(db_path: Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA_PATH.read_text())
        conn.commit()


def _migrate(conn) -> None:
    """Idempotent column additions for older DBs."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(entities)").fetchall()}
    if "sub_role" not in cols:
        conn.execute("ALTER TABLE entities ADD COLUMN sub_role TEXT")
    if "sub_role_reason" not in cols:
        conn.execute("ALTER TABLE entities ADD COLUMN sub_role_reason TEXT")
    # Soft-hide for the graph chat: a hidden node drops off the graph but the row +
    # all its data stay, so the analyst can always restore it (reversible removal).
    if "hidden" not in cols:
        conn.execute("ALTER TABLE entities ADD COLUMN hidden INTEGER DEFAULT 0")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entities_sub_role ON entities(sub_role)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS seeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id INTEGER NOT NULL,
            label TEXT,
            source_file TEXT,
            weight REAL DEFAULT 1.0,
            raw_name TEXT,
            notes TEXT,
            added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(entity_id, source_file),
            FOREIGN KEY (entity_id) REFERENCES entities(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_seeds_entity ON seeds(entity_id)")

    # OSINT enrichment tables (PRD: prd-osint-enrichment-2026-05-27)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS osint_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            env_var TEXT,
            enabled INTEGER DEFAULT 1,
            cost_estimate_usd REAL,
            docs_url TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS enrichment_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id INTEGER,
            provider_slug TEXT NOT NULL,
            query TEXT NOT NULL,
            mode TEXT,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT,
            cost_usd REAL,
            error_message TEXT,
            investigation TEXT,
            FOREIGN KEY (entity_id) REFERENCES entities(id),
            FOREIGN KEY (provider_slug) REFERENCES osint_providers(slug)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS enrichment_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            result_type TEXT,
            title TEXT,
            summary TEXT,
            url TEXT,
            raw_json TEXT,
            extracted_entity_id INTEGER,
            confidence TEXT,
            FOREIGN KEY (run_id) REFERENCES enrichment_runs(id),
            FOREIGN KEY (extracted_entity_id) REFERENCES entities(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_entity ON enrichment_runs(entity_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_provider ON enrichment_runs(provider_slug)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_results_run ON enrichment_results(run_id)")
    # Volume-decision state: a large result is flagged needs_decision in raw_json (full
    # set captured, nothing dropped); `decision` records the analyst's choice once made
    # (revert / cluster:<id> / reason) so the UI stops prompting. Idempotent migration.
    _res_cols = {r[1] for r in conn.execute("PRAGMA table_info(enrichment_results)")}
    if "decision" not in _res_cols:
        conn.execute("ALTER TABLE enrichment_results ADD COLUMN decision TEXT")

    # Locally-stored API keys (gitignored DB). Older DBs lack this column.
    provider_cols = {r[1] for r in conn.execute("PRAGMA table_info(osint_providers)")}
    if "api_key" not in provider_cols:
        conn.execute("ALTER TABLE osint_providers ADD COLUMN api_key TEXT")

    # The investigator agent's process trail (JSON: summary, narration, tools_used,
    # turns, cost) stored on its run so the UI can show "how it investigated".
    run_cols = {r[1] for r in conn.execute("PRAGMA table_info(enrichment_runs)")}
    if "agent_process" not in run_cols:
        conn.execute("ALTER TABLE enrichment_runs ADD COLUMN agent_process TEXT")

    # Watchlist flag on entities + the alerts table (auto-flagging feature).
    entity_cols = {r[1] for r in conn.execute("PRAGMA table_info(entities)")}
    if "flagged" not in entity_cols:
        conn.execute("ALTER TABLE entities ADD COLUMN flagged INTEGER NOT NULL DEFAULT 0")
    if "flagged_note" not in entity_cols:
        conn.execute("ALTER TABLE entities ADD COLUMN flagged_note TEXT")
    if "thumbnail" not in entity_cols:
        conn.execute("ALTER TABLE entities ADD COLUMN thumbnail TEXT")
    # case_type: the per-case schema's entity type (wallet_address, scam_domain…),
    # set by the typing pass. entity_type stays the regex surface type (ip, domain,
    # crypto_wallet) so pivot links keep working; case_type is the analytic label.
    if "case_type" not in entity_cols:
        conn.execute("ALTER TABLE entities ADD COLUMN case_type TEXT")
    # provenance: how this node entered the graph — ingest:<report> | enrich:<provider> |
    # agent | analyst. First-class so "where did this come from" is queryable, not buried
    # in prose (issue graph-provenance-fields).
    if "provenance" not in entity_cols:
        conn.execute("ALTER TABLE entities ADD COLUMN provenance TEXT")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id INTEGER NOT NULL,
            report_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            investigation TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            UNIQUE(entity_id, report_id, alert_type),
            FOREIGN KEY (entity_id) REFERENCES entities(id),
            FOREIGN KEY (report_id) REFERENCES reports(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_entity ON alerts(entity_id)")

    # Analysis tables are otherwise created lazily by `analyze`. Ensure the ones
    # the scorer + Focus + entity views read exist on every connect, so
    # auto-recalibration on the FIRST ingest (and the web reads) don't no-op.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS clusters ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, "
        "kind TEXT, description TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cluster_members ("
        "cluster_id INTEGER, entity_id INTEGER, PRIMARY KEY (cluster_id, entity_id), "
        "FOREIGN KEY (cluster_id) REFERENCES clusters(id), "
        "FOREIGN KEY (entity_id) REFERENCES entities(id))"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS enrichment_links ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER NOT NULL, "
        "label TEXT NOT NULL, url TEXT NOT NULL, "
        "FOREIGN KEY (entity_id) REFERENCES entities(id))"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS typed_relationships ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, src_entity_id INTEGER NOT NULL, "
        "dst_entity_id INTEGER NOT NULL, rel_type TEXT NOT NULL, confidence TEXT, "
        "evidence TEXT, UNIQUE(src_entity_id, dst_entity_id, rel_type), "
        "FOREIGN KEY (src_entity_id) REFERENCES entities(id), "
        "FOREIGN KEY (dst_entity_id) REFERENCES entities(id))"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_typed_src ON typed_relationships(src_entity_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_typed_dst ON typed_relationships(dst_entity_id)")
    # Typed entity properties (registrar, A-record, ASN, dates…) as real queryable fields,
    # written by the enrich adapters — not buried in freetext dossiers. One canonical value
    # per (entity, key); re-enrich UPDATEs in place. (issue node-properties-table)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS node_properties ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER NOT NULL, "
        "key TEXT NOT NULL, value TEXT NOT NULL, value_type TEXT NOT NULL DEFAULT 'string', "
        "provenance TEXT, confidence TEXT DEFAULT 'medium', "
        "UNIQUE(entity_id, key), "
        "FOREIGN KEY (entity_id) REFERENCES entities(id))"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_node_props_entity ON node_properties(entity_id)")
    # Supersession status on the derived graph: a correction can retire an edge
    # without deleting it (graph reads filter status='active').
    typed_cols = {r[1] for r in conn.execute("PRAGMA table_info(typed_relationships)")}
    if "status" not in typed_cols:
        conn.execute("ALTER TABLE typed_relationships ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    # provenance: how this edge was established (the tool/value or 'agent'/'analyst'),
    # first-class instead of squeezed into evidence (issue graph-provenance-fields).
    if "provenance" not in typed_cols:
        conn.execute("ALTER TABLE typed_relationships ADD COLUMN provenance TEXT")
    # Time bounds: when this edge was first/last observed (ISO-8601 UTC). Re-observation
    # UPDATEs last_seen in place — same (src,dst,rel_type) = same edge, never a duplicate
    # row (stricter than OpenCTI's ±30-day window; deliberate, the UNIQUE constraint
    # stays). NULL on pre-existing edges (observed before time bounds existed) — readers
    # must tolerate NULL. (issue edge-time-bounds)
    if "first_seen" not in typed_cols:
        conn.execute("ALTER TABLE typed_relationships ADD COLUMN first_seen TEXT")
    if "last_seen" not in typed_cols:
        conn.execute("ALTER TABLE typed_relationships ADD COLUMN last_seen TEXT")
    # Per-case conditional-formatting rules (issue graph-style-rules): cytoscape
    # selector -> style JSON, applied to the graph canvas in position order.
    # investigation NULL = the unscoped/all-cases bucket.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS style_rules ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, investigation TEXT, "
        "label TEXT NOT NULL, selector TEXT NOT NULL, style_json TEXT NOT NULL, "
        "enabled INTEGER NOT NULL DEFAULT 1, position INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_style_rules_inv ON style_rules(investigation)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entity_scores ("
        "entity_id INTEGER PRIMARY KEY, threat_score REAL, degree INTEGER, "
        "report_count INTEGER, FOREIGN KEY (entity_id) REFERENCES entities(id))"
    )

    # Linked-image candidates: image URLs found in report text (scrape-based cases link
    # to images instead of embedding them). Stored as 'pending'; the analyst approves
    # each one before it's fetched (status -> fetched/skipped/error). Nothing auto-fetches.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS linked_image_candidates ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL, "
        "investigation TEXT, url TEXT NOT NULL, domain TEXT, "
        "status TEXT NOT NULL DEFAULT 'pending', asset_id INTEGER, error TEXT, "
        "UNIQUE(investigation, url), "
        "FOREIGN KEY (report_id) REFERENCES reports(id))"
    )

    # Claims: provenance layer behind the graph. Every assertion (role,
    # attribute, relationship) tied to its source report, with supersession.
    # predicate convention: relationship claims use 'rel:<object_entity_id>' so a
    # changed rel_type for the same pair is a same-predicate value conflict.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id INTEGER NOT NULL,
            report_id INTEGER,
            claim_type TEXT NOT NULL,          -- 'role' | 'attribute' | 'relationship'
            predicate TEXT NOT NULL,
            value TEXT,
            object_entity_id INTEGER,
            confidence TEXT,
            evidence TEXT,
            status TEXT NOT NULL DEFAULT 'active',  -- 'active'|'superseded'|'rejected'
            superseded_by INTEGER,
            source TEXT,                       -- 'backfill'|'extract'|'manual'
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT,
            UNIQUE(entity_id, report_id, claim_type, predicate, value, object_entity_id),
            FOREIGN KEY (entity_id) REFERENCES entities(id),
            FOREIGN KEY (report_id) REFERENCES reports(id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_entity ON claims(entity_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_pred ON claims(entity_id, predicate, status)")
    # Attribution on a claim — analyst assertions (source='manual') carry the name
    # of the analyst who overrode the report/AI. Older DBs lack the column.
    claim_cols = {r[1] for r in conn.execute("PRAGMA table_info(claims)")}
    if "author" not in claim_cols:
        conn.execute("ALTER TABLE claims ADD COLUMN author TEXT")

    # Analyst layer: notes + an optional dossier override, kept SEPARATE from the
    # AI-generated vault dossier so regeneration never wipes analyst work.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entity_annotations (
            entity_id INTEGER PRIMARY KEY,
            notes TEXT,                 -- analyst's own notes (markdown)
            dossier_override TEXT,      -- analyst-edited dossier (NULL = use AI version)
            notes_updated_at TEXT,
            dossier_updated_at TEXT,
            FOREIGN KEY (entity_id) REFERENCES entities(id)
        )
    """)
    # Light multi-analyst: attribution on the analyst layer (no auth — a name set
    # per session) so a shared instance shows whose note is whose.
    ann_cols = {r[1] for r in conn.execute("PRAGMA table_info(entity_annotations)")}
    if "notes_author" not in ann_cols:
        conn.execute("ALTER TABLE entity_annotations ADD COLUMN notes_author TEXT")
    if "dossier_author" not in ann_cols:
        conn.execute("ALTER TABLE entity_annotations ADD COLUMN dossier_author TEXT")

    # Activity log: who did what, when — the shared progress trail.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyst TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_id INTEGER,
            report_id INTEGER,
            investigation TEXT,
            detail TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_created ON activity(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_case ON activity(investigation)")

    # Per-analyst 'since you last looked' tracking for the Signals inbox. One
    # last-seen timestamp per (analyst, scope); scope is the case slug or
    # '__all__'. No auth — analyst is a per-session cookie name.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyst_views (
            analyst TEXT NOT NULL,
            scope TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            PRIMARY KEY (analyst, scope)
        )
    """)

    # Analyst notes ON a report (the report workspace). Free-text the analyst
    # owns, attributed — separate from the report's extracted content.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS report_annotations (
            report_id INTEGER PRIMARY KEY,
            notes TEXT,
            notes_author TEXT,
            notes_updated_at TEXT,
            FOREIGN KEY (report_id) REFERENCES reports(id)
        )
    """)

    # Per-case adaptive ontology. The "Understand" step proposes an entity/role
    # schema fit to THIS case's domain (crypto-fraud needs wallet/promoter, not
    # operator/channel); the analyst approves it before classification runs.
    # status: 'proposed' (agent wrote it, awaiting analyst) | 'approved' (analyst
    # signed off — consolidate may now use it). schema_json holds the full schema.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_schemas (
            case_slug TEXT PRIMARY KEY,
            schema_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'proposed',
            proposed_at TEXT,
            approved_at TEXT,
            approved_by TEXT
        )
    """)

    # Seed provider catalog (idempotent — INSERT OR IGNORE on unique slug)
    providers_seed = [
        ("perplexity", "Perplexity Sonar / Deep / Reasoning", "search", "PERPLEXITY_API_KEY",
         "AI answers with citations. Best first-pass for who/what questions.", 0.005,
         "https://docs.perplexity.ai/"),
        ("tavily", "Tavily Search + Extract", "search", "TAVILY_API_KEY",
         "Agent-optimized search. Cheap basic mode, deeper advanced mode.", 0.005,
         "https://docs.tavily.com/"),
        ("exa", "Exa AI semantic search", "search", "EXA_API_KEY",
         "Semantic search + company/people endpoints. Long-form deep research.", 0.005,
         "https://docs.exa.ai/"),
        ("apify", "Apify Actors (LinkedIn, IG, Telegram, Twitter, +50)", "scrape", "APIFY_API_TOKEN",
         "Run 55+ ready-made scrapers. Pay per actor run.", 0.10,
         "https://docs.apify.com/"),
        ("jina", "Jina Reader / Search / Deepsearch", "reader", "JINA_API_KEY",
         "Convert any URL to clean markdown. Search + deepsearch endpoints.", 0.001,
         "https://jina.ai/reader/"),
        # Threat-intel + infra recon, ported from huntkit's MCP servers.
        ("virustotal", "VirusTotal (domain / IP / hash / URL)", "reputation", "VIRUSTOTAL_API_KEY",
         "Reputation + detection stats for a domain, IP, file hash, or URL. Free: 4/min, 500/day.",
         0.0, "https://www.virustotal.com/gui/join-us"),
        ("abusech", "abuse.ch — URLhaus + ThreatFox", "reputation", "ABUSECH_AUTH_KEY",
         "Is a host/URL a known malware point (URLhaus) or a known IOC (ThreatFox)?",
         0.0, "https://auth.abuse.ch/"),
        ("crtsh", "crt.sh certificate transparency", "infra", None,
         "Enumerate subdomains + related hosts from certificate transparency logs. Keyless.",
         0.0, "https://crt.sh/"),
        ("infra", "Infra recon (WHOIS / DNS / reverse-DNS)", "infra", None,
         "WHOIS registration, DNS records, and reverse DNS via local whois + dig. Keyless.",
         0.0, "https://en.wikipedia.org/wiki/WHOIS"),
        ("shodan", "Shodan (host ports / services / CVEs)", "infra", "SHODAN_API_KEY",
         "Open ports, running services + banners, hostnames, and known CVEs for an IP. "
         "Works keyless (InternetDB); add a key for banners + org/ASN.",
         0.0, "https://account.shodan.io/"),
        ("censys", "Censys (host services / ports / certs)", "infra", "CENSYS_PLATFORM_TOKEN",
         "Services, ports, TLS/cert data, ASN, and DNS names for an IP. Platform: enter "
         "'PAT:ORGID' (token + Org ID from the console URL). Legacy: enter 'ID:SECRET'.",
         0.0, "https://platform.censys.io/settings/api"),
        ("whoisxml", "WhoisXML (reverse-whois / DNS history)", "infra", "WHOISXML_API_KEY",
         "Sibling domains by registrant (reverse-whois) and historical DNS resolutions. "
         "Keyed: WHOISXML_API_KEY.",
         0.0, "https://www.whoisxmlapi.com/"),
        # Flowsint-inspired enrichers (native to kipi, no Flowsint dependency).
        ("gravatar", "Gravatar (email -> profile + linked accounts)", "social", None,
         "An email's public Gravatar profile + the social accounts the owner linked. Keyless.",
         0.0, "https://docs.gravatar.com/api/profiles/"),
        ("ipgeo", "IP geolocation + ASN (ip-api)", "infra", None,
         "Geolocation, ISP, org, and autonomous system (ASN) for an IP or domain. Keyless.",
         0.0, "https://ip-api.com/docs"),
        ("username", "Username presence sweep (curated platforms)", "social", None,
         "Which curated platforms a handle exists on (GitHub, Reddit, Keybase, Telegram, "
         "YouTube, +). Keyless; bot-walled sites omitted.",
         0.0, "https://github.com/reconurge/flowsint"),
        ("wallet", "Crypto wallet (BTC keyless / ETH via Etherscan)", "chain", None,
         "Balance + transaction counterparties for a BTC (mempool.space, keyless) or ETH "
         "(Etherscan, free ETHERSCAN_API_KEY) address.",
         0.0, "https://etherscan.io/apis"),
        ("email", "Email intel (triage + header->IP)", "infra", None,
         "user@domain -> MX/SPF/DMARC posture, mail provider, disposable flag; "
         "mode=headers: raw headers -> Received hop chain + public source IPs "
         "feeding the dns/RDAP/VT pivots. Keyless (dnspython).",
         0.0, "https://www.rfc-editor.org/rfc/rfc7208"),
    ]
    for slug, name, cat, env, desc, cost, docs in providers_seed:
        conn.execute(
            "INSERT OR IGNORE INTO osint_providers "
            "(slug, display_name, category, env_var, description, cost_estimate_usd, docs_url) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (slug, name, cat, env, desc, cost, docs),
        )

    _backfill_investigations(conn)

    # Investigation TYPE (the coarse label identified at ingest, deterministic-
    # first). Lives on investigations (exists from first ingest, before any
    # schema). type_status mirrors the schema gate: proposed → approved.
    inv_cols = {r[1] for r in conn.execute("PRAGMA table_info(investigations)")}
    if "investigation_type" not in inv_cols:
        conn.execute("ALTER TABLE investigations ADD COLUMN investigation_type TEXT")
    if "type_confidence" not in inv_cols:
        conn.execute("ALTER TABLE investigations ADD COLUMN type_confidence REAL")
    if "type_status" not in inv_cols:
        conn.execute("ALTER TABLE investigations ADD COLUMN type_status TEXT DEFAULT 'proposed'")
    if "type_scores" not in inv_cols:
        conn.execute("ALTER TABLE investigations ADD COLUMN type_scores TEXT")

    # Investigation OBJECTIVE — the analyst's free-text goal for the case, typed at
    # intake. The scope anchor: it shapes the Understand schema prompt, steers the
    # investigator (_case_thesis), and frames the synthesis brief. One per case.
    if "objective" not in inv_cols:
        conn.execute("ALTER TABLE investigations ADD COLUMN objective TEXT")

    # Heterogeneous evidence: a CSV/dataset is not a prose report. evidence_kind
    # tags what a row IS; parent_report_id links dataset child-records to their
    # source. Defaults keep every existing report a plain 'report'.
    rep_cols = {r[1] for r in conn.execute("PRAGMA table_info(reports)")}
    if "evidence_kind" not in rep_cols:
        conn.execute("ALTER TABLE reports ADD COLUMN evidence_kind TEXT DEFAULT 'report'")
    if "parent_report_id" not in rep_cols:
        conn.execute("ALTER TABLE reports ADD COLUMN parent_report_id INTEGER")

    # Chat transcript — the durable record behind the chat-led investigator. One
    # row per turn: analyst message, agent burst (reply + step trail + graph
    # deltas), UI event, or system note. The warm session is in-memory + reaped;
    # this is what survives reload/reap so chat + canvas share one memory.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chat_turns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation TEXT NOT NULL,
            role TEXT NOT NULL,
            text TEXT NOT NULL,
            deltas_json TEXT,
            step_trail_json TEXT,
            capped INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_chat_turns_case ON chat_turns(investigation, id)")


INVESTIGATIONS_DDL = """
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    client TEXT,
    case_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def _backfill_investigations(conn: sqlite3.Connection) -> None:
    """Promote distinct reports.investigation tags into the investigations table.

    Idempotent. Global pool, case-scoped views: reports.investigation stays the
    slug join key, so existing entity rows are never rewritten. Reports with a
    NULL/blank tag are filed under the 'unfiled' case so every report maps to
    exactly one case.
    """
    conn.execute(INVESTIGATIONS_DDL)

    untagged = conn.execute(
        "SELECT COUNT(*) FROM reports "
        "WHERE investigation IS NULL OR TRIM(investigation) = ''"
    ).fetchone()[0]
    if untagged:
        conn.execute(
            "UPDATE reports SET investigation = 'unfiled' "
            "WHERE investigation IS NULL OR TRIM(investigation) = ''"
        )

    slugs = [
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT investigation FROM reports "
            "WHERE investigation IS NOT NULL AND TRIM(investigation) != ''"
        )
    ]
    for slug in slugs:
        conn.execute(
            "INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?, ?)",
            (slug, slug),
        )


def set_objective(conn: sqlite3.Connection, case: str, objective: str) -> None:
    """Set the case's free-text objective (the scope anchor). Registers the case
    row if it doesn't exist yet, so this is safe to call before any ingest."""
    case = (case or "").strip()
    if not case:
        return
    conn.execute("INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?, ?)",
                 (case, case))
    conn.execute("UPDATE investigations SET objective = ? WHERE slug = ?",
                 ((objective or "").strip() or None, case))


def get_objective(conn: sqlite3.Connection, case: str | None) -> str:
    """The case's free-text objective, or '' if none set."""
    if not case:
        return ""
    row = conn.execute("SELECT objective FROM investigations WHERE slug = ?",
                       (case,)).fetchone()
    return (row["objective"] or "").strip() if row and row["objective"] else ""


@contextmanager
def connect(db_path: Path = DB_PATH, migrate: bool = True):
    # 60s timeout so concurrent writers (e.g. ingest while consolidate runs)
    # wait for the lock instead of dying immediately.
    # migrate=False is for hot read-only probes (e.g. resolve_key) that must not
    # re-run the full schema migration on every call.
    conn = sqlite3.connect(db_path, timeout=60.0)
    conn.row_factory = sqlite3.Row
    # WAL so a long writer (the consolidate pass) never blocks readers. Without it,
    # the rollback-journal writer takes an EXCLUSIVE lock for minutes and every
    # synchronous read in an async route stalls the whole event loop — the UI
    # freezes ("tabs don't move", Process "looks stopped") until the write commits.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 60000")
    if migrate:
        _migrate(conn)
        # Commit the migration immediately. Python's sqlite3 leaves the migration's
        # writes in an OPEN transaction, which holds the write lock for the ENTIRE
        # `with` block. A long-lived caller (the investigator swarm holds this
        # connection open across a multi-minute volley) would then block every other
        # writer — each parallel worker's land_findings() fails with "database is
        # locked". Committing here releases the lock; the caller's own writes still
        # commit (or roll back on error) at the end of the block, unchanged.
        conn.commit()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def insert_report(conn, source_path: str, source_hash: str, source_type: str,
                  title: str | None, investigation: str | None, raw_text: str) -> int:
    cur = conn.execute(
        "INSERT OR IGNORE INTO reports (source_path, source_hash, source_type, title, investigation, raw_text) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (source_path, source_hash, source_type, title, investigation, raw_text),
    )
    if cur.lastrowid:
        return cur.lastrowid
    row = conn.execute("SELECT id FROM reports WHERE source_hash = ?", (source_hash,)).fetchone()
    return row["id"]


def upsert_entity(conn, canonical_name: str, entity_type: str, report_id: int,
                  provenance: str | None = None) -> int:
    canonical_name = canonical_name.strip()
    row = conn.execute(
        "SELECT id, provenance FROM entities WHERE canonical_name = ?", (canonical_name,)
    ).fetchone()
    if row:
        # Backfill provenance on a pre-existing node that has none — first stamp wins,
        # so a node that re-appears keeps how it ORIGINALLY entered the graph.
        if provenance and not row["provenance"]:
            conn.execute("UPDATE entities SET provenance = ? WHERE id = ?",
                         (provenance, row["id"]))
        return row["id"]
    cur = conn.execute(
        "INSERT INTO entities (canonical_name, entity_type, first_seen_report_id, provenance) "
        "VALUES (?, ?, ?, ?)",
        (canonical_name, entity_type, report_id, provenance),
    )
    return cur.lastrowid


def add_alias(conn, entity_id: int, alias: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO aliases (entity_id, alias) VALUES (?, ?)",
        (entity_id, alias.strip()),
    )


def add_mention(conn, entity_id: int, report_id: int, surface_form: str,
                context: str, char_offset: int | None = None,
                asset_id: int | None = None) -> None:
    conn.execute(
        "INSERT INTO mentions (entity_id, report_id, asset_id, surface_form, context, char_offset) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (entity_id, report_id, asset_id, surface_form, context, char_offset),
    )


def asset_entities(conn, asset_id: int):
    return conn.execute(
        "SELECT DISTINCT e.id, e.canonical_name, e.entity_type "
        "FROM mentions m JOIN entities e ON e.id = m.entity_id "
        "WHERE m.asset_id = ? ORDER BY e.entity_type, e.canonical_name",
        (asset_id,),
    ).fetchall()


def add_relationship(conn, src_id: int, dst_id: int, rel_type: str,
                     report_id: int | None, evidence: str | None,
                     confidence: float = 0.5) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO relationships "
        "(src_entity_id, dst_entity_id, rel_type, report_id, evidence, confidence) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (src_id, dst_id, rel_type, report_id, evidence, confidence),
    )


def upsert_typed_relationship(conn, src_entity_id: int, dst_entity_id: int,
                              rel_type: str, *, confidence: str | None = "medium",
                              evidence: str | None = None, status: str = "active",
                              provenance: str | None = None,
                              observed_at: str | None = None) -> bool:
    """THE single writer for typed_relationships (issue edge-time-bounds).

    Same (src, dst, rel_type) = same edge: a re-observation UPDATEs last_seen in
    place instead of being dropped by INSERT OR IGNORE. first_seen is the earliest
    RECORDED observation (a legacy NULL edge gets backfilled on its next sighting).
    Existing confidence/evidence/status/provenance are never downgraded — they fill
    only when empty, and a retired (superseded) edge stays retired on re-observation.
    Timestamps use the SQLite-native 'YYYY-MM-DD HH:MM:SS' UTC format so SQL
    MIN/MAX comparisons work against CURRENT_TIMESTAMP columns (the mixed-format
    trap from the TTFN metric bug). Returns True when a NEW edge row was created,
    False on a re-observation (callers that count created edges rely on this).
    """
    observed = observed_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    # The pre-SELECT only feeds the return value (created vs re-observed); the write
    # itself is a single atomic upsert, so a concurrent writer can never hit the
    # UNIQUE constraint (the old INSERT OR IGNORE sites never threw — neither do we).
    row = conn.execute(
        "SELECT id FROM typed_relationships "
        "WHERE src_entity_id = ? AND dst_entity_id = ? AND rel_type = ?",
        (src_entity_id, dst_entity_id, rel_type),
    ).fetchone()
    # MIN/MAX keep the bounds honest when observations arrive out of order
    # (a replayed/older observed_at must not push last_seen backwards or
    # leave first_seen later than last_seen). String compare is safe: one
    # fixed 'YYYY-MM-DD HH:MM:SS' format.
    conn.execute(
        "INSERT INTO typed_relationships "
        "(src_entity_id, dst_entity_id, rel_type, confidence, evidence, status, "
        " provenance, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(src_entity_id, dst_entity_id, rel_type) DO UPDATE SET "
        "  first_seen = MIN(COALESCE(typed_relationships.first_seen, excluded.first_seen), "
        "                   excluded.first_seen), "
        "  last_seen = MAX(COALESCE(typed_relationships.last_seen, excluded.last_seen), "
        "                  excluded.last_seen), "
        "  confidence = COALESCE(typed_relationships.confidence, excluded.confidence), "
        "  evidence = CASE WHEN typed_relationships.evidence IS NULL "
        "                    OR typed_relationships.evidence = '' "
        "                  THEN excluded.evidence ELSE typed_relationships.evidence END, "
        "  provenance = COALESCE(typed_relationships.provenance, excluded.provenance)",
        (src_entity_id, dst_entity_id, rel_type, confidence, evidence, status,
         provenance, observed, observed),
    )
    return row is None


def find_entity_by_name(conn, name: str):
    return conn.execute(
        "SELECT * FROM entities WHERE canonical_name = ? "
        "OR id IN (SELECT entity_id FROM aliases WHERE alias = ?)",
        (name, name),
    ).fetchone()


def entity_mentions(conn, entity_id: int):
    return conn.execute(
        "SELECT m.*, r.title AS report_title, r.source_path FROM mentions m "
        "JOIN reports r ON m.report_id = r.id WHERE m.entity_id = ? ORDER BY r.ingested_at",
        (entity_id,),
    ).fetchall()


def entity_connections(conn, entity_id: int):
    return conn.execute(
        "SELECT e.canonical_name, e.entity_type, rel.rel_type, rel.evidence, r.title AS report_title "
        "FROM relationships rel "
        "JOIN entities e ON e.id = CASE WHEN rel.src_entity_id = ? THEN rel.dst_entity_id ELSE rel.src_entity_id END "
        "LEFT JOIN reports r ON r.id = rel.report_id "
        "WHERE rel.src_entity_id = ? OR rel.dst_entity_id = ?",
        (entity_id, entity_id, entity_id),
    ).fetchall()


def all_entities(conn):
    return conn.execute("SELECT * FROM entities ORDER BY entity_type, canonical_name").fetchall()


def all_reports(conn):
    return conn.execute("SELECT * FROM reports ORDER BY ingested_at").fetchall()


def add_asset(conn, report_id: int, file_path: str, source_kind: str,
              page_number: int | None = None, image_index: int | None = None,
              ocr_text: str | None = None) -> int:
    cur = conn.execute(
        "INSERT OR IGNORE INTO assets (report_id, file_path, source_kind, "
        "page_number, image_index, ocr_text) VALUES (?, ?, ?, ?, ?, ?)",
        (report_id, file_path, source_kind, page_number, image_index, ocr_text),
    )
    if cur.lastrowid:
        return cur.lastrowid
    row = conn.execute(
        "SELECT id FROM assets WHERE report_id = ? AND file_path = ?",
        (report_id, file_path),
    ).fetchone()
    return row["id"]


def report_assets(conn, report_id: int):
    return conn.execute(
        "SELECT * FROM assets WHERE report_id = ? "
        "ORDER BY page_number, image_index",
        (report_id,),
    ).fetchall()


def delete_report(conn, report_id: int) -> dict:
    """Completely remove a report and everything derived ONLY from it.

    Entities first-seen in this report that appear in NO other report are deleted
    outright (with their links). Entities that ALSO appear elsewhere are kept —
    their first-seen pointer is moved to a surviving report and only this report's
    mentions are dropped, so other reports keep their data. The case is removed if
    it has no reports left. Nothing in other cases is touched.
    """
    rep = conn.execute("SELECT investigation FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not rep:
        return {"error": "report not found"}
    case = rep["investigation"]

    exclusive = []
    for row in conn.execute("SELECT id FROM entities WHERE first_seen_report_id = ?", (report_id,)):
        eid = row["id"]
        other = conn.execute(
            "SELECT report_id FROM mentions WHERE entity_id = ? AND report_id != ? LIMIT 1",
            (eid, report_id)).fetchone()
        if other:
            conn.execute("UPDATE entities SET first_seen_report_id = ? WHERE id = ?",
                         (other["report_id"], eid))   # keep it, reassign first-seen
        else:
            exclusive.append(eid)                       # only in this report → drop fully

    if exclusive:
        ph = ",".join("?" for _ in exclusive)
        # Enrichment chain references entities (results.extracted_entity_id,
        # runs.entity_id) AND results FK their run — clear results (both link paths)
        # before runs, before the entity DELETE, or the FK constraint fails.
        for sql in (
            f"DELETE FROM enrichment_results WHERE extracted_entity_id IN ({ph})",
            f"DELETE FROM enrichment_results WHERE run_id IN "
            f"(SELECT id FROM enrichment_runs WHERE entity_id IN ({ph}))",
            f"DELETE FROM enrichment_runs WHERE entity_id IN ({ph})",
        ):
            try:
                conn.execute(sql, exclusive)
            except Exception:
                pass
        for tbl, col in [("mentions", "entity_id"), ("relationships", "src_entity_id"),
                         ("relationships", "dst_entity_id"), ("typed_relationships", "src_entity_id"),
                         ("typed_relationships", "dst_entity_id"), ("claims", "entity_id"),
                         ("entity_scores", "entity_id"), ("aliases", "entity_id"),
                         ("cluster_members", "entity_id"), ("entity_annotations", "entity_id"),
                         ("seeds", "entity_id"), ("alerts", "entity_id"),
                         ("enrichment_links", "entity_id"), ("node_properties", "entity_id")]:
            try:
                conn.execute(f"DELETE FROM {tbl} WHERE {col} IN ({ph})", exclusive)
            except Exception:
                pass
        conn.execute(f"DELETE FROM entities WHERE id IN ({ph})", exclusive)

    # report-scoped rows for entities that survive (their mention in THIS report).
    for tbl in ["mentions", "assets", "relationships", "claims", "alerts", "report_annotations"]:
        try:
            conn.execute(f"DELETE FROM {tbl} WHERE report_id = ?", (report_id,))
        except Exception:
            pass
    conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))

    case_removed = False
    if case:
        left = conn.execute("SELECT COUNT(*) FROM reports WHERE investigation = ?", (case,)).fetchone()[0]
        if left == 0:
            conn.execute("DELETE FROM investigations WHERE slug = ?", (case,))
            case_removed = True
    conn.commit()
    try:
        from investigations import analyze
        analyze.compute_threat_scores(conn)
    except Exception:
        pass
    return {"ok": True, "deleted_report": report_id, "entities_removed": len(exclusive),
            "case": case, "case_removed": case_removed}


def delete_investigation(conn, case: str) -> dict:
    """Delete an ENTIRE investigation: every report in it plus all case-scoped
    artifacts. Irreversible.

    Entity safety mirrors delete_report: entities shared with other cases survive
    (only this case's mentions drop); entities exclusive to this case are removed.
    Case-scoped tables that delete_report's per-report cascade doesn't reach
    (schema, agent enrichment runs, linked-image candidates, activity, view marks)
    are cleared here first.
    """
    case = (case or "").strip()
    if not case:
        return {"error": "case required"}
    exists = conn.execute("SELECT 1 FROM investigations WHERE slug = ?", (case,)).fetchone()
    report_ids = [r["id"] for r in conn.execute(
        "SELECT id FROM reports WHERE investigation = ?", (case,))]
    if not exists and not report_ids:
        return {"error": "investigation not found"}

    # Agent findings: delete results before their runs (results join via run_id).
    conn.execute(
        "DELETE FROM enrichment_results WHERE run_id IN "
        "(SELECT id FROM enrichment_runs WHERE investigation = ?)", (case,))
    runs_removed = conn.execute(
        "DELETE FROM enrichment_runs WHERE investigation = ?", (case,)).rowcount
    for tbl in ["linked_image_candidates", "activity", "chat_turns"]:
        try:
            conn.execute(f"DELETE FROM {tbl} WHERE investigation = ?", (case,))
        except Exception:
            pass
    conn.execute("DELETE FROM case_schemas WHERE case_slug = ?", (case,))
    conn.execute("DELETE FROM analyst_views WHERE scope = ?", (case,))

    # Each report drops its own entities/mentions/claims/alerts/assets and removes
    # the investigations row once the case empties.
    entities_removed = 0
    for rid in report_ids:
        res = delete_report(conn, rid)
        if isinstance(res, dict):
            entities_removed += res.get("entities_removed", 0)

    # Objective-only / empty case: no reports, so delete_report never ran — drop
    # the row explicitly. (No-op when the loop above already removed it.)
    conn.execute("DELETE FROM investigations WHERE slug = ?", (case,))
    conn.commit()
    return {"ok": True, "case": case, "reports_removed": len(report_ids),
            "entities_removed": entities_removed, "runs_removed": runs_removed}


def _serialize_chat_json(value):
    """Serialize a chat turn's deltas/steps for storage. None -> NULL.

    Never silently lossy: nested non-serializable values degrade to their string
    form via default=str; if even that fails, a visible {"_unserializable": true}
    marker is stored instead of dropping the turn detail.
    """
    if value is None:
        return None
    try:
        return json.dumps(value, default=str)
    except Exception:
        # Broad on purpose: default=str can invoke a value's __str__, which may
        # raise any exception type. The contract is "never lossy" — a turn is
        # always stored with a visible marker, never dropped.
        return json.dumps({"_unserializable": True})


def add_chat_turn(conn, case: str, role: str, text: str, deltas=None,
                  steps=None, capped: bool = False) -> int:
    """Append one turn to a case's chat transcript; return the new turn id.

    `role` is analyst | agent | ui_event | system. `deltas`/`steps` are arbitrary
    JSON-able values (dict/list) or None. A blank/None case is a caller bug and
    raises ValueError — investigation is NOT NULL and must never become a
    catch-all bucket (cross-case privacy). created_at is timezone-aware UTC.
    """
    case = (case or "").strip()
    if not case:
        raise ValueError("add_chat_turn: case is required (got blank/None)")
    created_at = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO chat_turns "
        "(investigation, role, text, deltas_json, step_trail_json, capped, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (case, role, text, _serialize_chat_json(deltas),
         _serialize_chat_json(steps), 1 if capped else 0, created_at),
    )
    conn.commit()
    return cur.lastrowid


def get_chat_turns(conn, case: str, limit: int | None = None):
    """Return a case's chat transcript ordered oldest-first (id ASC).

    `limit` returns the most-recent N turns, still in id-ASC order (so a render
    can append them top-to-bottom). Case-scoped: a case only ever sees its own
    turns. deltas_json/step_trail_json stay raw JSON strings — callers parse.
    """
    if limit is not None:
        rows = conn.execute(
            "SELECT * FROM (SELECT * FROM chat_turns WHERE investigation = ? "
            "ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
            (case, limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM chat_turns WHERE investigation = ? ORDER BY id ASC",
            (case,)).fetchall()
    return rows


def move_report(conn, report_id: int, target_case: str) -> dict:
    """Move a report from its current case to another case.

    Case membership lives entirely on reports.investigation (+ the report's own
    alerts). Entities are a global pool keyed by report_id, so mentions, assets,
    claims and relationships follow the report automatically — only the case tag
    moves. The target case is created if new; the source case is removed if it
    has no reports left (same cleanup delete_report does).
    """
    target = (target_case or "").strip()
    if not target:
        return {"error": "target case required"}
    rep = conn.execute(
        "SELECT investigation FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not rep:
        return {"error": "report not found"}
    source = rep["investigation"]
    if source == target:
        return {"error": f"report is already in {target}", "case": target}

    conn.execute("INSERT OR IGNORE INTO investigations (slug, case_name) VALUES (?, ?)",
                 (target, target))
    conn.execute("UPDATE reports SET investigation = ? WHERE id = ?", (target, report_id))
    conn.execute("UPDATE alerts SET investigation = ? WHERE report_id = ?", (target, report_id))

    source_case_removed = False
    if source:
        left = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE investigation = ?", (source,)).fetchone()[0]
        if left == 0:
            conn.execute("DELETE FROM investigations WHERE slug = ?", (source,))
            source_case_removed = True
    conn.commit()
    return {"ok": True, "report_id": report_id, "from": source, "to": target,
            "source_case_removed": source_case_removed}


def db_stats(conn) -> dict:
    return {
        "reports": conn.execute("SELECT COUNT(*) AS n FROM reports").fetchone()["n"],
        "entities": conn.execute("SELECT COUNT(*) AS n FROM entities").fetchone()["n"],
        "mentions": conn.execute("SELECT COUNT(*) AS n FROM mentions").fetchone()["n"],
        "relationships": conn.execute("SELECT COUNT(*) AS n FROM relationships").fetchone()["n"],
        "assets": conn.execute("SELECT COUNT(*) AS n FROM assets").fetchone()["n"],
        "top_entities": conn.execute(
            "SELECT e.canonical_name, e.entity_type, COUNT(m.id) AS mention_count "
            "FROM entities e LEFT JOIN mentions m ON m.entity_id = e.id "
            "GROUP BY e.id ORDER BY mention_count DESC LIMIT 10"
        ).fetchall(),
    }
