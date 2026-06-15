-- kipi-investigations SQLite schema
-- 5 tables: reports, entities, mentions, relationships, aliases

-- A case/client workspace. reports.investigation is the slug join key
-- (global entity pool, case-scoped views).
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    client TEXT,
    case_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT NOT NULL,
    source_hash TEXT NOT NULL UNIQUE,
    source_type TEXT NOT NULL,
    title TEXT,
    investigation TEXT,
    ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    raw_text TEXT
);

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_name TEXT NOT NULL UNIQUE,
    entity_type TEXT NOT NULL,
    first_seen_report_id INTEGER,
    first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    sub_role TEXT,
    sub_role_reason TEXT,
    flagged INTEGER NOT NULL DEFAULT 0,   -- analyst watchlist toggle
    flagged_note TEXT,
    provenance TEXT,                      -- how this node entered the graph:
                                          -- ingest:<report> | enrich:<provider> | agent | analyst
    FOREIGN KEY (first_seen_report_id) REFERENCES reports(id)
);

-- NOTE: the derived graph table `typed_relationships` (and `node_properties`) are created
-- + migrated lazily in storage/db.py, not here. typed_relationships carries a first-class
-- `provenance TEXT` column alongside rel_type/confidence/evidence/status (the same
-- provenance vocabulary as entities above).

-- Auto-generated alerts: a flagged/known actor reappears, or an actor crosses
-- into a new case. One row per (entity, report, type) — detection is idempotent.
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    report_id INTEGER NOT NULL,
    alert_type TEXT NOT NULL,        -- 'watchlist' | 'cross_case'
    severity TEXT NOT NULL,          -- 'high' | 'medium' | 'low'
    message TEXT NOT NULL,
    investigation TEXT,              -- case the triggering report belongs to
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    UNIQUE(entity_id, report_id, alert_type),
    FOREIGN KEY (entity_id) REFERENCES entities(id),
    FOREIGN KEY (report_id) REFERENCES reports(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_entity ON alerts(entity_id);

CREATE INDEX IF NOT EXISTS idx_entities_sub_role ON entities(sub_role);

CREATE TABLE IF NOT EXISTS aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    alias TEXT NOT NULL,
    UNIQUE(entity_id, alias),
    FOREIGN KEY (entity_id) REFERENCES entities(id)
);

CREATE TABLE IF NOT EXISTS mentions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    report_id INTEGER NOT NULL,
    asset_id INTEGER,
    surface_form TEXT NOT NULL,
    context TEXT,
    char_offset INTEGER,
    FOREIGN KEY (entity_id) REFERENCES entities(id),
    FOREIGN KEY (report_id) REFERENCES reports(id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_entity_id INTEGER NOT NULL,
    dst_entity_id INTEGER NOT NULL,
    rel_type TEXT NOT NULL,
    report_id INTEGER,
    evidence TEXT,
    confidence REAL DEFAULT 0.5,
    UNIQUE(src_entity_id, dst_entity_id, rel_type, report_id),
    FOREIGN KEY (src_entity_id) REFERENCES entities(id),
    FOREIGN KEY (dst_entity_id) REFERENCES entities(id),
    FOREIGN KEY (report_id) REFERENCES reports(id)
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    page_number INTEGER,
    image_index INTEGER,
    ocr_text TEXT,
    UNIQUE(report_id, file_path),
    FOREIGN KEY (report_id) REFERENCES reports(id)
);

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
);

CREATE INDEX IF NOT EXISTS idx_seeds_entity ON seeds(entity_id);
CREATE INDEX IF NOT EXISTS idx_mentions_entity ON mentions(entity_id);
CREATE INDEX IF NOT EXISTS idx_mentions_report ON mentions(report_id);
CREATE INDEX IF NOT EXISTS idx_rel_src ON relationships(src_entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_dst ON relationships(dst_entity_id);
CREATE INDEX IF NOT EXISTS idx_aliases_alias ON aliases(alias);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_assets_report ON assets(report_id);


CREATE TABLE IF NOT EXISTS osint_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    category TEXT,
    env_var TEXT,
    enabled INTEGER DEFAULT 1,
    cost_estimate_usd REAL,
    docs_url TEXT,
    api_key TEXT          -- locally-stored key (gitignored DB); env var is fallback
);

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
);

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
);

CREATE INDEX IF NOT EXISTS idx_runs_entity ON enrichment_runs(entity_id);
CREATE INDEX IF NOT EXISTS idx_runs_provider ON enrichment_runs(provider_slug);
CREATE INDEX IF NOT EXISTS idx_results_run ON enrichment_results(run_id);

-- Chat transcript: the durable record behind the chat-led investigator. One row
-- per turn (analyst message, agent burst, UI event, system note). The warm
-- session is in-memory + reaped; this survives reload/reap so chat + canvas
-- share one memory.
CREATE TABLE IF NOT EXISTS chat_turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation TEXT NOT NULL,
    role TEXT NOT NULL,
    text TEXT NOT NULL,
    deltas_json TEXT,
    step_trail_json TEXT,
    capped INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_turns_case ON chat_turns(investigation, id);

-- Tradecraft gates run from the chat (Scope / Challenge / Premortem are tracked gates;
-- Timeline / Target / Reality-check are helper steps). A step is "done" when its row
-- exists — code-enforced state the warm agent can't skip, surfaced as a checklist in the
-- chat and a soft nudge at brief time. One current artifact per (case, step); re-running
-- overwrites it.
CREATE TABLE IF NOT EXISTS case_tradecraft (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation TEXT NOT NULL,
    step TEXT NOT NULL,
    content TEXT,
    analyst TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(investigation, step)
);
CREATE INDEX IF NOT EXISTS idx_tradecraft_case ON case_tradecraft(investigation);
