# investigations — kipi-investigations product code

Compounding intel memory layer. Drop reports → entity + relationship graph → Obsidian vault.

## Quick start (when Acme Intel's zip arrives)

```bash
cd ~/projects/kipi-investigations

# 1. unzip into the inbox
unzip ~/Downloads/ally-reports.zip -d investigations/inbox/

# 2. ingest everything
./invctl ingest --inbox --investigation case-b

# 3. correlate (find cross-report entities + auto-link aliases)
./invctl correlate

# 4. export the Obsidian vault
./invctl export-vault

# 5. open the vault in Obsidian
open -a Obsidian investigations/vault
```

## CLI reference

Use `./invctl <command>` from the project root (wrapper auto-uses the venv).

| Command | What it does |
|---|---|
| `init` | Create SQLite schema |
| `ingest <file>` | Ingest one file |
| `ingest --inbox` | Ingest all files in `investigations/inbox/` |
| `query "<entity>"` | Show every mention of an entity with context |
| `connections "<entity>"` | Show entities connected to this one |
| `correlate` | Find cross-report entities, auto-link aliases |
| `export-vault [--out PATH]` | (Re)generate Obsidian vault |
| `export-report [--out PATH]` | Generate analyst-readable summary MD |
| `stats` | DB stats + top entities |

## Supported file types

| Extension | Source type | Notes |
|---|---|---|
| `.pdf` | pdf | Needs `pdfplumber` or `pypdf` or `pdftotext` (poppler) |
| `.md`, `.markdown` | markdown | Strips frontmatter + code fences |
| `.txt` | text | Raw text |
| `.csv`, `.tsv` | csv | Flattens to `header: value | ...` per row |
| `.json` | telegram_json | Handles both kipi harvest format + Telegram channel export |
| `.png`, `.jpg`, `.jpeg` | screenshot | OCR via Tesseract — multi-language: eng, ara, fas, heb, rus, chi |

## How entity extraction works

Regex-first, no LLM in v1. Catches:
- emails, URLs, @handles
- Telegram channels (t.me/...)
- phone numbers
- SHA256 + MD5 hashes
- IPv4 addresses
- crypto wallets (BTC + ETH)
- domains (common TLDs)
- person names (title-prefixed + capitalized proper-noun candidates)

False positives are expected for `person_candidate`. Phase 2 will add LLM-assisted NER to disambiguate.

## Cross-report correlation

When the same entity (by canonical name OR alias) appears in 2+ reports, it surfaces in:
- `invctl correlate` output
- Entity Obsidian page (shows mention from every report)
- Index page (shows entity count per type)

## Obsidian vault layout

```
vault/
├── _index.md           # entity-by-type + report list
├── entities/
│   ├── ali.khorasani@protonmail.com.md
│   ├── t.me/case-b_team.md
│   └── ...
└── reports/
    ├── Handala-Op-Alpha.md
    └── ...
```

Open in Obsidian. Use the graph view (toggle with `Ctrl+G` / `Cmd+G`). Filter by `tags: [entity, person]` etc.

## Smoke test

```bash
python3 investigations/tests/test_pipeline.py
```

Should print 4 `[ok]` lines and `=== ALL TESTS PASSED ===`.

## Known limitations (v1)

- `person_candidate` regex is greedy (catches "Sample Handala Demo" headings as a person). LLM-assisted NER in v2.
- No deduplication across slightly-different name spellings beyond simple token overlap. Use `correlate` to surface candidate aliases.
- Screenshot OCR is best-effort. Install pytesseract for real OCR.
- Single-user local SQLite. Multi-user AWS deploy is a separate path.
