# kipi-investigations

Drop a dense intel report on it. Get a live, investigated entity graph.

kipi turns documents — PDFs, screenshots, spreadsheets, pasted notes — into a
typed entity graph. An autonomous investigator agent then digs the open web
and builds the graph out in front of you: infrastructure pivots, typed edges,
gated findings, a written brief. The analyst stays the top authority — every
schema, finding, and edge can be confirmed, corrected, or rejected.

Two capabilities rarely found together (absent from every commercial OSINT
platform we researched): document ingestion → entities, and real graph
analytics (centrality, communities, pathfinding) on the investigation canvas.

## Quickstart (10 minutes)

```bash
git clone <repo-url> kipi-investigations && cd kipi-investigations
./install.sh                           # venv + deps + DB; checks tesseract/claude
export ANTHROPIC_API_KEY=sk-ant-...    # the ONE required key
./invctl serve                         # open http://127.0.0.1:8765
```

Then:

1. **Reports** → drop a PDF (or paste notes). Entities extract on upload.
2. **Schema gate** → approve the proposed per-case ontology (one click — the
   agent fits the entity types and roles to YOUR case's domain).
3. **Process** → consolidation, typing, correlation, scoring, graph
   analytics, the brief. Watch the step bar.
4. **Graph** → ask the investigator chat to dig
   (`investigate suspicious-domain.com`) and watch nodes land live.

## Keys

| Key | Required? | Without it |
|---|---|---|
| `ANTHROPIC_API_KEY` | **Yes** | No entity classification, no schema proposal, no brief |
| `claude` CLI (+ node 18+) | Optional | The autonomous investigator agent is disabled; ingest, Process, and the graph still work |
| `tesseract` binary | Optional | Scanned-PDF / screenshot OCR skipped |
| `VIRUSTOTAL_API_KEY` | Optional | VT reputation pivots report needs-key and skip |
| Apify / Perplexity / Tavily / Exa / WhoisXML / Censys / abuse.ch / HudsonRock / Etherscan | Optional | Each reports needs-key and skips cleanly |
| Keyless belt | — | whois, DNS, RDAP, reverse-DNS, crt.sh, Shodan InternetDB, Gravatar, IP-geo, username sweep, email triage (MX/SPF/DMARC + header→IP), BTC wallet — all work with zero keys |

## The analyst's graph

- **Layouts** — force (default), hierarchy (dagre), ego rings around the
  selected node, circle.
- **Pathfinding** — pick two nodes; the shortest path lights up, everything
  else dims. "How is this wallet connected to that channel" in two clicks.
- **Graph analytics** — betweenness centrality finds the broker between two
  cells; Louvain communities split a sockpuppet net into operating cells.
  Computed per case, stored as node properties, drive styling.
- **Conditional formatting** — persisted per-case style rules with an editor:
  betweenness→size, analyst-vs-AI origin→border, community→color (opt-in).
- **Collection nodes** — 200 crt.sh subdomains fold into one expandable
  "200 domains" bucket instead of flooding the canvas.
- **Time-bounded edges** — re-observing a relationship updates its
  first-seen/last-seen instead of duplicating it.
- **Provenance everywhere** — every node and edge knows how it entered the
  graph (ingest, enrichment provider, agent, analyst).

## Demo flow (the GIF shot list)

1. Drag a PDF onto Reports — entity chips appear.
2. Schema gate: approve the proposed ontology.
3. Process: the step bar runs; the graph fills.
4. Chat: `investigate <seed-domain>` — nodes land live as the agent digs.
5. Layout switcher → ego rings on the seed.
6. Path mode: wallet → telegram channel; the path pops.
7. Style rules: toggle community colors on.
8. Collection bucket: expand "20 domains".
9. Deliverables: the written brief.

## Docs

The full reference lives in `docs/`: architecture (02), data model (03),
operator guide (04), OSINT enrichment (08), the adaptive pipeline (16), the
investigator agent (17), security + privacy (15), troubleshooting (13).

## Privacy posture

Everything runs locally: SQLite database, local vault, local assets. The only
required external call is the Anthropic API for classification and judgment.
OSINT lookups go to the providers you enable. Run
`bash scripts/oss_secrets_audit.sh` before sharing anything.

## License

[Elastic License 2.0](LICENSE) (source-available). You can use kipi freely —
including in your paid investigation work — modify it, and self-host it. You
may NOT offer kipi itself as a hosted/managed service or product; commercial
licensing of the software stays with the licensor (KTLYST Labs). Questions:
open an issue.
