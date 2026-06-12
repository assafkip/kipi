# kipi

**Drop a dense intel report on it. Get a live, investigated entity graph.**

![kipi building an investigation graph live](docs/demo.gif)

The graph above built itself. One seed domain went in. An agent pulled WHOIS, DNS, certificates, and the live sites, then pivoted on what it found. No queries to write. [Watch the full 75 seconds, with sound.](docs/demo.mp4)

kipi turns documents into an investigation. PDFs, screenshots, spreadsheets, pasted notes go in. A typed entity graph comes out. Then an autonomous investigator digs the open web and builds the graph out in front of you: infrastructure pivots, typed edges, gated findings, a written brief.

The analyst stays the top authority. Every schema, finding, and edge gets confirmed, corrected, or rejected by a human. The machine proposes. You decide.

Two things sit together here that I never found in one commercial OSINT platform: document ingestion into entities, and real graph analytics (centrality, communities, pathfinding) on the same investigation canvas.

## What you're watching

The demo runs a real case. Two seed domains go in: `trumpfundus.com` and `trumpstake.us`.

By the end, kipi has mapped a Russian-language affiliate fraud network. White-label fake crypto casinos. The backend operator is registered to a shell company in Reykjavík, one month after Brian Krebs killed its predecessor. 20,000+ affiliates. 60 to 80 percent of stolen deposits, paid out in crypto. A Musk-branded clone, flagged for phishing, sitting in the same cluster.

Then it writes the brief. Every claim carries its source and an evidence grade. A DNS record grades an A. An analyst's read is a lead, nothing more. Nothing gets promoted on a name match.

That grading is the point. Most OSINT output reads like a pile of links. This reads like a case.

## Quickstart (10 minutes)

```bash
git clone https://github.com/assafkip/kipi.git && cd kipi
./install.sh                           # venv + deps + DB; checks tesseract/claude
export ANTHROPIC_API_KEY=sk-ant-...    # the ONE required key
./invctl serve                         # open http://127.0.0.1:8765
```

Then:

1. **Reports** → drop a PDF (or paste notes). Entities extract on upload.
2. **Schema gate** → approve the proposed per-case ontology (one click; the agent fits the entity types and roles to your case's domain).
3. **Process** → consolidation, typing, correlation, scoring, graph analytics, the brief. Watch the step bar.
4. **Graph** → tell the investigator chat to dig (`investigate suspicious-domain.com`) and watch nodes land live.

## Keys

One key is required. Everything else degrades gracefully.

| Key | Required? | Without it |
|---|---|---|
| `ANTHROPIC_API_KEY` | **Yes** | No entity classification, no schema proposal, no brief |
| `claude` CLI (+ node 18+) | Optional | The autonomous investigator agent is disabled; ingest, Process, and the graph still work |
| `tesseract` binary | Optional | Scanned-PDF / screenshot OCR skipped |
| `VIRUSTOTAL_API_KEY` | Optional | VT reputation pivots report needs-key and skip |
| Apify / Perplexity / Tavily / Exa / WhoisXML / Censys / abuse.ch / HudsonRock / Etherscan | Optional | Each reports needs-key and skips cleanly |
| Keyless belt | — | whois, DNS, RDAP, reverse-DNS, crt.sh, Shodan InternetDB, Gravatar, IP-geo, username sweep, email triage (MX/SPF/DMARC + header→IP), BTC wallet. All work with zero keys. |

## The analyst's graph

- **Layouts** — force (default), hierarchy (dagre), ego rings around the selected node, circle.
- **Pathfinding** — pick two nodes; the shortest path lights up, everything else dims. "How is this wallet connected to that channel" in two clicks.
- **Graph analytics** — betweenness centrality finds the broker between two cells; Louvain communities split a sockpuppet net into operating cells. Computed per case, stored as node properties, drive styling.
- **Conditional formatting** — persisted per-case style rules with an editor: betweenness→size, analyst-vs-AI origin→border, community→color (opt-in).
- **Collection nodes** — 200 crt.sh subdomains fold into one expandable "200 domains" bucket instead of flooding the canvas.
- **Time-bounded edges** — re-observing a relationship updates its first-seen/last-seen instead of duplicating it.
- **Provenance everywhere** — every node and edge knows how it entered the graph (ingest, enrichment provider, agent, analyst).

## Runs locally

Everything runs on your machine: SQLite database, local vault, local assets. The only required external call is the Anthropic API for classification and judgment. OSINT lookups go to the providers you enable, nowhere else. Run `bash scripts/oss_secrets_audit.sh` before sharing anything.

## License

[Elastic License 2.0](LICENSE), source-available. Use kipi freely, including in your paid investigation work. Modify it. Self-host it for your own use. You may not sell kipi itself, or offer it to others as a hosted or managed service. Commercial licensing of the software stays with KTLYST Labs.

In plain terms: run it, fork it, use it on client work. Don't repackage it and sell it.

## Who built this

I spent 12 years running threat intelligence and investigations at LinkedIn, Google, Meta, and ElevenLabs. kipi is the tool I wanted on every one of those desks, and never had.

The repo is free. If you have a network that needs mapping, or you want a case run for you, reach me through KTLYST Labs. The code is open. The tradecraft is the offer.
