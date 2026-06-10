"""invctl — kipi-investigations CLI."""
import argparse
import hashlib
import sys
from pathlib import Path

from investigations.storage import db
from investigations.ingest import (extractor, pdf, pdf_assets, markdown,
                                   csv_ingest, xlsx_ingest, telegram, screenshot,
                                   docx_ingest)
from investigations.correlate import engine as correlate_engine
from investigations.export import obsidian as obsidian_export
from investigations.export import report as report_export
from investigations.export import canvas as canvas_export
from investigations.export import intel_exports
from investigations import consolidate as consolidate_mod
from investigations import analyze as analyze_mod
from investigations import profile as profile_mod
from investigations import synthesize as synthesize_mod
from investigations import seed as seed_mod
from investigations import alerts as alerts_mod
from investigations import claims as claims_mod
from investigations import focus as focus_mod
from investigations import briefs as briefs_mod
from investigations.enrich import all_adapters, get_adapter
from investigations.enrich import runner as enrich_runner

ROOT = Path(__file__).resolve().parents[2]
INBOX = ROOT / "investigations" / "inbox"
REPORTS_DIR = ROOT / "investigations" / "reports"
VAULT_DIR = ROOT / "investigations" / "vault"
ASSETS_DIR = ROOT / "investigations" / "assets"

EXTRACTORS = {
    ".pdf": (pdf.extract_text, "pdf"),
    ".md": (markdown.extract_text, "markdown"),
    ".markdown": (markdown.extract_text, "markdown"),
    ".txt": (lambda p: p.read_text(encoding="utf-8", errors="replace"), "text"),
    ".csv": (csv_ingest.extract_text, "csv"),
    ".tsv": (csv_ingest.extract_text, "csv"),
    ".xlsx": (xlsx_ingest.extract_text, "xlsx"),
    ".xls": (xlsx_ingest.extract_text, "xlsx"),
    ".docx": (docx_ingest.extract_text, "docx"),
    ".json": (telegram.extract_text, "telegram_json"),
    ".png": (screenshot.extract_text, "screenshot"),
    ".jpg": (screenshot.extract_text, "screenshot"),
    ".jpeg": (screenshot.extract_text, "screenshot"),
}


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _title_from(path: Path) -> str:
    if path.suffix in (".md", ".markdown"):
        t = markdown.extract_title(path)
        if t:
            return t
    return path.stem.replace("_", " ").replace("-", " ")


def cmd_init(_args):
    db.init_db()
    print(f"Initialized DB at {db.DB_PATH}")


def cmd_reset(_args):
    import shutil
    for t in [db.DB_PATH, VAULT_DIR, ASSETS_DIR, REPORTS_DIR]:
        if t.is_file():
            t.unlink()
            print(f"  removed file: {t}")
        elif t.is_dir():
            shutil.rmtree(t)
            t.mkdir(parents=True, exist_ok=True)
            print(f"  cleared dir:  {t}")
    db.init_db()
    print(f"Reset complete. Inbox kept intact: {INBOX}")


def cmd_ingest(args):
    if args.inbox:
        # Any file is fair game — known extractors handle their types, unmapped
        # extensions fall back to a plain-text read (binary files skip in
        # _ingest_one). Investigative notes/exports shouldn't need a known suffix.
        paths = sorted(p for p in INBOX.iterdir()
                       if p.is_file() and not p.name.startswith("."))
        if not paths:
            print(f"Inbox empty: {INBOX}")
            return
    else:
        paths = [Path(args.file).resolve()]
    if not db.DB_PATH.exists():
        db.init_db()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with db.connect() as conn:
        new_ids = []
        for p in paths:
            rid = _ingest_one(conn, p, args.investigation)
            if rid:
                new_ids.append(rid)
        # Auto-recalibrate: fold the new intel into the ranking immediately
        # (deterministic — no LLM). The heavier clusters/relationships pass
        # still needs `./invctl analyze`; the Focus gap panel flags that.
        try:
            analyze_mod.compute_threat_scores(conn)
            focus_mod.run(conn, VAULT_DIR, llm_summary=False)
            print("  recalibrated Focus ranking (scores refreshed)")
        except Exception as exc:
            print(f"  (Focus recalibration skipped: {exc})")
        # Capture this report's claims so contradictions with prior reports surface.
        try:
            claims_mod.backfill(conn)
        except Exception as exc:
            print(f"  (claims backfill skipped: {exc})")
        # Auto-detect corrections: pull the prose role/attribute claims from each
        # NEW report (LLM pass) so a report that contradicts an earlier one surfaces
        # on its own — no manual `corrections --extract`. Skips gracefully if the
        # LLM is unavailable; existing reports need a one-time catch-up extract.
        if new_ids:
            try:
                extracted_claims = sum(
                    claims_mod.extract_claims_for_report(conn, rid) for rid in new_ids)
                open_contras = len(claims_mod.detect_contradictions(conn))
                print(f"  detected corrections: {extracted_claims} prose claim(s) "
                      f"extracted, {open_contras} open contradiction(s) to review")
            except Exception as exc:
                print(f"  (claim extraction skipped: {exc})")


def _read_text_fallback(path: Path) -> str | None:
    """Best-effort plain-text read for an unmapped extension. Returns None if the
    file looks binary (high share of decode-replacement chars), so we don't ingest
    an image/zip as garbage text."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        return None
    bad = raw.count("�")
    if bad and bad / max(1, len(raw)) > 0.10:
        return None
    return raw


def _ingest_one(conn, path: Path, investigation: str | None):
    ext = path.suffix.lower()
    # Unmapped extension → try a plain-text read (investigative notes, exports,
    # logs) instead of silently dropping it. Binary files still skip.
    use_text_fallback = ext not in EXTRACTORS and ext != ".pdf"
    if use_text_fallback and _read_text_fallback(path) is None:
        print(f"  skip (binary / empty, unsupported ext): {path.name}")
        return
    file_hash = _hash_file(path)
    existing = conn.execute(
        "SELECT id FROM reports WHERE source_hash = ?", (file_hash,)
    ).fetchone()
    if existing:
        print(f"  already ingested: {path.name} (report_id={existing['id']})")
        return

    # Structured tabular ingest: type columns → typed entities (deterministic).
    # One 'dataset' report per file, row-capped. Covers CSV/TSV + Excel.
    if ext in (".csv", ".tsv", ".xlsx", ".xls"):
        from investigations.ingest import record_ingest
        try:
            out = record_ingest.ingest(conn, path, file_hash, investigation)
        except Exception as exc:
            print(f"  structured ingest failed ({exc}); falling back to flat text")
            out = None
        if out:
            archive_path = REPORTS_DIR / f"{out['report_id']:04d}_{path.name}"
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            if not archive_path.exists():
                archive_path.write_bytes(path.read_bytes())
            n_alerts = alerts_mod.detect_for_report(conn, out["report_id"])
            cap = f" (capped at {out['rows']}/{out['row_total']} rows)" if out["capped"] else ""
            print(f"  ingested dataset: {path.name} → report_id={out['report_id']}, "
                  f"{out['typed_columns']} typed col(s), {out['entities']} entities{cap}, alerts={n_alerts}")
            return out["report_id"]
        # No structured rows → fall through to the flat extractor (csv/xlsx text).

    # Documents with embedded images (PDF, DOCX) extract each image as a viewable
    # asset (OCR'd) rather than folding the OCR into the body text — so email
    # screenshots inside a Word doc are visible in Sources, same as PDF pages.
    doc_assets_extracted = []
    doc_image_kind = None
    report_id_placeholder_dir = None
    if ext == ".pdf":
        source_type = "pdf"
        title = _title_from(path)
        doc_image_kind = "pdf_image"
        report_id_placeholder_dir = ASSETS_DIR / f"_pending_{file_hash[:12]}"
        try:
            result = pdf_assets.extract(path, report_id_placeholder_dir)
            text = result.text
            doc_assets_extracted = result.assets
        except Exception as exc:
            print(f"  FAILED PDF extract {path.name}: {exc}")
            return
    elif ext == ".docx":
        from investigations.ingest import docx_assets
        source_type = "docx"
        title = _title_from(path)
        doc_image_kind = "docx_image"
        report_id_placeholder_dir = ASSETS_DIR / f"_pending_{file_hash[:12]}"
        try:
            result = docx_assets.extract(path, report_id_placeholder_dir)
            text = result.text
            doc_assets_extracted = result.assets
        except Exception as exc:
            print(f"  FAILED DOCX extract {path.name}: {exc}")
            return
    else:
        if use_text_fallback:
            extract_fn, source_type = _read_text_fallback, "text"
        else:
            extract_fn, source_type = EXTRACTORS[ext]
        try:
            text = extract_fn(path)
        except Exception as exc:
            print(f"  FAILED to extract {path.name}: {exc}")
            return
        title = _title_from(path)

    report_id = db.insert_report(
        conn, str(path), file_hash, source_type, title, investigation, text
    )

    if doc_assets_extracted:
        report_assets_dir = ASSETS_DIR / f"report_{report_id:04d}"
        report_assets_dir.mkdir(parents=True, exist_ok=True)
        for asset in doc_assets_extracted:
            new_path = report_assets_dir / asset.saved_path.name
            if asset.saved_path.exists():
                asset.saved_path.rename(new_path)
            asset_db_id = db.add_asset(
                conn, report_id, str(new_path.relative_to(ROOT)),
                source_kind=doc_image_kind,
                page_number=asset.page_number,
                image_index=asset.image_index,
                ocr_text=asset.ocr_text,
            )
            if asset.ocr_text:
                per_image_entities = extractor.extract_all(asset.ocr_text)
                for e in per_image_entities:
                    eid = db.upsert_entity(conn, e.canonical, e.entity_type, report_id)
                    if e.surface != e.canonical:
                        db.add_alias(conn, eid, e.surface)
                    db.add_mention(
                        conn, eid, report_id, e.surface, e.context, e.offset,
                        asset_id=asset_db_id,
                    )
        if report_id_placeholder_dir is not None:
            try:
                report_id_placeholder_dir.rmdir()
            except OSError:
                pass

    # Screenshots: the uploaded image IS the evidence. Register it as a single
    # asset so it's viewable in Sources / "Read the pages" and its OCR text is
    # searchable (the Sources feed reads from assets, not raw_text). Entities
    # found in the OCR text get linked to this asset below.
    screenshot_asset_id = None
    if source_type == "screenshot":
        report_assets_dir = ASSETS_DIR / f"report_{report_id:04d}"
        report_assets_dir.mkdir(parents=True, exist_ok=True)
        asset_copy = report_assets_dir / path.name
        if not asset_copy.exists():
            asset_copy.write_bytes(path.read_bytes())
        screenshot_asset_id = db.add_asset(
            conn, report_id, str(asset_copy.relative_to(ROOT)),
            source_kind="screenshot", page_number=1, image_index=0, ocr_text=text,
        )

    extracted = extractor.extract_all(text)
    for e in extracted:
        eid = db.upsert_entity(conn, e.canonical, e.entity_type, report_id)
        if e.surface != e.canonical:
            db.add_alias(conn, eid, e.surface)
        db.add_mention(conn, eid, report_id, e.surface, e.context, e.offset,
                       asset_id=screenshot_asset_id)

    relationships = extractor.infer_relationships(text, extracted)
    for a, b, rel_type in relationships:
        a_id = db.upsert_entity(conn, a.canonical, a.entity_type, report_id)
        b_id = db.upsert_entity(conn, b.canonical, b.entity_type, report_id)
        if a_id != b_id:
            db.add_relationship(
                conn, a_id, b_id, rel_type, report_id,
                evidence=a.context[:200], confidence=0.4,
            )

    archive_path = REPORTS_DIR / f"{report_id:04d}_{path.name}"
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if not archive_path.exists():
        archive_path.write_bytes(path.read_bytes())

    # Auto-flag: watchlist hits + cross-case reappearances in this new report.
    n_alerts = alerts_mod.detect_for_report(conn, report_id)

    n_assets = len(doc_assets_extracted) + (1 if screenshot_asset_id else 0)
    print(f"  ingested: {path.name} → report_id={report_id}, "
          f"entities={len(extracted)}, rels={len(relationships)}, "
          f"assets={n_assets}, alerts={n_alerts}")
    return report_id


def backfill_screenshot_assets(conn) -> dict:
    """One-time repair: screenshot reports ingested before screenshots registered
    their own image as an asset show 0 assets and aren't viewable in Sources.
    For each such report, recover the archived image, register it as a screenshot
    asset (ocr_text = the report's raw_text), and link the report's existing
    mentions to it. Idempotent: reports that already have an asset are skipped.
    """
    repaired, missing = 0, []
    rows = conn.execute(
        "SELECT id, source_path, raw_text FROM reports WHERE source_type = 'screenshot' "
        "AND id NOT IN (SELECT DISTINCT report_id FROM assets)").fetchall()
    for r in rows:
        rid = r["id"]
        name = Path(r["source_path"]).name
        # Prefer the archived copy; fall back to the original source path.
        candidates = list(REPORTS_DIR.glob(f"{rid:04d}_*")) or (
            [Path(r["source_path"])] if r["source_path"] else [])
        src = next((c for c in candidates if c.is_file()), None)
        if not src:
            missing.append(rid)
            continue
        report_assets_dir = ASSETS_DIR / f"report_{rid:04d}"
        report_assets_dir.mkdir(parents=True, exist_ok=True)
        asset_copy = report_assets_dir / name
        if not asset_copy.exists():
            asset_copy.write_bytes(src.read_bytes())
        aid = db.add_asset(
            conn, rid, str(asset_copy.relative_to(ROOT)),
            source_kind="screenshot", page_number=1, image_index=0,
            ocr_text=r["raw_text"],
        )
        conn.execute(
            "UPDATE mentions SET asset_id = ? WHERE report_id = ? AND asset_id IS NULL",
            (aid, rid))
        repaired += 1
    conn.commit()
    return {"repaired": repaired, "missing_image": missing, "checked": len(rows)}


def cmd_query(args):
    with db.connect() as conn:
        entity = db.find_entity_by_name(conn, args.name)
        if not entity:
            print(f"No entity matching: {args.name}")
            sys.exit(1)
        print(f"# {entity['canonical_name']} ({entity['entity_type']})\n")
        mentions = db.entity_mentions(conn, entity["id"])
        print(f"## {len(mentions)} mention(s)\n")
        for m in mentions:
            print(f"### {m['report_title']}")
            print(f"> {m['context']}\n")


def cmd_connections(args):
    with db.connect() as conn:
        entity = db.find_entity_by_name(conn, args.name)
        if not entity:
            print(f"No entity matching: {args.name}")
            sys.exit(1)
        rows = db.entity_connections(conn, entity["id"])
        print(f"# Connections for {entity['canonical_name']} ({len(rows)})\n")
        seen = set()
        for r in rows:
            key = (r["canonical_name"], r["rel_type"])
            if key in seen:
                continue
            seen.add(key)
            ctx = f"  via {r['report_title']}" if r["report_title"] else ""
            print(f"- [{r['entity_type']}] {r['canonical_name']} ({r['rel_type']}){ctx}")


def cmd_understand(args):
    from investigations import understand as understand_mod
    with db.connect() as conn:
        print(f"Reading case '{args.case}' to propose a schema…")
        schema = understand_mod.discover_schema(conn, args.case)
        if args.approve:
            understand_mod.save_schema(conn, args.case, schema, status="approved", analyst="cli")
    print(f"\nProposed schema for '{args.case}': {schema.get('domain','')}")
    print(f"  {schema.get('summary','')}")
    print("  Roles:")
    for r in schema.get("roles", []):
        tag = " (actor)" if r.get("actor") else ""
        print(f"    {r['name']}{tag} — {r.get('description','')}")
    print(f"  Sub-roles: {', '.join(s['name'] for s in schema.get('sub_roles', []))}")
    print(f"  Entity types: {', '.join(t['name'] for t in schema.get('entity_types', []))}")
    if args.approve:
        print("\n  Status: APPROVED (consolidate --case will use it)")
    else:
        print("\n  Status: PROPOSED. Approve in the web UI (/schema) or re-run with --approve.")


def cmd_detect_type(args):
    from investigations.intake import types as types_mod
    with db.connect() as conn:
        result = types_mod.detect(conn, args.case, use_llm=not args.no_llm)
    print(f"\nInvestigation type for '{args.case}': {result['type']}  "
          f"(confidence {result.get('confidence','?')}, {result.get('method','')})")
    for t, s in (result.get("scores") or {}).items():
        print(f"  {t}: {s}")
    print(f"\n  Status: {result['status']}. Confirm/override on /schema.")


def cmd_osint_tool(args):
    """The investigator agent's tool belt: run one OSINT adapter, print results as
    text. Kept deliberately simple + read-only so it's safe to allowlist for the
    agent (Bash(./invctl osint-tool:*))."""
    from investigations.enrich import registry
    if args.list:
        for a in registry.all_adapters():
            if not getattr(a, "env_var", None):
                kind = "keyless"
            elif a.is_configured():
                kind = "configured"
            else:
                kind = "needs-key"
            print(f"{a.slug}\t{kind}\t{a.display_name}")
        return
    if not args.provider or not args.query:
        print("usage: osint-tool <provider> <query> [--mode M]   |   osint-tool --list")
        return
    try:
        adapter = registry.get_adapter(args.provider)
    except KeyError as exc:
        print(f"ERROR: {exc}")
        return
    # Dead provider (needs a key, has none): SKIP cleanly instead of spending a real
    # call that errors. Signals the agent NOT to retry — don't waste a turn on it.
    if getattr(adapter, "env_var", None) and not adapter.is_configured():
        print(f"SKIP ({args.provider}): not configured — no API key set. "
              f"Do not retry this provider.")
        return
    try:
        results = adapter.run(args.query, mode=args.mode)
    except Exception as exc:
        print(f"ERROR ({args.provider}): {exc}")
        return
    if not results:
        print(f"(no results from {args.provider} for {args.query!r})")
        return
    for r in results:
        print(f"## {r.title}")
        if getattr(r, "url", None):
            print(f"URL: {r.url}")
        if getattr(r, "confidence", None):
            print(f"confidence: {r.confidence}")
        print(r.summary or "")
        print()


def cmd_investigate(args):
    from investigations.agent import investigator
    with db.connect() as conn:
        if args.entity:
            out = investigator.investigate_entity(conn, args.entity, case=args.case,
                                                  max_turns=args.max_turns)
        else:
            # Whole-case: ONE bounded agent, no fan-out (RULE-114 — matches the web default).
            # --deep runs the SAME agent multi-pass (re-seeds the uninvestigated inventory).
            deep = getattr(args, "deep", False)
            out = investigator.investigate_case_agentic(
                conn, args.case, max_turns=args.max_turns,
                max_passes=investigator.CASE_MAX_PASSES if deep else 1, deep=deep)
    import json as _json
    print(_json.dumps(out, indent=2)[:4000])


def cmd_enumerate(args):
    """Stage-1 deterministic enumeration (speed-cost-staged-rollout plan)."""
    from investigations.enrich import enumerate as enum_mod
    with db.connect() as conn:
        out = enum_mod.enumerate_infra(conn, args.case, seeds=args.seed,
                                       on_event=lambda m: print(f"  {m}"))
    print(f"enumerated: {len(out['seeds'])} seed(s) + {len(out['tier2'])} tier-2, "
          f"{out['results']} result(s)")
    if out["skipped_no_recipe"]:
        print(f"  no infra recipe for: {', '.join(out['skipped_no_recipe'])}")


def cmd_diff_run(args):
    """Stage-0 differential gate (speed-cost-staged-rollout plan). --save freezes a
    baseline; a plain run diffs against it and exits non-zero on a FAIL verdict so
    the gate is scriptable."""
    from investigations.tests import diff_harness
    if args.snapshot_only:
        with db.connect() as conn:
            snap = diff_harness.snapshot_case(conn, args.case)
    else:
        snap = diff_harness.run_and_snapshot(args.case)
    if args.save:
        path = diff_harness.save_baseline(snap)
        print(f"baseline frozen: {path} "
              f"({snap['entity_count']} entities, {snap['edge_count']} edges)")
        return
    baseline = diff_harness.load_baseline(args.baseline or args.case)
    diff = diff_harness.diff_snapshots(baseline, snap)
    print(diff_harness.format_report(diff, baseline, snap))
    if diff["verdict"] != "pass":
        raise SystemExit(1)


def cmd_reextract(args):
    from investigations import reextract as reextract_mod
    with db.connect() as conn:
        out = reextract_mod.run(conn, getattr(args, "case", None))
    print(f"\nRe-extract complete: {out['reports']} report(s), "
          f"{out['new_entities']} new entities, {out['new_mentions']} new mentions")
    for t, n in sorted(out["by_type"].items(), key=lambda x: -x[1]):
        print(f"    {t}: {n}")


def cmd_correlate_fingerprints(args):
    from investigations import fingerprints as fp_mod
    with db.connect() as conn:
        res = fp_mod.correlate(conn, getattr(args, "case", None))
        hubs = fp_mod.shared(conn, getattr(args, "case", None))
    print(f"\nCross-domain correlation: {res['edges_created']} edges, "
          f"{res['shared_fingerprints']} shared fingerprint(s)")
    for h in hubs[:20]:
        print(f"  [{h['type']}] {h['fingerprint'][:40]} links {h['partner_count']}: "
              f"{', '.join(p['name'] for p in h['partners'][:6])}")


def cmd_type(args):
    from investigations import understand as understand_mod, typing as typing_mod
    with db.connect() as conn:
        schema = understand_mod.approved_schema(conn, args.case)
        if schema is None:
            print(f"No APPROVED schema for '{args.case}'. Run: ./invctl understand {args.case} --approve")
            return
        result = typing_mod.run(conn, args.case, schema)
    print(f"\nTyping pass complete: {result}")


def cmd_graph_metrics(args):
    from investigations import graph_metrics as gm
    with db.connect() as conn:
        result = gm.run(conn, args.case)
    print(f"\nGraph metrics: {result}")


def cmd_consolidate(args):
    schema = None
    case = getattr(args, "case", None)
    with db.connect() as conn:
        if case:
            from investigations import understand as understand_mod
            schema = understand_mod.approved_schema(conn, case)
            if schema is None:
                print(f"No APPROVED schema for '{case}'. Run: ./invctl understand {case} --approve")
                return
        stats = consolidate_mod.run(conn, dry_run=args.dry_run,
                                    only_new=args.only_new, schema=schema, case=case)
    print("\nConsolidation complete:")
    print(f"  Clusters processed: {stats['clusters']}")
    print(f"  Entities merged:    {stats['merged']}")
    print(f"  Marked noise:       {stats['noise']}")
    print(f"  Roles:")
    for role, count in sorted(stats["roles"].items(), key=lambda x: -x[1]):
        print(f"    {role}: {count}")
    if stats.get("sub_roles"):
        print(f"  Actor sub_roles:")
        for sr, count in sorted(stats["sub_roles"].items(), key=lambda x: -x[1]):
            print(f"    {sr}: {count}")


def cmd_analyze(_args):
    with db.connect() as conn:
        result = analyze_mod.run(conn, VAULT_DIR)
    print(f"\nAnalysis complete: {result}")


def cmd_profile(args):
    roles = set(args.roles.split(",")) if args.roles else {"operator", "channel", "ioc"}
    with db.connect() as conn:
        result = profile_mod.run(conn, VAULT_DIR, roles=roles)
    print(f"\nProfiles complete: {result}")


def cmd_seed(args):
    case_file = Path(args.file).resolve()
    if not case_file.exists():
        print(f"Case file not found: {case_file}")
        sys.exit(1)
    with db.connect() as conn:
        result = seed_mod.run(conn, case_file, default_weight=args.weight)
    print(f"\nSeed ingestion: {result['matched']} / {result['candidates']} matched")
    print(f"  case file: {result['case_file']}")
    print(f"  weight:    {result['weight']}")
    if result["seeds_added"]:
        print(f"\n  Seeds added:")
        for s in result["seeds_added"]:
            note = f" — {s['note']}" if s["note"] else ""
            print(f"    [eid={s['entity_id']}] {s['raw_name']} (w={s['weight']}){note}")
    if result["unmatched"]:
        print(f"\n  Unmatched ({len(result['unmatched'])}) — these names didn't match any entity:")
        for raw, note in result["unmatched"][:20]:
            print(f"    - {raw}{('  — ' + note) if note else ''}")
        if len(result["unmatched"]) > 20:
            print(f"    … and {len(result['unmatched']) - 20} more")
    print(f"\nNext: ./invctl analyze && ./invctl focus")


def cmd_seeds_list(_args):
    with db.connect() as conn:
        rows = seed_mod.list_seeds(conn)
    print(f"Active seeds: {len(rows)}")
    for r in rows:
        print(f"  [w={r['weight']:.1f}] {r['canonical_name'] or r['raw_name']} "
              f"({r['entity_type'] or '?'}/{r['sub_role'] or '—'}) "
              f"from {Path(r['source_file']).name if r['source_file'] else '?'}")


def cmd_seeds_clear(_args):
    with db.connect() as conn:
        n = seed_mod.clear_seeds(conn)
    print(f"Cleared {n} seed(s)")


def cmd_focus(args):
    with db.connect() as conn:
        result = focus_mod.run(conn, VAULT_DIR, llm_summary=not args.no_llm)
    print(f"\nFocus brief: {result['focus_path']}")
    print(f"  generated:       {result['generated_at']}")
    print(f"  top entities:    {result['top_n']}")
    print(f"  newly elevated:  {result['newly_elevated']}")
    print(f"  cooling off:     {result['cooling']}")


def cmd_enrich_list(_args):
    """Show all OSINT providers + configured status."""
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT slug, display_name, category, env_var, cost_estimate_usd, docs_url "
            "FROM osint_providers ORDER BY slug"
        ).fetchall()
    print(f"OSINT providers ({len(rows)}):")
    for r in rows:
        try:
            adapter = get_adapter(r["slug"])
            configured = "[*]" if adapter.is_configured() else "[ ]"
        except KeyError:
            configured = "[?]"
        cost = f"~${r['cost_estimate_usd']:.3f}/call" if r["cost_estimate_usd"] else "?"
        print(f"  {configured} {r['slug']:12s} {r['display_name']}")
        print(f"        env: {r['env_var']}  |  {cost}  |  {r['docs_url']}")
    print()
    print("[*] = configured  [ ] = missing env var  [?] = unknown")


def cmd_enrich_run(args):
    investigation = args.investigation
    with db.connect() as conn:
        result = enrich_runner.run_and_persist(
            conn, args.provider, args.query,
            entity_id=args.entity, mode=args.mode,
            investigation=investigation, timeout=args.timeout,
        )
    print(f"\nEnrichment run #{result['run_id']}: {result['status']}")
    if result["status"] == "success":
        print(f"  results: {result['result_count']}")
        print(f"  cost:    ${result['cost_usd']:.4f}")
        print(f"  elapsed: {result['elapsed_seconds']}s")
    else:
        print(f"  error: {result.get('error')}")


def cmd_enrich_history(args):
    where = []
    params: list = []
    if args.entity:
        where.append("entity_id = ?")
        params.append(args.entity)
    if args.provider:
        where.append("provider_slug = ?")
        params.append(args.provider)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(args.limit)
    with db.connect() as conn:
        rows = conn.execute(
            f"SELECT id, provider_slug, query, mode, status, started_at, "
            f"cost_usd, entity_id, error_message "
            f"FROM enrichment_runs {where_sql} "
            f"ORDER BY id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    if not rows:
        print("No enrichment runs match.")
        return
    print(f"Enrichment history ({len(rows)}):")
    for r in rows:
        bits = [f"#{r['id']}", r["status"], r["provider_slug"]]
        if r["mode"]:
            bits.append(f"({r['mode']})")
        if r["entity_id"]:
            bits.append(f"entity#{r['entity_id']}")
        if r["cost_usd"]:
            bits.append(f"${r['cost_usd']:.4f}")
        bits.append(r["started_at"])
        head = "  ".join(bits)
        print(f"  {head}")
        print(f"    query: {r['query'][:120]}")
        if r["error_message"]:
            print(f"    error: {r['error_message'][:200]}")


def cmd_briefs(args):
    with db.connect() as conn:
        result = briefs_mod.run(
            conn, VAULT_DIR,
            threshold=args.threshold,
            llm_summary=not args.no_llm,
            report_id=args.report_id,
        )
    print(f"\nBriefs written: {result['briefs_dir']}")
    print(f"  groups:      {result['groups']}")
    print(f"  standalone:  {result['standalone']}")
    print(f"  threshold:   {result['threshold']}")
    print(f"  llm summary: {result['llm_summary']}")
    print(f"  edges audited: {result['edges_audited']}")
    print(f"\nIndex: {result['briefs_dir']}/INDEX.md")


def cmd_synthesize(args):
    case = getattr(args, "case", None)
    with db.connect() as conn:
        out_path = synthesize_mod.run(conn, VAULT_DIR, case=case)
    print(f"\nSynthesis brief: {out_path}")


def cmd_corrections(args):
    with db.connect() as conn:
        if args.resolve:
            print(claims_mod.resolve(conn, args.resolve)); return
        if args.reject:
            print(claims_mod.reject(conn, args.reject)); return
        if args.extract is not None:
            if args.extract:
                n = claims_mod.extract_claims_for_report(conn, args.extract)
                print(f"Extracted {n} claim(s) from report {args.extract}.")
            else:
                total = 0
                for r in conn.execute("SELECT id FROM reports").fetchall():
                    total += claims_mod.extract_claims_for_report(conn, r["id"])
                print(f"Extracted {total} claim(s) across all reports.")
            return
        claims_mod.backfill(conn)
        cons = claims_mod.detect_contradictions(conn)
    if not cons:
        print("No contradictions detected."); return
    print(f"{len(cons)} contradiction(s) to review:")
    for c in cons:
        print(f"  {c['entity_name']} — {c['label']}:")
        for cl in c["claims"]:
            print(f"    claim #{cl['id']}: {cl['value']!r}  (report: {cl['report_title']})")
        print(f"    resolve with: ./invctl corrections --resolve <claim_id>")


def cmd_alerts(args):
    with db.connect() as conn:
        if args.scan:
            n = alerts_mod.scan_all(conn)
            print(f"Scanned all reports — {n} new alert(s).")
            return
        if args.ack is not None:
            alerts_mod.acknowledge(conn, args.ack)
            print(f"Acknowledged alert {args.ack}.")
            return
        rows = alerts_mod.list_alerts(conn, include_ack=args.all)
    if not rows:
        print("No open alerts.")
        return
    print(f"{len(rows)} alert(s):")
    for a in rows:
        ack = " (ack)" if a["acknowledged"] else ""
        print(f"  #{a['id']} [{a['severity']}] {a['alert_type']}: {a['message']}{ack}")


def cmd_export_intel(args):
    out_dir = Path(args.out).resolve() if args.out else (ROOT / "investigations" / "exports")
    out_dir.mkdir(parents=True, exist_ok=True)
    with db.connect() as conn:
        if args.format in ("stix", "all"):
            stix_path = intel_exports.export_stix(conn, out_dir / "stix_bundle.json")
            print(f"  STIX: {stix_path}")
        if args.format in ("csv", "all"):
            csv_paths = intel_exports.export_csv(conn, out_dir / "csv")
            for k, v in csv_paths.items():
                print(f"  {k}: {v}")
        if args.format in ("misp", "all"):
            misp_path = intel_exports.export_misp(conn, out_dir / "misp_event.json")
            print(f"  MISP: {misp_path}")


def cmd_correlate(_args):
    with db.connect() as conn:
        overlap = correlate_engine.cross_report_overlap(conn)
        print(f"# Entities in >1 report ({len(overlap)})\n")
        for o in overlap:
            print(f"- [{o['entity_type']}] {o['canonical_name']} "
                  f"in {o['report_count']} reports: {o['reports']}")
        linked = correlate_engine.auto_link_aliases(conn)
        print(f"\nAuto-linked {linked} alias pair(s)")


def cmd_export_vault(args):
    out = Path(args.out).resolve() if args.out else VAULT_DIR
    with db.connect() as conn:
        result = obsidian_export.export(conn, out, assets_root=ASSETS_DIR)
        canvas_path = canvas_export.export(conn, out)
        result["canvas"] = str(canvas_path.relative_to(out))
        try:
            iocs_path = canvas_export.export_iocs(conn, out)
            result["canvas_iocs"] = str(iocs_path.relative_to(out))
        except Exception as exc:
            result["canvas_iocs_error"] = str(exc)
        try:
            diff_path = canvas_export.export_diff(conn, out)
            result["canvas_diff"] = str(diff_path.relative_to(out))
        except Exception as exc:
            result["canvas_diff_error"] = str(exc)
        print(f"Exported vault: {result}")


def cmd_export_report(args):
    out = Path(args.out).resolve() if args.out else (ROOT / "investigations" / "summary.md")
    with db.connect() as conn:
        report_export.export(conn, out)
        print(f"Exported summary: {out}")


def backfill_docx_assets(conn) -> dict:
    """One-time repair: DOCX reports ingested before docx extracted embedded
    images as assets show 0 assets, so their email screenshots aren't viewable in
    Sources. For each such report, re-open the source/archived .docx, save each
    embedded image as a docx_image asset (OCR'd), and link any entities found in
    that image's OCR to it. Existing report-level mentions (from the old folded
    OCR text) are left as-is. Idempotent: reports that already have assets skip.
    """
    from investigations.ingest import docx_assets
    repaired_reports, total_assets, missing = 0, 0, []
    rows = conn.execute(
        "SELECT id, source_path FROM reports WHERE source_type = 'docx' "
        "AND id NOT IN (SELECT DISTINCT report_id FROM assets)").fetchall()
    for r in rows:
        rid = r["id"]
        candidates = list(REPORTS_DIR.glob(f"{rid:04d}_*")) or (
            [Path(r["source_path"])] if r["source_path"] else [])
        src = next((c for c in candidates if c.is_file()), None)
        if not src:
            missing.append(rid)
            continue
        report_assets_dir = ASSETS_DIR / f"report_{rid:04d}"
        try:
            result = docx_assets.extract(src, report_assets_dir)
        except Exception as exc:
            print(f"  report {rid}: docx extract failed ({exc})")
            missing.append(rid)
            continue
        for asset in result.assets:
            aid = db.add_asset(
                conn, rid, str(asset.saved_path.relative_to(ROOT)),
                source_kind="docx_image", page_number=asset.page_number,
                image_index=asset.image_index, ocr_text=asset.ocr_text)
            total_assets += 1
            if asset.ocr_text:
                for e in extractor.extract_all(asset.ocr_text):
                    eid = db.upsert_entity(conn, e.canonical, e.entity_type, rid)
                    if e.surface != e.canonical:
                        db.add_alias(conn, eid, e.surface)
                    db.add_mention(conn, eid, rid, e.surface, e.context, e.offset,
                                   asset_id=aid)
        if result.assets:
            repaired_reports += 1
    conn.commit()
    return {"repaired_reports": repaired_reports, "assets_added": total_assets,
            "missing_or_failed": missing, "checked": len(rows)}


def cmd_backfill_docx_assets(_args):
    with db.connect() as conn:
        result = backfill_docx_assets(conn)
    print(f"Backfill: {result['assets_added']} image asset(s) across "
          f"{result['repaired_reports']}/{result['checked']} docx report(s).")
    if result["missing_or_failed"]:
        print(f"  no source / extract failed for report id(s): {result['missing_or_failed']}")
    if result["assets_added"]:
        print("  Run `./invctl export-vault` to make the images viewable in Sources.")


def cmd_backfill_screenshot_assets(_args):
    with db.connect() as conn:
        result = backfill_screenshot_assets(conn)
    print(f"Backfill: repaired {result['repaired']}/{result['checked']} screenshot "
          f"report(s) with no asset.")
    if result["missing_image"]:
        print(f"  no image found for report id(s): {result['missing_image']}")
    if result["repaired"]:
        print("  Run `./invctl export-vault` to make the images viewable in Sources.")


def cmd_serve(args):
    from investigations.webapp import app as webapp
    webapp.run(host=args.host, port=args.port, reload=args.reload)


def cmd_stats(_args):
    with db.connect() as conn:
        s = db.db_stats(conn)
        print(f"Reports: {s['reports']}")
        print(f"Entities: {s['entities']}")
        print(f"Mentions: {s['mentions']}")
        print(f"Relationships: {s['relationships']}")
        if "assets" in s:
            print(f"Assets: {s['assets']}")
        print("\nTop entities by mention:")
        for r in s["top_entities"]:
            print(f"  {r['canonical_name']} ({r['entity_type']}): {r['mention_count']}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="invctl")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(func=cmd_init)
    sub.add_parser("reset").set_defaults(func=cmd_reset)

    ing = sub.add_parser("ingest")
    ing.add_argument("file", nargs="?")
    ing.add_argument("--inbox", action="store_true")
    ing.add_argument("--investigation", default=None)
    ing.set_defaults(func=cmd_ingest)

    q = sub.add_parser("query")
    q.add_argument("name")
    q.set_defaults(func=cmd_query)

    c = sub.add_parser("connections")
    c.add_argument("name")
    c.set_defaults(func=cmd_connections)

    sub.add_parser("correlate").set_defaults(func=cmd_correlate)

    cs = sub.add_parser("consolidate")
    cs.add_argument("--dry-run", action="store_true")
    cs.add_argument("--only-new", action="store_true",
                    help="Only process entities not yet classified (notes IS NULL)")
    cs.add_argument("--case", default=None,
                    help="Classify only this case's entities using its approved schema")
    cs.set_defaults(func=cmd_consolidate)

    un = sub.add_parser("understand", help="Propose a per-case entity/role schema (the Understand step)")
    un.add_argument("case", help="Investigation slug to model")
    un.add_argument("--approve", action="store_true",
                    help="Approve the proposed schema immediately (skip the review gate)")
    un.set_defaults(func=cmd_understand)

    ty = sub.add_parser("type", help="Typing pass: fit entities to the case schema + recover missed ones")
    ty.add_argument("case", help="Investigation slug (needs an approved schema)")
    ty.set_defaults(func=cmd_type)

    dt = sub.add_parser("detect-type", help="Identify the investigation type (deterministic-first)")
    dt.add_argument("case", help="Investigation slug")
    dt.add_argument("--no-llm", action="store_true", help="Deterministic only, never call the LLM")
    dt.set_defaults(func=cmd_detect_type)

    ot = sub.add_parser("osint-tool", help="Run one OSINT adapter (the investigator agent's tool belt)")
    ot.add_argument("provider", nargs="?", help="adapter slug (crtsh, infra, virustotal, …)")
    ot.add_argument("query", nargs="?", help="domain / ip / indicator / search query")
    ot.add_argument("--mode", default=None)
    ot.add_argument("--list", action="store_true", help="list available adapters")
    ot.set_defaults(func=cmd_osint_tool)

    iv = sub.add_parser("investigate", help="Run the investigator agent on an entity or a whole case (one bounded agent; --deep for multi-pass)")
    iv.add_argument("--entity", default=None, help="entity name to investigate (omit for whole-case)")
    iv.add_argument("--case", default=None, help="case slug (scopes landing)")
    iv.add_argument("--max-turns", type=int, default=12)
    iv.add_argument("--concurrency", type=int, default=4, help="(deprecated — whole-case no longer fans out)")
    iv.add_argument("--deep", action="store_true", help="multi-pass: re-seed the uninvestigated inventory until dry")
    iv.set_defaults(func=cmd_investigate)

    en = sub.add_parser("enumerate", help="Deterministic infra enumeration over a case's seeds (zero LLM): type belts + tier-2, lands nodes/edges")
    en.add_argument("case", help="case slug")
    en.add_argument("--seed", action="append", default=None, help="explicit seed (repeatable; default: case roster)")
    en.set_defaults(func=cmd_enumerate)

    dr = sub.add_parser("diff-run", help="Differential gate: run the whole-case agent and diff the graph vs the frozen baseline (--save to freeze)")
    dr.add_argument("case", help="case slug")
    dr.add_argument("--save", action="store_true", help="freeze this run as the baseline instead of diffing")
    dr.add_argument("--snapshot-only", action="store_true", help="snapshot/diff the CURRENT graph without running the agent")
    dr.add_argument("--baseline", default=None, help="diff against ANOTHER case's frozen baseline (A/B on a fresh case with the same seeds)")
    dr.set_defaults(func=cmd_diff_run)

    rx = sub.add_parser("reextract", help="Re-run the extractor over existing reports (backfill new entity types)")
    rx.add_argument("--case", default=None, help="Only this case (default: all)")
    rx.set_defaults(func=cmd_reextract)

    cf = sub.add_parser("correlate-fingerprints", help="Link entities sharing a tracking tag / WalletConnect id / nameserver")
    cf.add_argument("--case", default=None, help="Only this case (default: all)")
    cf.set_defaults(func=cmd_correlate_fingerprints)

    sub.add_parser("analyze").set_defaults(func=cmd_analyze)

    pr = sub.add_parser("profile")
    pr.add_argument("--roles", default=None,
                    help="Comma-separated roles (default: operator,channel,ioc)")
    pr.set_defaults(func=cmd_profile)

    syn = sub.add_parser("synthesize", help="Cross-report brief (global or per-case)")
    syn.add_argument("--case", default=None,
                     help="Investigation slug — brief covers only that case's reports")
    syn.set_defaults(func=cmd_synthesize)

    co = sub.add_parser("corrections", help="Detect/resolve cross-report contradictions")
    co.add_argument("--resolve", type=int, default=None,
                    help="Make this claim id authoritative; supersede competing claims")
    co.add_argument("--reject", type=int, default=None, help="Mark a claim id as wrong")
    co.add_argument("--extract", nargs="?", const=0, type=int, default=None,
                    help="LLM-extract claims from a report id (or all reports if no id)")
    co.set_defaults(func=cmd_corrections)

    al = sub.add_parser("alerts", help="List/scan auto-generated alerts")
    al.add_argument("--scan", action="store_true",
                    help="(Re)scan every report for watchlist + cross-case alerts")
    al.add_argument("--ack", type=int, default=None, help="Acknowledge alert by id")
    al.add_argument("--all", action="store_true", help="Include acknowledged alerts")
    al.set_defaults(func=cmd_alerts)

    sd = sub.add_parser("seed", help="Ingest known-bad-actor case file as priors")
    sd.add_argument("file", help="Path to case-file markdown")
    sd.add_argument("--weight", type=float, default=1.5,
                    help="Prior weight (default 1.5; >2 is strong, <1 is soft)")
    sd.set_defaults(func=cmd_seed)

    sdl = sub.add_parser("seeds-list", help="List active seed priors")
    sdl.set_defaults(func=cmd_seeds_list)

    sdc = sub.add_parser("seeds-clear", help="Remove all seeds")
    sdc.set_defaults(func=cmd_seeds_clear)

    fc = sub.add_parser("focus", help="Generate vault/focus.md (top targets + diff vs last run)")
    fc.add_argument("--no-llm", action="store_true",
                    help="Skip LLM summary, use template fallback")
    fc.set_defaults(func=cmd_focus)

    # Grouped briefs (relatedness across reports)
    br = sub.add_parser("briefs", help="Generate per-group analysis briefs (relatedness-aware)")
    br.add_argument("--threshold", type=float, default=0.15,
                    help="Jaccard threshold to treat reports as related (default 0.15)")
    br.add_argument("--no-llm", action="store_true",
                    help="Skip LLM summary; just write structure + facts")
    br.add_argument("--report-id", type=int, default=None,
                    help="Only regenerate the brief containing this report id")
    br.set_defaults(func=cmd_briefs)

    # OSINT enrichment
    er = sub.add_parser("enrich", help="OSINT enrichment via provider adapters")
    er_sub = er.add_subparsers(dest="enrich_cmd", required=True)

    el = er_sub.add_parser("list", help="Show all providers + configured status")
    el.set_defaults(func=cmd_enrich_list)

    err = er_sub.add_parser("run", help="Run an enrichment query against a provider")
    err.add_argument("--provider", required=True, help="provider slug (perplexity/tavily/exa/apify/jina)")
    err.add_argument("--query", required=True, help="query string")
    err.add_argument("--mode", default=None, help="provider-specific mode (e.g. sonar, deep, reasoning)")
    err.add_argument("--entity", type=int, default=None, help="attach run to entity id")
    err.add_argument("--investigation", default=None, help="case tag")
    err.add_argument("--timeout", type=int, default=90)
    err.set_defaults(func=cmd_enrich_run)

    eh = er_sub.add_parser("history", help="Show recent enrichment runs")
    eh.add_argument("--entity", type=int, default=None)
    eh.add_argument("--provider", default=None)
    eh.add_argument("--limit", type=int, default=20)
    eh.set_defaults(func=cmd_enrich_history)

    ev = sub.add_parser("export-vault")
    ev.add_argument("--out", default=None)
    ev.set_defaults(func=cmd_export_vault)

    er = sub.add_parser("export-report")
    er.add_argument("--out", default=None)
    er.set_defaults(func=cmd_export_report)

    ex = sub.add_parser("export-intel")
    ex.add_argument("--format", choices=["stix", "csv", "misp", "all"], default="all")
    ex.add_argument("--out", default=None)
    ex.set_defaults(func=cmd_export_intel)

    gm = sub.add_parser("graph-metrics",
                        help="Centrality + Louvain communities over the case subgraph -> node_properties")
    gm.add_argument("case", help="Case slug")
    gm.set_defaults(func=cmd_graph_metrics)

    sub.add_parser("stats").set_defaults(func=cmd_stats)

    sub.add_parser("backfill-screenshot-assets",
                   help="Register pre-existing screenshot images as viewable assets"
                   ).set_defaults(func=cmd_backfill_screenshot_assets)

    sub.add_parser("backfill-docx-assets",
                   help="Extract embedded images from pre-existing DOCX reports as viewable assets"
                   ).set_defaults(func=cmd_backfill_docx_assets)

    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument("--reload", action="store_true")
    sv.set_defaults(func=cmd_serve)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
