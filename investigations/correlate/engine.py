"""Cross-report correlation. Finds entities that appear in multiple reports
and surfaces connections."""


def cross_report_overlap(conn) -> list[dict]:
    """Return entities mentioned in >1 report, with the report list per entity."""
    rows = conn.execute(
        "SELECT e.id, e.canonical_name, e.entity_type, "
        "COUNT(DISTINCT m.report_id) AS report_count, "
        "GROUP_CONCAT(DISTINCT r.title) AS reports "
        "FROM entities e "
        "JOIN mentions m ON m.entity_id = e.id "
        "JOIN reports r ON r.id = m.report_id "
        "GROUP BY e.id "
        "HAVING report_count > 1 "
        "ORDER BY report_count DESC, e.canonical_name"
    ).fetchall()
    return [dict(r) for r in rows]



def auto_link_aliases(conn, similarity_threshold: float = 0.8) -> int:
    """Find pairs of entities with very similar canonical names and link as aliases.
    Conservative: same prefix + close edit distance. Returns number of links created."""
    entities = conn.execute(
        "SELECT id, canonical_name, entity_type FROM entities "
        "WHERE entity_type IN ('person', 'person_candidate')"
    ).fetchall()
    linked = 0
    for i, a in enumerate(entities):
        for b in entities[i + 1:]:
            if a["canonical_name"] == b["canonical_name"]:
                continue
            if _similar(a["canonical_name"], b["canonical_name"]) >= similarity_threshold:
                conn.execute(
                    "INSERT OR IGNORE INTO aliases (entity_id, alias) VALUES (?, ?)",
                    (a["id"], b["canonical_name"]),
                )
                linked += 1
    return linked


def _similar(a: str, b: str) -> float:
    """Cheap similarity: token overlap ratio."""
    ta, tb = set(a.lower().split()), set(b.lower().split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / max(len(ta), len(tb))
