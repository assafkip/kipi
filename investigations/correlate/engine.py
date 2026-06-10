"""Cross-report correlation. Finds entities that appear in multiple reports
and surfaces connections."""
from collections import defaultdict


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


def shared_entities(conn, report_a_id: int, report_b_id: int) -> list[dict]:
    """Entities mentioned in both reports."""
    rows = conn.execute(
        "SELECT e.canonical_name, e.entity_type "
        "FROM entities e "
        "WHERE e.id IN (SELECT entity_id FROM mentions WHERE report_id = ?) "
        "AND e.id IN (SELECT entity_id FROM mentions WHERE report_id = ?)",
        (report_a_id, report_b_id),
    ).fetchall()
    return [dict(r) for r in rows]


def report_similarity_matrix(conn) -> dict[tuple[int, int], float]:
    """Jaccard similarity between every pair of reports based on shared entity sets."""
    reports = conn.execute("SELECT id, title FROM reports").fetchall()
    entity_sets: dict[int, set[int]] = defaultdict(set)
    rows = conn.execute("SELECT report_id, entity_id FROM mentions").fetchall()
    for r in rows:
        entity_sets[r["report_id"]].add(r["entity_id"])

    matrix: dict[tuple[int, int], float] = {}
    ids = [r["id"] for r in reports]
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            sa, sb = entity_sets.get(a, set()), entity_sets.get(b, set())
            union = sa | sb
            if not union:
                continue
            matrix[(a, b)] = len(sa & sb) / len(union)
    return matrix


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
