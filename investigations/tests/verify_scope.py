"""Manual scope check: hit the running webapp and compare per-case counts.

Usage: start the app, then
  .venv/bin/python -m investigations.tests.verify_scope <base_url>

Asserts every scoped API returns no more than the all-cases count for each
case (no cross-case leak), and that at least one case is a strict subset.
"""
import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8793"


def get(path, case):
    req = urllib.request.Request(BASE + path, headers={"Cookie": f"case={case}"})
    return json.load(urllib.request.urlopen(req))


def n(d, key):
    v = d.get(key)
    return len(v) if isinstance(v, list) else v


def check_cross_edges(cases):
    """/api/bridges cross_edges must not reference entities outside the case.

    A pure count check misses this: the leaking array AND the all-cases array
    both cap at 200, so 'case <= all' passes while the case view is full of
    another investigation's edges. Check endpoint identity instead.
    """
    bad = False
    for c in cases:
        if c == "__all__":
            continue
        ents = {e["id"] for e in get("/api/entities?limit=5000", c).get("entities", [])}
        edges = get("/api/bridges", c).get("cross_edges", [])
        outside = [e for e in edges
                   if e.get("src_id") not in ents or e.get("dst_id") not in ents]
        if outside:
            bad = True
            ex = outside[0]
            print(f"FAIL: /api/bridges cross_edges leak in {c}: {len(outside)} of "
                  f"{len(edges)} edges touch out-of-case entities "
                  f"(e.g. {ex.get('src_name')} -> {ex.get('dst_name')})")
        else:
            print(f"ok: cross_edges scoped for {c} ({len(edges)} edges, all in-case)")
    return bad


def check_multi_case():
    """A multi-case selection returns the UNION: ≥ each single case, ≤ all-cases."""
    n = lambda case: len(get("/api/entities?limit=5000", case).get("entities", []))
    a, b = n("case-a"), n("case-b")
    multi, allc = n("case-a,case-b"), n("__all__")
    ok = max(a, b) <= multi <= allc and multi >= a and multi >= b
    print(f"{'ok' if ok else 'FAIL'}: multi-case union entities={multi} "
          f"(singles {a}/{b}, all {allc})")
    return not ok


def main():
    endpoints = [
        ("/api/entities?limit=5000", "entities"),
        ("/api/graph?min_score=0&in_cluster_only=false", "nodes"),
        ("/api/bridges", "bridges"),
        ("/api/clusters", "clusters"),
        ("/api/sub-roles", "sub_roles"),
        ("/api/seeds", "seeds"),
    ]
    cases = ["__all__", "case-a", "case-b"]
    header = "endpoint".ljust(42) + "".join(c.rjust(14) for c in cases)
    print(header)
    print("-" * len(header))
    leak = False
    subset_seen = False
    for path, key in endpoints:
        vals = [n(get(path, c), key) for c in cases]
        all_v = vals[0]
        for v in vals[1:]:
            if v is not None and all_v is not None:
                if v > all_v:
                    leak = True
                if v < all_v:
                    subset_seen = True
        print(path[:42].ljust(42) + "".join(str(v).rjust(14) for v in vals))
    print()
    for c in cases:
        s = get("/api/stats", c)
        print(f"stats[{c}]: reports={s['reports']} entities={s['entities']}")

    print()
    if check_cross_edges(cases):
        leak = True
    if check_multi_case():
        leak = True

    print()
    if leak:
        print("FAIL: a case returned MORE than all-cases, or cross_edges leaked")
        sys.exit(1)
    if not subset_seen:
        print("FAIL: no endpoint showed a strict per-case subset (scoping not applied?)")
        sys.exit(1)
    print("PASS: every case scoped, no leak, strict subsets present")
    sys.exit(0)


if __name__ == "__main__":
    main()
