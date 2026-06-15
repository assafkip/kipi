"""Per-node run progress renders in the LEFT dig card (issue rps-2, run-progress-semantics).

Structural assertions over graph.html: the run-progress block renders per-target chips
from the dig's progress.targets, with a live elapsed clock + ETA, and the "running never
reads 0 findings" rule is in the chip logic. The block lives inside the left Runs-rail dig
card (surfaces stay decoupled). Live behaviour (chips animate queued→running→done, elapsed
ticks, ETA shows) is screenshot-verified on the native-app server.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GRAPH = REPO / "investigations" / "webapp" / "templates" / "graph.html"


def src():
    return GRAPH.read_text()


def test_run_progress_block_exists_in_left_dig_card():
    s = src()
    i_rail = s.find("LEFT TASK RAIL")
    i_block = s.find("RUN PROGRESS")
    i_drawer = s.find("Selected node panel")
    assert i_rail != -1 and i_block != -1 and i_drawer != -1, "markers missing"
    # The block must live in the left rail/dig card, before the right node drawer —
    # surfaces stay decoupled (graph-ui-three-surfaces).
    assert i_rail < i_block < i_drawer, "run-progress block must render in the left dig card"


def test_renders_per_target_chips_from_progress_targets():
    s = src()
    assert 'x-for="t in digs[did].progress.targets"' in s, \
        "per-target chips not driven by progress.targets"
    assert "targetChip(t)" in s and "targetChipClass(t)" in s, \
        "chip label/class helpers not wired into the template"


def test_running_target_never_reads_zero_findings():
    # The core semantics: a running target shows ⟳, a finished zero-result shows neutral
    # 'none' — never '0 findings' as a mid-run verdict (the false-negative this fixes).
    s = src()
    i = s.find("targetChip(t) {")
    assert i != -1, "targetChip helper missing"
    body = s[i:i + 400]
    assert "'⟳ '" in body, "running state must render a spinner glyph, not a count"
    assert "none" in body, "zero-result finished target must read 'none', not '0 findings'"
    # The literal mid-run false-negative must not be the running label.
    assert "0 findings" not in body


def test_live_elapsed_and_eta_helpers_referenced():
    s = src()
    assert "runElapsed(digs[did])" in s, "elapsed clock not rendered"
    assert "runEta(digs[did])" in s, "ETA not rendered"
    # The helpers exist and read clockNow (so Alpine re-renders each tick).
    assert "runElapsed(dig) {" in s and "runEta(dig) {" in s, "elapsed/eta helpers missing"
    assert "clockNow" in s, "elapsed clock has no ticking source"


def test_progress_block_uses_x_if_not_x_show():
    # finding-1: x-show evaluates child x-for/x-text even while hidden, throwing on a fresh
    # dig's progress:null. The block must be an x-if template so the subtree is absent until
    # progress.targets exists.
    s = src()
    i = s.find("RUN PROGRESS")
    block = s[i:i + 700]
    assert 'x-if="digs[did].progress && digs[did].progress.targets' in block, \
        "run-progress block must be gated by x-if (template), not x-show"


def test_elapsed_freezes_at_run_end():
    # finding-2: a finished card must not keep ticking when a later run restarts clockNow.
    s = src()
    assert "elapsed_s_final" in s, "no frozen-elapsed snapshot — finished cards will inflate"
    i = s.find("runElapsed(dig) {")
    body = s[i:i + 500]
    assert "elapsed_s_final" in body, "runElapsed must read the frozen value once not live"
    assert "runIsLive(dig)" in body, "runElapsed must branch on whether the run is still live"


def test_set_run_owns_a_rail_card():
    # finding-3 (the critical one): a SET run (the founder's 0/7 multi-select case) must own a
    # synthetic rail card so its per-node chips render — expandSelected/investigateSelected
    # must NOT set runDigId=null (which left the set run with no card to render into).
    s = src()
    assert "openSetRunDig(" in s, "no synthetic set-run card helper"
    assert s.count("this.runDigId = null;   // a set run is not owned") == 0, \
        "set-run handlers still null runDigId — the set run would render no progress card"
    # both set handlers route through the synthetic card
    assert "openSetRunDig(this.selectedSet.length)" in s
    # the synthetic card hides single-node transforms (it has no node to transform)
    assert '_setRun' in s and 'x-show="!digs[did]._setRun"' in s, \
        "set-run card must hide the single-node Transforms section"


def test_chip_has_full_title_for_truncated_labels():
    # finding-5: the chip truncates; a :title carries the full label so the trailing verdict
    # (· none / · K) is recoverable on hover.
    s = src()
    assert ':title="targetChip(t)"' in s, "chip is truncatable with no title to recover the verdict"


def test_progress_block_introduces_no_browser_nav():
    # The frontend-wiring ratchet guards the whole file; this is a focused guard that the
    # new run-card code added no same-origin browser nav (window.open / location.* / target=_blank).
    s = src()
    i_block = s.find("RUN PROGRESS")
    j_block = s.find("Transforms</div>", i_block)
    block = s[i_block:j_block]
    for bad in ("window.open", "location.href", "location.assign", "location.reload", "_blank"):
        assert bad not in block, f"run-progress block must not use {bad}"


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\nPASS: {len(fns)} tests")
    sys.exit(0)
