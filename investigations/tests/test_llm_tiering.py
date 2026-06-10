"""PRD-02: enforce the model-tier rule so cheap work never silently runs on the
expensive model (Acme Intel's opening complaint). Classification / extraction / typing must
pin CLASSIFY_MODEL (Haiku); judgment / synthesis use the default (Sonnet).

This is a deterministic source guard: it asserts each known call site carries (or omits)
the model pin. If someone adds a classify call without the pin, this fails.

Run: .venv/bin/python -m investigations.tests.test_llm_tiering
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _src(rel):
    return (ROOT / "investigations" / rel).read_text(encoding="utf-8")


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


# (file, a substring ON or beside the specific classify call) → near that call there
# must be both an llm.ask* and a CLASSIFY_MODEL pin. The hint targets the ONE classify
# call so a judgment call elsewhere in the same file (e.g. graph_chat's reply) is ignored.
CLASSIFY_SITES = [
    ("consolidate.py", "mechanical classification"),  # comment beside the dedup call
    ("typing.py", "llm.ask_json(_retype_prompt"),     # re-type entities to schema
    ("typing.py", "llm.ask_json(_extract_prompt"),    # recover missed typed entities
    ("claims.py", "Extract the claims"),
    ("intake/types.py", "What kind of investigation"),
    ("webapp/graph_chat.py", 'f"Message: {message}'),  # the intent-parse call
    ("ask.py", "system=MAP_SYSTEM, timeout=120"),     # map step of the full sweep
]

# These are judgment/synthesis — they must NOT pin CLASSIFY_MODEL.
JUDGMENT_SITES = [
    ("synthesize.py", "brief_md = llm.ask("),
    ("understand.py", "raw = llm.ask_json(_build_prompt"),
    ("agent/swarm.py", "PLANNER_SYSTEM"),
]


def test_classify_sites_pin_haiku():
    for rel, _hint in CLASSIFY_SITES:
        src = _src(rel)
        _check(f"{rel} pins CLASSIFY_MODEL somewhere",
               "model=llm.CLASSIFY_MODEL" in src or "model=CLASSIFY_MODEL" in src)


def test_each_classify_call_is_pinned():
    # The classify call identified by each hint must sit next to both an llm.ask* and a
    # CLASSIFY_MODEL pin. Targets the specific call, ignoring judgment calls in the file.
    for rel, hint in CLASSIFY_SITES:
        src = _src(rel)
        idx = src.find(hint)
        _check(f"{rel} has the classify call ({hint[:28]}…)", idx != -1)
        window = src[max(0, idx - 400): idx + 400]
        _check(f"{rel} classify call near an llm.ask*", "llm.ask" in window)
        _check(f"{rel} classify call is Haiku-pinned", "CLASSIFY_MODEL" in window)


def test_judgment_sites_use_default_model():
    for rel, hint in JUDGMENT_SITES:
        src = _src(rel)
        idx = src.find(hint)
        _check(f"{rel} has the judgment call ({hint[:24]}…)", idx != -1)
        window = src[max(0, idx - 200): idx + 200]
        _check(f"{rel} judgment call does NOT pin CLASSIFY_MODEL",
               "CLASSIFY_MODEL" not in window)


def main():
    test_classify_sites_pin_haiku()
    test_each_classify_call_is_pinned()
    test_judgment_sites_use_default_model()
    print("\nPASS: test_llm_tiering")


if __name__ == "__main__":
    main()
