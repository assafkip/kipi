"""Skill -> hook wiring is ENFORCED, not aspirational (skill-hook-pairing rule).

The recurring bug this kills: a deterministic lint/gate script gets authored but never
WIRED into a hook config, so it never fires and the paired skill's rules are ungated. The
audit found 8 such orphans. Manual one-by-one wiring treats symptoms; this test fixes the
generator -- it makes the invalid state fail the suite.

It enforces the manifest at q-system/.q-system/skill-hook-manifest.json:
  1. every kipi skill is TRIAGED in the manifest (a new untriaged skill -> red);
  2. every 'wired' claim is a hook that EXISTS on disk AND is REFERENCED in a wired config
     (.claude/settings.json or a plugin hooks.json) -- a 'wired' claim that's actually an
     orphan -> red (the exact bug);
  3. the 'debt' set may only SHRINK -- a new ungated skill that isn't in debt_baseline -> red;
  4. a 'debt' skill whose hook IS in fact wired -> red (forces the status flip when you pay
     down debt, so the manifest can't lie in the other direction either).

Run: .venv/bin/python -m pytest investigations/tests/test_skill_hooks_wired.py -q
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
# In .claude/ (NOT q-system/) on purpose: the kipi-update skeleton sync rsyncs q-system/
# with --delete and wipes instance files there. .claude/ is outside the sync surface.
MANIFEST = ROOT / ".claude" / "skill-hook-manifest.json"
_SCRIPT_RE = re.compile(r"[A-Za-z0-9_-]+\.(?:py|sh)")
# Search roots for "does this hook script exist" -- deliberately excludes .venv (huge) and
# dist/ (build artifacts that shadow the real sources).
_SEARCH_ROOTS = ("q-system", "plugins", "investigations", ".claude")


def _load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def _skills_on_disk() -> set[str]:
    out = set()
    for pat in ("plugins/*/skills/*/SKILL.md", "q-investigate/skills/*/SKILL.md"):
        for p in ROOT.glob(pat):
            if "/dist/" not in str(p):
                out.add(p.parent.name)
    return out


def _wired_config_files() -> list[Path]:
    files = [ROOT / ".claude" / "settings.json", ROOT / ".claude" / "settings.local.json"]
    files += [p for p in ROOT.glob("plugins/*/hooks/hooks.json") if "/dist/" not in str(p)]
    return [f for f in files if f.exists()]


def _wired_script_basenames() -> set[str]:
    refs: set[str] = set()
    for f in _wired_config_files():
        refs |= set(_SCRIPT_RE.findall(f.read_text()))
    return refs


def _script_exists(name: str) -> bool:
    for root in _SEARCH_ROOTS:
        base = ROOT / root
        if not base.exists():
            continue
        for p in base.rglob(name):
            s = str(p)
            if "/.venv/" in s or "/dist/" in s or "__pycache__" in s:
                continue
            return True
    return False


# --- the invariants ---------------------------------------------------------

def test_every_skill_is_triaged():
    manifest = _load_manifest()
    declared = set(manifest["skills"])
    on_disk = _skills_on_disk()
    untriaged = on_disk - declared
    assert not untriaged, (
        f"skills on disk but NOT triaged in skill-hook-manifest.json: {sorted(untriaged)}. "
        f"Triage each: wired / debt / in-script / interpretive.")
    stale = declared - on_disk
    assert not stale, f"manifest names skills that no longer exist on disk: {sorted(stale)}"


def test_wired_claims_are_real():
    """A 'wired' status must be a hook that EXISTS and is REFERENCED in a wired config.
    This is the orphan-catcher: a script on disk that no config references is NOT wired."""
    manifest = _load_manifest()
    wired_refs = _wired_script_basenames()
    for skill, spec in manifest["skills"].items():
        if spec["status"] != "wired":
            continue
        for hook in spec.get("hooks", []):
            assert _script_exists(hook), f"{skill}: wired hook {hook} does not exist on disk"
            assert hook in wired_refs, (
                f"{skill}: hook {hook} is claimed 'wired' but is NOT referenced in any wired "
                f"config (settings.json / a plugin hooks.json) -- it's an ORPHAN, it never fires")


def test_debt_only_shrinks():
    """The ratchet: the set of ungated skills can only shrink. A new ungated skill that
    isn't in debt_baseline fails here -- you must wire it or deliberately add it to baseline."""
    manifest = _load_manifest()
    baseline = set(manifest["debt_baseline"])
    current_debt = {s for s, v in manifest["skills"].items() if v["status"] == "debt"}
    grew = current_debt - baseline
    assert not grew, (
        f"new ungated skill(s) added without acknowledgement: {sorted(grew)}. Either wire a "
        f"hook (status 'wired') or add to debt_baseline in this diff (a deliberate act).")
    # baseline must reference only real, debt-status skills (no stale ratchet entries).
    stale_baseline = baseline - current_debt
    assert not stale_baseline, (
        f"debt_baseline lists skills that are no longer 'debt': {sorted(stale_baseline)} -- "
        f"remove them so the ratchet keeps tightening.")


def test_debt_hooks_not_actually_wired():
    """Forcing function: when you wire a debt skill's hook, this turns red until you flip its
    status to 'wired' + drop it from debt_baseline. Keeps the manifest from lying either way."""
    manifest = _load_manifest()
    wired_refs = _wired_script_basenames()
    for skill, spec in manifest["skills"].items():
        if spec["status"] != "debt":
            continue
        wired_now = [h for h in spec.get("hooks", []) if h in wired_refs]
        assert not wired_now, (
            f"{skill} is marked 'debt' but its hook(s) {wired_now} ARE wired now -- flip its "
            f"status to 'wired' and remove it from debt_baseline.")


def test_manifest_is_valid():
    manifest = _load_manifest()
    valid = {"wired", "debt", "in-script", "interpretive"}
    for skill, spec in manifest["skills"].items():
        assert spec["status"] in valid, f"{skill}: bad status {spec['status']!r}"
