"""In-app navigation layer (issue in-app-nav-layer, finding-5).

Structural assertions over the template sources that the window.kipiNav shim
exists, the Back/breadcrumb chrome is present, the [[entity]] cross-links bind
an in-app handler, and the 12 converted templates route same-origin navigation
through kipiNav instead of raw browser primitives. This is the issue's
required_check; the broader ratchet (test_frontend_wiring.py) is the standing
gate.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
T = REPO / "investigations" / "webapp" / "templates"

CONVERTED = [
    "_layout.html", "_chat.html", "_process_panel.html", "alerts.html",
    "cases.html", "corrections.html", "cross-domain.html", "entity.html",
    "findings.html", "runs.html", "synthesis.html", "report-builder.html",
]

# Same browser-delegated-nav class the ratchet bans (incl. the bare
# `location = '/'` assignment the ratchet is tightened to catch in issue 1).
_RAW_NAV = re.compile(
    r"""window\.open\(\s*['"`]/"""
    r"""|\blocation\.reload\s*\("""
    r"""|\b(?:window\.)?location\s*\.\s*(?:href\s*=|assign\(|replace\()\s*['"`]/"""
    r"""|\b(?:window\.)?location\s*=\s*['"`]/"""
)


def test_kipinav_shim_defined_in_layout():
    src = (T / "_layout.html").read_text()
    assert "window.kipiNav" in src, "kipiNav shim missing from _layout.html"
    for method in ("go(", "back(", "refresh(", "openGraph(", "entity("):
        assert method in src, f"kipiNav.{method} missing"


def test_back_and_breadcrumb_chrome_present():
    src = (T / "_layout.html").read_text()
    assert "kipiNav.back()" in src, "Back affordance not wired to kipiNav.back()"
    assert 'id="kipi-breadcrumb"' in src, "breadcrumb element missing"


def test_entity_crosslinks_bind_inapp_handler():
    for fname in ("synthesis.html", "entity.html"):
        src = (T / fname).read_text()
        # the [[entity]] replace now emits a handler, not a dead href="#"
        assert "kipiNav.entity(" in src, f"{fname}: [[entity]] not wired to kipiNav.entity"


def test_converted_templates_use_kipinav_not_raw_nav():
    offenders = []
    for fname in CONVERTED:
        for lineno, line in enumerate((T / fname).read_text().splitlines(), 1):
            if "wiring-allow" in line:
                continue  # the shim's documented primitive lines
            if _RAW_NAV.search(line):
                offenders.append(f"{fname}:{lineno}: {line.strip()[:100]}")
    assert not offenders, "raw browser-delegated nav still present:\n" + "\n".join(offenders)
