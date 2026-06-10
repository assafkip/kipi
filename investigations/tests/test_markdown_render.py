"""Agent/report text shown in tabs must render markdown (so '**Source:**' shows bold,
not literal asterisks) — and must escape HTML first so report/agent text can't inject
markup. Guards the server-side `md` Jinja filter.

Run: .venv/bin/python -m investigations.tests.test_markdown_render
"""
from investigations.webapp.app import _md_to_html as md


def _check(label, cond):
    assert cond, f"FAIL: {label}"
    print(f"  ok  {label}")


def test_bold():
    _check("**bold** → <strong>", "<strong>Source:</strong>" in md("**Source:** agent enrichment"))


def test_header():
    _check("# header → <strong>", "<strong>What we found</strong>" in md("# What we found"))


def test_list():
    out = md("- a\n- b")
    _check("bullets → <ul><li>", "<ul" in out and "<li>a</li>" in out and "<li>b</li>" in out)


def test_paragraphs():
    out = md("line one\n\nline two")
    _check("blank line → separate <p>", out.count("<p>") == 2)


def test_html_is_escaped():
    out = md("<script>alert(1)</script> **x**")
    _check("raw HTML escaped (no injection)", "<script>" not in out and "&lt;script&gt;" in out)
    _check("markdown still applied after escaping", "<strong>x</strong>" in out)


def test_empty_safe():
    _check("None → empty", md(None) == "")


def main():
    test_bold(); test_header(); test_list(); test_paragraphs()
    test_html_is_escaped(); test_empty_safe()
    print("\nPASS: test_markdown_render")


if __name__ == "__main__":
    main()
