"""Domain extraction across weird/abusive TLDs.

Abuse + fraud domains live on cheap TLDs (.xyz/.top/.icu/.cyou/.tk/.sbs), so DOMAIN_RE
captures ANY final label and extract_all validates it against DOMAIN_TLDS. The set is
broad on abuse gTLDs + common ccTLDs (incl .us) but OMITS the ccTLDs that collide with
source-file extensions, so README.md / main.py never get typed as domains.

Run: .venv/bin/python3 -m pytest investigations/tests/test_domain_tlds.py -q
 or: .venv/bin/python3 -m investigations.tests.test_domain_tlds
"""
from investigations.ingest.extractor import extract_all, DOMAIN_TLDS


def _domains(text):
    return {e.canonical for e in extract_all(text) if e.entity_type == "domain"}


def test_abuse_tlds_extract():
    got = _domains("trumpstake.us evilscam.xyz freebux.top giveaway.tk "
                   "casino.icu promo.cyou drop.sbs cheap.cfd")
    for d in ["trumpstake.us", "evilscam.xyz", "freebux.top", "giveaway.tk",
              "casino.icu", "promo.cyou", "drop.sbs", "cheap.cfd"]:
        assert d in got, f"missed abuse domain {d}: {got}"


def test_source_filenames_are_not_domains():
    code = ("README.md main.py lib.rs build.sh index.js config.json data.yaml "
            "notes.txt report.pdf image.png app.so module.go")
    assert _domains(code) == set()


def test_legacy_tlds_still_extract():
    got = _domains("foo.com bar.net baz.io site.ai host.me dom.co x.info y.biz z.org")
    for d in ["foo.com", "bar.net", "baz.io", "site.ai", "host.me",
              "dom.co", "x.info", "y.biz", "z.org"]:
        assert d in got, f"regressed legacy domain {d}: {got}"


def test_collision_cctlds_omitted():
    for bad in ["md", "py", "rs", "sh", "so", "pe"]:
        assert bad not in DOMAIN_TLDS


def test_subdomains_keep_full_host():
    assert "api.evilscam.xyz" in _domains("api.evilscam.xyz resolves to 1.2.3.4")


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run()
