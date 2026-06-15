"""Non-crypto enrichment primitives (PRD-5) — EXIF, ASN, phone.

Wiring + parse tests, NO network (exiftool subprocess + Cymru DNS monkeypatched; phone is
a real offline libphonenumber parse, deterministic). Mirrors test_osint_providers_batch.
Pins: the asn-orphan close (asn in both ip + asn recipes, _classify("AS..")=="asn"), the
ip belt gains asn, and EXIF GPS -> a typed geo property.

Run: .venv/bin/python -m pytest investigations/tests/test_enrich_primitives.py -q
"""
from investigations.enrich import registry, exif, asn, phone, promote, properties
from investigations.agent import osint_mcp, investigator

NEW = ["exif", "asn", "phone"]
TOOL = {"exif": "exif_extract", "asn": "asn_lookup", "phone": "phone_parse"}
WATCHED = {"exif": ("indicator", "fingerprint"), "asn": ("ip", "asn"), "phone": ("phone",)}


# --- contract --------------------------------------------------------------

def test_registered_keyless():
    slugs = {a.slug for a in registry.all_adapters()}
    for s in NEW:
        assert s in slugs
        a = registry.get_adapter(s)
        assert a.slug == s and a.env_var is None and a.is_configured() is True


def test_deterministic_tier():
    for s in NEW:
        assert s in registry.DETERMINISTIC_SLUGS


def test_watched_types_subset():
    for s in NEW:
        assert not set(registry.get_adapter(s).watched_types) - registry.TRANSFORM_TYPES


def test_recipe_presence():
    for s in NEW:
        for etype in WATCHED[s]:
            slugs = [slug for slug, _ in registry._TRANSFORM_RECIPES[etype]]
            assert s in slugs, f"{s} missing from {etype} recipe"


def test_asn_orphan_closed():
    # asn now has BOTH a producer (in the ip recipe) and a consumer (the asn recipe).
    # It lives in the on-demand menu, NOT the auto one-hop belt (the belt stays minimal +
    # keyless-instant; asn does a live DNS lookup, so it is analyst/agent-invoked).
    assert "asn" in [s for s, _ in registry._TRANSFORM_RECIPES["ip"]]
    assert "asn" in [s for s, _ in registry._TRANSFORM_RECIPES["asn"]]


def test_mcp_calls_present():
    src = open(osint_mcp.__file__).read()
    for s in NEW:
        assert f'_call("{s}"' in src, f'osint_mcp missing _call("{s}")'


def test_allowlist_persona_and_crew():
    for s in NEW:
        tool = TOOL[s]
        assert f"mcp__kipi-osint__{tool}" in investigator._KIPI_MCP_TOOLS
        assert tool in investigator.PERSONA, f"{tool} not routed in PERSONA"
        assert tool in investigator.CASE_PERSONA, f"{tool} not routed in CASE_PERSONA"
    # asn belongs to the infra crew (it's infra, the audit O-1 contradiction does not apply).
    infra_crew = next(c for c in investigator.ROLE_AGENTS if c["role"] == "infra")
    assert "mcp__kipi-osint__asn_lookup" in infra_crew["tools"]


# --- promote._classify ASN rule --------------------------------------------

def test_classify_asn():
    assert promote._classify("AS15169") == "asn"
    assert promote._classify("as15169") == "asn"
    # no regression
    assert promote._classify("example.com") == "domain"
    assert promote._classify("@handle") == "handle"


# --- parse -----------------------------------------------------------------

_EXIF = {"GPSLatitude": 37.7749, "GPSLongitude": -122.4194, "Make": "Apple",
         "Model": "iPhone 12", "SerialNumber": "ABC123XYZ", "CreateDate": "2026:01:01 12:00:00"}


def test_exif_parse(monkeypatch):
    monkeypatch.setattr(exif.shutil, "which", lambda b: "/usr/bin/exiftool")
    monkeypatch.setattr(exif, "_run_exiftool", lambda path, timeout=60: dict(_EXIF))
    out = exif.ExifAdapter().run("/tmp/photo.jpg")
    assert "Apple iPhone 12" in out[0].title
    titles = [r.title for r in out[1:]]
    assert "37.7749,-122.4194" in titles and "ABC123XYZ" in titles
    # GPS lands as a typed geo property.
    props = {p.key: (p.value, p.value_type) for p in properties.extract_properties("exif", out[0].raw_json)}
    assert props["gps"] == ("37.7749,-122.4194", "geo")
    assert props["device_make"][0] == "Apple"


def test_exif_needs_binary(monkeypatch):
    monkeypatch.setattr(exif.shutil, "which", lambda b: None)
    out = exif.ExifAdapter().run("/tmp/photo.jpg")
    assert len(out) == 1 and "not installed" in out[0].title


def test_exif_ingest_summary(monkeypatch):
    monkeypatch.setattr(exif, "_run_exiftool", lambda path, timeout=60: dict(_EXIF))
    block = exif.exif_summary_for_ingest("/tmp/photo.jpg")
    assert block.startswith("[EXIF]") and "GPS: 37.7749,-122.4194" in block
    monkeypatch.setattr(exif, "_run_exiftool", lambda path, timeout=60: None)
    assert exif.exif_summary_for_ingest("/tmp/photo.jpg") == ""


def test_asn_parse(monkeypatch):
    def fake(name, timeout=10):
        if "origin.asn.cymru.com" in name:
            return "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
        if "AS15169.asn.cymru.com" in name:
            return "15169 | US | arin | 2000-03-30 | Google LLC, US"
        return None
    monkeypatch.setattr(asn, "_cymru_txt", fake)
    out = asn.AsnAdapter().run("8.8.8.8")
    assert "AS15169" in out[0].title
    titles = [r.title for r in out[1:]]
    assert "AS15169" in titles and "Google LLC, US" in titles
    assert promote._classify("AS15169") == "asn"


def test_phone_parse_offline():
    import phonenumbers
    e164 = phonenumbers.format_number(
        phonenumbers.example_number("US"), phonenumbers.PhoneNumberFormat.E164)
    out = phone.PhoneAdapter().run(e164)
    assert out[0].raw_json["valid"] is True
    assert out[0].raw_json["phone_country"] == "US"
    assert out[0].raw_json["line_type"] in (
        "FIXED_LINE", "MOBILE", "FIXED_LINE_OR_MOBILE", "VOIP", "UNKNOWN")
