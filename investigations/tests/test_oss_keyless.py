"""Zero-optional-keys boot (issue oss-keyless-degradation, PRD
oss-release-readiness).

The OSS posture: BYO Anthropic key ONLY. With every optional provider env var
stripped and an ISOLATED temp DB (the founder's live database is never touched
— finding-3), the keyless tool belt stays usable, keyed providers report
needs-key/SKIP without crashing or burning retries, and the LLM client raises
its NAMED error rather than falling back to the metered `claude -p` path.

Run: .venv/bin/python3 -m pytest investigations/tests/test_oss_keyless.py -q
"""
import io
import tempfile
import types
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from investigations.enrich import registry
from investigations.storage import db

# The strip-list derives from the registry itself (a hard-coded copy would
# drift the moment a new keyed adapter lands and silently stop proving the
# keyless posture), plus secondary vars adapters read outside env_var.
_OPTIONAL_ENV = sorted(
    {a.env_var for a in registry.all_adapters() if getattr(a, "env_var", None)}
    | {"ETHERSCAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET"}
)

# The keyless core that must stay configured with zero keys anywhere.
_KEYLESS = {"crtsh", "infra", "gravatar", "ipgeo", "username", "wallet", "email"}


@pytest.fixture
def no_keys(mp):
    """Strip every optional key from the env AND isolate the DB (a temp file —
    the founder's live DB may hold stored provider keys and must not be read
    or written by this test)."""
    for var in _OPTIONAL_ENV + ["ANTHROPIC_API_KEY"]:
        mp.delenv(var, raising=False)
    p = Path(tempfile.mkdtemp()) / "keyless.db"
    db.init_db(p)
    orig = db.connect

    def _isolated_connect(migrate=True, db_path=None):
        # FORCE the temp DB even when a code path passes its own db_path —
        # the live database must be unreachable from this test, period.
        return orig(db_path=p, migrate=migrate)

    mp.setattr(db, "connect", _isolated_connect)
    return p


def test_keyless_core_stays_configured(no_keys):
    configured = {a.slug for a in registry.configured_adapters()}
    missing = _KEYLESS - configured
    assert missing == set(), f"keyless providers lost without keys: {missing}"


# Keyed-but-keyless-capable: jina works without a key (a key only raises rate
# limits) — its is_configured() override returning True is deliberate.
_KEYLESS_CAPABLE = {"jina", "shodan"}   # shodan: keyless InternetDB tier


def test_keyed_providers_report_needs_key_not_crash(no_keys):
    for a in registry.all_adapters():
        if not getattr(a, "env_var", None) or a.slug in _KEYLESS_CAPABLE:
            continue
        assert a.is_configured() is False, f"{a.slug} claims configured with no key"


def test_keyless_capable_keyed_providers_stay_usable(no_keys):
    # jina (key only raises rate limits) and shodan (keyless InternetDB tier)
    # must POSITIVELY stay configured with zero keys — the exemption above is
    # not allowed to mask a regression to needs-key.
    configured = {a.slug for a in registry.configured_adapters()}
    assert _KEYLESS_CAPABLE <= configured, _KEYLESS_CAPABLE - configured


def test_belt_skip_line_tells_the_agent_not_to_retry(no_keys):
    # EVERY unconfigured keyed provider must print the SKIP sentinel — one
    # clean line, no provider call, no exception (no retry burn). Not just
    # virustotal: a custom is_configured regression elsewhere must fail here.
    from investigations.cli.invctl import cmd_osint_tool
    for a in registry.all_adapters():
        if not getattr(a, "env_var", None) or a.slug in _KEYLESS_CAPABLE:
            continue
        args = types.SimpleNamespace(list=False, provider=a.slug,
                                     query="example.com", mode=None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_osint_tool(args)
        out = buf.getvalue()
        assert "SKIP" in out and "Do not retry" in out, (a.slug, out)


def test_belt_list_marks_keyless_vs_needs_key(no_keys):
    from investigations.cli.invctl import cmd_osint_tool
    args = types.SimpleNamespace(list=True, provider=None, query=None, mode=None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_osint_tool(args)
    lines = {l.split("\t")[0]: l.split("\t")[1] for l in buf.getvalue().splitlines() if "\t" in l}
    for slug in _KEYLESS:
        assert lines.get(slug) == "keyless", (slug, lines.get(slug))
    assert lines.get("virustotal") == "needs-key"


def test_llm_client_raises_named_error_without_anthropic_key(no_keys, mp):
    # With no Anthropic key + the seatbelt on, the client must raise its NAMED
    # error (never silently fall back to the metered `claude -p` path).
    mp.setenv("KIPI_REQUIRE_API", "1")
    from investigations.llm import client as llm
    with pytest.raises(llm.LLMError) as exc:
        llm.ask("say hi", system="system")
    assert "ANTHROPIC_API_KEY" in str(exc.value)
