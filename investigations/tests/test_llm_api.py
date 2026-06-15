"""Live verification of the Anthropic API path in the LLM client.

Skips when ANTHROPIC_API_KEY is absent (CI / keyless runs), so it never breaks the
suite. With a key present it makes ONE real, tiny call to prove:
  - the API path activates (use_api True),
  - a cached system block + JSON request round-trips,
  - the token cost is a fraction of the ~48k `claude -p` boot overhead.

Run it from a shell that has the key:
    .venv/bin/python -m pytest investigations/tests/test_llm_api.py -s
"""
import json
import os
import urllib.request

import pytest

from investigations.llm import client as llm


# Real-API test: marked `live` so CI / keyless runs auto-skip it (conftest), and it still
# self-skips without a key. Opt in with --run-live or ANTHROPIC_API_KEY.
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not os.environ.get("ANTHROPIC_API_KEY"),
        reason="no ANTHROPIC_API_KEY — API path dormant, CLI fallback in use",
    ),
]

SYSTEM = "You classify words. Return JSON only."
PROMPT = ('Classify each as fruit or tool: ["apple","hammer","pear"]. '
          'Return {"items":[{"name":...,"kind":...}]}')


def test_api_path_active():
    assert llm.use_api() is True


def test_ask_json_roundtrips_via_api():
    res = llm.ask_json(PROMPT, system=SYSTEM, timeout=60)
    assert isinstance(res, dict)
    assert "items" in res and len(res["items"]) == 3


def test_token_cost_is_lean(capsys):
    # Same body the client builds, but instrumented to read usage. A lean API call
    # should be well under the ~48k input tokens a `claude -p` call costs to boot.
    body = {
        "model": llm.DEFAULT_MODEL,
        "max_tokens": 1024,
        "system": [{"type": "text", "text": SYSTEM,
                    "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": PROMPT}],
    }
    req = urllib.request.Request(
        llm.API_URL, data=json.dumps(body).encode(), method="POST",
        headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                 "anthropic-version": llm.API_VERSION,
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        usage = json.loads(r.read().decode()).get("usage", {})
    total_in = (usage.get("input_tokens", 0)
                + usage.get("cache_creation_input_tokens", 0)
                + usage.get("cache_read_input_tokens", 0))
    with capsys.disabled():
        print(f"\n  model={llm.DEFAULT_MODEL}  total_input={total_in}  "
              f"output={usage.get('output_tokens', 0)}  "
              f"(claude -p baseline ~48,000)")
    assert total_in < 10_000  # vs ~48k for the CLI boot
