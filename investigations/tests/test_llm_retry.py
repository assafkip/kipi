"""Deterministic tests for the LLM client's API path: per-call model routing and
429/529 retry-with-backoff. No network, no key, no tokens — urlopen and sleep are
stubbed. These lock in the safety property that makes parallel calls safe: a transient
rate-limit retries instead of silently dropping a batch."""
import io
import json
import urllib.error

import pytest

from investigations.llm import client as llm


@pytest.fixture(autouse=True)
def _api_env(monkeypatch):
    # Activate the API path; make backoff instant so tests don't actually sleep.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(llm.time, "sleep", lambda _s: None)


class _Resp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _ok(text="ok"):
    return {"content": [{"type": "text", "text": text}]}


def _http(code):
    return urllib.error.HTTPError("http://x", code, "err", None, io.BytesIO(b'{"e":1}'))


def _patch(monkeypatch, behaviors, captured=None):
    """urlopen stub: returns/raises the behavior for each successive call."""
    state = {"n": 0}

    def fake(req, timeout=None):
        if captured is not None:
            captured.append(json.loads(req.data))
        b = behaviors[min(state["n"], len(behaviors) - 1)]
        state["n"] += 1
        if isinstance(b, Exception):
            raise b
        return _Resp(b)

    fake.state = state
    monkeypatch.setattr(llm.urllib.request, "urlopen", fake)
    return fake


def test_model_param_is_sent(monkeypatch):
    cap = []
    _patch(monkeypatch, [_ok()], captured=cap)
    llm.ask("hi", model="my-model")
    assert cap[0]["model"] == "my-model"


def test_default_model_when_unset(monkeypatch):
    cap = []
    _patch(monkeypatch, [_ok()], captured=cap)
    llm.ask("hi")
    assert cap[0]["model"] == llm.DEFAULT_MODEL


def test_max_tokens_param_is_sent(monkeypatch):
    cap = []
    _patch(monkeypatch, [_ok()], captured=cap)
    llm.ask("hi", max_tokens=32768)
    assert cap[0]["max_tokens"] == 32768


def test_default_max_tokens_when_unset(monkeypatch):
    cap = []
    _patch(monkeypatch, [_ok()], captured=cap)
    llm.ask("hi")
    assert cap[0]["max_tokens"] == llm.DEFAULT_MAX_TOKENS


def test_retries_429_then_succeeds(monkeypatch):
    f = _patch(monkeypatch, [_http(429), _http(429), _ok("done")])
    assert llm.ask("hi") == "done"
    assert f.state["n"] == 3  # two 429s + one success


def test_retries_529_overloaded(monkeypatch):
    f = _patch(monkeypatch, [_http(529), _ok("done")])
    assert llm.ask("hi") == "done"
    assert f.state["n"] == 2


def test_retries_socket_timeout(monkeypatch):
    # A bare socket read-timeout (TimeoutError) is a sibling of URLError, not a subclass —
    # it must be retried explicitly or it crashes the whole call (the analyze bug).
    f = _patch(monkeypatch, [TimeoutError("read timed out"), _ok("done")])
    assert llm.ask("hi") == "done"
    assert f.state["n"] == 2


def test_gives_up_after_budget(monkeypatch):
    f = _patch(monkeypatch, [_http(429)])  # always rate-limited
    with pytest.raises(llm.LLMError):
        llm.ask("hi")
    assert f.state["n"] == llm.API_MAX_RETRIES + 1  # initial + retries, then raise


def test_auth_error_is_terminal_no_retry(monkeypatch):
    f = _patch(monkeypatch, [_http(401)])
    with pytest.raises(llm.LLMError):
        llm.ask("hi")
    assert f.state["n"] == 1  # 401 must NOT retry


def _ok_usage(inp=200, out=5):
    return {"content": [{"type": "text", "text": "ok"}],
            "usage": {"input_tokens": inp, "output_tokens": out}}


def _reset_meter(monkeypatch, **flags):
    monkeypatch.setattr(llm, "_token_state",
                        {"total_in": 0, "total_out": 0, "calls": 0, "tripped": False})
    for k, v in flags.items():
        monkeypatch.setattr(llm, k, v)


def test_debug_mode_records_usage(monkeypatch, tmp_path):
    f = tmp_path / "tok.jsonl"
    _reset_meter(monkeypatch, DEBUG_TOKENS=True, DEBUG_TOKENS_FILE=str(f), DEBUG_TOKEN_CAP=0)
    _patch(monkeypatch, [_ok_usage(123)])
    llm.ask("hi")
    rec = json.loads(f.read_text().strip().splitlines()[0])
    assert rec["total_in"] == 123 and rec["cum_in"] == 123


def test_token_cap_trips_and_halts(monkeypatch):
    # First call records 200 input tokens > cap 100 → trips; the next call must halt.
    _reset_meter(monkeypatch, DEBUG_TOKENS=False, DEBUG_TOKEN_CAP=100)
    _patch(monkeypatch, [_ok_usage(200)])
    llm.ask("hi")
    assert llm._token_state["tripped"] is True
    with pytest.raises(llm.LLMError):
        llm.ask("hi")  # circuit-breaker: no new call past the cap
