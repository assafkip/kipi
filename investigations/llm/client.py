"""LLM client.

Default path is the Anthropic Messages API (lean — system + data only, ~5k
tokens/call, with prompt caching on the system block so an identical schema prompt
is charged once across a whole batch pass). Falls back to the `claude` CLI when no
ANTHROPIC_API_KEY is set, so the keyless subscription mode still works.

Why this matters: the CLI path (`claude -p`) boots the entire Claude Code agent —
its own system prompt + this project's CLAUDE.md + every rule file — into context on
EVERY call. Measured ~48k input tokens for a do-nothing call; the actual
classification task is ~5k. So ~90% of every token was agent-boot overhead the task
never used, multiplied by ~100 calls per Process run. The API path sends only the
prompt + a cached system block. Measured ~10x token reduction.
"""
import json
import os
import random
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

# Resolve the `claude` CLI portably: env override → PATH → the common local install.
# Hardcoding a single user's path broke every other machine (incl. Docker).
import shutil as _shutil
CLAUDE_BIN = (os.environ.get("KIPI_CLAUDE_BIN")
              or _shutil.which("claude")
              or "claude")  # last resort: let the OS PATH-resolve at exec time

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
# Sonnet is the default for judgment work (the brief, dossiers): capable, far cheaper
# than Opus. Override with KIPI_LLM_MODEL.
DEFAULT_MODEL = os.environ.get("KIPI_LLM_MODEL", "claude-sonnet-4-6")
# Haiku for the mechanical bulk passes (entity classify / re-type / gap extraction).
# The literature is consistent: routing classification/extraction to a small model is
# ~12x cheaper with minimal quality loss for those task types. Callers pass model=
# CLASSIFY_MODEL explicitly; judgment passes keep DEFAULT_MODEL. Override with
# KIPI_CLASSIFY_MODEL (e.g. set it back to claude-sonnet-4-6 if dedup quality dips).
CLASSIFY_MODEL = os.environ.get("KIPI_CLASSIFY_MODEL", "claude-haiku-4-5-20251001")
DEFAULT_MAX_TOKENS = int(os.environ.get("KIPI_LLM_MAX_TOKENS", "8192"))
DEFAULT_TIMEOUT = 180
# Retry budget for transient API failures (429 rate limit, 529 overloaded, network).
# Without this a single 429 mid-volley silently loses a whole batch — and concurrency
# pushes harder into rate-limit territory, so retry is a REQUIREMENT for safe parallel,
# not a nicety. Exponential backoff + jitter, honoring Retry-After when present.
API_MAX_RETRIES = int(os.environ.get("KIPI_API_MAX_RETRIES", "4"))
API_BACKOFF_BASE = float(os.environ.get("KIPI_API_BACKOFF_BASE", "1.0"))
API_BACKOFF_CAP = float(os.environ.get("KIPI_API_BACKOFF_CAP", "30.0"))

# ---- Debug mode: token meter + hard circuit-breaker ----
# With KIPI_DEBUG_TOKENS=1 every API call's real usage is appended to a JSONL file so a
# run can be watched live. With KIPI_DEBUG_TOKEN_CAP=<N> the client HALTS once cumulative
# input tokens cross N — no new calls start (in-flight ones finish), so a token burn
# can't run away: it stops itself and leaves the meter file for the RCA.
DEBUG_TOKENS = os.environ.get("KIPI_DEBUG_TOKENS", "").strip() not in ("", "0", "false", "no")
DEBUG_TOKENS_FILE = os.environ.get(
    "KIPI_DEBUG_TOKENS_FILE", os.path.join(tempfile.gettempdir(), "kipi_token_debug.jsonl"))
DEBUG_TOKEN_CAP = int(os.environ.get("KIPI_DEBUG_TOKEN_CAP", "0") or "0")  # 0 = no cap
_token_lock = threading.RLock()
_token_state = {"total_in": 0, "total_out": 0, "calls": 0, "tripped": False}


def _record_usage(model: str, usage: dict) -> None:
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    cr = usage.get("cache_read_input_tokens", 0)
    cw = usage.get("cache_creation_input_tokens", 0)
    total_in = inp + cr + cw
    with _token_lock:
        _token_state["total_in"] += total_in
        _token_state["total_out"] += out
        _token_state["calls"] += 1
        if DEBUG_TOKEN_CAP and _token_state["total_in"] > DEBUG_TOKEN_CAP:
            _token_state["tripped"] = True
        snap = dict(_token_state)
        if DEBUG_TOKENS:
            rec = {"model": model, "in": inp, "out": out, "cache_read": cr,
                   "cache_write": cw, "total_in": total_in,
                   "cum_in": snap["total_in"], "calls": snap["calls"]}
            try:
                with open(DEBUG_TOKENS_FILE, "a") as f:
                    f.write(json.dumps(rec) + "\n")
            except OSError:
                pass


def _token_gate() -> None:
    """Raise once the debug token cap is tripped, so no new call spends more."""
    if _token_state["tripped"]:
        raise LLMError(
            f"KIPI_DEBUG_TOKEN_CAP ({DEBUG_TOKEN_CAP}) exceeded — halting to RCA. "
            f"Spent ~{_token_state['total_in']:,} input tokens over "
            f"{_token_state['calls']} calls.")


class LLMError(RuntimeError):
    pass


def use_api() -> bool:
    """API path is active when a key is present. Never logs or returns the key."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _require_api() -> bool:
    """Seatbelt: when set, refuse to fall back to the expensive `claude -p` path. Stops
    a misconfigured run (key missing from the env) from silently burning ~48k tokens/call."""
    return os.environ.get("KIPI_REQUIRE_API", "").strip() not in ("", "0", "false", "no")


def ask(prompt: str, system: str | None = None,
        timeout: int = DEFAULT_TIMEOUT, tools: bool = True,
        model: str | None = None, max_tokens: int | None = None) -> str:
    """Send prompt, return plain text.

    Uses the Anthropic API when ANTHROPIC_API_KEY is set, otherwise the `claude` CLI.
    `tools` only affects the CLI fallback (MCP servers on/off); the API path never
    loads tools, so it ignores the flag. `model` overrides the model for this call
    (e.g. CLASSIFY_MODEL for bulk classification); None → DEFAULT_MODEL. `max_tokens`
    overrides the output cap for big-output calls (e.g. analyze clustering); None →
    DEFAULT_MAX_TOKENS. Only affects the API path."""
    if use_api():
        return _ask_api(prompt, system, timeout, model, max_tokens)
    if _require_api():
        raise LLMError(
            "KIPI_REQUIRE_API is set but ANTHROPIC_API_KEY is not in this process's "
            "environment — refusing to fall back to the expensive `claude -p` path "
            "(~48k tokens/call). Start the server from a shell where the key is loaded, "
            "or unset KIPI_REQUIRE_API to allow the CLI fallback."
        )
    return _ask_cli(prompt, system, timeout, tools)


def _backoff_seconds(attempt: int, retry_after: float | None) -> float:
    """Delay before the next retry. Honors a server Retry-After; otherwise exponential
    backoff with jitter, capped."""
    if retry_after is not None:
        return min(retry_after, API_BACKOFF_CAP)
    raw = API_BACKOFF_BASE * (2 ** attempt)
    return min(raw, API_BACKOFF_CAP) + random.uniform(0, API_BACKOFF_BASE)


def _ask_api(prompt: str, system: str | None, timeout: int,
             model: str | None = None, max_tokens: int | None = None) -> str:
    _token_gate()  # debug circuit-breaker: refuse to start a new call past the cap
    body = {
        "model": model or DEFAULT_MODEL,
        "max_tokens": max_tokens or DEFAULT_MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        # Cache the system block: it's byte-identical across every batch in a pass, so
        # it's billed once (cache write) then read near-free for the rest (5-min TTL).
        body["system"] = [{
            "type": "text",
            "text": system,
            "cache_control": {"type": "ephemeral"},
        }]
    data = json.dumps(body).encode("utf-8")

    last_detail = ""
    for attempt in range(API_MAX_RETRIES + 1):
        req = urllib.request.Request(
            API_URL, data=data, method="POST",
            headers={
                "x-api-key": os.environ["ANTHROPIC_API_KEY"],
                "anthropic-version": API_VERSION,
                "content-type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # Auth errors are terminal — retrying won't help.
            if exc.code in (401, 403):
                raise LLMError("Anthropic API auth failed — check ANTHROPIC_API_KEY")
            last_detail = exc.read().decode("utf-8", "replace")[:300]
            # 429 (rate limit) / 529 (overloaded) are transient → back off and retry.
            if exc.code in (429, 529) and attempt < API_MAX_RETRIES:
                ra = exc.headers.get("retry-after") if exc.headers else None
                try:
                    ra = float(ra) if ra is not None else None
                except (TypeError, ValueError):
                    ra = None
                time.sleep(_backoff_seconds(attempt, ra))
                continue
            if exc.code in (429, 529):
                raise LLMError(f"Anthropic API {exc.code} after {API_MAX_RETRIES} "
                               f"retries: {last_detail}")
            raise LLMError(f"Anthropic API HTTP {exc.code}: {last_detail}")
        except (urllib.error.URLError, TimeoutError) as exc:
            # Transient network blip or socket read-timeout → retry; give up after the
            # budget. TimeoutError is a sibling of URLError (both OSError), not a subclass,
            # so it must be named explicitly or a read-timeout slips past and crashes.
            last_detail = str(exc) or type(exc).__name__
            if attempt < API_MAX_RETRIES:
                time.sleep(_backoff_seconds(attempt, None))
                continue
            raise LLMError(f"Anthropic API network/timeout error after "
                           f"{API_MAX_RETRIES} retries: {last_detail}")

        _record_usage(body["model"], payload.get("usage") or {})
        parts = payload.get("content") or []
        text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
        if not text:
            raise LLMError(f"Anthropic API returned no text: {str(payload)[:300]}")
        return text.strip()

    # Unreachable: the loop either returns or raises. Defensive guard.
    raise LLMError(f"Anthropic API exhausted retries: {last_detail}")


def _ask_cli(prompt: str, system: str | None, timeout: int, tools: bool) -> str:
    full_prompt = prompt
    if system:
        full_prompt = f"{system}\n\n---\n\n{prompt}"
    # --setting-sources user: load only the user-global settings, NOT this project's
    # CLAUDE.md + ~13k tokens of rule files. A classification call needs none of that;
    # measured ~10k tokens shaved off every call (the single biggest CLI-path saving).
    cmd = [CLAUDE_BIN, "-p", full_prompt, "--output-format", "text",
           "--setting-sources", "user"]
    if not tools:
        # No MCP boot on pure-text passes — skips the project's MCP servers.
        cmd.append("--strict-mcp-config")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout, check=True,
        )
    except subprocess.TimeoutExpired:
        raise LLMError(f"claude CLI timeout after {timeout}s")
    except subprocess.CalledProcessError as exc:
        raise LLMError(f"claude CLI error (rc={exc.returncode}): {exc.stderr[:500]}")
    return result.stdout.strip()


def ask_json(prompt: str, system: str | None = None,
             timeout: int = DEFAULT_TIMEOUT, tools: bool = True,
             model: str | None = None, max_tokens: int | None = None) -> dict:
    """Send prompt expecting JSON output. Extracts JSON from response."""
    response = ask(
        prompt + "\n\nReply with ONLY valid JSON. No prose, no markdown fences, "
        "no preamble. Just the JSON object.",
        system=system, timeout=timeout, tools=tools, model=model, max_tokens=max_tokens,
    )
    response = response.strip()
    if response.startswith("```"):
        lines = response.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        response = "\n".join(lines).strip()
    # strict=False allows raw control characters (literal newlines/tabs) inside
    # string values. The model frequently emits multi-line "context"/"evidence"
    # strings with real newlines, which strict JSON rejects — that was silently
    # dropping whole extraction batches.
    try:
        return json.loads(response, strict=False)
    except json.JSONDecodeError as exc:
        start = response.find("{")
        end = response.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(response[start:end + 1], strict=False)
            except json.JSONDecodeError:
                pass
        raise LLMError(
            f"Could not parse JSON from response: {exc}\nResponse was: {response[:1000]}"
        )
