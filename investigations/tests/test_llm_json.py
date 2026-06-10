"""ask_json must tolerate raw control characters inside string values.

The model emits multi-line "context"/"evidence" strings with literal newlines,
which strict JSON rejects. That silently dropped whole extraction batches in the
typing pass (extract_missing recovered 0 despite the model finding entities).

Run: .venv/bin/python -m investigations.tests.test_llm_json
"""
from investigations.llm import client


class _MP:
    def __init__(self): self._u = []
    def setattr(self, obj, name, val):
        self._u.append((obj, name, getattr(obj, name))); setattr(obj, name, val)
    def undo(self):
        for o, n, v in reversed(self._u): setattr(o, n, v)
        self._u = []


def test_control_chars_in_strings(mp):
    # A real-shaped response: a context value with a raw newline mid-string.
    bad = '{"entities": [{"name": "trumpstake.us", "context": "a widget was added\n  to the page"}]}'
    mp.setattr(client, "ask", lambda *a, **k: bad)
    out = client.ask_json("x")
    assert out["entities"][0]["name"] == "trumpstake.us", out
    assert "\n" in out["entities"][0]["context"], "newline preserved in value"
    print("  ok  ask_json parses raw newlines inside string values")


def test_still_strips_fences(mp):
    mp.setattr(client, "ask", lambda *a, **k: '```json\n{"a": "b\nc"}\n```')
    out = client.ask_json("x")
    assert out["a"] == "b\nc", out
    print("  ok  ask_json still strips code fences + tolerates control chars together")


def main():
    mp = _MP()
    try:
        test_control_chars_in_strings(mp)
        test_still_strips_fences(mp)
    finally:
        mp.undo()
    print("\nPASS: test_llm_json")


if __name__ == "__main__":
    main()
