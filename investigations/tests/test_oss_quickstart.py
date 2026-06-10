"""The README quickstart is PROVEN, not marketed (issue
oss-readme-quickstart-proof, PRD oss-release-readiness, finding-5).

A stranger's path, executed for real: git-clone HEAD of this repo into a temp
dir (file:// — no network), run ./install.sh there, then ingest a sample note
and assert entities landed. No founder-machine assumptions; the clone has no
.env, no live DB, no optional keys. The LLM-dependent steps (schema, Process)
are NOT exercised — extraction is deterministic and key-free, which is exactly
what the quickstart's first minutes deliver.

Also guards the README content contract (key matrix, feature tour, shot list).

Run: .venv/bin/python3 -m pytest investigations/tests/test_oss_quickstart.py -q
"""
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"


# ---------- README content contract ----------

def test_readme_exists_with_quickstart_and_key_matrix():
    text = README.read_text()
    assert "## Quickstart" in text
    assert "./install.sh" in text and "./invctl serve" in text
    assert "ANTHROPIC_API_KEY" in text
    assert "| Key | Required? | Without it |" in text
    assert "Keyless belt" in text


def test_readme_has_feature_tour_and_gif_shot_list():
    text = README.read_text()
    for feature in ("Layouts", "Pathfinding", "Graph analytics",
                    "Conditional formatting", "Collection nodes"):
        assert feature in text, feature
    assert "GIF shot list" in text
    assert "License" in text and "Elastic License 2.0" in text   # the founder-picked license


def test_readme_has_no_founder_machine_paths():
    text = README.read_text()
    for bad in ("assafkip", "threat-intel-agent", "/Users/", "serve-debug"):
        assert bad not in text, bad


# ---------- the clean-clone proof ----------

def test_quickstart_works_from_a_clean_clone(tmp_path):
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", f"file://{ROOT}", str(clone)],
                   check=True, timeout=120)
    assert (clone / "install.sh").is_file(), "install.sh must be tracked"

    # A stranger's env: no optional keys, no Anthropic key. KIPI_REQUIRE_API=1
    # seatbelts the LLM client so a founder machine's authenticated `claude`
    # CLI can never silently serve the fallback (no hidden token spend, no
    # founder-machine dependence in the proof).
    env = {k: v for k, v in os.environ.items()
           if not k.endswith(("_API_KEY", "_TOKEN", "_AUTH_KEY"))}
    env.pop("ANTHROPIC_API_KEY", None)
    env["KIPI_REQUIRE_API"] = "1"

    res = subprocess.run(["bash", "install.sh"], cwd=clone, env=env,
                         capture_output=True, text=True, timeout=900)
    assert res.returncode == 0, res.stdout[-2000:] + res.stderr[-2000:]
    assert "done." in res.stdout

    # Drop a sample note and ingest it — extraction is deterministic + keyless.
    sample = clone / "investigations" / "inbox" / "sample-note.md"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_text(
        "Phishing infra: evil-sender.biz resolves to 185.220.101.42. "
        "Contact scam@evil-sender.biz, channel t.me/evilchannel.\n")
    res = subprocess.run(["./invctl", "ingest", str(sample)], cwd=clone,
                         env=env, capture_output=True, text=True, timeout=300)
    assert res.returncode == 0, res.stdout[-2000:] + res.stderr[-2000:]

    out = subprocess.run(
        [str(clone / ".venv" / "bin" / "python"), "-c",
         "from investigations.storage import db\n"
         "with db.connect() as conn:\n"
         "    rows = {r[0]: r[1] for r in conn.execute("
         "'SELECT canonical_name, entity_type FROM entities')}\n"
         "print(repr(rows))"],
        cwd=clone, env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-1000:]
    rows = eval(out.stdout.strip())   # repr of a {name: type} dict from our own code
    # Each extractor class from the sample landed with the right surface type.
    assert rows.get("evil-sender.biz") == "domain", rows
    assert rows.get("185.220.101.42") == "ip", rows
    assert rows.get("scam@evil-sender.biz") == "email", rows
    assert any(k.startswith("t.me/evilchannel") and v == "telegram_channel"
               for k, v in rows.items()), rows

    # The documented launch command actually serves: boot ./invctl serve on a
    # spare port in the clone and poll the root page for HTTP 200.
    import socket
    import time
    import urllib.request
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(["./invctl", "serve", "--port", str(port)],
                            cwd=clone, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 60
        status = None
        while time.time() < deadline:
            try:
                status = urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=3).status
                break
            except Exception:
                time.sleep(1)
        assert status == 200, f"serve never answered (last={status})"
    finally:
        proc.terminate()
        proc.wait(timeout=15)
