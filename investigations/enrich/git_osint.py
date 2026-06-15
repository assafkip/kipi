"""Git commit-author email mining — public repos leak real operator emails.

A developer/operator's public repository exposes commit-author emails in its git history.
That is a strong identity crosslink: a mined email is T2 only when it CORROBORATES an
already-scraped email (the anchor rule — a phone/email needs a second independent source).
On its own it is a lead, so child rows are low-confidence and land gated in /enrich, never
a findings file until a second source matches.

Keyless: shells out to the system `git` (clone --bare --filter=blob:none + git log), like
infra.py's whois/dig shell-out. Self-guards on `shutil.which("git")`. No new pip dep.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_REPO_URL_RE = re.compile(r"^https?://(github\.com|gitlab\.com)/[\w.-]+/[\w.-]+/?$", re.I)
_HANDLE_RE = re.compile(r"^@?[A-Za-z0-9_-]{1,39}$")


def _mine_repo(repo_url: str, timeout: int = 90) -> list[tuple[str, str]]:
    """(email, name) pairs from a repo's commit history. Bare blobless clone, fast."""
    url = repo_url.rstrip("/")
    if not url.endswith(".git"):
        url += ".git"
    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run(
                ["git", "clone", "--bare", "--filter=blob:none", url, tmp],
                capture_output=True, timeout=timeout, check=True)
            proc = subprocess.run(
                ["git", "--git-dir", tmp, "log", "--all", "--format=%ae|%an"],
                capture_output=True, timeout=timeout, check=True)
        except subprocess.CalledProcessError as exc:
            raise EnrichmentError(f"git mining failed: {exc.stderr.decode('utf-8', 'replace')[:200]}")
        except subprocess.SubprocessError as exc:
            raise EnrichmentError(f"git mining failed: {exc}")
    seen, out = set(), []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        email, _, name = line.partition("|")
        email = email.strip().lower()
        if email and "@" in email and email not in seen and "noreply" not in email:
            seen.add(email)
            out.append((email, name.strip()))
    return out


def _first_repo_for_handle(handle: str, timeout: int) -> str | None:
    """The handle's first public repo clone URL via the keyless GitHub API."""
    h = handle.lstrip("@")
    req = urllib.request.Request(
        f"https://api.github.com/users/{urllib.parse.quote(h)}/repos?per_page=5&sort=pushed",
        headers={"User-Agent": "kipi-investigations", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            repos = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise EnrichmentError(f"GitHub API for @{h}: {exc}")
    for repo in repos if isinstance(repos, list) else []:
        if not repo.get("fork") and repo.get("clone_url"):
            return repo["clone_url"]
    return repos[0]["clone_url"] if isinstance(repos, list) and repos else None


class GitOsintAdapter(Adapter):
    slug = "git_osint"
    watched_types = ("url", "handle")
    display_name = "Git commit-author email mining"
    env_var = None  # keyless (system git)
    category = "identity"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 90) -> list[EnrichmentResult]:
        q = (query or "").strip()
        if not q:
            raise EnrichmentError("git_osint: empty query")
        if shutil.which("git") is None:
            raise EnrichmentError("git_osint: system `git` not found on PATH")
        if _REPO_URL_RE.match(q):
            repo_url = q
        elif _HANDLE_RE.match(q):
            repo_url = _first_repo_for_handle(q, timeout)
            if not repo_url:
                return [EnrichmentResult(
                    result_type="document",
                    title=f"git_osint: @{q.lstrip('@')} — no public repos",
                    summary="No minable public repositories found for this handle.",
                    confidence="low")]
        else:
            raise EnrichmentError("git_osint: pass a github/gitlab repo URL or a handle")
        pairs = _mine_repo(repo_url, timeout)
        header = EnrichmentResult(
            result_type="document",
            title=f"git_osint: {repo_url} — {len(pairs)} author email(s)",
            summary=("Commit-author emails (T2 only when they corroborate a scraped email; "
                     "alone they are leads):\n"
                     + "\n".join(f"- {e} ({n})" for e, n in pairs[:25])),
            url=repo_url,
            raw_json={"repo": repo_url, "emails": [e for e, _ in pairs],
                      "tier": "T2_candidate", "lead": True},
            confidence="medium")
        rows = [EnrichmentResult(
            result_type="document", title=email,
            summary=f"Commit-author email from {repo_url} ({name}). Lead — corroborate.",
            raw_json={"tier": "T2_candidate", "anchor_corroborates": True},
            confidence="low") for email, name in pairs]
        return [header] + rows
