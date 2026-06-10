"""Username presence adapter — a handle -> which platforms it exists on.

Keyless. The Maigret/Sherlock idea, deliberately SCOPED to a curated set of platforms
that return a clean present/absent signal (status code or a JSON marker). We do NOT
copy Maigret's 3000-site list: most of it bot-walls or false-positives, and the long
tail rots constantly. The sites here either 404 cleanly on a missing user or expose a
JSON lookup, so a hit is trustworthy.

Bot-walled platforms (X / Instagram / TikTok) are intentionally omitted rather than
reported as a guess — a wrong "found" is worse than a known gap.

Emits a header (found / absent / errored counts) + one promotable `url` result per
found profile. Checks run concurrently with a tight per-site timeout.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{2,40}$")

# Each site: (name, profile_url_template, detector).
# detector is one of:
#   ("status",)                 -> HTTP 200 means present, 404 means absent
#   ("contains", marker)        -> body contains marker => present
#   ("json_present", path,val)  -> JSON at dotted-path equals/!=val (see _check)
_SITES = [
    ("GitHub", "https://github.com/{u}", ("status",)),
    ("GitLab", "https://gitlab.com/{u}", ("status",)),
    ("Reddit", "https://www.reddit.com/user/{u}/about.json", ("json_present", "data.id")),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?username={u}",
     ("json_code", "them")),
    ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{u}.json", ("json_notnull",)),
    ("DevTo", "https://dev.to/{u}", ("status",)),
    ("Medium", "https://medium.com/@{u}", ("status",)),
    ("YouTube", "https://www.youtube.com/@{u}", ("status",)),
    ("Telegram", "https://t.me/{u}", ("contains", "tgme_page_title")),
    ("Gravatar", "https://gravatar.com/{u}", ("status",)),
]

_TIMEOUT_PER_SITE = 6


def _fetch(url: str, timeout: int) -> tuple[int, str]:
    """GET a URL -> (status_code, body). status 0 on network error."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except (urllib.error.URLError, OSError):
        return 0, ""


def _dig(obj, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _check(name: str, template: str, detector: tuple, username: str) -> dict:
    """Return {site, present, status, url} for one site. present is True/False/None
    (None = indeterminate / errored)."""
    url = template.format(u=username)
    status, body = _fetch(url, _TIMEOUT_PER_SITE)
    kind = detector[0]
    present: bool | None = None
    if status == 0:
        present = None
    elif kind == "status":
        present = True if status == 200 else (False if status == 404 else None)
    elif kind == "contains":
        present = bool(status == 200 and detector[1] in body)
    elif kind in ("json_present", "json_code", "json_notnull"):
        if status != 200:
            present = False if status == 404 else None
        else:
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                present = None
            else:
                if kind == "json_present":
                    present = _dig(data, detector[1]) is not None
                elif kind == "json_code":
                    present = isinstance(data, dict) and data.get(detector[1]) is not None
                elif kind == "json_notnull":
                    present = data is not None
    # The public profile URL (strip the .json/api suffix used only for detection).
    public = url
    if name == "Reddit":
        public = f"https://www.reddit.com/user/{username}"
    elif name == "Keybase":
        public = f"https://keybase.io/{username}"
    elif name == "HackerNews":
        public = f"https://news.ycombinator.com/user?id={username}"
    return {"site": name, "present": present, "status": status, "url": public}


class UsernameAdapter(Adapter):
    slug = "username"
    display_name = "Username presence sweep (curated platforms)"
    env_var = None  # keyless
    category = "social"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["default"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 60) -> list[EnrichmentResult]:
        username = (query or "").strip().lstrip("@")
        if not _HANDLE_RE.match(username):
            raise EnrichmentError(
                "username: pass a bare handle (2-40 chars, letters/digits/._-), no @")

        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=min(10, len(_SITES))) as pool:
            futs = {pool.submit(_check, n, t, d, username): n for n, t, d in _SITES}
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception:
                    results.append({"site": futs[fut], "present": None,
                                    "status": 0, "url": ""})

        found = [r for r in results if r["present"] is True]
        absent = [r for r in results if r["present"] is False]
        indet = [r for r in results if r["present"] is None]

        header_summary = (
            f"Checked {len(results)} platforms for '{username}'.\n"
            f"FOUND ({len(found)}): {', '.join(r['site'] for r in found) or 'none'}\n"
            f"absent ({len(absent)}): {', '.join(r['site'] for r in absent) or 'none'}\n"
            f"indeterminate ({len(indet)}): {', '.join(r['site'] for r in indet) or 'none'}\n"
            "Note: X / Instagram / TikTok are omitted (bot-walled — a guess would be noise).")
        header = EnrichmentResult(
            result_type="document",
            title=f"Username sweep: {username} — found on {len(found)}/{len(results)}",
            summary=header_summary,
            raw_json={"username": username, "found": [r["url"] for r in found],
                      "results": results},
            confidence="medium")

        items = [EnrichmentResult(
            result_type="url",
            title=f"{r['site']}: {username}",
            summary=f"Handle '{username}' is present on {r['site']}.",
            url=r["url"],
            confidence="medium") for r in found if r["url"]]
        return [header] + items
