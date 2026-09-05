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
from urllib.parse import urlencode as _urlencode
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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
    # ARCTIC SHIFT, not reddit.com. `www.reddit.com/user/<u>/about.json` returns
    # 403 from any datacenter IP, and this detector reads a 403 as
    # INDETERMINATE, so the Reddit row returned None from every host that is not
    # a home connection. The mirror needs no auth.
    #
    # Its answer is WEAKER AND HONEST, and the detector is renamed so the row
    # does not quietly start meaning something new: `reddit_public_activity`
    # proves a handle has PUBLIC ACTIVITY, not that the account exists. A lurker
    # reads absent.
    ("Reddit", "https://www.reddit.com/user/{u}", ("reddit_public_activity",)),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?username={u}",
     ("json_code", "them")),
    ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{u}.json", ("json_notnull",)),
    ("DevTo", "https://dev.to/{u}", ("status",)),
    ("Medium", "https://medium.com/@{u}", ("status",)),
    ("YouTube", "https://www.youtube.com/@{u}", ("status",)),
    ("Telegram", "https://t.me/{u}", ("contains", "tgme_page_title")),
    ("Gravatar", "https://gravatar.com/{u}", ("status",)),
]


from investigations.enrich import reddit_arctic as _reddit_arctic


def _reddit_has_public_activity(username: str, *, limit: int = 5) -> bool:
    """True when the handle has posts or comments in the Arctic Shift archive.

    A WEAKER CLAIM than "this account exists", deliberately. A lurker with no
    public activity reads absent, and the detector name says so rather than
    letting the row quietly mean something new.
    """
    url = _reddit_arctic.ARCTIC_BASE + "/api/comments/search?" + \
        _urlencode({"author": username, "limit": limit, "sort": "desc",
                    "fields": "id"})
    rows = _reddit_arctic._items(
        _reddit_arctic._get_json(url, _reddit_arctic.DEFAULT_TIMEOUT))
    if rows:
        return True
    url = _reddit_arctic.ARCTIC_BASE + "/api/posts/search?" + \
        _urlencode({"author": username, "limit": limit, "sort": "desc",
                    "fields": "id"})
    return bool(_reddit_arctic._items(
        _reddit_arctic._get_json(url, _reddit_arctic.DEFAULT_TIMEOUT)))

_TIMEOUT_PER_SITE = 6

# WhatsMyName data is vendored here; it makes the validators DATA-DRIVEN (the recurring
# junk-node fix is deterministic body-validators, NOT another retro-clean pass — see MEMORY
# graph-noise-needs-one-admission-gate). Curated _SITES still take precedence; wmn entries
# only ADD a platform when they expose a clean e_string (existence) or m_string (missing).
_WMN_DATA = Path(__file__).parent / "data" / "wmn-data.json"


def _load_wmn(path=_WMN_DATA) -> list[tuple]:
    """Build (name, uri_template, detector) tuples from a vendored WhatsMyName snapshot.
    e_string -> ('contains', e_string); else m_string -> ('status_absent', m_string).
    A site with neither marker is skipped (a bare 200 is not a trustworthy 'found')."""
    try:
        sites = json.loads(path.read_text()).get("sites", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    out = []
    for s in sites:
        name = s.get("name")
        uri = s.get("uri_check")
        if not name or not uri or "{account}" not in uri:
            continue
        template = uri.replace("{account}", "{u}")
        if s.get("e_string"):
            out.append((name, template, ("contains", s["e_string"])))
        elif s.get("m_string"):
            out.append((name, template, ("status_absent", s["m_string"])))
    return out


def _all_sites() -> list[tuple]:
    """Curated _SITES + vendored wmn entries, curated winning on a name clash."""
    curated_names = {n for n, _, _ in _SITES}
    return _SITES + [s for s in _load_wmn() if s[0] not in curated_names]


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
    kind = detector[0]
    present: bool | None = None

    if kind == "reddit_public_activity":
        # No _fetch: this asks the mirror, not the profile page.
        #
        # MEASURED, four handles, because an empty answer and an error had to be
        # told apart before either could be trusted:
        #   spez                                  5 posts,  5 comments
        #   AutoModerator                         5 posts,  5 comments
        #   a well formed, unused handle          0 posts,  0 comments
        #   a 35-character handle                 HTTP 400
        # So EMPTY is a real absent, and the 400 is the mirror refusing a handle
        # longer than Reddit's own 20-character limit, where indeterminate is
        # the right answer: nothing was looked up, so nothing was learned.
        try:
            present = _reddit_has_public_activity(username)
        except Exception:
            present = None          # a refused read is indeterminate, never absent
        return {"site": name, "present": present,
                "status": 200 if present is not None else 0, "url": url}

    status, body = _fetch(url, _TIMEOUT_PER_SITE)
    if status == 0:
        present = None
    elif kind == "status":
        present = True if status == 200 else (False if status == 404 else None)
    elif kind == "status_absent":
        # The false-positive fix: a 200 with the platform's MISSING marker = absent
        # (IG login-wall / TikTok "couldn't find" / Telegram "Contact" all 200-no-account).
        marker = detector[1]
        if status == 404:
            present = False
        elif status == 200:
            present = marker not in body
        else:
            present = None
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
    watched_types = ('handle', 'username')  # NOT person: run() takes a bare handle (_HANDLE_RE), a spaced name is a guaranteed fail
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
        sites = _all_sites()
        with ThreadPoolExecutor(max_workers=min(10, len(sites))) as pool:
            futs = {pool.submit(_check, n, t, d, username): n for n, t, d in sites}
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
