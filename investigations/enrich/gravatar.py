"""Gravatar adapter — email -> public profile + linked social accounts.

Keyless. Gravatar exposes a public profile JSON for any email that has one, keyed by
the MD5 of the lowercased, trimmed address. A hit confirms the email is real + active
and frequently lists the owner's linked accounts (GitHub, X, etc.) — each a promotable
pivot. A miss (404) is itself intel: the email has no Gravatar.

  https://gravatar.com/<md5>.json   (profile, 404 when none)
  https://gravatar.com/avatar/<md5> (avatar image)

Emits a header result (display name / username / bio / location) plus one promotable
`url` result per linked account, so the analyst can promote the linked profiles.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_PROFILE_URL = "https://gravatar.com/{hash}.json"
_AVATAR_URL = "https://gravatar.com/avatar/{hash}"


def _email_hash(email: str) -> str:
    """Gravatar's identifier: MD5 of the trimmed, lowercased email."""
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def _get_json(url: str, timeout: int) -> dict | None:
    """GET a Gravatar JSON profile. None on 404 (no profile); raise on other errors."""
    req = urllib.request.Request(url, headers={"User-Agent": "kipi-investigations"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise EnrichmentError(f"Gravatar HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise EnrichmentError(f"Gravatar network error: {exc}")
    except json.JSONDecodeError:
        raise EnrichmentError("Gravatar returned non-JSON (rate limited or down)")


def _parse_entry(data: dict) -> dict:
    """Pull the first profile entry out of the Gravatar response envelope."""
    entries = data.get("entry") or []
    return entries[0] if entries and isinstance(entries[0], dict) else {}


class GravatarAdapter(Adapter):
    slug = "gravatar"
    display_name = "Gravatar (email -> profile + linked accounts)"
    env_var = None  # keyless
    category = "social"
    cost_per_call_usd = 0.0

    def modes(self) -> list[str]:
        return ["default"]

    def run(self, query: str, mode: str | None = None,
            timeout: int = 30) -> list[EnrichmentResult]:
        email = (query or "").strip().lower()
        if "@" not in email:
            raise EnrichmentError("gravatar: pass an email address")
        h = _email_hash(email)
        data = _get_json(_PROFILE_URL.format(hash=h), timeout)
        avatar = _AVATAR_URL.format(hash=h)

        if not data:
            return [EnrichmentResult(
                result_type="document",
                title=f"Gravatar: {email} [no profile]",
                summary="No Gravatar profile for this email (cleared — the address has "
                        "no public Gravatar identity).",
                confidence="low")]

        entry = _parse_entry(data)
        display = entry.get("displayName") or entry.get("preferredUsername") or ""
        username = entry.get("preferredUsername") or ""
        about = entry.get("aboutMe") or ""
        location = entry.get("currentLocation") or ""
        profile_url = entry.get("profileUrl") or f"https://gravatar.com/{h}"
        accounts = [a for a in (entry.get("accounts") or []) if isinstance(a, dict)]

        lines = [f"display name: {display}" if display else "",
                 f"username: {username}" if username else "",
                 f"location: {location}" if location else "",
                 f"about: {about}" if about else "",
                 f"avatar: {avatar}",
                 f"linked accounts: {len(accounts)}"]
        header = EnrichmentResult(
            result_type="profile",
            title=f"Gravatar: {email}" + (f" — {display}" if display else ""),
            summary="\n".join(s for s in lines if s),
            url=profile_url,
            raw_json={"email": email, "hash": h, "display_name": display,
                      "username": username, "about": about, "location": location,
                      "avatar": avatar,
                      "accounts": [{"domain": a.get("domain"), "url": a.get("url"),
                                    "username": a.get("username")} for a in accounts]},
            confidence="high")

        items = []
        for a in accounts:
            url = (a.get("url") or "").strip()
            if not url:
                continue
            svc = a.get("shortname") or a.get("domain") or "account"
            items.append(EnrichmentResult(
                result_type="url",
                title=f"{svc}: {a.get('username') or url}",
                summary=f"Linked from {email}'s Gravatar profile ({svc}).",
                url=url,
                confidence="medium"))
        return [header] + items
