"""Data sources: the GitHub Advisory Database (REST + search) and package registries."""
from __future__ import annotations

import os
import re
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterator, Optional

from .http import NotFound, get_json

API = "https://api.github.com"


@lru_cache(maxsize=1)
def github_token() -> Optional[str]:
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        return tok
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def _gh_headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    tok = github_token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


def iter_advisories(ecosystem: str, limit: int, published: Optional[str] = None) -> Iterator[dict]:
    """Reviewed advisories for one ecosystem, newest first."""
    q = {"type": "reviewed", "ecosystem": ecosystem, "per_page": "100", "sort": "published", "direction": "desc"}
    if published:
        q["published"] = published
    url: Optional[str] = f"{API}/advisories?{urllib.parse.urlencode(q)}"
    seen = 0
    while url and seen < limit:
        body, headers = get_json(url, _gh_headers(), ttl=3600, with_headers=True)
        for adv in body:
            if adv.get("withdrawn_at"):
                continue
            yield adv
            seen += 1
            if seen >= limit:
                return
        m = _NEXT.search(headers.get("link", ""))
        url = m.group(1) if m else None


def get_advisory(ghsa_id: str) -> dict:
    return get_json(f"{API}/advisories/{ghsa_id}", _gh_headers(), ttl=3600)


_OPEN_PR_INDEX: Optional[dict[str, list[dict]]] = None
_GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")


def open_prs_index() -> dict[str, list[dict]]:
    """Every open PR in github/advisory-database, keyed by the GHSA ids in its title.

    One paged list (~20 calls) instead of one search per advisory: the search API allows only
    30 requests a minute, which made larger scans stop early."""
    global _OPEN_PR_INDEX
    if _OPEN_PR_INDEX is None:
        index: dict[str, list[dict]] = {}
        url: Optional[str] = f"{API}/repos/github/advisory-database/pulls?state=open&per_page=100"
        while url:
            body, headers = get_json(url, _gh_headers(), ttl=1800, with_headers=True)
            for pr in body:
                for ghsa in set(_GHSA.findall(pr["title"])):
                    index.setdefault(ghsa, []).append(
                        {"number": pr["number"], "title": pr["title"], "url": pr["html_url"]})
            m = _NEXT.search(headers.get("link", ""))
            url = m.group(1) if m else None
        _OPEN_PR_INDEX = index
    return _OPEN_PR_INDEX


def open_prs_for(ghsa_id: str) -> list[dict]:
    """Open community PRs in github/advisory-database that already touch this advisory."""
    return open_prs_index().get(ghsa_id, [])


@dataclass
class PackageInfo:
    ecosystem: str
    name: str
    url: str
    versions: list[str] = field(default_factory=list)
    # pip: versions whose every file is yanked, or that have no files at all
    unavailable: set[str] = field(default_factory=set)


def fetch_package(ecosystem: str, name: str) -> Optional[PackageInfo]:
    """None when the registry has no such package."""
    try:
        if ecosystem == "npm":
            enc = urllib.parse.quote(name, safe="@")
            body = get_json(
                f"https://registry.npmjs.org/{enc}",
                {"Accept": "application/vnd.npm.install-v1+json"},
            )
            return PackageInfo("npm", name, f"https://www.npmjs.com/package/{name}", list(body.get("versions", {})))
        if ecosystem == "pip":
            body = get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
            releases = body.get("releases", {})
            unavailable = {v for v, files in releases.items() if not files or all(f.get("yanked") for f in files)}
            return PackageInfo("pip", name, f"https://pypi.org/project/{name}/", list(releases), unavailable)
    except NotFound:
        return None
    raise ValueError(f"unsupported ecosystem {ecosystem}")
