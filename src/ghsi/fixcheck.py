"""Does the release an advisory calls "patched" actually contain the fix commit it references?

If the patched release is *older* than the fix, everyone on that release is told they are safe
while they are not (a false negative in Dependabot and every OSV-based scanner). That makes it
the most harmful kind of advisory error, and it's checkable from git alone, for any ecosystem.

compare(base=fix_commit, head=release_tag) on the GitHub API returns:
  ahead / identical → the tag contains the commit (fine)
  behind            → the tag predates the commit: the fix is NOT in the "patched" release
  diverged          → different branches; usually a backport with a different SHA (needs a human)
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Optional

from .http import NotFound, RateLimitLow

COMMIT_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})\b")

# compare(owner, repo, base, head) -> status string, or None when a ref doesn't exist
Compare = Callable[[str, str, str, str], Optional[str]]


@dataclass
class FixFinding:
    ghsa_id: str
    package: str
    patched: str
    repo: str
    commit: str
    tag: str
    status: str
    confidence: str
    message: str
    evidence: dict = field(default_factory=dict)


def tag_candidates(package: str, version: str) -> list[str]:
    short = package.split("/")[-1]
    names = [f"v{version}", version, f"{package}@{version}", f"{short}@{version}",
             f"{short}-v{version}", f"{short}-{version}", f"{short}/v{version}", f"release-{version}"]
    return list(dict.fromkeys(names))


def fix_commits(adv: dict) -> list[tuple[str, str, str]]:
    out = []
    for ref in adv.get("references") or []:
        m = COMMIT_URL.match(ref)
        if m:
            out.append((m.group(1), m.group(2), m.group(3)))
    return list(dict.fromkeys(out))


def check_fix_in_release(adv: dict, compare: Compare) -> list[FixFinding]:
    commits = fix_commits(adv)
    if not commits:
        return []
    findings = []
    for v in adv.get("vulnerabilities") or []:
        fp = v.get("first_patched_version")
        if not fp:
            continue
        pkg = v["package"]["name"]
        entry: list[FixFinding] = []
        shipped = False
        for owner, repo, sha in commits:
            tag, status = None, None
            for cand in tag_candidates(pkg, fp):
                status = compare(owner, repo, sha, cand)
                if status is not None:
                    tag = cand
                    break
            if tag is None:
                continue
            if status in ("ahead", "identical"):
                # Advisories often list the fix plus later hardening commits: one shipped commit is enough.
                shipped = True
                break
            if status == "behind":
                conf, msg = "high", f"Release {tag} predates fix commit {sha[:9]}: {fp} cannot contain the fix."
            else:
                conf, msg = "medium", f"Fix commit {sha[:9]} is on a different branch than {tag} (backport?)."
            entry.append(FixFinding(adv["ghsa_id"], pkg, fp, f"{owner}/{repo}", sha, tag, status, conf, msg))
        if not shipped:
            findings += entry
    return findings


def github_compare(get_json_fn, headers: dict) -> Compare:
    """Look up each repo's tags once, then spend one compare call per (commit, tag) that exists."""
    tags_cache: dict[str, set] = {}

    def tags(owner: str, repo: str) -> set:
        key = f"{owner}/{repo}"
        if key not in tags_cache:
            try:
                refs = get_json_fn(f"https://api.github.com/repos/{key}/git/matching-refs/tags/", headers, ttl=24 * 3600)
                tags_cache[key] = {r["ref"][len("refs/tags/"):] for r in refs}
            except NotFound:
                tags_cache[key] = set()
        return tags_cache[key]

    def compare(owner: str, repo: str, base: str, head: str) -> Optional[str]:
        if head not in tags(owner, repo):
            return None
        url = (f"https://api.github.com/repos/{owner}/{repo}/compare/"
               f"{urllib.parse.quote(base, safe='')}...{urllib.parse.quote(head, safe='@')}?per_page=1")
        try:
            return get_json_fn(url, headers, ttl=24 * 3600).get("status")
        except NotFound:
            return None
        except RateLimitLow:
            raise
        except Exception:
            return None  # e.g. 422 when the commit lives in a fork
    return compare
