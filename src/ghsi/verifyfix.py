"""Content check for fix-in-release leads: are the lines a fix commit adds present in the release?

Commit ancestry alone gives false positives: projects like Symfony ship a security fix in a
release through a separate commit and merge the referenced commit later. What matters is the
code, so this compares the fix's added lines (non-test files) with the files at the release tag.
"""
from __future__ import annotations

import urllib.parse
from typing import Optional

from .http import NotFound, get_json

API = "https://api.github.com"
TESTY = ("test", "spec", "fixture", "__snapshots__", "changelog", ".md", "docs/")


def _added_lines(patch: str) -> list[str]:
    out = []
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            s = line[1:].strip()
            if len(s) >= 12 and not s.startswith(("//", "#", "*", "/*")):
                out.append(s)
    return out


def presence(repo: str, sha: str, tag: str, headers: dict, max_files: int = 4) -> Optional[dict]:
    """Share of the fix's added source lines found in the tagged release; None if not checkable."""
    try:
        c = get_json(f"{API}/repos/{repo}/commits/{sha}", headers, ttl=24 * 3600)
    except NotFound:
        return None
    if len(c.get("parents", [])) > 1:
        return {"merge_commit": True}
    files = [f for f in c.get("files", []) if f.get("patch") and f["status"] != "removed"
             and not any(t in f["filename"].lower() for t in TESTY)][:max_files]
    total = found = 0
    per_file = {}
    for f in files:
        lines = _added_lines(f["patch"])
        if not lines:
            continue
        try:
            body = get_json(f"{API}/repos/{repo}/contents/{urllib.parse.quote(f['filename'])}?ref={urllib.parse.quote(tag, safe='')}",
                            {**headers, "Accept": "application/vnd.github.raw+json"}, ttl=24 * 3600)
            text = body if isinstance(body, str) else ""
        except NotFound:
            text = ""
        except Exception:
            continue
        hit = sum(1 for l in lines if l in text)
        per_file[f["filename"]] = f"{hit}/{len(lines)}"
        total += len(lines)
        found += hit
    if not total:
        return None
    return {"ratio": round(found / total, 2), "files": per_file, "date": c["commit"]["committer"]["date"]}
