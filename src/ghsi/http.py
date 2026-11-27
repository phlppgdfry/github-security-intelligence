"""Small HTTP layer: JSON GETs with an on-disk cache, a polite User-Agent and retries."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any, Optional

USER_AGENT = "github-security-intelligence/0.1 (+https://github.com/phlppgdfry/github-security-intelligence)"
CACHE_DIR = pathlib.Path(os.environ.get("GHSI_CACHE", pathlib.Path.home() / ".cache" / "ghsi"))
DEFAULT_TTL = 6 * 3600


class NotFound(Exception):
    pass


class RateLimitLow(Exception):
    """Raised before the GitHub API budget runs dry, so the user's own gh/CI calls keep working."""


RATE_FLOOR = int(os.environ.get("GHSI_RATE_FLOOR", "500"))


def get_json(
    url: str,
    headers: Optional[dict[str, str]] = None,
    ttl: int = DEFAULT_TTL,
    with_headers: bool = False,
) -> Any:
    key = hashlib.sha256((url + json.dumps(headers or {}, sort_keys=True)).encode()).hexdigest()
    path = CACHE_DIR / f"{key}.json"
    if ttl and path.exists() and time.time() - path.stat().st_mtime < ttl:
        cached = json.loads(path.read_text())
        if cached.get("status") == 404:
            raise NotFound(url)
        return (cached["body"], cached["headers"]) if with_headers else cached["body"]

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read())
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            remaining = resp_headers.get("x-ratelimit-remaining")
            if remaining is not None and "api.github.com" in url and int(remaining) < RATE_FLOOR:
                _store(path, {"status": 200, "body": body, "headers": {k: v for k, v in resp_headers.items() if k in ("link", "etag")}})
                raise RateLimitLow(f"GitHub API budget down to {remaining}; stopping early")
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _store(path, {"status": 404})
                raise NotFound(url) from e
            if e.code in (403, 429) and e.headers.get("x-ratelimit-remaining") == "0":
                raise RateLimitLow("GitHub API rate limit exhausted") from e
            if e.code in (403, 429, 500, 502, 503) and attempt < 3:
                time.sleep(int(e.headers.get("retry-after", 0) or 2 ** (attempt + 1)))
                continue
            raise
        except urllib.error.URLError:
            if attempt < 3:
                time.sleep(2 ** (attempt + 1))
                continue
            raise
    # Cache only header fields we use; never persist auth-related ones.
    keep = {k: v for k, v in resp_headers.items() if k in ("link", "etag")}
    _store(path, {"status": 200, "body": body, "headers": keep})
    return (body, keep) if with_headers else body


def _store(path: pathlib.Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
