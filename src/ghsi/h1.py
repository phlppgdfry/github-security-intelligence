"""Read-only HackerOne Hacker API client with a scope guard for GitHub's bug bounty program.

Nothing here submits a report or writes to HackerOne. Submitting stays a human action on
hackerone.com, so every report is read and sent by the researcher who owns it.

Credentials come from the environment (HACKERONE_API_IDENTIFIER + HACKERONE_API_TOKEN) or from the
macOS Keychain item `ghsi-hackerone` that `ghsi h1 login` writes. The token never touches disk in
plain text, never goes on a command line, and is never cached.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator, Optional

from . import bounty_github as rules

API = "https://api.hackerone.com/v1/hackers"
KEYCHAIN_SERVICE = "ghsi-hackerone"
USER_AGENT = "github-security-intelligence/0.1 (h1 read-only client)"
CACHE_DIR = pathlib.Path(os.environ.get("GHSI_CACHE", pathlib.Path.home() / ".cache" / "ghsi"))
SCOPE_TTL = 6 * 3600


class H1Error(Exception):
    pass


class NoCredentials(H1Error):
    pass


# ---------------------------------------------------------------- credentials

@dataclasses.dataclass(frozen=True)
class Credentials:
    identifier: str
    token: str

    def header(self) -> str:
        raw = f"{self.identifier}:{self.token}".encode()
        return "Basic " + base64.b64encode(raw).decode()


_SAFE = re.compile(r"^[A-Za-z0-9_.@+/=\-]+$")


def _keychain_identifier() -> Optional[str]:
    try:
        out = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE],
                             capture_output=True, text=True, check=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    m = re.search(r'"acct"<blob>="([^"]*)"', out)
    return m.group(1) if m else None


def load_credentials() -> Credentials:
    ident, token = os.environ.get("HACKERONE_API_IDENTIFIER"), os.environ.get("HACKERONE_API_TOKEN")
    if ident and token:
        return Credentials(ident, token)
    ident = _keychain_identifier()
    if ident:
        try:
            token = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", ident, "-w"],
                                   capture_output=True, text=True, check=True).stdout.strip()
        except subprocess.CalledProcessError:
            token = ""
        if token:
            return Credentials(ident, token)
    raise NoCredentials("no HackerOne API token found: run `ghsi h1 login --identifier <name>` "
                        "(token from https://hackerone.com/settings/api_token/edit)")


def store_credentials(creds: Credentials) -> None:
    """Write to the login Keychain through `security -i`, so the token is not visible in `ps`."""
    for value in (creds.identifier, creds.token):
        if not _SAFE.match(value):
            raise H1Error("identifier/token contains unexpected characters; refusing to store it")
    cmd = f'add-generic-password -U -s {KEYCHAIN_SERVICE} -a "{creds.identifier}" -l "HackerOne API (ghsi)" -w "{creds.token}"\n'
    res = subprocess.run(["security", "-i"], input=cmd, capture_output=True, text=True)
    if res.returncode != 0 or "error" in (res.stderr or "").lower():
        raise H1Error("could not write the Keychain item: " + (res.stderr or "").strip())


def delete_credentials() -> bool:
    ident = _keychain_identifier()
    if not ident:
        return False
    subprocess.run(["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", ident], capture_output=True)
    return True


# ---------------------------------------------------------------- API client

class Client:
    """GET-only client. 429s are retried with Retry-After; scope data has its own 50 req/min limit."""

    def __init__(self, creds: Optional[Credentials] = None):
        self.creds = creds or load_credentials()

    def get(self, path: str, params: Optional[dict] = None) -> Any:
        url = path if path.startswith("https://") else API + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        if urllib.parse.urlsplit(url).hostname != "api.hackerone.com":
            raise H1Error(f"refusing to send credentials to {url}")
        req = urllib.request.Request(url, headers={
            "Authorization": self.creds.header(), "Accept": "application/json", "User-Agent": USER_AGENT})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 3:
                    time.sleep(int(e.headers.get("retry-after") or 2 ** (attempt + 2)))
                    continue
                if e.code == 401:
                    raise H1Error("401 from HackerOne: identifier or token is wrong, or the token was revoked") from e
                if e.code == 403:
                    raise H1Error("403 from HackerOne: this token has no access to that resource") from e
                if e.code == 404:
                    raise H1Error(f"404 from HackerOne: {path}") from e
                if e.code in (500, 502, 503) and attempt < 3:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise H1Error(f"HackerOne returned HTTP {e.code} for {path}") from e
            except urllib.error.URLError as e:
                if attempt < 3:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise H1Error(f"network error talking to HackerOne: {e.reason}") from e
        raise H1Error("HackerOne kept rate limiting; try again in a minute")

    def paginate(self, path: str, page_size: int = 100, limit: int = 10_000) -> Iterator[dict]:
        url: Optional[str] = API + path + ("&" if "?" in path else "?") + urllib.parse.urlencode({"page[size]": page_size})
        seen = 0
        while url and seen < limit:
            body = self.get(url)
            for item in body.get("data") or []:
                yield item
                seen += 1
            url = (body.get("links") or {}).get("next")

    # convenience wrappers -------------------------------------------------
    def program(self, handle: str) -> dict:
        return self.get(f"/programs/{urllib.parse.quote(handle)}")

    def structured_scopes(self, handle: str) -> list[dict]:
        return list(self.paginate(f"/programs/{urllib.parse.quote(handle)}/structured_scopes"))

    def scope_exclusions(self, handle: str) -> list[dict]:
        return list(self.paginate(f"/programs/{urllib.parse.quote(handle)}/scope_exclusions"))

    def my_reports(self, limit: int = 200) -> list[dict]:
        return list(self.paginate("/me/reports", limit=limit))

    def balance(self) -> Any:
        return self.get("/payments/balance")


# ---------------------------------------------------------------- scope

@dataclasses.dataclass
class ScopeEntry:
    asset_type: str
    identifier: str
    eligible_for_submission: bool
    eligible_for_bounty: bool
    max_severity: Optional[str] = None
    instruction: Optional[str] = None
    source: str = "hackerone"

    @classmethod
    def from_api(cls, item: dict) -> "ScopeEntry":
        a = item.get("attributes") or {}
        return cls(asset_type=a.get("asset_type") or "OTHER", identifier=(a.get("asset_identifier") or "").strip(),
                   eligible_for_submission=bool(a.get("eligible_for_submission")),
                   eligible_for_bounty=bool(a.get("eligible_for_bounty")),
                   max_severity=a.get("max_severity"), instruction=a.get("instruction"))


def scope_cache_path(handle: str) -> pathlib.Path:
    return CACHE_DIR / f"h1-scope-{handle}.json"


def load_scope(handle: str = "github", refresh: bool = False, client: Optional[Client] = None) -> tuple[list[ScopeEntry], str]:
    """HackerOne scope plus, for GitHub, the subdomain wildcards from bounty.github.com.

    HackerOne lists `github.com` and `npmjs.com` as single URLs, while bounty.github.com/scope says
    "all subdomains". Explicit HackerOne entries are more specific than those wildcards, so an
    out-of-scope host such as `enterprise.github.com` still loses."""
    entries, src = _load_scope(handle, refresh, client)
    if handle == "github" and src != "builtin":
        entries = entries + [e for e in builtin_github_scope() if e.asset_type == "WILDCARD"]
    return entries, src


def _load_scope(handle: str, refresh: bool, client: Optional[Client]) -> tuple[list[ScopeEntry], str]:
    """Scope from HackerOne (cached 6 h). Without credentials, fall back to the last cache, then the built-in copy."""
    path = scope_cache_path(handle)
    if not refresh and path.exists() and time.time() - path.stat().st_mtime < SCOPE_TTL:
        return [ScopeEntry(**e) for e in json.loads(path.read_text())["entries"]], "cache"
    try:
        client = client or Client()
        entries = [ScopeEntry.from_api(i) for i in client.structured_scopes(handle)]
    except NoCredentials:
        if path.exists():
            return [ScopeEntry(**e) for e in json.loads(path.read_text())["entries"]], "stale-cache"
        if handle == "github":
            return builtin_github_scope(), "builtin"
        raise
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                                "entries": [dataclasses.asdict(e) for e in entries]}, indent=1))
    return entries, "hackerone"


def builtin_github_scope() -> list[ScopeEntry]:
    out = [ScopeEntry("WILDCARD", f"*.{d}", True, True, None, None, "bounty.github.com") for d in rules.IN_SCOPE_DOMAINS]
    out += [ScopeEntry("URL", d, True, True, None, None, "bounty.github.com") for d in rules.IN_SCOPE_DOMAINS]
    out += [ScopeEntry("OTHER", p, True, True, None, None, "bounty.github.com") for p in rules.IN_SCOPE_PRODUCTS]
    return out


@dataclasses.dataclass
class Verdict:
    target: str
    status: str  # in-scope | out-of-scope | unknown
    reason: str
    entry: Optional[ScopeEntry] = None

    @property
    def exit_code(self) -> int:
        return {"in-scope": 0, "out-of-scope": 1}.get(self.status, 2)


def _host_of(target: str) -> Optional[str]:
    t = target.strip()
    if "://" not in t and (re.search(r"\s", t) or "." not in t):
        return None  # a product name such as "GitHub CLI"
    if "://" not in t:
        t = "https://" + t
    host = urllib.parse.urlsplit(t).hostname
    return host.rstrip(".").lower() if host else None


def _host_matches(host: str, pattern: str) -> bool:
    p = pattern.strip().lower()
    if "://" in p:
        p = urllib.parse.urlsplit(p).hostname or ""
    p = p.split("/")[0].rstrip(".")
    if p.startswith("*."):
        base = p[2:]
        return host == base or host.endswith("." + base)
    return host == p


def check_target(target: str, entries: list[ScopeEntry]) -> Verdict:
    """Decide whether a URL/host may be tested. Most specific match wins; any doubt means 'unknown' (don't test)."""
    host = _host_of(target)
    if not host:
        # Products without a host (GitHub CLI, Desktop, npm CLI, GHES …): match by name.
        name = target.strip().lower()
        for e in entries:
            if e.identifier.lower() == name:
                return _verdict_for(target, e)
        return Verdict(target, "unknown", "not a host and no product with that exact name in scope")
    try:
        ipaddress.ip_address(host)
        return Verdict(target, "unknown", "raw IP address: only test hosts GitHub lists by name")
    except ValueError:
        pass

    for label in rules.OUT_OF_SCOPE_HOST_PREFIXES:
        for d in rules.IN_SCOPE_DOMAINS:
            if label.endswith("*"):
                if host.startswith(label[:-1]) and host.endswith("." + d):
                    return Verdict(target, "out-of-scope", f"bounty.github.com excludes {label}{d}")
            elif host == f"{label}.{d}" or host.endswith(f".{label}.{d}"):
                return Verdict(target, "out-of-scope", f"bounty.github.com excludes {label}.{d} (third-party operated)")

    hosty = [e for e in entries if e.asset_type in ("URL", "WILDCARD", "DOMAIN", "API") and e.identifier]
    matches = [e for e in hosty if _host_matches(host, e.identifier)]
    if not matches:
        return Verdict(target, "unknown", f"{host} matches no scope entry; GitHub says unlisted assets are NOT in scope")

    def specificity(e: ScopeEntry) -> tuple[int, int]:
        ident = e.identifier.lower()
        return (0 if "*" in ident else 1, len(ident))

    best = max(matches, key=lambda e: (specificity(e), not e.eligible_for_submission))
    return _verdict_for(target, best)


def _verdict_for(target: str, e: ScopeEntry) -> Verdict:
    if not e.eligible_for_submission:
        return Verdict(target, "out-of-scope", f"listed as out of scope: {e.identifier}", e)
    bounty = "bounty-eligible" if e.eligible_for_bounty else "no bounty (submission only)"
    sev = f", max severity {e.max_severity}" if e.max_severity else ""
    return Verdict(target, "in-scope", f"{e.identifier} — {bounty}{sev} [{e.source}]", e)


# ---------------------------------------------------------------- report lint

REQUIRED_SECTIONS = ["Summary", "Scope", "Steps to reproduce", "Impact", "Test accounts"]
_SECRET_PATTERNS = {
    "GitHub token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "npm token": re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    "AWS key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "session cookie": re.compile(r"\b(user_session|_gh_sess|__Host-user_session_same_site)=[A-Za-z0-9%_\-]{20,}"),
}
_OFFSITE_MEDIA = re.compile(r"https?://(www\.)?(youtube\.com|youtu\.be|vimeo\.com|loom\.com|pastebin\.com|gist\.github\.com|"
                            r"imgur\.com|drive\.google\.com|dropbox\.com)\S*", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def lint_report(text: str) -> list[tuple[str, str]]:
    """Return (level, message) pairs. 'error' blocks submission, 'warn' needs a human look."""
    found: list[tuple[str, str]] = []
    headings = {h.strip().lower() for h in re.findall(r"^#{1,6}\s+(.+?)\s*$", text, re.M)}
    for s in REQUIRED_SECTIONS:
        if not any(h.startswith(s.lower()) for h in headings):
            found.append(("error", f"missing section '## {s}'"))
    steps = re.search(r"^#{1,6}\s+Steps to reproduce.*?$(.*?)(^#{1,6}\s|\Z)", text, re.M | re.S | re.I)
    if steps and len(re.findall(r"^\s*(\d+[.)]|[-*])\s+\S", steps.group(1), re.M)) < 2:
        found.append(("error", "steps to reproduce need at least two written steps (video-only reports can be ineligible)"))
    for name, rx in _SECRET_PATTERNS.items():
        if rx.search(text):
            found.append(("error", f"looks like a live {name} in the report: redact it and rotate it"))
    for m in _OFFSITE_MEDIA.finditer(text):
        found.append(("error", f"off-site media/paste link {m.group(0)}: upload files directly to HackerOne instead"))
    for m in set(_EMAIL.findall(text)):
        if not m.lower().endswith(("@wearehackerone.com", "@example.com", "@github.com")):
            found.append(("warn", f"email address {m}: if it is not yours, redact it (PII rule)"))
    if re.search(r"\{\{.+?\}\}|TODO|<fill", text):
        found.append(("error", "template placeholders are still in the report"))
    builtin = builtin_github_scope()
    for url in set(re.findall(r"https?://[^\s)>\]`]+", text)):
        host = _host_of(url) or ""
        if any(host == d or host.endswith("." + d) for d in rules.IN_SCOPE_DOMAINS):
            v = check_target(url, builtin)
            if v.status == "out-of-scope":
                found.append(("error", f"{url}: {v.reason}"))
    return found


REPORT_TEMPLATE = """# {title}

<!-- Draft for hackerone.com/github. ghsi never submits; you paste this yourself after `ghsi h1 lint`. -->

## Summary

One paragraph: what is broken, where, and who can abuse it.

## Scope

- Asset: {asset}
- `ghsi h1 check` verdict: {verdict}
- Weakness (CWE): <fill>
- Suggested severity: <fill> (none / low / medium / high / critical)

## Steps to reproduce

1. Signed in as test account A (`<fill>`), …
2. …
3. Observe …

## Impact

What an attacker gains, against whom, and what they need first. No hypothetical chains:
show the step that crosses a security boundary.

## Test accounts

- Accounts used (all owned by me, email aliases on @wearehackerone.com): <fill>
- Repositories / organizations used (all owned by me): <fill>
- Source IP addresses during testing: <fill>
- Request volume: manual, well under the program's automation limit.

## Supporting material

Screenshots and HTTP requests/responses uploaded as attachments on HackerOne (no external links).
Personal data of other users: none accessed. Any accidental copy was deleted on <fill>.
"""
