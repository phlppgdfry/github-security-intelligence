"""`ghsi h1 …` — HackerOne login, scope guard, own reports, report drafts and lint. Read-only towards HackerOne."""
from __future__ import annotations

import argparse
import getpass
import pathlib
import re
import subprocess
import sys

from . import bounty_github as rules
from . import h1


def _client_or_exit() -> h1.Client:
    try:
        return h1.Client()
    except h1.NoCredentials as e:
        sys.exit(str(e))


def cmd_login(args) -> int:
    if args.from_clipboard:
        token = subprocess.run(["pbpaste"], capture_output=True, text=True).stdout.strip()
    elif not sys.stdin.isatty():
        token = sys.stdin.readline().strip()
    else:
        token = getpass.getpass("HackerOne API token (hidden): ").strip()
    if not token:
        sys.exit("no token given (copy it from https://hackerone.com/settings/api_token/edit)")
    creds = h1.Credentials(args.identifier.strip(), token)
    try:
        h1.Client(creds).program(rules.PROGRAM_HANDLE)  # cheap authenticated read proves the pair works
    except h1.H1Error as e:
        sys.exit(f"token not stored: {e}")
    h1.store_credentials(creds)
    if args.from_clipboard:
        subprocess.run(["pbcopy"], input="", text=True)  # don't leave the token on the clipboard
    print(f"ok: token for '{creds.identifier}' verified against HackerOne and stored in the Keychain ({h1.KEYCHAIN_SERVICE})")
    return 0


def cmd_logout(args) -> int:
    print("Keychain item removed" if h1.delete_credentials() else "nothing stored")
    return 0


def cmd_status(args) -> int:
    try:
        creds = h1.load_credentials()
    except h1.NoCredentials as e:
        print(f"auth: missing — {e}")
        return 1
    c = h1.Client(creds)
    print(f"auth: identifier '{creds.identifier}'")
    prog = c.program(args.program)
    a = prog.get("attributes") or {}
    print(f"program: {a.get('name') or args.program} ({rules.PROGRAM_URL if args.program == 'github' else args.program})"
          f" — state {a.get('state', '?')}, offers bounties: {a.get('offers_bounties', '?')}")
    reports = c.my_reports()
    states: dict[str, int] = {}
    for r in reports:
        s = (r.get("attributes") or {}).get("state", "?")
        states[s] = states.get(s, 0) + 1
    print(f"my reports: {len(reports)}" + (" (" + ", ".join(f"{k} {v}" for k, v in sorted(states.items())) + ")" if states else ""))
    entries, src = h1.load_scope(args.program, client=c)
    bounty = sum(e.eligible_for_bounty and e.eligible_for_submission for e in entries)
    print(f"scope: {len(entries)} assets, {bounty} bounty-eligible (source: {src})")
    return 0


def cmd_scope(args) -> int:
    try:
        entries, src = h1.load_scope(args.program, refresh=args.refresh)
    except h1.H1Error as e:
        sys.exit(str(e))
    if args.bounty_only:
        entries = [e for e in entries if e.eligible_for_bounty and e.eligible_for_submission]
    if src != "hackerone" and src != "cache":
        print(f"(source: {src} — run `ghsi h1 login` for the live HackerOne scope)\n")
    print("| In scope | Bounty | Max severity | Type | Asset |\n|---|---|---|---|---|")
    for e in sorted(entries, key=lambda e: (not e.eligible_for_submission, not e.eligible_for_bounty, e.asset_type, e.identifier)):
        print(f"| {'yes' if e.eligible_for_submission else 'NO'} | {'yes' if e.eligible_for_bounty else '—'} | "
              f"{e.max_severity or '—'} | {e.asset_type} | `{e.identifier}` |")
    print(f"\n{len(entries)} entries, source {src}. Cache: {h1.scope_cache_path(args.program)}")
    return 0


def cmd_check(args) -> int:
    try:
        entries, src = h1.load_scope(args.program)
    except h1.H1Error as e:
        sys.exit(str(e))
    worst = 0
    for t in args.targets:
        v = h1.check_target(t, entries)
        mark = {"in-scope": "IN SCOPE ", "out-of-scope": "OUT      ", "unknown": "UNKNOWN  "}[v.status]
        print(f"{mark} {t}  —  {v.reason}")
        if v.entry and v.entry.instruction and args.verbose:
            print("          instruction: " + " ".join(v.entry.instruction.split())[:400])
        worst = max(worst, v.exit_code)
    if src not in ("hackerone", "cache"):
        print(f"(scope source: {src}; log in for the live HackerOne list)", file=sys.stderr)
    return worst


def cmd_reports(args) -> int:
    reports = _client_or_exit().my_reports(limit=args.limit)
    if not reports:
        print("no reports yet")
        return 0
    print("| # | State | Program | Severity | Created | Title |\n|---|---|---|---|---|---|")
    for r in reports:
        a = r.get("attributes") or {}
        team = (((r.get("relationships") or {}).get("program") or {}).get("data") or {}).get("attributes", {}).get("handle", "")
        sev = ((((r.get("relationships") or {}).get("severity") or {}).get("data") or {}).get("attributes") or {}).get("rating", "")
        print(f"| [{r.get('id')}](https://hackerone.com/reports/{r.get('id')}) | {a.get('state', '')} | {team} | {sev} | "
              f"{(a.get('created_at') or '')[:10]} | {a.get('title', '')} |")
    return 0


def cmd_rules(args) -> int:
    print(f"GitHub Security Bug Bounty — {rules.PROGRAM_URL} (rules read {rules.READ_ON}; re-read {rules.SOURCES['rules']})\n")
    print("Before you test — every line must be a yes:")
    for line in rules.BEFORE_YOU_TEST:
        print(f"  [ ] {line}")
    print("\nWhen you report:")
    for line in rules.WHEN_YOU_REPORT:
        print(f"  [ ] {line}")
    print("\nIneligible (don't spend time here):")
    for line in rules.INELIGIBLE_HIGHLIGHTS:
        print(f"  - {line}")
    print("\nRewards (public / private program, guidelines):")
    for sev, pub, priv in rules.REWARDS:
        print(f"  {sev:<17} {pub:<10} {priv}")
    print("\nContacts:")
    for k, v in rules.CONTACTS.items():
        print(f"  {k}: {v}")
    return 0


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "report"


def cmd_draft(args) -> int:
    try:
        entries, _ = h1.load_scope(args.program)
        v = h1.check_target(args.asset, entries)
        verdict = f"{v.status} — {v.reason}"
    except h1.H1Error:
        verdict = "not checked"
    out = pathlib.Path(args.out or f"reports/{_slug(args.title)}.md")
    if out.exists() and not args.force:
        sys.exit(f"{out} exists (use --force to overwrite)")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(h1.REPORT_TEMPLATE.format(title=args.title, asset=args.asset, verdict=verdict))
    print(f"draft written: {out}\nnext: fill it in, then `ghsi h1 lint {out}`")
    return 0


def cmd_lint(args) -> int:
    issues = h1.lint_report(pathlib.Path(args.file).read_text())
    for level, msg in issues:
        print(f"{level.upper():5} {msg}")
    errors = sum(1 for lvl, _ in issues if lvl == "error")
    print(("ready to paste into HackerOne" if not issues else
           f"{errors} error(s), {len(issues) - errors} warning(s)") + " — ghsi never submits for you")
    return 1 if errors else 0


def register(sub) -> None:
    p = sub.add_parser("h1", help="HackerOne: login, scope guard, own reports, report drafts (read-only)")
    hs = p.add_subparsers(dest="h1cmd", required=True)

    s = hs.add_parser("login", help="verify an API token and store it in the macOS Keychain")
    s.add_argument("--identifier", required=True, help="API token identifier (shown next to the token on HackerOne)")
    s.add_argument("--from-clipboard", action="store_true", help="read the token from the clipboard, then clear it")
    s.set_defaults(fn=cmd_login)
    hs.add_parser("logout", help="remove the Keychain item").set_defaults(fn=cmd_logout)

    s = hs.add_parser("status", help="auth, program state, my reports, scope size")
    s.add_argument("--program", default=rules.PROGRAM_HANDLE)
    s.set_defaults(fn=cmd_status)

    s = hs.add_parser("scope", help="structured scope of a program (default: github)")
    s.add_argument("--program", default=rules.PROGRAM_HANDLE)
    s.add_argument("--refresh", action="store_true")
    s.add_argument("--bounty-only", action="store_true")
    s.set_defaults(fn=cmd_scope)

    s = hs.add_parser("check", help="may I test this? exit 0 in scope, 1 out, 2 unknown")
    s.add_argument("targets", nargs="+", help="URL, host or product name")
    s.add_argument("--program", default=rules.PROGRAM_HANDLE)
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_check)

    s = hs.add_parser("reports", help="my HackerOne reports")
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(fn=cmd_reports)

    hs.add_parser("rules", help="GitHub bounty checklist, ineligible list, rewards").set_defaults(fn=cmd_rules)

    s = hs.add_parser("draft", help="write a report skeleton in GitHub's required shape")
    s.add_argument("title")
    s.add_argument("--asset", required=True)
    s.add_argument("--program", default=rules.PROGRAM_HANDLE)
    s.add_argument("--out")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_draft)

    s = hs.add_parser("lint", help="check a draft for missing sections, secrets, PII and off-site links")
    s.add_argument("file")
    s.set_defaults(fn=cmd_lint)
