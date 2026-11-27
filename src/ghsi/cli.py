"""ghsi — find, verify and draft improvements to GitHub Advisory Database entries.

  ghsi scan  --ecosystem pip --limit 500        leads, written to out/
  ghsi draft GHSA-xxxx-xxxx-xxxx                evidence pack + contribution text for one advisory
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from concurrent.futures import ThreadPoolExecutor

from . import sources
from .checks import HIGH, LOW, MEDIUM, check_advisory

ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


def _packages_for(advs: list[dict]) -> dict:
    wanted = {(v["package"]["ecosystem"], v["package"]["name"]) for a in advs for v in a.get("vulnerabilities") or []
              if v["package"]["ecosystem"] in ("npm", "pip")}
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(zip(wanted, pool.map(lambda k: sources.fetch_package(*k), wanted)))


def cmd_scan(args: argparse.Namespace) -> int:
    advs = []
    for eco in args.ecosystem:
        advs += list(sources.iter_advisories(eco, args.limit, args.published))
    print(f"fetched {len(advs)} reviewed advisories", file=sys.stderr)
    pkgs = _packages_for(advs)
    findings = [f for a in advs for f in check_advisory(a, pkgs)]
    findings = [f for f in findings if ORDER[f.confidence] <= ORDER[args.min_confidence]]
    findings.sort(key=lambda f: (ORDER[f.confidence], f.check, f.ghsa_id))

    # Don't duplicate work already waiting for the curators.
    for f in findings:
        f.evidence["open_prs"] = sources.open_prs_for(f.ghsa_id) if f.confidence != LOW else []

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%MZ")
    (out / f"scan-{stamp}.json").write_text(json.dumps(
        {"scanned": len(advs), "ecosystems": args.ecosystem, "findings": [f.to_dict() for f in findings]}, indent=2))
    md = render_markdown(findings, len(advs), args.ecosystem)
    (out / f"scan-{stamp}.md").write_text(md)
    print(md)
    return 0


def render_markdown(findings, scanned: int, ecosystems: list[str]) -> str:
    lines = [f"# Advisory scan — {', '.join(ecosystems)}", "",
             f"{scanned} reviewed advisories checked, {len(findings)} leads. "
             "Every lead needs a primary source (release notes, fix commit, changelog) before it is submitted.", "",
             "| Confidence | Check | Advisory | Package | Detail | Open PRs |", "|---|---|---|---|---|---|"]
    for f in findings:
        prs = ", ".join(f"[#{p['number']}]({p['url']})" for p in f.evidence.get("open_prs", [])) or "—"
        lines.append(f"| {f.confidence} | `{f.check}` | [{f.ghsa_id}](https://github.com/advisories/{f.ghsa_id}) "
                     f"| {f.ecosystem}/{f.package} | {f.message.replace('|', '/')} | {prs} |")
    return "\n".join(lines) + "\n"


def cmd_draft(args: argparse.Namespace) -> int:
    adv = sources.get_advisory(args.ghsa)
    pkgs = _packages_for([adv])
    findings = check_advisory(adv, pkgs)
    prs = sources.open_prs_for(args.ghsa)
    print(f"# Contribution draft — {adv['ghsa_id']}\n")
    print(f"**{adv['summary']}**  \nhttps://github.com/advisories/{adv['ghsa_id']}  \n"
          f"Source: {adv.get('source_code_location') or '—'}  \nCVE: {adv.get('cve_id') or '—'}\n")
    if prs:
        print("> ⚠️ Open PRs already exist — read them before drafting anything:")
        for p in prs:
            print(f"> - #{p['number']} {p['title']} {p['url']}")
        print()
    print("## Current version data\n")
    for v in adv.get("vulnerabilities") or []:
        print(f"- {v['package']['ecosystem']}/{v['package']['name']}: range `{v['vulnerable_version_range']}`, "
              f"first patched `{v.get('first_patched_version')}`")
    print("\n## Automated leads\n")
    for f in findings or []:
        print(f"- **{f.check}** ({f.confidence}): {f.message}")
    if not findings:
        print("- none")
    print("\n## References on the advisory\n")
    for r in adv.get("references") or []:
        print(f"- {r}")
    print("\n## Before you submit (all must be true)\n")
    for item in (
        "I found a primary source (release notes, tag, fix commit or changelog) that proves the change.",
        "The source is linked in 'Reason for change'.",
        "No open PR already proposes this change.",
        "The change is about facts (versions, package name, references), not opinion about severity.",
    ):
        print(f"- [ ] {item}")
    print("\n## Reason for change (template — rewrite with what you verified)\n")
    print("```\n<What is wrong> → <what it should be>.\n"
          "Evidence: <link to release / commit / changelog>.\n"
          "Registry: <link to package version list>.\n```")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ghsi", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="check reviewed advisories against registry data")
    s.add_argument("--ecosystem", nargs="+", default=["pip", "npm"], choices=["pip", "npm"])
    s.add_argument("--limit", type=int, default=300, help="advisories per ecosystem, newest first")
    s.add_argument("--published", help="date filter, e.g. 2026-01-01..2026-11-27")
    s.add_argument("--min-confidence", default=MEDIUM, choices=[HIGH, MEDIUM, LOW])
    s.add_argument("--out", default="out")
    s.set_defaults(fn=cmd_scan)
    d = sub.add_parser("draft", help="evidence pack and contribution text for one advisory")
    d.add_argument("ghsa")
    d.set_defaults(fn=cmd_draft)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
