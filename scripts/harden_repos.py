#!/usr/bin/env python3
"""Turn on GitHub's security features across every repository an account owns.

  harden_repos.py settings   Dependabot alerts everywhere; secret scanning, push protection and
                             CodeQL default setup on public repos
  harden_repos.py alerts     count open Dependabot alerts per repo (after GitHub has scanned)
  harden_repos.py group      add .github/dependabot.yml that bundles security fixes into one PR,
                             only in repos with 2+ open alerts and no existing Dependabot config
  harden_repos.py fixes      turn on Dependabot security updates (the fix PRs)

Forks and archived repositories are skipped. Results go to out/harden-<step>.json.

Secret scanning, push protection and CodeQL on *private* repositories need GitHub Secret Protection /
Code Security, which GitHub sells to organizations only, so the script doesn't try them on private
repos of a personal account. See README for the source.
"""
from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "out"

# Dependabot ecosystem names, keyed by a manifest file that signals them.
MANIFESTS = {
    "package.json": "npm", "requirements.txt": "pip", "pyproject.toml": "pip", "Pipfile": "pip",
    "Gemfile": "bundler", "composer.json": "composer", "go.mod": "gomod", "Cargo.toml": "cargo",
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle", "Package.swift": "swift",
    "Dockerfile": "docker",
}


def gh(*args: str, input_json: dict | None = None) -> tuple[int, str]:
    cmd = ["gh", "api", *args]
    if input_json is not None:
        cmd += ["--input", "-"]
    p = subprocess.run(cmd, input=json.dumps(input_json) if input_json is not None else None,
                       capture_output=True, text=True)
    return p.returncode, (p.stdout or p.stderr).strip()


def repos() -> list[dict]:
    p = subprocess.run(["gh", "repo", "list", "--limit", "1000", "--json",
                        "nameWithOwner,visibility,isFork,isArchived,defaultBranchRef"],
                       capture_output=True, text=True, check=True)
    return [r for r in json.loads(p.stdout) if not r["isFork"] and not r["isArchived"]]


def ok(rc: int, out: str) -> str:
    if rc == 0:
        return "on"
    try:
        return "error: " + json.loads(out).get("message", out)[:120]
    except ValueError:
        return "error: " + out.splitlines()[-1][:120]


def step_settings(rs: list[dict]) -> list[dict]:
    res = []
    for r in rs:
        n, public = r["nameWithOwner"], r["visibility"] == "PUBLIC"
        row = {"repo": n, "visibility": r["visibility"].lower()}
        row["dependabot_alerts"] = ok(*gh("-X", "PUT", f"repos/{n}/vulnerability-alerts"))
        if public:
            row["secret_scanning+push_protection"] = ok(*gh("-X", "PATCH", f"repos/{n}", input_json={
                "security_and_analysis": {"secret_scanning": {"status": "enabled"},
                                          "secret_scanning_push_protection": {"status": "enabled"}}}))
            rc, out = gh("-X", "PATCH", f"repos/{n}/code-scanning/default-setup",
                         input_json={"state": "configured", "query_suite": "default"})
            row["codeql"] = "on" if rc == 0 else ok(rc, out)
        else:
            row["secret_scanning+push_protection"] = row["codeql"] = "n/a (private, personal account)"
        res.append(row)
        print(f"{n:60} {row['dependabot_alerts']:6} {row['secret_scanning+push_protection'][:30]:32} {row['codeql'][:40]}")
    return res


def step_alerts(rs: list[dict]) -> list[dict]:
    res = []
    for r in rs:
        n = r["nameWithOwner"]
        rc, out = gh("--paginate", f"repos/{n}/dependabot/alerts?state=open&per_page=100",
                     "--jq", '.[] | [.security_advisory.severity, .dependency.package.ecosystem, .dependency.package.name] | @tsv')
        lines = [l for l in out.splitlines() if l and rc == 0]
        sev = {}
        for l in lines:
            s = l.split("\t")[0]
            sev[s] = sev.get(s, 0) + 1
        res.append({"repo": n, "visibility": r["visibility"].lower(), "open_alerts": len(lines), "by_severity": sev,
                    "packages": sorted({l.split("\t")[2] for l in lines})[:30], "error": None if rc == 0 else out[:120]})
    for x in sorted(res, key=lambda x: -x["open_alerts"]):
        if x["open_alerts"]:
            print(f"{x['repo']:60} {x['open_alerts']:4}  {x['by_severity']}")
    print(f"total open alerts: {sum(x['open_alerts'] for x in res)} in {sum(1 for x in res if x['open_alerts'])} repos")
    return res


def ecosystems_in(n: str, branch: str) -> list[tuple[str, str]]:
    rc, out = gh(f"repos/{n}/git/trees/{branch}?recursive=1", "--jq", ".tree[] | select(.type==\"blob\") | .path")
    if rc != 0:
        return []
    found = set()
    for path in out.splitlines():
        if "node_modules/" in path or "/vendor/" in path or path.startswith("vendor/"):
            continue
        name = path.rsplit("/", 1)[-1]
        if name in MANIFESTS:
            d = "/" + path.rsplit("/", 1)[0] if "/" in path else "/"
            found.add((MANIFESTS[name], d))
    return sorted(found)


def dependabot_yml(entries: list[tuple[str, str]]) -> str:
    lines = ["# Bundles Dependabot security fixes into one pull request per ecosystem and directory.",
             "# open-pull-requests-limit: 0 turns off routine version bumps; security updates still run.",
             "version: 2", "updates:"]
    for eco, d in entries:
        lines += [f'  - package-ecosystem: "{eco}"', f'    directory: "{d}"',
                  "    schedule:", '      interval: "weekly"', "    open-pull-requests-limit: 0",
                  "    groups:", "      security-fixes:", "        applies-to: security-updates",
                  '        patterns: ["*"]']
    return "\n".join(lines) + "\n"


def step_group(rs: list[dict], min_alerts: int = 2) -> list[dict]:
    alerts = {x["repo"]: x for x in json.loads((OUT / "harden-alerts.json").read_text())}
    res = []
    for r in rs:
        n = r["nameWithOwner"]
        a = alerts.get(n, {}).get("open_alerts", 0)
        if a < min_alerts:
            continue
        branch = (r.get("defaultBranchRef") or {}).get("name") or "main"
        exists = any(gh(f"repos/{n}/contents/.github/{f}?ref={branch}")[0] == 0
                     for f in ("dependabot.yml", "dependabot.yaml"))
        if exists:
            res.append({"repo": n, "alerts": a, "result": "skipped: has its own Dependabot config"})
            continue
        entries = ecosystems_in(n, branch)
        if not entries:
            res.append({"repo": n, "alerts": a, "result": "skipped: no manifest found"})
            continue
        body = {"message": "Group Dependabot security updates into one PR\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
                "content": base64.b64encode(dependabot_yml(entries).encode()).decode(), "branch": branch}
        rc, out = gh("-X", "PUT", f"repos/{n}/contents/.github/dependabot.yml", input_json=body)
        res.append({"repo": n, "alerts": a, "ecosystems": entries, "result": "committed" if rc == 0 else ok(rc, out)})
        print(f"{n:60} {a:4} alerts  {res[-1]['result']}")
    return res


def step_fixes(rs: list[dict]) -> list[dict]:
    res = []
    for r in rs:
        n = r["nameWithOwner"]
        res.append({"repo": n, "security_updates": ok(*gh("-X", "PUT", f"repos/{n}/automated-security-fixes"))})
    bad = [x for x in res if x["security_updates"] != "on"]
    print(f"security updates on: {len(res) - len(bad)}/{len(res)}")
    for x in bad:
        print(f"  {x['repo']}: {x['security_updates']}")
    return res


def main() -> int:
    step = sys.argv[1] if len(sys.argv) > 1 else ""
    fn = {"settings": step_settings, "alerts": step_alerts, "group": step_group, "fixes": step_fixes}.get(step)
    if not fn:
        print(__doc__)
        return 2
    rs = repos()
    print(f"{len(rs)} repositories (forks and archived skipped)\n")
    res = fn(rs)
    OUT.mkdir(exist_ok=True)
    (OUT / f"harden-{step}.json").write_text(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
