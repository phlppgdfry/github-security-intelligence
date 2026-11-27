#!/usr/bin/env python3
"""Add a least-privilege top-level `permissions:` block to GitHub Actions workflows that have none.

Without it, GITHUB_TOKEN gets the repository's default scopes, which can include write access
(CodeQL rule actions/missing-workflow-permissions). The script infers what each workflow needs from
the actions and commands it uses, and leaves anything it can't infer for a human.

  workflow_permissions.py plan   out/wfperm-alerts.json -> out/wfperm-plan.json (no changes)
  workflow_permissions.py apply  commit the planned blocks (one commit per workflow file)
"""
from __future__ import annotations

import base64
import json
import pathlib
import re
import subprocess
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "out"

# (pattern in the workflow text, scopes it needs)
NEEDS = [
    (r"actions/deploy-pages@", {"pages": "write", "id-token": "write"}),
    (r"peaceiris/actions-gh-pages@|JamesIves/github-pages-deploy-action@", {"contents": "write"}),
    (r"\bgit push\b|stefanzweifel/git-auto-commit-action@|EndBug/add-and-commit@", {"contents": "write"}),
    (r"softprops/action-gh-release@|ncipollo/release-action@|actions/create-release@|\bgh release (create|upload)\b",
     {"contents": "write"}),
    (r"peter-evans/create-pull-request@", {"contents": "write", "pull-requests": "write"}),
    (r"marocchino/sticky-pull-request-comment@|\bgh pr (comment|review|edit|merge)\b", {"pull-requests": "write"}),
    (r"\bgh issue (comment|create|edit|close)\b|peter-evans/create-or-update-comment@", {"issues": "write"}),
    (r"github/codeql-action/upload-sarif@", {"security-events": "write"}),
    (r"actions/attest-build-provenance@|actions/attest@", {"id-token": "write", "attestations": "write"}),
    (r"ghcr\.io", {"packages": "write"}),
]
# Things that use the token in ways we can't read off the text: a human decides.
UNSURE = r"actions/github-script@|secrets\.GITHUB_TOKEN|github\.token|GH_TOKEN|GITHUB_TOKEN"
LEVEL = {"read": 1, "write": 2}


def gh(*args, input_json=None):
    p = subprocess.run(["gh", "api", *args, *(["--input", "-"] if input_json is not None else [])],
                       input=json.dumps(input_json) if input_json is not None else None, capture_output=True, text=True)
    return p.returncode, p.stdout


def plan_one(text: str) -> tuple[dict | None, str]:
    if re.search(r"^permissions\s*:", text, re.M):
        return None, "already has top-level permissions (job-level gap: fix by hand)"
    if re.search(r"^\s+permissions\s*:", text, re.M):
        return None, "has job-level permissions on some jobs: fix by hand"
    perms = {"contents": "read"}
    for pat, need in NEEDS:
        if re.search(pat, text):
            for k, v in need.items():
                if LEVEL.get(v, 0) > LEVEL.get(perms.get(k, ""), 0):
                    perms[k] = v
    # A token mention is fine when a known pattern above already explains it (e.g. gh release with GH_TOKEN).
    explained = len(perms) > 1 or perms["contents"] == "write"
    if re.search(UNSURE, text) and not explained:
        return None, "uses the token in a way the script can't classify: review by hand"
    if "pull_request_target" in text:
        return None, "pull_request_target workflow: review by hand"
    return perms, "ok"


def block(perms: dict) -> str:
    lines = ["permissions:"] + [f"  {k}: {v}" for k, v in perms.items()]
    return "\n".join(lines) + "\n\n"


def insert(text: str, perms: dict) -> str:
    m = re.search(r"^jobs\s*:", text, re.M)
    if not m:
        raise ValueError("no top-level jobs:")
    return text[:m.start()] + block(perms) + text[m.start():]


def cmd_plan():
    items = json.loads((OUT / "wfperm-alerts.json").read_text())
    plan = []
    for it in items:
        rc, out = gh(f"repos/{it['repo']}/contents/{it['path']}")
        if rc:
            plan.append({**it, "status": "file not found"})
            continue
        meta = json.loads(out)
        text = base64.b64decode(meta["content"]).decode()
        perms, why = plan_one(text)
        plan.append({**it, "sha": meta["sha"], "perms": perms, "status": why})
    (OUT / "wfperm-plan.json").write_text(json.dumps(plan, indent=1))
    for p in plan:
        print(f"{p['repo'].split('/')[1]:45} {p['path'].split('/')[-1]:32} {p['status'] if not p.get('perms') else p['perms']}")


def cmd_apply():
    plan = json.loads((OUT / "wfperm-plan.json").read_text())
    for p in plan:
        if not p.get("perms"):
            continue
        rc, out = gh(f"repos/{p['repo']}/contents/{p['path']}")
        meta = json.loads(out)
        if meta["sha"] != p["sha"]:
            p["result"] = "changed since plan, skipped"
            continue
        new = insert(base64.b64decode(meta["content"]).decode(), p["perms"])
        body = {"message": "ci: least-privilege GITHUB_TOKEN permissions\n\nAddresses CodeQL actions/missing-workflow-permissions.\n\n"
                           "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
                "content": base64.b64encode(new.encode()).decode(), "sha": meta["sha"]}
        rc, out = gh("-X", "PUT", f"repos/{p['repo']}/contents/{p['path']}", input_json=body)
        p["result"] = "committed" if rc == 0 else "error"
        print(f"{p['repo'].split('/')[1]:45} {p['path'].split('/')[-1]:32} {p['result']}")
    (OUT / "wfperm-applied.json").write_text(json.dumps(plan, indent=1))


if __name__ == "__main__":
    {"plan": cmd_plan, "apply": cmd_apply}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: print(__doc__))()
