# Phase 3 — security baseline on every repository (2026-11-27)

`scripts/harden_repos.py` turned GitHub's security features on across all 168 repositories the account
owns (9 forks and 18 archived repositories were skipped: forks aren't ours, archived ones are read-only).

## What is on

| Feature | Public (106) | Private (62) | What it does |
|---|---|---|---|
| Dependabot alerts | ✅ 106 | ✅ 62 | Flags dependencies with a known vulnerability (from the GitHub Advisory Database) |
| Dependabot security updates | ✅ 106 | ✅ 62 | Opens a PR that upgrades the vulnerable dependency |
| Secret scanning | ✅ 106 | ❌ not offered | Scans the full git history for leaked keys and tokens |
| Push protection | ✅ 106 | ❌ not offered | Blocks a push that contains a key |
| CodeQL (default setup) | ✅ 106 (100 with analyzable code) | ❌ not offered | Static analysis of our own code on every push and PR |

**Why not all five on private repositories:** GitHub offers secret scanning, push protection and code
scanning on private repositories only through GitHub Secret Protection / Code Security, which it sells to
organizations on Team or Enterprise plans (GitHub Docs, `data/reusables/gated-features/*`). The API
refuses it on a personal account. Tested on one private repo:
`422 Secret scanning is not available for this repository` and `403 Code scanning is not enabled`.
The local gitleaks pre-commit hook covers leaked keys for private repositories.

## Keeping the PR flow manageable

Security updates were switched on **last**. First, repos with 2 or more alerts got a `.github/dependabot.yml`
that bundles all security fixes into one PR per ecosystem and directory (`groups: applies-to: security-updates`),
with `open-pull-requests-limit: 0` so Dependabot opens no routine version bumps. 18 repos got the file; one
(staysignal) kept its own config. The result is PRs like *"Bump the security-fixes group across 1 directory
with 11 updates"* instead of 11 separate PRs.

## First results

| | Count | Where |
|---|---|---|
| Dependabot alerts (open) | 899 in 22 repos | Logistics-Master 449, harbor-pulse 88, YardExx-platform 70, Fyesto 59, staysignal 57, cabine 53 |
| Dependabot PRs (first hour) | 38 in 10 repos | More arrive over the next hours |
| Secret scanning alerts | 0 | No leaked keys found in public history |
| CodeQL alerts | 195 (1 critical, 132 high, 62 medium) | Logistics-Master 76, enterprise-ai-product-design-studio 10, ai-money-playbook 9, harborvoice-ai 9 |

Most common CodeQL findings: missing rate limiting on Express routes (69), workflows without a
`permissions:` block (51), incomplete URL sanitization (17), DOM XSS (13).
The critical one is a server-side request forgery in `airtable-enterprise-platform/src/client/metadataClient.ts:177`.

## Follow-up done (2026-11-27)

| Item | Result |
|---|---|
| Critical SSRF in airtable-enterprise-platform | Fixed in [PR #1](https://github.com/phlppgdfry/airtable-enterprise-platform/pull/1) (merged). IDs must be prefix + letters/digits and are URL-encoded; cursor/limit are validated integers; 8 new tests; the alert is gone on the PR ref. |
| 51 `missing-workflow-permissions` alerts (37 workflow files, 33 repos) | `scripts/workflow_permissions.py` inferred each workflow's needs and added a top-level `permissions:` block: `contents: read` for all 37. Two were checked by hand (a `git push` to GitLab with its own token, and a build-time read of public GitHub data). CI after the change: 32 success; 1 pre-existing failure (buffer-ai-content-operations, failing since 2026-11-07); 1 Playwright failure caused by `ubuntu-latest` moving to 26.04, fixed by pinning `ubuntu-24.04`. |

## Still open (ongoing maintenance, not configuration)

1. Merge the Dependabot PRs as they arrive. Check major-version bumps (e.g. vite 5 → 8) first. When a PR has a
   stale lockfile, comment `@dependabot recreate`.
2. Go through the remaining high CodeQL findings per repo, starting with the portfolio flagships. Most are
   missing rate limiting on demo Express servers and URL-sanitization checks.
3. buffer-ai-content-operations: its own tests have failed since 2026-11-07. This is unrelated to security.
