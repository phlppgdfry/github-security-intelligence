# Roadmap: GitHub security recognition, step by step

Status per phase. Facts are checked against GitHub's docs and real advisory data; dates are
targets, not guarantees.

| # | Goal | Status | Evidence / next step |
|---|---|---|---|
| 1 | **Developer Program Member** badge | ✅ already earned | Shown on the profile (octicon `cpu`). Requirement: an integration using the GitHub API plus a support email. This repo and `github-stars` both qualify. |
| 2 | **Security advisory credit** (as *analyst*) | 🔄 in progress | Merged community PRs to `github/advisory-database` get the submitter credited as `analyst` (checked on GHSA-23m2-mghx-vqmf, GHSA-cpwx-vrp4-4pq7, GHSA-5cjw-f85j-cv6r, GHSA-gcqx-w48m-w2h4). Submitted round 1 (2026-11-27): [#11998](https://github.com/github/advisory-database/pull/11998) praisonai, [#11999](https://github.com/github/advisory-database/pull/11999) deepseek-tui, [#12000](https://github.com/github/advisory-database/pull/12000) Snipe-IT. Round 2 (2026-11-28), unflagged vulnerable releases: [#12019](https://github.com/github/advisory-database/pull/12019) + [#12020](https://github.com/github/advisory-database/pull/12020) music-metadata, [#12021](https://github.com/github/advisory-database/pull/12021) seroval (critical), [#12022](https://github.com/github/advisory-database/pull/12022) Home Assistant. The queue holds ~1,700 open PRs, so expect weeks. |
| 3 | Security engineering on own repos | ✅ configured (2026-11-27) | All 168 repos: Dependabot alerts + security updates; 106 public: secret scanning, push protection, CodeQL. Results and triage list: [docs/phase-3-security-baseline.md](docs/phase-3-security-baseline.md). |
| 4 | Remediation credits in open source | 🔄 waiting on maintainers: ElevenLabs reports in triage (Track A). Track B (find a new vulnerability) closed without a finding; effort moved to Track C, 4 more evidence-backed Advisory Database PRs ([plan + log](docs/phase-4-5-plan.md)) | Maintainers can credit `remediation_developer` / `remediation_verifier` on a GHSA. Candidates: the open webhook-signature PRs (elevenlabs-js#509, elevenlabs-python#947), but only if the maintainers treat them as security fixes. |
| 5 | **Security Bug Bounty Hunter** badge | ⏳ long-term | Only through a valid report to GitHub's own program (HackerOne), inside its rules, using your own test accounts. Train first: PortSwigger Academy, Hacker101. No date promised. |

## Phase 2 working loop

1. `ghsi scan --verify-gaps` → pick high/medium leads with no open PR.
2. Prove it: tag compare / fix commit / release notes / registry page.
3. `ghsi draft GHSA-…` → fill in the "Reason for change" with the links.
4. Submit through **Suggest improvements for this vulnerability** on github.com (your own account).
5. Log it in `contributions/` with the PR link and the outcome.
