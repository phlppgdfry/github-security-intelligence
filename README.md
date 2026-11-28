# github-security-intelligence

Find, verify and draft **evidence-backed corrections** to the
[GitHub Advisory Database](https://github.com/advisories).

`ghsi` compares the version data of reviewed advisories with what the package registries
actually published, flags contradictions, and builds an evidence pack for a human to verify
before anything is submitted. It's a lead generator, not an oracle: the curation team only
accepts changes backed by primary sources, and so does this workflow.

```text
GitHub Advisory API ──► ghsi scan ──► leads (high / medium / low)
npm + PyPI registries ─┘                 │
                                         ▼
                        human verification (tags, fix commits, release notes)
                                         │
                                         ▼
                   ghsi draft GHSA-… ──► "Suggest improvements" on github.com
```

## Contribute: earn your first advisory credit

Every lead is a question a human has to answer. Verify one, and if the data really is wrong, submit the
correction from your own account: when GitHub merges it you're credited as an **analyst** on the
advisory. Step-by-step with a real example: [docs/first-advisory-credit.md](docs/first-advisory-credit.md).
Code contributions are welcome too: see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[`good first issue`](https://github.com/phlppgdfry/github-security-intelligence/labels/good%20first%20issue) label.

## Install and run

```bash
uv sync
uv run ghsi scan --ecosystem pip npm --limit 300     # writes out/scan-<time>.{md,json}
uv run ghsi fixcheck --ecosystem npm pip go --limit 400  # is the fix commit inside the "patched" release?
uv run ghsi draft GHSA-xxxx-xxxx-xxxx                # evidence pack + contribution template
```

Auth: uses `GITHUB_TOKEN`/`GH_TOKEN`, or falls back to `gh auth token`. Responses are cached
in `~/.cache/ghsi` (6 h for registries, 1 h for advisories) so repeated runs stay polite.

## Checks

| Check | Confidence | What it means |
|---|---|---|
| `patch_not_published` | high | The first patched version doesn't exist on the registry. |
| `patch_inside_range` | high | The "patched" version is itself inside the vulnerable range. |
| `package_not_found` | high | The registry has no package with this name. |
| `unclassified_versions` | medium | Installable releases between the range and the patch are marked neither vulnerable nor patched. |
| `patch_yanked` | medium | The first patched version is yanked or has no files on PyPI. |
| `range_bound_not_published` | medium | An inclusive upper bound (`<= X`) names a version that was never published. |
| `range_unparseable` / `patch_unparseable` | medium | The data doesn't follow GHSA or ecosystem version syntax. |
| `no_patch_but_newer_releases` | low | No fix listed, but newer stable releases exist. A fix may have shipped, or the range needs extending. |

Leads that already have an **open PR** in `github/advisory-database` are marked, so nobody
duplicates work the curators are already reviewing.

## Fix-in-release check

`ghsi fixcheck` works for any ecosystem from git alone: for each advisory with a fix-commit reference, it
finds the tag of the "patched" version and asks GitHub whether the tag contains the commit. If the release
*predates* the fix, everyone on that release is told they're safe when they aren't.

Ancestry is only a first filter. `ghsi.verifyfix` then checks whether the fix's added source lines are in
the release, and a human confirms against the published artifact (crate, wheel, tarball).

Of the 64 high-confidence leads in the first run (2,400 advisories), most were explained on inspection:
monorepo tags that belong to another package (highcharts, jhipster, libp2p), security releases shipped
through a separate commit (Symfony), deliberate maintainer choices written in the advisory (nuxt: a
dependency floor already fixed 4.4.4), and git tags that don't match the published artifact (ag-psd).
Two were real errors, both submitted: Snipe-IT and deepseek-tui.

## Gap check

`ghsi scan --verify-gaps` takes every `unclassified_versions` lead (published releases between the range
and the patch) and asks git whether any fix commit is in those releases. If none is and the patched
release has one, the lead becomes **high**: those releases are vulnerable and nobody is alerted.

Behind it is a recurring pattern: the range is copied from a "last known affected" version written when the
report came in, and the maintainer ships a few more releases before the fix. Round 2 (2026-11-28) found
four of these: music-metadata 11.13–11.15 (twice; the advisory itself says 11.15.0 is vulnerable),
seroval 1.6.1 (critical; no git tags, proven from the npm tarballs) and Home Assistant 2026.2.2
([#12019](https://github.com/github/advisory-database/pull/12019)–[#12022](https://github.com/github/advisory-database/pull/12022)).

## What verification taught the tool

A lead is a question, not an answer. Two real examples from the first scan (2026-11-27):

- **soupsieve, GHSA-6655-6qjp-jx7x.** Flagged because 3.0 and 3.0.1 sit between `<= 2.10`
  and the patch `3.0.2`. The fix commits are in tag 3.0, but 3.0.2's release notes say 3.0 and
  3.0.1 were **yanked**. The curators picked the first installable fix on purpose, so there's
  nothing to correct. The check now ignores yanked releases (`test_yanked_releases_are_not_a_gap`).
- **praisonai, GHSA-26mh-57q7-jfvr.** Flagged because 4.6.78 was never published to PyPI.
  That alone wouldn't matter, but checking the fix showed that the named file didn't change in
  4.6.78 and the blamed allowlist is still there in 4.8.2. Submitted as
  [github/advisory-database#11998](https://github.com/github/advisory-database/pull/11998). See
  [`contributions/GHSA-26mh-57q7-jfvr.md`](contributions/GHSA-26mh-57q7-jfvr.md).
- **Snipe-IT, GHSA-fc33-6w3q-538h.** "Patched in 8.6.1", but the permission checks only arrived in
  8.6.2. Submitted as [#12000](https://github.com/github/advisory-database/pull/12000).
- **deepseek-tui, GHSA-62f5-cp2p-vq95.** The published 0.8.41 crate still contains the vulnerable code,
  but the range excluded it. Submitted as [#11999](https://github.com/github/advisory-database/pull/11999).

## Bug bounty toolkit (`ghsi h1`)

Read-only HackerOne Hacker API client for GitHub's bug bounty program. It has a scope guard that
rejects unlisted, look-alike and third-party hosts, GitHub's rules as checklists, and report drafts
plus a lint step that catches leaked tokens, PII and off-site media. It never submits: you do that
on HackerOne yourself. Also available as a local MCP server (`uv run --extra mcp ghsi-mcp`). Setup and
training route: [docs/phase-5-bug-bounty.md](docs/phase-5-bug-bounty.md).

```sh
uv run ghsi h1 check https://gist.github.com https://blog.github.com   # IN SCOPE / OUT
uv run ghsi h1 rules
```

## Rules this project follows

- Facts only: versions, package names, references. No severity opinions without a source.
- Every submitted change links a primary source (tag compare, fix commit, release notes).
- Check for open PRs first, and don't flood the curators: a few well-proven PRs beat many weak ones.
- AI may help find leads. A human verifies and submits every contribution.

## Development

```bash
uv run --group dev pytest -q      # offline; no network in tests
```

MIT licensed.
