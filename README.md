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

## Install and run

```bash
uv sync
uv run ghsi scan --ecosystem pip npm --limit 300     # writes out/scan-<time>.{md,json}
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

## What verification taught the tool

A lead is a question, not an answer. Two real examples from the first scan (2026-11-27):

- **soupsieve, GHSA-6655-6qjp-jx7x.** Flagged because 3.0 and 3.0.1 sit between `<= 2.10`
  and the patch `3.0.2`. The fix commits are in tag 3.0, but 3.0.2's release notes say 3.0 and
  3.0.1 were **yanked**. The curators picked the first installable fix on purpose, so there's
  nothing to correct. The check now ignores yanked releases (`test_yanked_releases_are_not_a_gap`).
- **praisonai, GHSA-26mh-57q7-jfvr.** Flagged because 4.6.78 was never published to PyPI.
  That alone wouldn't matter, but checking the fix showed that the named file didn't change in
  4.6.78 and the blamed allowlist is still there in 4.8.2. See
  [`contributions/GHSA-26mh-57q7-jfvr.md`](contributions/GHSA-26mh-57q7-jfvr.md).

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
