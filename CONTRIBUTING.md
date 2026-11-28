# Contributing

Thanks for helping make the GitHub Advisory Database more accurate. There are two ways to help,
and both are welcome:

1. **Improve the tool** (code, checks, ecosystems, docs) with a pull request to this repo.
2. **Verify a lead and submit a correction** to [`github/advisory-database`](https://github.com/github/advisory-database)
   under your own account. When the curators merge it, GitHub credits you as an *analyst* on the
   advisory. [docs/first-advisory-credit.md](docs/first-advisory-credit.md) walks you through it.

## Ground rules

- **Facts only.** Versions, package names, commits, release notes. No severity opinions without a source.
- **Prove before you submit.** A lead is a question, not an answer. Most leads have a good explanation
  (monorepo tags, yanked releases, a deliberate curator choice). Read the advisory text and check the
  published artifact before you call something wrong.
- **Check for open PRs first.** `ghsi` marks leads that already have an open PR in `github/advisory-database`.
  Don't duplicate work the curators are reviewing.
- **Don't flood the curators.** A few well-proven PRs beat many weak ones. The queue is long and every weak
  PR costs a human reviewer time.
- **AI may help find leads. A human verifies and submits every contribution.**
- Be kind. This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Development setup

```bash
git clone https://github.com/phlppgdfry/github-security-intelligence
cd github-security-intelligence
uv sync --group dev
uv run --group dev pytest -q     # offline; tests never touch the network
```

Network commands (`scan`, `fixcheck`, `draft`) need a GitHub token: `GITHUB_TOKEN`/`GH_TOKEN`, or a
logged-in `gh` CLI. Responses are cached in `~/.cache/ghsi`.

## Pull requests to this repo

- One change per PR, with a test. Tests use fixtures, never live HTTP.
- New check? Add it to the table in the README with its confidence level and *why* it can be wrong.
- New ecosystem in `scan`? Add a registry fetcher in `src/ghsi/sources.py`, a version key in
  `src/ghsi/versions.py` if the ecosystem needs its own ordering, and a fixture-based test.
- Keep output reproducible: sort findings, no timestamps inside the rows.

## Claiming an issue

Comment "I'd like to take this" on the issue. If there's no PR or update after 14 days, someone else
may pick it up. Issues labelled `good first issue` have a clear scope and a pointer to the code involved.

## Questions

Open a [discussion](https://github.com/phlppgdfry/github-security-intelligence/discussions) or an issue.
