# Your first GitHub security advisory credit

Anyone with a GitHub account can suggest a correction to a reviewed advisory in the
[GitHub Advisory Database](https://github.com/advisories). When the curators merge it, your account is
credited on the advisory as an **analyst**, and the advisory credit shows on your profile.

This guide walks through one real correction from start to finish:
[GHSA-p6vx-979v-rg4c](https://github.com/advisories/GHSA-p6vx-979v-rg4c) (seroval, critical),
submitted as [github/advisory-database#12021](https://github.com/github/advisory-database/pull/12021).

> **Before you start:** a correction only helps if it's true. Expect most leads to be explained on
> inspection. Finding *nothing to fix* is a normal, useful result.

## 1. Find a lead

```bash
uv sync
uv run ghsi scan --ecosystem npm pip --limit 300 --verify-gaps
```

Open `out/scan-<time>.md`. Pick a **high** or **medium** lead with no open PR. In the seroval case the
scanner reported:

| Check | What it saw |
|---|---|
| `unclassified_versions` | npm has `1.6.1`, but the range says `<= 1.6.0` and the patch is `1.6.2`. Is 1.6.1 vulnerable or fixed? Nobody says. |

`--verify-gaps` then looked for the fix commit in 1.6.1. The repo has no git tags for 1.6.x, so git
couldn't answer: a human had to.

## 2. Prove it from primary sources

Write down every fact with the place you checked it. For seroval:

| # | Fact | Source |
|---|---|---|
| 1 | The fix adds an `isThennable()` check to `deserializePromise`. | fix commit diff |
| 2 | The published `seroval-1.6.1.tgz` has no such check (identical to 1.6.0); `1.6.2` has it in all four bundles. | `npm pack seroval@1.6.1` and `@1.6.2`, then `grep` |
| 3 | 1.6.1 was published *after* the advisory text was written ("through the current 1.6.0"), and isn't deprecated. | npm registry timestamps + advisory text |

Check the **published artifact** (tarball, wheel, crate), not only git: tags and releases don't always
match. And read the whole advisory: sometimes the curators already explain the choice you're about to
"fix" (for example yanked releases).

## 3. Draft the change

```bash
uv run ghsi draft GHSA-p6vx-979v-rg4c
```

This writes an evidence pack and a template for the **Reason for change**. Keep it short and factual:

> 1.6.1 is still vulnerable but is outside the range `<= 1.6.0`. The first fixed release is 1.6.2, which
> this advisory already lists as patched. [three numbered facts with links]
>
> Proposed: vulnerable `>= 0.12.0, < 1.6.2`, patched 1.6.2 (unchanged).

## 4. Submit it yourself

On the advisory page, click **Suggest improvements for this vulnerability**, change only the fields your
evidence supports, and paste the reason. GitHub opens the PR in `github/advisory-database` from your
account. Tip: in that form write cross-repo links as `owner/repo#123`; a bare `#123` links to the
advisory-database repo.

## 5. Wait, and answer questions

The review queue is long (often weeks). If a curator asks something, answer with a source. If they
decline, that's information too: note why in your log so the next lead is better.

## Log it

Keep a short record per contribution, like the files in [`contributions/`](../contributions/): status, the
change, the verified facts and the PR link. It makes follow-up easy and shows others how you reasoned.
