# GHSA-4ghv-53cq-7wp3 — Home Assistant 2026.2.2 not flagged

Status: **submitted 2026-11-28, in review**: [github/advisory-database#12022](https://github.com/github/advisory-database/pull/12022)

Change: pip `homeassistant` `< 2026.2.2` → `< 2026.2.3` (patched stays 2026.2.3).
Impact: 2026.2.2 has the old redirect handling but is outside the range (patched is 2026.2.3).

## Verified facts

| # | Fact | How |
|---|---|---|
| 1 | Fix: PR #162941 "Block redirect to localhost", merged to dev 2026-02-13 18:31 (`815c708`), milestone **2026.2.3**, cherry-picked as `0f3c7ca`. | PR API |
| 2 | Release notes list #162941 under 2026.2.3; 2026.2.2's notes don't mention it. | release bodies |
| 3 | `homeassistant/helpers/aiohttp_client.py`: 0/58 added fix lines at tag 2026.2.2, 58/58 at 2026.2.3. Neither commit is in 2026.2.2 (compare: diverged); the cherry-pick `0f3c7ca` is in 2026.2.3 (ahead). | compare + `verifyfix` |
| 4 | PyPI: 2026.2.2 uploaded 2026-02-13 20:17, not yanked; 2026.2.3 2026-02-20. | PyPI JSON |

## Reason for change (summary of the submitted text)

> 2026.2.2 doesn't contain the fix, but the range `< 2026.2.2` excludes it, while the patched version is 2026.2.3.
>
> 1. The fix, #162941 "Block redirect to localhost", has milestone 2026.2.3 and is listed in the 2026.2.3 release notes, not in 2026.2.2's.
> 2. Neither 815c708d19aa (dev) nor its release-branch cherry-pick 0f3c7ca2772b is in tag 2026.2.2 (GitHub compare: diverged). The cherry-pick is in 2026.2.3.
> 3. homeassistant/helpers/aiohttp_client.py at 2026.2.2 has none of the lines the fix adds; at 2026.2.3 it has all of them.
> 4. 2026.2.2 is on PyPI and not yanked.
>
> Proposed: vulnerable `< 2026.2.3`, patched 2026.2.3 (unchanged).
