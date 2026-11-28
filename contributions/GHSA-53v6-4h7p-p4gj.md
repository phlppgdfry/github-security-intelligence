# GHSA-53v6-4h7p-p4gj + GHSA-jjpr-9cvf-cq55 — music-metadata 11.13.0–11.15.0 not flagged

Status: **submitted 2026-11-28, in review**: [#12019](https://github.com/github/advisory-database/pull/12019) (GHSA-53v6, APEv2) and [#12020](https://github.com/github/advisory-database/pull/12020) (GHSA-jjpr, ID3v2)

Change (both advisories): npm `music-metadata` `<= 11.12.3` → `< 11.16.0` (patched stays 11.16.0).
Impact: three published releases (11.13.0, 11.14.0, 11.15.0) contain the vulnerable parsers but sit
outside the range, so their users get no Dependabot alert. GHSA-53v6's own text says
"`music-metadata` 11.15.0 is vulnerable" and runs its PoC on 11.15.0.

## How it was found

`ghsi scan` → `unclassified_versions`: three releases between the range and the patch.

## Verified facts

| # | Fact | How |
|---|---|---|
| 1 | Fix commits: `b3bf52c` (APEv2, PR #2744) and `b033db6` (ID3v2, PR #2743), both 2026-09-22. | advisory refs |
| 2 | Both are `behind` v11.12.3, v11.13.0, v11.14.0 and v11.15.0, and `ahead` of v11.16.0. | GitHub compare |
| 3 | Added fix lines present: v11.15.0 0/33 (APEv2Parser.ts), 0/5 (ID3v2Parser.ts); v11.16.0 30/33 and 5/5. | `ghsi.verifyfix.presence` |
| 4 | npm: 11.13.0 (2026-06-07), 11.14.0 (2026-07-14), 11.15.0 (2026-08-18) published, none deprecated; 11.16.0 on 2026-09-22. | registry.npmjs.org |
| 5 | No open PR in github/advisory-database for either GHSA. | open-PR index |

## Reason for change (summary of the submitted text)

> The vulnerable range `<= 11.12.3` leaves out three published releases that still contain the vulnerable code: 11.13.0, 11.14.0 and 11.15.0. The fix is only in 11.16.0.
>
> 1. This advisory's description says "music-metadata 11.15.0 is vulnerable" and the PoC runs on 11.15.0.
> 2. The fix commits b3bf52cb6021 (APEv2, #2744) and b033db675b91 (ID3v2, #2743) are not in v11.13.0, v11.14.0 or v11.15.0 (GitHub compare: behind) and are in v11.16.0 (ahead).
> 3. lib/apev2/APEv2Parser.ts and lib/id3v2/ID3v2Parser.ts at v11.15.0 contain none of the lines those commits add; v11.16.0 does.
> 4. All three releases are on npm and not deprecated.
>
> Proposed: vulnerable `< 11.16.0`, patched 11.16.0 (unchanged).

## What the PR changes

The form produced a one-line data change in both: `database_specific.last_known_affected_version_range: "<= 11.12.3"`
is removed. The OSV `events` already said `fixed: 11.16.0`; GitHub's displayed range came from the
"last known affected" value recorded when the report was written. That pattern is behind all four
corrections of 2026-11-28 (see README).
