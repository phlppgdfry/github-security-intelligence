# GHSA-p6vx-979v-rg4c — seroval 1.6.1 not flagged (critical)

Status: **submitted 2026-11-28, in review**: [github/advisory-database#12021](https://github.com/github/advisory-database/pull/12021)

Change: npm `seroval` `>= 0.12.0, <= 1.6.0` → `>= 0.12.0, < 1.6.2` (patched stays 1.6.2).
Impact: 1.6.1 ships the unpatched Promise deserializer but is outside the range.

## Verified facts (published tarballs, not git: the repo has no 1.6.x tags)

| # | Fact | How |
|---|---|---|
| 1 | Fix `f1ffcc9` adds `isThennable()` and `if (isThennable(deserialized)) throw new SerovalMalformedNodeError(...)` in `deserializePromise` / `deserializePromiseFulfill`. | commit diff |
| 2 | `seroval-1.6.1.tgz` `dist/dev/index.js` `deserializePromise`: no thenable check, identical to 1.6.0. `seroval-1.6.2.tgz` has it. All 4 bundles (esm/cjs, dev/prod) agree: 0 checks in 1.6.1, 1 in 1.6.2. | npm tarballs |
| 3 | npm: 1.6.0 2026-07-29, 1.6.1 2026-08-04 03:25, 1.6.2 2026-08-04 03:38; none deprecated. | registry |
| 4 | Advisory text: "affects every plugin-capable release from 0.12.0 through the current 1.6.0", written before 1.6.1 shipped. | advisory |

## Reason for change (summary of the submitted text)

> 1.6.1 is still vulnerable but is outside the range `<= 1.6.0`. The first fixed release is 1.6.2, which this advisory already lists as patched.
>
> 1. The fix f1ffcc96d259 adds `isThennable()` and makes `deserializePromise` throw `SerovalMalformedNodeError` when the fulfilled value is a thenable.
> 2. In the published npm tarball seroval-1.6.1.tgz, `deserializePromise` in dist/index.js, dist/index.cjs and dist/dev/* has no such check; its code is identical to 1.6.0. seroval-1.6.2.tgz contains the check in all four bundles.
> 3. The description says the issue affects releases "through the current 1.6.0"; 1.6.1 was published afterwards (2026-08-04), 13 minutes before 1.6.2, and is not deprecated on npm.
>
> Proposed: vulnerable `>= 0.12.0, < 1.6.2`, patched 1.6.2 (unchanged).
