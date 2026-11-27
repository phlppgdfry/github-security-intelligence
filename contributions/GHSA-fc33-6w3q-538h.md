# GHSA-fc33-6w3q-538h — Snipe-IT user view / print authorization bypass

Status: **submitted, in review**: [github/advisory-database#12000](https://github.com/github/advisory-database/pull/12000) (2026-11-27)

Change: composer `snipe/snipe-it` `<= 8.6.0 → 8.6.1` → `< 8.6.2 → 8.6.2`, plus the two real fix commits as references.
Impact: users on **8.6.1** were told they're patched, but they're still vulnerable.

## How it was found

`ghsi fixcheck`: the referenced commit 374f426 is after tag v8.6.1. That commit turned out to be about bulk
check-in, not this issue, so the real fix was looked up via the files the advisory names.

## Verified facts

| # | Fact | How |
|---|---|---|
| 1 | The checks that close the issue were added in `dafd72af5945` (user view, 2026-06-08) and `f4cac9635868` (print page, 2026-06-09): `@can('view', License/Accessory/Consumable::class)`. | commit diffs |
| 2 | Both are in v8.6.2, not in v8.6.1 (released 2026-05-27). | compare: behind for v8.6.1, ahead for v8.6.2 |
| 3 | `users/view.blade.php` and `users/print.blade.php` in v8.6.1 have no such checks (same as v8.6.0). v8.6.2 has them. | file contents at each tag |
| 4 | The advisory already links release v8.6.2. 8.6.0, 8.6.1 and 8.6.2 are all on Packagist. | advisory refs, Packagist p2 API |
