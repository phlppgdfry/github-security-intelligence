# GHSA-xqc2-xf4c-x3h3 — React Server Components RCE (react-server-dom-parcel)

Status: **candidate, low impact** — valid, but changes no scanner result.

Lead: `patch_not_published` for npm/react-server-dom-parcel, entry `>= 19.0.0, < 19.0.9 → 19.0.9`.

## Verified facts (2026-11-27)

- npm has no 19.0.x release of `react-server-dom-parcel`; the first stable release is 19.1.0
  (https://www.npmjs.com/package/react-server-dom-parcel?activeTab=versions).
  The entry matches zero published versions and its patch 19.0.9 doesn't exist.
- The entry mirrors upstream: facebook/react's repository advisory lists 19.0.0–19.0.8 for all
  three `react-server-dom-*` packages, and GHSA-fv66-9v8q-g76r has the same `= 19.0.0 → 19.0.1`
  parcel entry.
- Precedent: curators accept version fixes on React advisories when they change detection
  (github/advisory-database#6494, merged), and keep upstream's version data when the change
  is a judgement call (#6547, closed).

## Assessment

Removing the parcel 19.0 entry is factually right but has no practical effect, so it ranks
below leads that change what Dependabot reports. Submit only after the stronger leads,
and if so, propose it for both GHSA-xqc2-xf4c-x3h3 and GHSA-fv66-9v8q-g76r with the npm link.
