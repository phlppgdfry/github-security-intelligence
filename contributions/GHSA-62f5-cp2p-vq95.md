# GHSA-62f5-cp2p-vq95 — CodeWhale / deepseek-tui `instructions` override

Status: **submitted, in review**: [github/advisory-database#11999](https://github.com/github/advisory-database/pull/11999) (2026-11-27)

Change: crates.io `deepseek-tui` `>= 0.8.8, < 0.8.41` → `>= 0.8.8, <= 0.8.41`, no patched version.

## How it was found

`ghsi fixcheck`: fix commit 43563356b is *after* tag v0.8.41. The content check (`verifyfix`) found
only 42% of the fix's lines in that tag. Then the **published crate** was checked, because that
artifact is what users install.

## Verified facts

| # | Fact | How |
|---|---|---|
| 1 | crates.io deepseek-tui 0.8.41 (2026-07-28, sha256 `dcc3f156…`) was built from commit `faf5e07` (2026-05-21). | `.cargo_vcs_info.json` in the crate; checksum matches the crates.io API |
| 2 | `faf5e07` predates the fix `43563356b` (2026-06-21). | compare `43563356b...faf5e07` = behind |
| 3 | The crate contains the exact vulnerable snippet the advisory quotes (`src/main.rs:4314-4320`) and none of the fix's warnings or tests. | grep of the unpacked crate |
| 4 | 0.8.41 is the last deepseek-tui crate. The project continues as `codewhale-tui` (first version 0.8.41). | crates.io API |
| 5 | Sibling GHSA-gx45-xrj5-g6c4 (same fix commit, same function) and 7 more CodeWhale advisories already say `<= 0.8.41`. | `/advisories?affects=deepseek-tui` |
| 6 | npm deepseek-tui 0.8.41 / 0.8.42 / 0.8.47 are deprecation stubs (README + postinstall notice only), so the npm entries are right. | unpacked tarballs |

Side effect: the web form keeps one CVSS vector and dropped the v3 score. I asked the curators
in a PR comment to keep it.
