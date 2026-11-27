# GHSA-26mh-57q7-jfvr — PraisonAI "Broken AST Sandbox"

Status: **ready to submit** (2026-11-27)

Advisory: https://github.com/advisories/GHSA-26mh-57q7-jfvr
Upstream: https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-26mh-57q7-jfvr
Current data: PyPI `praisonai`, vulnerable `< 4.6.78`, first patched `4.6.78`
Open PRs for this GHSA in github/advisory-database: none (checked 2026-11-27)

## How it was found

`ghsi scan --ecosystem pip` flagged `patch_not_published`: PyPI goes 4.6.77 → 4.6.81, and
4.6.78–4.6.80 exist only as GitHub releases. That alone wouldn't justify a change (the set of
affected PyPI versions is the same), so the fix itself was checked.

## Verified facts

| # | Fact | How it was checked |
|---|---|---|
| 1 | `job_workflow.py` (holds `_exec_inline_python`) is **not** among the 43 files changed in v4.6.78. | [compare v4.6.77...v4.6.78](https://github.com/MervinPraison/PraisonAI/compare/v4.6.77...v4.6.78) |
| 2 | The advisory's PoC fails on the vulnerable version: on `praisonai==4.6.77` from PyPI, `import os` and `from os import getcwd` both return `Evaluation error: __import__ not found`. | Ran it in an isolated venv with a harmless payload (`os.getcwd()`) |
| 3 | The sandbox **was** escapable in 4.6.77 another way: `().__class__.__base__.__subclasses__()` is accepted (`ok: True`). | Same venv; only checked that it's accepted, nothing executed |
| 4 | That traversal stayed open in the same function until [#6368](https://github.com/MervinPraison/PraisonAI/pull/6368) (commit `1475c5842`, fixes [#6367](https://github.com/MervinPraison/PraisonAI/issues/6367), "Sandbox Escape (RCE)"). It first shipped in v4.7.25; v4.7.24 doesn't have it. | `compare/1475c5842...v4.7.24` = behind, `...v4.7.25` = ahead |
| 5 | Since v4.7.0 the code lives in the separate PyPI package **praisonai-code**, which `praisonai` depends on. The first praisonai-code with the fix is **0.1.22**. 0.1.21 doesn't have it, and 0.0.64 / 0.1.0 have the old code. | Diff of `job_workflow.py` inside the published wheels 0.1.21 → 0.1.22 (adds `_safe_getattr`, blocks `_`-prefixed attributes) |
| 6 | `praisonai` 4.7.25 is the first release that requires `praisonai-code>=0.1.22` (4.7.24 requires `>=0.1.21`). | PyPI `requires_dist` |

## Proposed change

- `praisonai` (PyPI): vulnerable `< 4.7.25`, first patched `4.7.25`
- add `praisonai-code` (PyPI): vulnerable `< 0.1.22`, first patched `0.1.22`
- add references: PR #6368, commit 1475c5842, issue #6367

## Reason for change (as submitted)

```
The patched version 4.6.78 isn't supported by the source, and the vulnerable code moved packages.

1. job_workflow.py, which contains _exec_inline_python, is not among the 43 files changed in v4.6.78:
   https://github.com/MervinPraison/PraisonAI/compare/v4.6.77...v4.6.78
2. On praisonai==4.6.77 from PyPI the advisory's PoC fails: `import os` returns
   "Evaluation error: __import__ not found", because the exec namespace's __builtins__ has no __import__.
   The sandbox was still escapable in that version via attribute traversal:
   `().__class__.__base__.__subclasses__()` is accepted.
3. That escape in the same function was closed by https://github.com/MervinPraison/PraisonAI/pull/6368
   (commit 1475c5842, fixes issue #6367 "Sandbox Escape (RCE)"). It first shipped in v4.7.25.
4. Since v4.7.0 this file is published in the separate PyPI package praisonai-code, which praisonai
   depends on. The published wheels show the fix first in praisonai-code 0.1.22 (0.1.21 still has the
   unguarded getattr). praisonai 4.7.25 is the first release that requires praisonai-code>=0.1.22.

Proposed: praisonai < 4.7.25 (patched 4.7.25); add praisonai-code < 0.1.22 (patched 0.1.22);
add PR #6368 and the fix commit as references.
```

## Outcome

- Submitted: _pending_
- PR: _pending_
- Result: _pending_
