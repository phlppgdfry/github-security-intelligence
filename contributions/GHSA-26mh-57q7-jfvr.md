# GHSA-26mh-57q7-jfvr — PraisonAI "Broken AST Sandbox"

Status: **draft, not submitted** — waiting on the dynamic check below.

Advisory: https://github.com/advisories/GHSA-26mh-57q7-jfvr
Upstream: https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-26mh-57q7-jfvr
Current data: pip/praisonai, vulnerable `< 4.6.78`, first patched `4.6.78`

## How it was found

`ghsi scan --ecosystem pip` flagged `patch_not_published`: PyPI goes 4.6.77 → 4.6.81;
4.6.78–4.6.80 exist only as GitHub releases. On its own that would not justify a change
(the set of affected PyPI versions is the same), so the fix itself was checked.

## Verified facts (2026-11-27)

1. **The file the advisory names did not change in 4.6.78.**
   `GET /repos/MervinPraison/PraisonAI/compare/v4.6.77...v4.6.78` lists 43 changed files;
   `src/praisonai/praisonai/cli/features/job_workflow.py` is not among them.
2. **The allowlist the advisory blames is unchanged in every release.**
   `allowed_modules = {'os', 'datetime', ...}` is present in `job_workflow.py` in all 44
   GitHub releases from v4.6.76 through v4.8.2 (moved to `src/praisonai-code/` in v4.7.0).
3. **The exploit as written depends on Python behaviour that doesn't hold.**
   The advisory says the missing `__import__` is "irrelevant because the code uses a real
   import statement". In CPython the `import` statement calls `__import__` from the frame's
   builtins. `_exec_inline_python` sets `__builtins__` to `_SAFE_BUILTINS`, which has no
   `__import__`; locally, `exec(compile('import os', '<w>', 'exec'), {'__builtins__': {...}})`
   raises `ImportError: __import__ not found`.

## What this means

Either the `import os` vector never worked (→ the advisory may need withdrawing), or it
worked and was never patched (→ "first patched 4.6.78" is wrong). Both contradict the
current data; which one is true decides the right contribution.

## Still to do before submitting

- [ ] Dynamic check: run the advisory's PoC (`import os` inside a `script:` step) against
      `praisonai==4.6.77` from PyPI in a throwaway venv. Use a harmless payload (`os.getcwd()`).
- [ ] Read the upstream advisory's PoC section again: does it rely on some other path that
      makes `__import__` available (e.g. a different executor)?
- [ ] Check open PRs on github/advisory-database for this GHSA (none on 2026-11-27).
- [ ] Choose the form: *withdrawal request* (if the PoC fails) or *range correction*.

## Reason for change (draft — rewrite once the check above is done)

```
The first patched version 4.6.78 is not supported by the code: job_workflow.py is unchanged
between v4.6.77 and v4.6.78 (compare: https://github.com/MervinPraison/PraisonAI/compare/v4.6.77...v4.6.78),
and the 'os' entry in allowed_modules is still present in v4.8.2.
Running the advisory's PoC against praisonai==4.6.77 <result>, because _SAFE_BUILTINS has no
__import__ and CPython's import statement requires it.
<Proposed change: withdraw / set range to ... with no patched version>.
```
