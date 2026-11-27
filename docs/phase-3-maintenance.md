# Phase 3 maintenance — Dependabot and CodeQL triage (2026-11-27)

After turning the security features on, the first wave of findings was worked through.

## Dependabot pull requests

`scripts/dependabot_triage.py` sorts every open Dependabot PR into safe / major / failing / pending
(safe = all checks pass and no major-version bump). Roughly 45 PRs were handled:

- **Merged after verification:** safe patches, and major bumps whose CI (or a local build/test) passed —
  including vite 5→8 (migrated `.js`→`.jsx` and plugin-react 6 where needed), TypeScript 7, AutoMapper 15
  (.NET build + 31 tests), uuid 14 (route modules load), fastapi 0.165/starlette for finrisk-ai.
- **Fixed then merged:** lockfiles regenerated with npm 10 for Node-22 CI; peer conflicts resolved with
  targeted bumps (cabine react 19.3.1 + plugin-rsc 0.5.39; ecoload serialize-javascript via npm overrides).
- **Closed with a reason:** Angular 17→22 jump (a migration, not a patch — the real transitive vulns were
  patched via overrides instead); a .NET OpenApi group with an internal NU1608 conflict; standalone MAUI
  version bumps (MAUI must track the SDK). `dependabot.yml` now ignores MAUI *version* updates while still
  allowing MAUI security updates, and groups security fixes into one PR per ecosystem.
- **Handed back to Dependabot:** stale lockfile-only PRs, via `@dependabot recreate`.

Result: open Dependabot alerts across public repos went from **899 to ~249**. Most of the remaining 230 are
in the Logistics-Master demo monorepo and need an Angular 17→22 migration (tracked, not a dependency bump).

## CodeQL

The critical SSRF (airtable) and the 51 workflow-permission alerts were fixed first (see
[phase-3-security-baseline.md](phase-3-security-baseline.md)). The remaining code alerts were then worked
through across ~15 repos, each fix verified (tests, a build, or a browser proof) before pushing:

- **Rate limiting:** `express-rate-limit` on the YardEx API servers, the harborvoice webhook and SPA
  fallback, the airtable webhook. (Clears the bulk of `js/missing-rate-limiting`.)
- **XSS:** escaped AIS-derived vessel names/destinations in the vessel tracker (proven in Chrome: a vessel
  named `<img src=x onerror=...>` fired 10× before, 0× after), the approval output in the design studio,
  and demo-page values in several repos.
- **Path traversal:** the vessel-eta-tracker static server served `/../delay-dna/package.json` (200);
  now resolved-and-prefix-checked (404), verified against a real outside file.
- **ReDoS:** an HTML tag-stripper that took 78.6 s on 200k `<` now runs in 4 ms; an override heuristic
  regex replaced with a linear `indexOf` check.
- **Log forging:** CR/LF stripped before logging request values in two .NET middlewares.
- **Prototype dispatch:** `views[name]()` guarded with `Object.hasOwn` so `#constructor` can't reach it.
- **Secrets:** removed a hard-coded token-signing fallback secret (pinecone); stopped printing an API key
  (beehiiv).
- Test-fixture and by-design findings were dismissed with a written justification (not just closed).
