# Phases 4 and 5 — plan (prepared 2026-11-27, nothing sent yet)

## Phase 4 — credit for fixing or finding a real vulnerability

A remediation or finder credit exists only on a published security advisory (GHSA). The **maintainer**
publishes it and chooses the credits. A merged security PR alone gives no credit, and a credit on a
repository advisory that GitHub reviews into the Advisory Database also counts toward the
*Security advisory credit* badge.

### Track A — ElevenLabs webhook verification: **sent 2026-11-27**, in triage

- Private reports: elevenlabs-js `GHSA-w5h4-c893-399x`, elevenlabs-python `GHSA-h775-qrfx-rqmm` (severity low, CWE-208 + CWE-20).
  Only the maintainers can see them. They decide whether to publish, and the credit follows if they do.

- PRs: elevenlabs/elevenlabs-js#509 and elevenlabs/elevenlabs-python#947. Both are open with no
  maintainer review yet.
- Both repositories accept **private vulnerability reports** (`/private-vulnerability-reporting` = enabled).
- Honest assessment: **low to medium chance.** The timing side channel in an HMAC hex comparison is real
  but hard to exploit over a network. The malformed-timestamp issue needs a validly signed payload.
  Maintainers may call this hardening rather than a vulnerability. That is their decision to make.
- What was sent (summary; the full reports are in the private advisories):

  > **Title:** Webhook signature check uses a non-constant-time comparison and accepts malformed timestamps
  >
  > `constructEvent` / `construct_event` compare the computed `v0=` HMAC with `!=`, which returns at the
  > first differing character. In the JS SDK, `t=abc` also turns the timestamp into `NaN`, which skips the
  > tolerance check. Fixes with tests are open as public PRs (#509, #947); the cross-SDK conformance results
  > are in phlppgdfry/elevenlabs-webhook-conformance. If you treat this as a security issue, a short advisory
  > would let users of older SDK versions know to upgrade. I'm happy to be credited as remediation developer.

### Track B — find something new with the tools from phase 2 and 3 (strongest route)

**First hunt (2026-11-27): no reportable finding.** CodeQL security-extended on two active projects that accept
private reports:
- SignalK/signalk-server @ c8f0ddd: 276 results. The 30 strongest were triaged by hand. Path injection is
  guarded by a strict regex. The SSRF is an admin-only, by-design issuer test. The "auth bypass" alerts
  are normal `jwt.verify` flows. The reflected text in a DELETE 401 can't be triggered cross-site.
- flytohub/flyto-core @ 71cb047: 16 results. The tar-slip alert points at code that is already hardened (the fix
  of an earlier advisory). The rest are test fixtures.

Lesson: projects with several recent advisories have often just been audited thoroughly. For the next hunt,
use **variant analysis**: take a recently fixed bug in a project and look for the same mistake elsewhere in
that codebase and in similar projects.

1. Use CodeQL (now familiar from phase 3) on actively maintained open-source projects that have private
   vulnerability reporting enabled. Start with the query classes it found in our own code: SSRF, URL
   sanitization, DOM XSS.
2. Confirm each finding by hand, with a minimal and harmless proof, on your own local install only.
3. Report it **privately** through the project's *Report a vulnerability* form, with a proposed patch.
4. If the maintainer publishes a GHSA, you get the *finder/reporter* credit, and *remediation developer*
   too if your patch is used.

Rules: never test against someone else's live service, never publish details before the fix, and
respect the project's SECURITY.md.

### Track C — keep the Advisory Database work going

Wait for the curators' response to #11998/#11999/#12000 first, then repeat the `ghsi fixcheck` loop at a
calm pace (a few proven PRs a month).

## Phase 5 — GitHub Security Bug Bounty Hunter

- Only through GitHub's own program on HackerOne (<https://bounty.github.com>), inside its scope and rules,
  using your own test accounts and test data.
- Prerequisites: a HackerOne account (you make it yourself), and the PortSwigger Web Security Academy
  (free) for access control, SSRF, XSS and auth flaws. Those are the same classes CodeQL showed in our code.
- Realistic expectation: months, not weeks. The badge needs a valid finding in a heavily tested product.
  No date is promised.
