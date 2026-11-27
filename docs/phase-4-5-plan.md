# Phases 4 and 5 — plan (prepared 2026-11-27, nothing sent yet)

## Phase 4 — credit for fixing or finding a real vulnerability

A remediation or finder credit exists only on a published security advisory (GHSA). The **maintainer**
publishes it and chooses the credits. A merged security PR alone gives no credit, and a credit on a
repository advisory that GitHub reviews into the Advisory Database also counts toward the
*Security advisory credit* badge.

### Track A — ElevenLabs webhook verification (ready, needs your OK to send)

- PRs: elevenlabs/elevenlabs-js#509 and elevenlabs/elevenlabs-python#947. Both are open with no
  maintainer review yet.
- Both repositories accept **private vulnerability reports** (`/private-vulnerability-reporting` = enabled).
- Honest assessment: **low to medium chance.** The timing side channel in an HMAC hex comparison is real
  but hard to exploit over a network. The malformed-timestamp issue needs a validly signed payload.
  Maintainers may call this hardening rather than a vulnerability. That is their decision to make.
- Draft private report (to send from your account via *Security → Report a vulnerability*):

  > **Title:** Webhook signature check uses a non-constant-time comparison and accepts malformed timestamps
  >
  > `constructEvent` / `construct_event` compare the computed `v0=` HMAC with `!=`, which returns at the
  > first differing character. In the JS SDK, `t=abc` also turns the timestamp into `NaN`, which skips the
  > tolerance check. Fixes with tests are open as public PRs (#509, #947); the cross-SDK conformance results
  > are in phlppgdfry/elevenlabs-webhook-conformance. If you treat this as a security issue, a short advisory
  > would let users of older SDK versions know to upgrade. I'm happy to be credited as remediation developer.

### Track B — find something new with the tools from phase 2 and 3 (strongest route)

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
