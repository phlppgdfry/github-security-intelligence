# Phase 5: GitHub Security Bug Bounty Hunter

The badge appears after a **valid report to GitHub's own bug bounty program**
([hackerone.com/github](https://hackerone.com/github)). This page covers the toolchain, the rules
as checklists, and a training route that ends at GitHub's real attack surface.

Rules read on bounty.github.com on 2026-11-28. Read them again before you start on a new target. The
live HackerOne scope (`ghsi h1 scope --refresh`) takes priority over the offline copy in
[`src/ghsi/bounty_github.py`](../src/ghsi/bounty_github.py).

## Toolchain (installed 2026-11-28)

| Piece | What it does | Status |
|---|---|---|
| **Burp Suite** 2026.11.3 (`brew install --cask burp-suite`) | Proxy, Repeater, Intruder, Scanner, Burp AT, the built-in Academy tab with Burp's browser | Professional through the Black Friday 2026 free offer (logged in); falls back to Community when that ends |
| **Burp MCP Server** (official PortSwigger BApp 1.4.0) | Lets Claude read your proxy history and send requests through Repeater. Every HTTP request and every read of project data needs your **approval** inside Burp, and config-editing tools are off | loaded, `http://127.0.0.1:9876/mcp` |
| **`ghsi h1`** (this repo) | HackerOne login (Keychain), scope guard, your own reports, GitHub's rules as checklists, report draft and lint | logged in as `phlppgdfryy` (2026-11-28); live scope 39 assets, 27 bounty-eligible |
| **`ghsi-mcp`** (this repo) | The same functions as a local, **read-only** MCP server. It cannot submit or comment | registered as `hackerone` |

Both MCP servers are listed in the shared agent-tools catalog (`burp`, `hackerone`) and active in the
`software-engineering`, `security-audit` and new `bug-bounty` profiles. The Burp server only answers
while Burp Suite is open.

HackerOne's structured scope lists `github.com` and `npmjs.com` as single URLs, while
bounty.github.com/scope says "all subdomains". For the `github` program `ghsi` adds those wildcards.
HackerOne's explicit out-of-scope entries (`enterprise.github.com`, `*.github.io`, `shop.github.com` …)
are more specific, so they still win.

### Test accounts (create in a private window: password, CAPTCHA and email code are yours)

| Account | Email | Role in tests |
|---|---|---|
| `phlppgdfryy-a` | `phlppgdfryy+a@wearehackerone.com` | attacker / org member |
| `phlppgdfryy-b` | `phlppgdfryy+b@wearehackerone.com` | victim / org owner of the test org |
| test org `phlppgdfryy-h1-lab` | owned by `-b` | private repos, teams, roles, apps |

Mail to the alias arrives in the inbox of your HackerOne account. Turn on 2FA for both accounts,
and never reuse your main account's password.

Why I built our own HackerOne client instead of using a community MCP: the Hacker API token can
read all your reports, including unfixed vulnerabilities. Our client sends that token only to
`api.hackerone.com` and only for GET requests. It stores the token only in the Keychain, never on
the command line or on disk.

### Log in (one time)

1. On HackerOne: **Settings → API Token** (`https://hackerone.com/settings/api_token/edit`). Create a
   token and note the *identifier* (shown next to it).
2. Copy the token value, then:

   ```sh
   uv run ghsi h1 login --identifier <identifier> --from-clipboard   # verifies, stores in Keychain, clears clipboard
   uv run ghsi h1 status
   ```

3. PortSwigger: sign in to your portswigger.net account in Burp's **Academy** tab, which tracks your
   lab progress there.

## Commands

```sh
ghsi h1 rules                                  # checklist: before you test / when you report / ineligible / rewards
ghsi h1 scope --bounty-only                    # live structured scope of hackerone.com/github
ghsi h1 check https://gist.github.com api.github.com blog.github.com   # exit 0 in, 1 out, 2 unknown
ghsi h1 draft "Private repo name leak via …" --asset api.github.com     # skeleton in GitHub's shape → reports/ (git-ignored)
ghsi h1 lint reports/private-repo-name-leak.md # missing sections, < 2 written steps, live tokens/cookies, PII, off-site media
ghsi h1 reports                                # your reports and their state
```

`check` treats any doubt as **don't test**: an unlisted host, a raw IP, a look-alike domain
(`evilgithub.com`, `github.com.evil.io`) and the third-party subdomains GitHub excludes (`blog.`,
`community.`, `shop.`, `resources.`, `email*`, …) all fail. Report drafts go to `reports/`, which is
in `.gitignore` because unfixed findings must never reach this public repo.

## Rules as habits

Before testing (from bounty.github.com/rules):

- Use only your own accounts, orgs and repos. Authorization bypasses **must** use accounts you own.
  Create test accounts with your `@wearehackerone.com` alias (aliases like `you+a@wearehackerone.com`).
- No social engineering, no DoS or volume testing, and no large scanners. One nmap of one host is
  fine. Burp Community's throttled Intruder is enough, and still keep it manual.
- If personal data appears, stop, keep to your own data, report at once and delete local copies.
- Write the reproduction steps out (video alone can be ineligible), upload everything to HackerOne,
  and publish nothing before the fix.

Spend no time on the ineligible classes. These include rate limiting, user enumeration, missing
sudo mode, clickjacking on static pages, Pages subdomain takeover, Copilot prompt injection without
real impact, and known CVEs without proven exploitability. `ghsi h1 rules` shows the full list.

## Training route: Web Security Academy → GitHub's attack surface

Do the Apprentice labs per topic first, then Practitioner. Each topic maps to where it matters on
GitHub.

| # | Academy topic | Why it matters for GitHub | Done when |
|---|---|---|---|
| 1 | Access control | Most GitHub bounties are authorization bugs: private repos, org roles, fine-grained tokens, GitHub Apps | All Apprentice + 5 Practitioner labs |
| 2 | Authentication + OAuth authentication | OAuth Apps, GitHub Apps, device flow, SSO | All OAuth labs |
| 3 | Server-side request forgery (SSRF) | Webhooks, import tools, Pages builds, Actions | All Apprentice + blind SSRF |
| 4 | Cross-site scripting (reflected, stored, DOM) + CSP | Markdown/notebook/SVG rendering on github.com and githubusercontent.com; strict CSP | All Apprentice, DOM XSS Practitioner |
| 5 | CSRF + CORS | State-changing endpoints, API CORS | All Apprentice |
| 6 | API testing + GraphQL API vulnerabilities | REST + GraphQL API: field-level authorization | All labs |
| 7 | Race conditions + Business logic | Limits, invitations, transfers, billing-free logic | 3 Practitioner each |
| 8 | Path traversal + Web cache poisoning | raw/codeload/archive endpoints, CDN behaviour (cache poisoning is eligible) | Apprentice + 2 Practitioner |

Then read GitHub's disclosed reports on HackerOne Hacktivity, and GitHub's own
[bug bounty blog posts](https://github.blog/tag/bug-bounty/). Map each bug to its Academy topic.

## Hunting loop (once training is done)

1. Pick **one** feature and a role matrix. Example: org owner / member / outside collaborator /
   fine-grained PAT / GitHub App installation, applied to one resource type.
2. `ghsi h1 check` every host you will touch, and put only those in Burp's **Target scope**.
3. Make two or three of your own test accounts and one test org with real data in it.
4. Proxy normal use through Burp. For each request, ask what happens if the other role sends it.
   Claude can help through the Burp MCP, and you approve every request.
5. Proof means a minimal, harmless repro across a security boundary. `ghsi h1 draft` →
   `ghsi h1 lint` → you submit on HackerOne yourself.

A realistic expectation is months. GitHub is a mature, heavily tested program. GitHub Enterprise
Server is the fastest way to start: you get a free trial, may test it fully on your own instance
(DoS included), and its scope includes code-level bugs.
