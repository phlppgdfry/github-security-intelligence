"""GitHub Security Bug Bounty: rules, scope and rewards as data.

Read from bounty.github.com on 2026-11-28 (rules, scope, targets, rewards, ineligible). The live
HackerOne structured scope (`ghsi h1 scope --refresh`) always wins over this copy; this file is the
offline fallback and the source for the checklist. Re-read the pages before every new target.
"""
from __future__ import annotations

READ_ON = "2026-11-28"
PROGRAM_HANDLE = "github"
PROGRAM_URL = "https://hackerone.com/github"
SOURCES = {
    "rules": "https://bounty.github.com/rules",
    "scope": "https://bounty.github.com/scope",
    "targets": "https://bounty.github.com/targets",
    "rewards": "https://bounty.github.com/rewards",
    "ineligible": "https://bounty.github.com/ineligible",
    "safe_harbor": "https://docs.github.com/site-policy/security-policies/github-bug-bounty-program-legal-safe-harbor",
}

IN_SCOPE_DOMAINS = [
    "github.com", "githubassets.com", "githubusercontent.com", "githubapp.com",
    "githubwebhooks.net", "github.net", "npmjs.com", "npmjs.org",
]

# Subdomain labels the scope page excludes (third-party operated or mail infrastructure).
# A trailing * means "any label starting with this".
OUT_OF_SCOPE_HOST_PREFIXES = [
    "blog", "community", "resources", "shop", "smtp", "sgmail", "mcmail", "livesend", "email*",
    "atom-io", "atom-io-staging", "reply",
]

IN_SCOPE_PRODUCTS = [
    "GitHub CLI", "GitHub Desktop", "GitHub Copilot App", "GitHub Mobile", "npm CLI",
    "GitHub Enterprise Server", "GitHub Enterprise Cloud",
]

TARGETS = [
    "GitHub.com", "GitHub API", "GitHub CSP", "GitHub Actions", "GitHub Pages", "GitHub Gist",
    "GitHub Enterprise Server", "GitHub Enterprise Cloud", "Dependabot", "GitHub Desktop", "GitHub Mobile",
    "GitHub CLI", "GitHub Copilot App", "GitHub Codespaces", "GitHub Copilot", "GitHub Education",
    "*.githubapp.com", "*.github.net", "*.githubusercontent.com", "GitHub Credentials", "npm Registry", "npm CLI",
]

REWARDS = [  # (severity, public program, private program); guidelines, not guarantees
    ("critical", "$10,000+", "$30,000+"),
    ("high", "$5,000", "$20,000"),
    ("medium", "$2,000", "$7,500"),
    ("low", "$250", "$1,000"),
    ("defense in depth", "swag", "swag"),
]

# The checklist `ghsi h1 rules` prints. Each line is something you can answer yes/no before testing.
BEFORE_YOU_TEST = [
    "The target passes `ghsi h1 check` (in scope, not a third-party subdomain).",
    "Every account, organization and repository I touch is my own (authorization bypass: own accounts only).",
    "My GitHub test accounts use my @wearehackerone.com alias (recommended by GitHub).",
    "No social engineering, phishing or physical attacks; no testing of other users' repos or orgs.",
    "No DDoS, volumetric tests, spam or large scanners. One nmap of one host is fine; 65k Burp Intruder requests in 2 min is not.",
    "DoS research only on my own GitHub Enterprise Server trial, or in repos/orgs I own; stop at the first sign of impact.",
    "If personal data shows up: stop, limit to my own data, report at once, delete every local copy.",
    "I am not (and was not in the last 6 months) a GitHub employee or contractor, and nobody like that helps me.",
]

WHEN_YOU_REPORT = [
    "Written reproduction steps (video alone can make the report ineligible).",
    "All material uploaded to HackerOne itself: no YouTube, pastebin or external file links.",
    "PII redacted in text and screenshots.",
    "Usernames and IP addresses used during testing listed (GitHub may ask for them).",
    "No public disclosure until a fix is public; write-ups allowed after, GitHub may ask to delay.",
    "If you can't accept money, say so in the report (a payout can't be taken back).",
]

INELIGIBLE_HIGHLIGHTS = [
    "Lack of rate limiting; email/username enumeration; missing sudo mode; timing attacks.",
    "Host header injection without impact; Unicode homoglyph phishing; profile-name impersonation.",
    "Clickjacking on static sites; issues needing local access, MITM or the victim following attacker instructions.",
    "Vulnerable upstream dependencies or known CVEs without demonstrated exploitability (30+ days after disclosure).",
    "Public OAuth client secrets in desktop/mobile apps (unless chained into account access).",
    "Content still cached after deletion; cache purging/eviction (cache poisoning IS eligible).",
    "Secret gist URLs; public repo data or metadata via the API; Actions step-to-step movement within one job.",
    "Dependabot code execution without a sandbox escape; vulnerabilities in packages themselves.",
    "Copilot: insecure code suggestions (copilot-safety@github.com), prompt injection without concrete impact.",
    "GitHub Pages subdomain takeover / custom domains; npm malicious packages (report to npm support).",
    "Typosquatting; open-source repositories; assets GitHub doesn't own.",
]

CONTACTS = {
    "questions": "bounty@github.com",
    "not a bounty issue (billing, npm malware, subdomain reclaim)": "https://support.github.com/request",
    "Copilot suggestion patterns": "copilot-safety@github.com",
    "abuse and phishing": "https://github.com/contact/report-abuse",
}
