import pytest

from ghsi import h1
from ghsi.h1 import ScopeEntry, check_target

LIVE_LIKE = [
    ScopeEntry("WILDCARD", "*.github.com", True, True, "critical"),
    ScopeEntry("URL", "github.com", True, True, "critical"),
    ScopeEntry("URL", "gist.github.com", True, True, "high"),
    ScopeEntry("URL", "status.github.com", False, False),
    ScopeEntry("WILDCARD", "*.githubusercontent.com", True, False),
    ScopeEntry("DOWNLOADABLE_EXECUTABLES", "GitHub CLI", True, True, "critical"),
]


@pytest.mark.parametrize("target,status", [
    ("https://github.com/settings/profile", "in-scope"),
    ("api.github.com", "in-scope"),
    ("https://gist.github.com/x", "in-scope"),
    ("https://status.github.com", "out-of-scope"),          # explicit out-of-scope entry beats the wildcard
    ("https://blog.github.com/2026", "out-of-scope"),        # bounty.github.com exclusion
    ("https://shop.github.com", "out-of-scope"),
    ("email.enterprise.github.com", "out-of-scope"),         # email* labels
    ("https://raw.githubusercontent.com/a/b", "in-scope"),
    ("https://evilgithub.com", "unknown"),                   # suffix trick must not match
    ("https://github.com.evil.io", "unknown"),
    ("https://140.82.112.3/", "unknown"),
    ("GitHub CLI", "in-scope"),
    ("Some Random App", "unknown"),
])
def test_check_target(target, status):
    assert check_target(target, LIVE_LIKE).status == status


def test_bounty_flag_in_reason():
    v = check_target("https://raw.githubusercontent.com/x", LIVE_LIKE)
    assert "no bounty" in v.reason and v.exit_code == 0
    assert check_target("https://evilgithub.com", LIVE_LIKE).exit_code == 2
    assert check_target("https://blog.github.com", LIVE_LIKE).exit_code == 1


def test_builtin_scope_covers_program_domains():
    b = h1.builtin_github_scope()
    assert check_target("https://registry.npmjs.org/x", b).status == "in-scope"
    assert check_target("https://example.com", b).status == "unknown"


def test_template_fails_lint_until_filled():
    draft = h1.REPORT_TEMPLATE.format(title="IDOR", asset="api.github.com", verdict="in-scope")
    msgs = [m for _, m in h1.lint_report(draft)]
    assert any("placeholders" in m for m in msgs)


GOOD = """# Private repo title leak via X

## Summary
Leak.

## Scope
- Asset: api.github.com

## Steps to reproduce
1. As account A, create private repo.
2. As account B, call the endpoint.
3. Observe the title.

## Impact
B learns private names.

## Test accounts
- alice-h1 (alice+a@wearehackerone.com), bob-h1
"""


def test_good_report_passes():
    assert [i for i in h1.lint_report(GOOD) if i[0] == "error"] == []


def test_lint_catches_secrets_media_and_pii():
    bad = GOOD + "\ntoken ghp_" + "a" * 36 + "\nvideo https://youtu.be/abc\ncontact victim@gmail.com\nsee https://blog.github.com/x\n"
    msgs = " ".join(m for _, m in h1.lint_report(bad))
    assert "GitHub token" in msgs and "off-site" in msgs and "victim@gmail.com" in msgs and "blog.github.com" in msgs


def test_lint_requires_written_steps():
    one_step = GOOD.replace("2. As account B, call the endpoint.\n3. Observe the title.\n", "")
    assert any("two written steps" in m for _, m in h1.lint_report(one_step))


def test_credentials_header_and_refusals(monkeypatch):
    c = h1.Credentials("me", "tok")
    assert c.header() == "Basic bWU6dG9r"
    with pytest.raises(h1.H1Error):
        h1.store_credentials(h1.Credentials('me"; rm', "tok"))
    with pytest.raises(h1.H1Error):
        h1.Client(c).get("https://evil.example/v1/hackers/me")


def test_env_credentials_win(monkeypatch):
    monkeypatch.setenv("HACKERONE_API_IDENTIFIER", "x")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "y")
    assert h1.load_credentials() == h1.Credentials("x", "y")
