import pytest

from ghsi.checks import check_advisory
from ghsi.sources import PackageInfo
from ghsi.versions import parse_range, pep440_key, satisfies, semver_key


def adv(*vulns, ghsa="GHSA-test-test-test"):
    return {"ghsa_id": ghsa, "vulnerabilities": [
        {"package": {"ecosystem": e, "name": n}, "vulnerable_version_range": r, "first_patched_version": p}
        for e, n, r, p in vulns]}


def pkg(eco, name, versions, unavailable=()):
    return {(eco, name): PackageInfo(eco, name, f"https://example/{name}", list(versions), set(unavailable))}


def checks(findings):
    return sorted(f.check for f in findings)


# --- version ordering -------------------------------------------------------

@pytest.mark.parametrize("lo,hi", [
    ("1.0.0-alpha", "1.0.0-alpha.1"),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
    ("1.0.0-beta.2", "1.0.0-beta.11"),
    ("1.0.0-rc.1", "1.0.0"),
    ("1.9.9", "1.10.0"),
])
def test_semver_precedence(lo, hi):
    assert semver_key(lo) < semver_key(hi)


def test_semver_rejects_non_semver():
    assert semver_key("1.2") is None and semver_key("latest") is None


def test_pep440_normalises():
    assert pep440_key("1.0") == pep440_key("1.0.0")


def test_range_satisfies():
    r = parse_range(">= 1.0.0, < 1.4.2")
    assert satisfies(semver_key, "1.4.1", r) is True
    assert satisfies(semver_key, "1.4.2", r) is False
    assert satisfies(semver_key, "0.9.0", r) is False


# --- checks -----------------------------------------------------------------

def test_clean_advisory_has_no_findings():
    a = adv(("npm", "x", "< 1.2.0", "1.2.0"))
    assert check_advisory(a, pkg("npm", "x", ["1.0.0", "1.1.0", "1.2.0", "1.3.0"])) == []


def test_patch_not_published():
    a = adv(("npm", "x", "< 1.2.0", "1.2.0"))
    f = check_advisory(a, pkg("npm", "x", ["1.1.0", "1.2.1"]))
    assert checks(f) == ["patch_not_published"]
    assert f[0].evidence["nearest_after"] == "1.2.1"


def test_patch_inside_range():
    a = adv(("pip", "x", "<= 2.0", "2.0"))
    assert "patch_inside_range" in checks(check_advisory(a, pkg("pip", "x", ["1.0", "2.0"])))


def test_unclassified_versions_between_range_and_patch():
    a = adv(("pip", "x", "<= 2.10", "3.0.2"))
    f = check_advisory(a, pkg("pip", "x", ["2.9", "2.10", "3.0", "3.0.1", "3.0.2"]))
    assert checks(f) == ["unclassified_versions"]
    assert f[0].evidence["versions"] == ["3.0", "3.0.1"]


def test_yanked_releases_are_not_a_gap():
    # soupsieve GHSA-6655-6qjp-jx7x: 3.0 and 3.0.1 contain the fix but were yanked,
    # so curators point at 3.0.2 on purpose. That's not an error.
    a = adv(("pip", "x", "<= 2.10", "3.0.2"))
    f = check_advisory(a, pkg("pip", "x", ["2.10", "3.0", "3.0.1", "3.0.2"], unavailable=["3.0", "3.0.1"]))
    assert f == []


def test_sibling_branch_ranges_are_not_a_gap():
    a = adv(("npm", "x", "< 1.2.5", "1.2.5"), ("npm", "x", ">= 2.0.0, < 2.1.3", "2.1.3"))
    published = ["1.2.4", "1.2.5", "1.3.0", "2.0.0", "2.1.2", "2.1.3"]
    assert check_advisory(a, pkg("npm", "x", published)) == []


def test_prereleases_ignored_in_gap():
    a = adv(("npm", "x", "< 1.0.0", "1.0.1"))
    assert check_advisory(a, pkg("npm", "x", ["0.9.0", "1.0.0-rc.1", "1.0.1"])) == []


def test_package_not_found():
    a = adv(("npm", "nope", "< 1.0.0", "1.0.0"))
    assert checks(check_advisory(a, {("npm", "nope"): None})) == ["package_not_found"]


def test_no_patch_but_newer_releases_is_low_confidence():
    a = adv(("npm", "x", "<= 1.0.0", None))
    f = check_advisory(a, pkg("npm", "x", ["1.0.0", "1.0.1", "2.0.0-beta.1"]))
    assert checks(f) == ["no_patch_but_newer_releases"]
    assert f[0].confidence == "low" and f[0].evidence["newer"] == ["1.0.1"]


def test_unparseable_range():
    a = adv(("npm", "x", "~1.2", "1.3.0"))
    assert checks(check_advisory(a, pkg("npm", "x", ["1.3.0"]))) == ["range_unparseable"]


def test_other_ecosystems_skipped():
    a = adv(("maven", "g:a", "< 1.0", "1.0"))
    assert check_advisory(a, {}) == []
