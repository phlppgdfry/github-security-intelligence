from ghsi.fixcheck import check_fix_in_release, fix_commits, tag_candidates

SHA = "a" * 40
SHA2 = "b" * 40


def adv(fp="1.2.3", refs=None, name="pkg"):
    return {"ghsa_id": "GHSA-x", "references": refs if refs is not None else [f"https://github.com/o/r/commit/{SHA}"],
            "vulnerabilities": [{"package": {"ecosystem": "npm", "name": name}, "first_patched_version": fp,
                                 "vulnerable_version_range": f"< {fp}"}]}


def fake(statuses):
    """statuses: {(sha, tag): status}; anything else -> missing ref."""
    return lambda o, r, base, head: statuses.get((base, head))


def test_extracts_commit_refs_only():
    a = adv(refs=["https://github.com/o/r/pull/1", f"https://github.com/o/r/commit/{SHA}", "https://nvd.nist.gov/x"])
    assert fix_commits(a) == [("o", "r", SHA)]


def test_tag_candidates_cover_monorepo_styles():
    c = tag_candidates("@scope/pkg", "1.0.0")
    assert {"v1.0.0", "1.0.0", "@scope/pkg@1.0.0", "pkg@1.0.0", "pkg-v1.0.0"} <= set(c)


def test_fix_in_release_is_fine():
    assert check_fix_in_release(adv(), fake({(SHA, "v1.2.3"): "ahead"})) == []


def test_release_predates_fix_is_high():
    f = check_fix_in_release(adv(), fake({(SHA, "v1.2.3"): "behind"}))
    assert [(x.confidence, x.status, x.tag) for x in f] == [("high", "behind", "v1.2.3")]


def test_falls_back_to_unprefixed_tag():
    f = check_fix_in_release(adv(), fake({(SHA, "1.2.3"): "behind"}))
    assert f[0].tag == "1.2.3"


def test_diverged_is_medium():
    f = check_fix_in_release(adv(), fake({(SHA, "v1.2.3"): "diverged"}))
    assert f[0].confidence == "medium"


def test_one_shipped_commit_clears_followups():
    a = adv(refs=[f"https://github.com/o/r/commit/{SHA}", f"https://github.com/o/r/commit/{SHA2}"])
    assert check_fix_in_release(a, fake({(SHA, "v1.2.3"): "ahead", (SHA2, "v1.2.3"): "behind"})) == []


def test_no_tag_found_no_finding():
    assert check_fix_in_release(adv(), fake({})) == []


def test_no_patch_or_no_commit_skipped():
    assert check_fix_in_release(adv(fp=None), fake({})) == []
    assert check_fix_in_release(adv(refs=[]), fake({})) == []
