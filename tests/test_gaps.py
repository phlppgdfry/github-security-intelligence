from ghsi.checks import HIGH, MEDIUM, Finding
from ghsi.gaps import verify_gap

ADV = {"ghsa_id": "GHSA-test", "references": [
    "https://github.com/o/r/commit/aaaaaaa", "https://github.com/o/r/commit/bbbbbbb"]}


def lead(versions=("11.13.0", "11.15.0")):
    return Finding("GHSA-test", "npm", "music-metadata", "unclassified_versions", MEDIUM, "gap",
                   "<= 11.12.3", "11.16.0", {"versions": list(versions)})


def fake(table):
    """table[(sha, tag)] = status; tags absent from the table don't exist."""
    return lambda owner, repo, sha, tag: table.get((sha, tag))


def test_gap_without_fix_becomes_high():
    t = {(s, f"v{v}"): ("ahead" if v == "11.16.0" else "behind") for s in ("aaaaaaa", "bbbbbbb")
         for v in ("11.13.0", "11.15.0", "11.16.0")}
    f = verify_gap(lead(), ADV, fake(t))
    assert f.confidence == HIGH and "< 11.16.0" in f.message
    assert f.evidence["gap_contains_fix"] == {"11.13.0": False, "11.15.0": False}


def test_cherry_pick_on_release_branch_counts():
    # dev commit diverged from both tags, release-branch cherry-pick only in the patch (Home Assistant case)
    t = {("aaaaaaa", "v11.13.0"): "diverged", ("aaaaaaa", "v11.16.0"): "diverged",
         ("bbbbbbb", "v11.13.0"): "diverged", ("bbbbbbb", "v11.16.0"): "ahead"}
    assert verify_gap(lead(["11.13.0"]), ADV, fake(t)).confidence == HIGH


def test_gap_that_already_has_the_fix_stays_medium():
    t = {("aaaaaaa", "v11.13.0"): "ahead", ("aaaaaaa", "v11.16.0"): "ahead"}
    f = verify_gap(lead(["11.13.0"]), ADV, fake(t))
    assert f.confidence == MEDIUM and f.evidence["gap_contains_fix"] == {"11.13.0": True}


def test_no_tags_or_no_commits_is_left_alone():
    assert verify_gap(lead(), ADV, fake({})).confidence == MEDIUM
    assert verify_gap(lead(), {"ghsa_id": "GHSA-test", "references": []}, fake({})).confidence == MEDIUM
