"""Are the releases between a vulnerable range and its patch really unfixed?

`unclassified_versions` flags releases that sit between the range and the first patched version.
Usually that's because the range was written when the report came in ("last known affected") and
the maintainer shipped more releases before the fix. If none of those releases contains a fix
commit while the patched release does, they're vulnerable and get no alert: the range should end
at the patch. Four real corrections came from exactly this (github/advisory-database#12019–#12022).

Ancestry only: a release counts as fixed when at least one referenced fix commit is in its tag
(a cherry-pick on a release branch is a different SHA, so list it if the advisory does). A human
still confirms with the code at the tag or the published artifact before submitting.
"""
from __future__ import annotations

from typing import Optional

from .checks import HIGH, Finding
from .fixcheck import Compare, fix_commits, tag_candidates

FIXED = ("ahead", "identical")


def _contains_fix(compare: Compare, commits, package: str, version: str) -> Optional[bool]:
    """True/False if some tag for this version exists in a fix commit's repo; None if no tag was found."""
    seen_tag = False
    for owner, repo, sha in commits:
        for cand in tag_candidates(package, version):
            status = compare(owner, repo, sha, cand)
            if status is None:
                continue
            seen_tag = True
            if status in FIXED:
                return True
            break
    return False if seen_tag else None


def verify_gap(finding: Finding, adv: dict, compare: Compare) -> Finding:
    """Upgrade an `unclassified_versions` lead to high when git shows the gap releases lack the fix."""
    if finding.check != "unclassified_versions" or not finding.first_patched_version:
        return finding
    commits = fix_commits(adv)
    if not commits:
        return finding
    patched = _contains_fix(compare, commits, finding.package, finding.first_patched_version)
    gap = {v: _contains_fix(compare, commits, finding.package, v) for v in finding.evidence.get("versions", [])}
    checked = {v: r for v, r in gap.items() if r is not None}
    finding.evidence["gap_contains_fix"] = gap
    finding.evidence["patched_contains_fix"] = patched
    if patched and checked and not any(checked.values()):
        finding.confidence = HIGH
        finding.message += (f". Git: no fix commit is in {', '.join(checked)}; {finding.first_patched_version} has one, "
                            f"so the range should end at < {finding.first_patched_version}.")
    return finding
