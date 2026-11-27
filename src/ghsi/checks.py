"""Consistency checks between an advisory's version data and what the registry actually published.

Every check is a pure function of (advisory, registry data) so it can be tested offline.
A finding is a *lead*, never a verdict: the curation team only accepts changes backed by
primary sources (release notes, fix commits, changelogs), and a human must find those.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

from .sources import PackageInfo
from .versions import KEYS, Range, RangeError, is_prerelease, parse_range, satisfies

# confidence: how often this pattern turned out to be a real, fixable error when checked by hand
HIGH, MEDIUM, LOW = "high", "medium", "low"


@dataclass
class Finding:
    ghsa_id: str
    ecosystem: str
    package: str
    check: str
    confidence: str
    message: str
    vulnerable_version_range: str
    first_patched_version: Optional[str]
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _norm(key_fn: Callable, versions: list[str]) -> dict:
    out = {}
    for v in versions:
        k = key_fn(v)
        if k is not None:
            out[k] = v
    return out


def check_advisory(adv: dict, packages: dict[tuple[str, str], Optional[PackageInfo]]) -> list[Finding]:
    findings: list[Finding] = []
    vulns = adv.get("vulnerabilities") or []
    ghsa = adv["ghsa_id"]

    # Parse every entry first so cross-entry checks (gaps) can see sibling ranges of the same package.
    parsed: list[tuple[dict, Optional[Range]]] = []
    for v in vulns:
        raw = v.get("vulnerable_version_range") or ""
        try:
            parsed.append((v, parse_range(raw) if raw else None))
        except RangeError:
            parsed.append((v, None))

    for v, rng in parsed:
        eco = v["package"]["ecosystem"]
        name = v["package"]["name"]
        key_fn = KEYS.get(eco)
        if key_fn is None:
            continue
        fp = v.get("first_patched_version")
        raw = v.get("vulnerable_version_range") or ""

        def mk(check: str, conf: str, msg: str, **ev) -> Finding:
            return Finding(ghsa, eco, name, check, conf, msg, raw, fp, ev)

        if rng is None:
            findings.append(mk("range_unparseable", MEDIUM, f"Vulnerable range {raw!r} is empty or not valid GHSA syntax."))
            continue

        pkg = packages.get((eco, name))
        if pkg is None:
            findings.append(mk("package_not_found", HIGH, f"{eco} registry has no package named {name!r}."))
            continue

        published = _norm(key_fn, pkg.versions)
        unavailable = {key_fn(u) for u in pkg.unavailable}

        if fp:
            fpk = key_fn(fp)
            if fpk is None:
                findings.append(mk("patch_unparseable", MEDIUM, f"First patched version {fp!r} is not a valid {eco} version."))
            else:
                if fpk not in published:
                    findings.append(mk(
                        "patch_not_published", HIGH,
                        f"First patched version {fp} was never published to the {eco} registry.",
                        registry=pkg.url, nearest_after=_nearest_after(fpk, published),
                    ))
                elif fpk in unavailable:
                    findings.append(mk(
                        "patch_yanked", MEDIUM,
                        f"First patched version {fp} is yanked or has no files on PyPI.",
                        registry=pkg.url,
                    ))
                if satisfies(key_fn, fp, rng):
                    findings.append(mk(
                        "patch_inside_range", HIGH,
                        f"First patched version {fp} is itself inside the vulnerable range {raw!r}.",
                    ))
                # Yanked releases are excluded: curators deliberately point users at the first
                # installable fix (e.g. soupsieve 3.0/3.0.1 yanked → first patched 3.0.2).
                installable = {k: raw for k, raw in published.items() if k not in unavailable}
                gap = _gap_versions(key_fn, fpk, rng, installable, [r for vv, r in parsed
                                    if r is not None and vv["package"]["name"] == name])
                if gap:
                    findings.append(mk(
                        "unclassified_versions", MEDIUM,
                        f"{len(gap)} published release(s) sit between the vulnerable range and the patch "
                        f"and are marked neither vulnerable nor patched: {', '.join(gap[:5])}"
                        + ("…" if len(gap) > 5 else ""),
                        versions=gap, registry=pkg.url,
                    ))
        else:
            up = rng.upper
            if up and up.op in ("<=", "=") and key_fn(up.version) is not None:
                upk = key_fn(up.version)
                if upk not in published:
                    findings.append(mk(
                        "range_bound_not_published", MEDIUM,
                        f"Inclusive upper bound {up.version} was never published; the range may name the wrong version.",
                        registry=pkg.url,
                    ))
                newer = sorted((k for k in published if k > upk and not is_prerelease(k)))
                if newer:
                    findings.append(mk(
                        "no_patch_but_newer_releases", LOW,
                        f"No patched version is listed, yet {len(newer)} stable release(s) after {up.version} exist "
                        f"(latest {published[newer[-1]]}). Either a fix shipped or the range needs extending.",
                        newer=[published[k] for k in newer[:10]], registry=pkg.url,
                    ))
    return findings


def _nearest_after(fpk, published: dict) -> Optional[str]:
    after = sorted(k for k in published if k > fpk)
    return published[after[0]] if after else None


def _gap_versions(key_fn, fpk, rng: Range, published: dict, sibling_ranges: list[Range]) -> list[str]:
    """Stable releases below the patch, above this entry's lower bound, covered by no range of this package."""
    low = rng.lower
    lowk = key_fn(low.version) if low else None
    out = []
    for k, raw in sorted(published.items()):
        if k >= fpk or is_prerelease(k):
            continue
        if lowk is not None and (k < lowk or (low.op == ">" and k == lowk)):
            continue
        if any(satisfies(key_fn, raw, r) for r in sibling_ranges):
            continue
        out.append(raw)
    return out
