"""Version parsing and GHSA range evaluation for npm (semver) and pip (PEP 440).

GHSA ranges use one syntax for every ecosystem: comma-separated constraints such
as ">= 1.0.0, < 1.4.2" or "= 2.0.0". Only the ordering of versions differs per
ecosystem, so each ecosystem supplies a key function and the range logic is shared.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@dataclass(frozen=True, order=True)
class SemverKey:
    major: int
    minor: int
    patch: int
    # A release sorts after its prereleases: (1,) > (0, ...)
    pre: tuple

    @property
    def is_prerelease(self) -> bool:
        return self.pre[0] == 0


def semver_key(raw: str) -> Optional[SemverKey]:
    m = _SEMVER.match(raw.strip())
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    if pre is None:
        pre_key: tuple = (1,)
    else:
        # semver 2.0 §11: numeric identifiers < alphanumeric ones, compared field by field
        parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
        pre_key = (0, parts)
    return SemverKey(int(major), int(minor), int(patch), pre_key)


def pep440_key(raw: str) -> Optional[Version]:
    try:
        return Version(raw.strip())
    except InvalidVersion:
        return None


KEYS: dict[str, Callable[[str], object]] = {"npm": semver_key, "pip": pep440_key}


def is_prerelease(key: object) -> bool:
    if isinstance(key, SemverKey):
        return key.is_prerelease
    if isinstance(key, Version):
        return key.is_prerelease or key.is_devrelease
    return False


_CONSTRAINT = re.compile(r"^\s*(<=|>=|<|>|=)\s*(\S+)\s*$")


@dataclass(frozen=True)
class Constraint:
    op: str
    version: str


@dataclass(frozen=True)
class Range:
    raw: str
    constraints: tuple[Constraint, ...]

    @property
    def upper(self) -> Optional[Constraint]:
        ups = [c for c in self.constraints if c.op in ("<", "<=", "=")]
        return ups[0] if len(ups) == 1 else None

    @property
    def lower(self) -> Optional[Constraint]:
        lows = [c for c in self.constraints if c.op in (">", ">=", "=")]
        return lows[0] if len(lows) == 1 else None


class RangeError(ValueError):
    pass


def parse_range(raw: str) -> Range:
    parts = [p for p in raw.split(",") if p.strip()]
    if not parts:
        raise RangeError(f"empty range: {raw!r}")
    out = []
    for p in parts:
        m = _CONSTRAINT.match(p)
        if not m:
            raise RangeError(f"unparseable constraint {p!r} in {raw!r}")
        out.append(Constraint(m.group(1), m.group(2)))
    return Range(raw, tuple(out))


def satisfies(key_fn: Callable[[str], object], version: str, rng: Range) -> Optional[bool]:
    """True/False if decidable, None if a version in the range can't be parsed."""
    v = key_fn(version)
    if v is None:
        return None
    for c in rng.constraints:
        b = key_fn(c.version)
        if b is None:
            return None
        ok = {
            "<": v < b,
            "<=": v <= b,
            ">": v > b,
            ">=": v >= b,
            "=": v == b,
        }[c.op]
        if not ok:
            return False
    return True
