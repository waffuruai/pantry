"""Ecosystem-agnostic version ordering, good enough to pick a fixed version.

OSV does the authoritative "is this version affected" matching server side;
this only orders candidate fixed versions and compares app versions to the
latest ones, so it favours being predictable over being exact."""

from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def key(version: str) -> tuple:
    """Sort key: numbers compare numerically, a pre-release word (rc, beta)
    sorts before the release it precedes, and build metadata is ignored."""
    v = version.strip()
    v = re.sub(r"^(v|version-|release-|r)(?=\d)", "", v, flags=re.I)
    v = v.split("+", 1)[0]
    if re.match(r"^\d+:", v):  # dpkg epoch
        v = v.split(":", 1)[1]
    out = []
    for t in _TOKEN.findall(v):
        out.append((2, int(t), "") if t.isdigit() else (0, 0, t.lower()))
    out.append((1, 0, ""))
    return tuple(out)


def lt(a: str, b: str) -> bool:
    return key(a) < key(b)


def numbers(version: str) -> list:
    return [int(n) for n in re.findall(r"\d+", version.split("+", 1)[0])]


def common_prefix(a: str, b: str) -> int:
    n = 0
    for x, y in zip(numbers(a), numbers(b)):
        if x != y:
            break
        n += 1
    return n


def pick_safe(installed: str, candidates) -> str | None:
    """The fixed version to recommend: newer than installed, on the closest
    release line (most leading numbers in common), lowest on that line."""
    newer = [c for c in set(candidates) if c and lt(installed, c)]
    if not newer:
        return None
    return sorted(newer, key=lambda c: (-common_prefix(installed, c), key(c)))[0]


def same_or_newer(installed: str, latest: str) -> bool:
    """True when installed is at least latest. Compares only as many numbers
    as both carry, so app version "2026.1" equals catalog "2026.1.0"."""
    a, b = numbers(installed), numbers(latest)
    n = min(len(a), len(b))
    if n == 0:
        return True
    return a[:n] >= b[:n]
