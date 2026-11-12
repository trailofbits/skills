"""Read Psalm's own version banner without guessing a version from a filename."""

from __future__ import annotations

import re


def psalm_version(output: str) -> tuple[int, int, int] | None:
    match = re.search(r"(?m)^Psalm (\d+)\.(\d+)\.(\d+)(?=[@+\s-]|$)", output)
    return tuple(map(int, match.groups())) if match else None


def psalm_major(output: str) -> int | None:
    version = psalm_version(output)
    return version[0] if version is not None else None
