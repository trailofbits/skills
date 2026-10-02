#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Validate common libFuzzer/AFL++ dictionary syntax without a fuzzer binary."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Conservative shared grammar, including AFL dictionary levels and numeric labels.
ENTRY = re.compile(r'^(?:[A-Za-z0-9_]+(?:@[0-9]+)?\s*=\s*)?"((?:[^"\\]|\\.)*)"$')
MAX_BYTES = {"libfuzzer": 64, "afl++": 128}


def decode_entry(value: str) -> bytes:
    """Decode the common dictionary escapes, tracking escaped backslashes."""
    if not value:
        raise ValueError("empty dictionary entry")
    result = bytearray()
    position = 0
    while position < len(value):
        character = value[position]
        if character == "\\":
            escape = value[position + 1 : position + 2]
            if escape in ("\\", '"'):
                result.append(ord(escape))
                position += 2
                continue
            if escape == "x" and re.fullmatch(
                r"[0-9A-Fa-f]{2}", value[position + 2 : position + 4]
            ):
                result.append(int(value[position + 2 : position + 4], 16))
                position += 4
                continue
            raise ValueError("invalid escape; use \\xHH for non-printable bytes")
        if not 32 <= ord(character) <= 126:
            raise ValueError("non-printable or non-ASCII byte; use \\xHH")
        result.append(ord(character))
        position += 1
    return bytes(result)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("dictionary", type=Path)
    parser.add_argument("--backend", choices=MAX_BYTES, default="libfuzzer")
    parser.add_argument("--min-entries", type=int, default=0)
    parser.add_argument("--max-entries", type=int, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    entries: list[bytes] = []
    errors: list[str] = []
    first_seen: dict[bytes, int] = {}
    if args.min_entries < 0 or (
        args.max_entries is not None and args.max_entries < args.min_entries
    ):
        print("invalid entry limits", file=sys.stderr)
        return 2
    try:
        contents = args.dictionary.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"cannot read dictionary: {error}", file=sys.stderr)
        return 1
    for line_number, raw in enumerate(contents.split("\n"), start=1):
        line = raw.strip()
        if line.startswith("# PARTIAL:"):
            errors.append(f"line {line_number}: unresolved partial extraction; review source")
        if not line or line.startswith("#"):
            continue
        match = ENTRY.fullmatch(line)
        if not match:
            errors.append(f"line {line_number}: invalid dictionary syntax")
            continue
        try:
            entry = decode_entry(match.group(1))
            if len(entry) > MAX_BYTES[args.backend]:
                raise ValueError(
                    f"{len(entry)} bytes exceeds {args.backend}'s "
                    f"{MAX_BYTES[args.backend]}-byte token limit"
                )
            if entry in first_seen:
                errors.append(f"line {line_number} duplicates line {first_seen[entry]}")
            else:
                first_seen[entry] = line_number
            entries.append(entry)
        except ValueError as error:
            errors.append(f"line {line_number}: {error}")
    if not entries:
        errors.append("dictionary contains no valid entries")
    if len(entries) < args.min_entries:
        errors.append(f"{len(entries)} entries; need at least {args.min_entries}")
    if args.max_entries is not None and len(entries) > args.max_entries:
        errors.append(f"{len(entries)} entries; maximum is {args.max_entries}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"valid dictionary: {len(entries)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
