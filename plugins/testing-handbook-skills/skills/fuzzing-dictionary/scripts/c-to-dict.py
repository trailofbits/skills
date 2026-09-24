#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Convert extracted C string literals to portable dictionary byte escapes."""

from __future__ import annotations

import re
import sys

ESCAPES = {
    "a": 7,
    "b": 8,
    "f": 12,
    "n": 10,
    "r": 13,
    "t": 9,
    "v": 11,
    "\\": 92,
    '"': 34,
    "'": 39,
    "?": 63,
}


def decode_literal(literal: str) -> bytes:
    value = literal[1:-1]
    result = bytearray()
    position = 0
    while position < len(value):
        character = value[position]
        if character != "\\":
            result.extend(character.encode("utf-8"))
            position += 1
            continue
        position += 1
        escape = value[position]
        if escape in ESCAPES:
            result.append(ESCAPES[escape])
            position += 1
            continue
        pattern = r"x([0-9A-Fa-f]+)" if escape == "x" else r"([0-7]{1,3})"
        match = re.match(pattern, value[position:])
        if not match:
            raise ValueError(f"unsupported C escape: \\{escape}")
        number = int(match.group(1), 16 if escape == "x" else 8)
        if number > 255:
            raise ValueError("C byte escape exceeds 255")
        result.append(number)
        position += len(match.group(0))
    return bytes(result)


def quote(value: bytes) -> str:
    pieces = []
    for byte in value:
        if byte in (34, 92):
            pieces.append("\\" + chr(byte))
        elif 32 <= byte <= 126:
            pieces.append(chr(byte))
        else:
            pieces.append(f"\\x{byte:02X}")
    return '"' + "".join(pieces) + '"'


def main() -> int:
    entries = set()
    try:
        for raw in sys.stdin:
            value = decode_literal(raw.rstrip("\r\n"))
            if value:
                entries.add(quote(value))
    except (ValueError, IndexError) as error:
        print(f"cannot convert source literal: {error}", file=sys.stderr)
        return 1
    if not entries:
        print("no nonempty string literals found", file=sys.stderr)
        return 1
    print("\n".join(sorted(entries)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
