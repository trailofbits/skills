#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Convert extracted C string literals to portable dictionary byte escapes."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

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
            # Input is decoded as latin-1 solely to preserve each original source byte.
            result.extend(character.encode("latin-1"))
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, help="extract ordinary byte literals from C/C++ source"
    )
    parser.add_argument(
        "--byte-lines", action="store_true", help="quote raw strings/man tokens from stdin"
    )
    parser.add_argument("--backend", choices=("libfuzzer", "afl++"), default="libfuzzer")
    args = parser.parse_args()
    limit = 64 if args.backend == "libfuzzer" else 128
    entries = set()
    problems = []
    try:
        data = args.source.read_bytes() if args.source else sys.stdin.buffer.read()
    except OSError as error:
        print(f"cannot read source: {error}", file=sys.stderr)
        return 1
    text = data.decode("latin-1")
    if args.source:
        # This is a candidate extractor, not a preprocessor. Skip comments and character
        # constants so their quotes cannot be mistaken for byte strings.
        token = re.compile(
            r"//[^\n]*|/\*.*?\*/|\'(?:[^\'\\]|\\.)*\'"
            r'|(?P<raw>(?:u8|[uUL])?R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})\(.*?\)(?P=delimiter)")'
            r'|(?P<string>(?:u8|[uUL])?"(?:[^"\\\r\n]|\\.)*")'
            r'|(?P<bad>"[^\r\n]*)',
            re.DOTALL,
        )
        candidates = []
        for match in token.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            if match.lastgroup in ("raw", "bad"):
                problems.append(
                    f"line {line}: unsupported raw or unterminated literal; inspect source"
                )
            elif match.lastgroup == "string":
                candidates.append((line, match.group()))
    else:
        candidates = list(enumerate(text.split("\n"), 1))
    for line, raw in candidates:
        if not raw:
            continue
        try:
            if args.byte_lines:
                value = raw.encode("latin-1")
            else:
                raw = raw.rstrip("\r")
                if not raw.startswith('"') or not raw.endswith('"'):
                    raise ValueError("unsupported prefixed or malformed C literal")
                value = decode_literal(raw)
            if len(value) > limit:
                problems.append(
                    f"line {line}: {len(value)} bytes exceeds {args.backend} limit {limit}; "
                    f"candidate {quote(value)}"
                )
            elif value:
                entries.add(quote(value))
        except (ValueError, IndexError) as error:
            problems.append(f"line {line}: {error}")
    for problem in problems:
        # Comments survive output redirection; a nonzero status prevents treating this
        # partial extraction as a complete validated dictionary.
        print(f"# PARTIAL: {problem}")
    if problems:
        print(f"partial extraction: {len(problems)} source item(s) require review", file=sys.stderr)
    if not entries:
        print("no nonempty string literals found", file=sys.stderr)
        return 1
    print("\n".join(sorted(entries)))
    return 2 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
