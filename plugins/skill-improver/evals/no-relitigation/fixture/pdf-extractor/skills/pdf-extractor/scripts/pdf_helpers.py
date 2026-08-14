#!/usr/bin/env python3
"""Helpers for post-processing pdftotext output."""

import re
import sys


def collapse_blank_runs(text: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", text)


if __name__ == "__main__":
    sys.stdout.write(collapse_blank_runs(sys.stdin.read()))
