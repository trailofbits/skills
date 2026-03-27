#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Deduplicate TOON-formatted C/C++ security findings.

Reads aggregated TOON findings from multiple workers and removes
duplicates based on location (file:line). When multiple bug-finders
flag the same source line, they are reporting the same underlying code
issue — the first finder's report wins, the rest are dropped.

Usage:
    uv run dedup_findings.py <findings_file> [--details <details_file>]

    findings_file:  File with concatenated findings[N]{...}: blocks (- for stdin)
    details_file:   File with concatenated detail TOON (tabular or nested)

    stdout: Deduplicated TOON (findings + filtered details + stats)
    exit 0 on success, 1 on error
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys

FINDINGS_HEADER_RE = re.compile(r"^findings\[\d+\]\{([^}]+)\}:\s*$")
TABULAR_HEADER_RE = re.compile(r"^(\w+)\[\d+\]\{([^}]+)\}:\s*$")
NESTED_ID_RE = re.compile(r"^\s+id:\s+(.+)$")


def parse_findings_blocks(text: str) -> tuple[list[str], list[dict[str, str]]]:
    """Parse all findings[N]{...}: blocks from concatenated TOON text.

    Returns (headers, rows) where each row is a dict keyed by header name.
    """
    all_rows: list[dict[str, str]] = []
    headers: list[str] = []
    current_headers: list[str] | None = None

    for line in text.splitlines():
        m = FINDINGS_HEADER_RE.match(line.strip())
        if m:
            current_headers = [h.strip() for h in m.group(1).split(",")]
            if not headers:
                headers = current_headers
            continue

        if current_headers and line.startswith(" ") and line.strip():
            reader = csv.reader(io.StringIO(line.strip()))
            for values in reader:
                if len(values) >= len(current_headers):
                    pairs = zip(current_headers, values[: len(current_headers)], strict=False)
                    all_rows.append(dict(pairs))
                break

        # Empty or non-data line — don't reset current_headers here because
        # some workers may emit blank lines between rows within the same block.
        # We reset only when a new header line is found.

    return headers, all_rows


def parse_tabular_detail_blocks(
    text: str,
) -> dict[str, tuple[list[str], list[dict[str, str]]]]:
    """Parse non-findings tabular blocks (details, data_flows, etc.).

    Returns {block_name: (headers, [row_dicts])}.
    """
    blocks: dict[str, tuple[list[str], list[dict[str, str]]]] = {}
    current_name: str = ""
    current_headers: list[str] | None = None

    for line in text.splitlines():
        m = TABULAR_HEADER_RE.match(line.strip())
        if m and m.group(1) != "findings":
            current_name = m.group(1)
            current_headers = [h.strip() for h in m.group(2).split(",")]
            if current_name not in blocks:
                blocks[current_name] = (current_headers, [])
            continue

        if current_name and current_headers and line.startswith(" ") and line.strip():
            reader = csv.reader(io.StringIO(line.strip()))
            for values in reader:
                if len(values) >= len(current_headers):
                    row = dict(zip(current_headers, values[: len(current_headers)], strict=False))
                    blocks[current_name][1].append(row)
                break

    return blocks


def parse_nested_finding_blocks(text: str) -> list[tuple[str, str]]:
    """Parse nested finding: blocks, returning (id, full_block_text) pairs."""
    results: list[tuple[str, str]] = []
    current_lines: list[str] = []
    current_id: str | None = None
    in_finding = False

    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "finding:":
            # Flush previous block
            if in_finding and current_id:
                results.append((current_id, "\n".join(current_lines)))
            current_lines = [line]
            current_id = None
            in_finding = True
            continue

        if in_finding:
            current_lines.append(line)
            m = NESTED_ID_RE.match(line)
            if m:
                current_id = m.group(1).strip()

    # Flush last block
    if in_finding and current_id:
        results.append((current_id, "\n".join(current_lines)))

    return results


def deduplicate(
    rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], set[str]]:
    """Deduplicate findings by location (file:line).

    When multiple finders flag the same source line, they are reporting the
    same underlying code issue (e.g., buffer-overflow-finder, string-issues-finder,
    and banned-functions-finder all flag the same strcpy call). The first finder's
    report wins; the rest are dropped as duplicates.

    Returns (unique_rows, kept_ids).
    """
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    kept_ids: set[str] = set()

    for row in rows:
        key = row.get("location", "")
        if key not in seen:
            seen.add(key)
            unique.append(row)
            kept_ids.add(row.get("id", ""))

    return unique, kept_ids


def format_toon_table(
    block_name: str,
    rows: list[dict[str, str]],
    headers: list[str],
) -> str:
    """Format rows back to a TOON tabular block."""
    out = io.StringIO()
    out.write(f"{block_name}[{len(rows)}]{{{','.join(headers)}}}:\n")

    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    for row in rows:
        csv_buf.seek(0)
        csv_buf.truncate()
        writer.writerow([row.get(h, "") for h in headers])
        out.write(f" {csv_buf.getvalue().strip()}\n")

    return out.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description="Deduplicate TOON-formatted findings")
    parser.add_argument(
        "findings_file",
        help="File with findings TOON (use - for stdin)",
    )
    parser.add_argument(
        "--details",
        help="File with detail TOON (tabular or nested) to filter",
    )
    args = parser.parse_args()

    # --- Read findings ---
    if args.findings_file == "-":
        findings_text = sys.stdin.read()
    else:
        try:
            with open(args.findings_file) as f:
                findings_text = f.read()
        except FileNotFoundError:
            print(f"Error: findings file not found: {args.findings_file}", file=sys.stderr)
            return 1

    # --- Parse and deduplicate ---
    headers, rows = parse_findings_blocks(findings_text)
    if not headers:
        headers = ["id", "bug_class", "title", "location", "function", "confidence"]

    original_count = len(rows)
    unique, kept_ids = deduplicate(rows)
    removed = original_count - len(unique)

    # --- Output deduplicated findings ---
    print(format_toon_table("findings", unique, headers))

    # --- Filter and output details if provided ---
    if args.details:
        try:
            with open(args.details) as f:
                details_text = f.read()
        except FileNotFoundError:
            print(f"Error: details file not found: {args.details}", file=sys.stderr)
            return 1

        # Try tabular format first (details[N]{...}:, data_flows[N]{...}:)
        tabular_blocks = parse_tabular_detail_blocks(details_text)
        if tabular_blocks:
            for block_name, (block_headers, block_rows) in tabular_blocks.items():
                filtered = [r for r in block_rows if r.get("id", "") in kept_ids]
                if filtered:
                    print(format_toon_table(block_name, filtered, block_headers))

        # Also handle nested finding: blocks
        nested = parse_nested_finding_blocks(details_text)
        if nested:
            filtered_nested = [block_text for fid, block_text in nested if fid in kept_ids]
            if filtered_nested:
                print("\n".join(filtered_nested))
                print()

    # --- Stats (also to stdout as TOON for the coordinator) ---
    print("dedup_stats:")
    print(f"  original_count: {original_count}")
    print(f"  after_dedup: {len(unique)}")
    print(f"  duplicates_removed: {removed}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
