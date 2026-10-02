#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Query a full `llvm-cov export` JSON file without reading it into the conversation.

    coverage-query.py --json coverage.json totals
    coverage-query.py --json coverage.json files
    coverage-query.py --json coverage.json functions [--uncovered-first] [--only-uncovered]
                      [--file REGEX] [--name REGEX] [--limit N]
    coverage-query.py --json coverage.json uncovered-lines --file REGEX [--context N]
    coverage-query.py --json coverage.json branches --file REGEX [--only-untaken]

`functions` lists every function (not a top-N) unless --limit is given; `uncovered-lines`
prints the source lines with zero execution count for one file, with their line numbers, so a
gate or dead branch can be cited as file:line; `branches` prints branch regions and their
true/false counts where the compiler recorded them. Output is plain text, one item per line.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not data.get("data"):
        sys.exit("coverage-query.py: export has no data records")
    return data["data"][0]


def pct(covered: int, count: int) -> str:
    return f"{(covered / count * 100):6.2f}%" if count else "   n/a "


def cmd_totals(export: dict, _args) -> None:
    t = export["totals"]
    for key in ("lines", "functions", "regions", "branches"):
        if key in t:
            s = t[key]
            print(f"{key:9s} {s['covered']:6d} / {s['count']:6d}  {pct(s['covered'], s['count'])}")


def cmd_files(export: dict, _args) -> None:
    for f in sorted(export["files"], key=lambda x: x["filename"]):
        s = f["summary"]
        ln, fn = s["lines"], s["functions"]
        print(
            f"{f['filename']}  lines {ln['covered']}/{ln['count']} "
            f"{pct(ln['covered'], ln['count'])}"
            f"  functions {fn['covered']}/{fn['count']}"
        )


def function_rows(export: dict, args) -> list[tuple]:
    rows = []
    file_re = re.compile(args.file) if getattr(args, "file", None) else None
    name_re = re.compile(args.name) if getattr(args, "name", None) else None
    # llvm-cov export applies -ignore-filename-regex to `files` but not to `functions`; keep the
    # function list consistent with the reported files.
    reported = {f["filename"] for f in export["files"]}
    for fn in export["functions"]:
        filename = fn["filenames"][0] if fn.get("filenames") else "?"
        if filename not in reported:
            continue
        if file_re and not file_re.search(filename):
            continue
        if name_re and not name_re.search(fn["name"]):
            continue
        regions = fn.get("regions", [])
        # region: [line_start, col_start, line_end, col_end, count, file_id, expanded_file_id, kind]
        total = len(regions)
        covered = sum(1 for r in regions if r[4] > 0)
        first_line = min((r[0] for r in regions), default=0)
        rows.append((fn["count"], covered, total, filename, first_line, fn["name"]))
    return rows


def cmd_functions(export: dict, args) -> None:
    rows = function_rows(export, args)
    if args.only_uncovered:
        rows = [r for r in rows if r[0] == 0]
    if args.uncovered_first:
        rows.sort(key=lambda r: (r[0] > 0, (r[1] / r[2]) if r[2] else 1.0, r[3], r[4]))
    else:
        rows.sort(key=lambda r: (r[3], r[4]))
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("(no functions matched)")
        return
    for count, covered, total, filename, line, name in rows:
        state = "NEVER RUN" if count == 0 else f"regions {covered}/{total}"
        print(f"{filename}:{line}  {name}  calls={count}  {state}")


def cmd_uncovered_lines(export: dict, args) -> None:
    file_re = re.compile(args.file)
    matched = [f for f in export["files"] if file_re.search(f["filename"])]
    if not matched:
        sys.exit(f"coverage-query.py: no file matches {args.file!r}")
    for f in matched:
        path = Path(f["filename"])
        source = (
            path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
        )
        zero_lines: set[int] = set()
        for seg in f.get("segments", []):
            # segment: [line, col, count, has_count, is_region_entry, is_gap_region]
            if seg[3] and seg[4] and seg[2] == 0 and not (len(seg) > 5 and seg[5]):
                zero_lines.add(seg[0])
        if not zero_lines:
            print(f"{f['filename']}: every instrumented region executed")
            continue
        print(f"{f['filename']}: {len(zero_lines)} region start(s) never executed")
        for line in sorted(zero_lines):
            for ctx in range(max(1, line - args.context), line + args.context + 1):
                text = source[ctx - 1] if 0 < ctx <= len(source) else ""
                marker = ">>" if ctx == line else "  "
                print(f"  {marker} {f['filename']}:{ctx}: {text}")
            if args.context:
                print()


def cmd_branches(export: dict, args) -> None:
    file_re = re.compile(args.file)
    shown = 0
    for f in export["files"]:
        if not file_re.search(f["filename"]):
            continue
        for b in f.get("branches", []):
            # branch: [line_start, col_start, line_end, col_end, true_count, false_count,
            #          file_id, expanded_file_id, kind]
            if args.only_untaken and b[4] > 0 and b[5] > 0:
                continue
            print(f"{f['filename']}:{b[0]}:{b[1]}  true={b[4]}  false={b[5]}")
            shown += 1
    if shown == 0:
        print("(no branch records matched; the build may not record branches)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--json", required=True, type=Path, help="llvm-cov export JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("totals")
    sub.add_parser("files")
    p = sub.add_parser("functions")
    p.add_argument("--uncovered-first", action="store_true")
    p.add_argument("--only-uncovered", action="store_true")
    p.add_argument("--file")
    p.add_argument("--name")
    p.add_argument("--limit", type=int, default=0)
    p = sub.add_parser("uncovered-lines")
    p.add_argument("--file", required=True)
    p.add_argument("--context", type=int, default=0)
    p = sub.add_parser("branches")
    p.add_argument("--file", required=True)
    p.add_argument("--only-untaken", action="store_true")
    args = parser.parse_args(argv)
    if not args.json.is_file():
        sys.exit(f"coverage-query.py: {args.json} not found")
    try:
        export = load(args.json)
    except json.JSONDecodeError as exc:
        sys.exit(f"coverage-query.py: {args.json} is not valid llvm-cov export JSON: {exc}")
    {
        "totals": cmd_totals,
        "files": cmd_files,
        "functions": cmd_functions,
        "uncovered-lines": cmd_uncovered_lines,
        "branches": cmd_branches,
    }[args.command](export, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
