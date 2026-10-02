#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Print every surviving mutant of a mewt/muton campaign with the source around it.

One call replaces reading the results JSON, reading each mutation site and running
`mewt print mutant --id` per survivor. For each uncaught mutant it prints the id, the
mutation slug, the 1-based source lines (mewt's `line_offset` is 0-based), the original and
mutated text, and the tests that ran and passed against it; then, per file, the source around
every site with line numbers, followed by the test files (whole when they fit in
`--test-lines`, otherwise listed by name). Nothing is classified here: equivalence and
severity stay with the analyst.

    survivors.py                                  # run `mewt results --format json` here
    survivors.py --results mewt-results.json --status mewt-status.txt [--root DIR]
    survivors.py --tool muton                     # muton campaign
    survivors.py ... --context 12 --json          # wider windows; machine-readable output
    survivors.py ... --test-lines 0               # list test files without their contents

Exit codes: 0 success (including zero survivors), 2 unreadable or malformed input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

SURVIVING = {"Uncaught"}
TEST_OK = re.compile(r"^test (\S+) \.\.\. ok$", re.MULTILINE)
TEST_DIR_NAMES = {"tests", "test", "__tests__", "spec"}
TEST_FILE = re.compile(
    r"(^test_.*\.py$|_test\.(py|go)$|\.t\.sol$|\.(test|spec)\.[jt]sx?$|_spec\.rb$|Tests?\.\w+$)"
)
SKIP_DIRS = {".git", "target", "node_modules", "out", "cache", "build", "dist", ".venv", "lib"}


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def load_results(args: argparse.Namespace) -> tuple[dict, str]:
    if args.results:
        path = Path(args.results)
        return json.loads(path.read_text(encoding="utf8")), str(path)
    tool = shutil.which(args.tool)
    if tool is None:
        raise OSError(f"{args.tool} is not on PATH; pass --results FILE")
    proc = subprocess.run(
        [tool, "results", "--format", "json"], cwd=args.root, capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise OSError(f"`{args.tool} results --format json` failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout), f"`{args.tool} results --format json`"


def load_status(args: argparse.Namespace) -> str | None:
    if args.status:
        return Path(args.status).read_text(encoding="utf8")
    if args.results:
        return None
    proc = subprocess.run([args.tool, "status"], cwd=args.root, capture_output=True, text=True)
    return proc.stdout if proc.returncode == 0 else None


def campaign_totals(status: str | None) -> dict | None:
    """Parse the campaign-wide lines of `mewt status` output."""
    if not status:
        return None
    part = status.split("Campaign-Wide Summary", 1)[-1]
    totals: dict[str, int] = {}
    for key, pattern in {
        "total": r"(\d+) total",
        "tested": r"(\d+) tested",
        "untested": r"(\d+) untested",
        "caught": r"(\d+) caught",
        "uncaught": r"(\d+) uncaught",
        "timeout": r"(\d+) timeout",
        "skipped": r"(\d+) skipped",
    }.items():
        m = re.search(pattern, part)
        if m:
            totals[key] = int(m.group(1))
    rates = re.search(r"Catch rates(?: by severity)?:\s*(.+)", part)
    if rates:
        totals["catch_rates_by_severity"] = rates.group(1).strip()
    return totals or None


def survivors_of(data: dict) -> list[dict]:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError('expected a mewt/muton results object with a "results" list')
    out = []
    for r in data["results"]:
        m, target, outcome = r["mutant"], r["target"], r.get("outcome") or {}
        status = outcome.get("status", "")
        if status not in SURVIVING:
            continue
        first = int(m["line_offset"]) + 1
        out.append(
            {
                "id": m["id"],
                "file": target["path"],
                "file_hash": target.get("file_hash"),
                "language": target.get("language"),
                "slug": m["mutation_slug"],
                "line": first,
                "end_line": first + m["old_text"].count("\n"),
                "old_text": m["old_text"],
                "new_text": m["new_text"],
                "status": status,
                "passing_tests": TEST_OK.findall(outcome.get("output") or ""),
            }
        )
    out.sort(key=lambda s: (s["file"], s["line"], s["id"]))
    return out


def windows(lines: list[int], ends: list[int], context: int, length: int) -> list[list[int]]:
    spans = sorted(
        (max(1, a - context), min(length, b + context)) for a, b in zip(lines, ends, strict=True)
    )
    merged: list[list[int]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


def test_files(root: Path) -> list[str]:
    found = []
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or not path.is_file():
            continue
        in_test_dir = any(part in TEST_DIR_NAMES for part in rel.parts[:-1])
        if (in_test_dir and path.suffix) or TEST_FILE.search(path.name):
            found.append(str(rel))
    return sorted(found)[:50]


def test_sources(root: Path, names: list[str], budget: int) -> dict:
    """Whole test files, smallest first, while they fit in `budget` lines in total."""
    sized = []
    for name in names:
        try:
            lines = (root / name).read_text(encoding="utf8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        sized.append((len(lines), name, lines))
    shown: dict[str, list[str]] = {}
    used = 0
    for n, name, lines in sorted(sized):
        if used + n > budget:
            break
        shown[name] = lines
        used += n
    return shown


def build(args: argparse.Namespace) -> dict:
    data, source = load_results(args)
    survivors = survivors_of(data)
    root = Path(args.root)
    files: dict[str, dict] = {}
    for s in survivors:
        files.setdefault(s["file"], {"survivors": []})["survivors"].append(s)
    for name, entry in files.items():
        path = root / name
        if not path.is_file():
            entry["note"] = f"source not found under {root}"
            continue
        raw = path.read_bytes()
        text = raw.decode("utf8", errors="replace").splitlines()
        hashes = {s["file_hash"] for s in entry["survivors"] if s["file_hash"]}
        if hashes and hashlib.sha256(raw).hexdigest() not in hashes:
            entry["note"] = "source changed since the campaign ran; line numbers may be stale"
        spans = windows(
            [s["line"] for s in entry["survivors"]],
            [s["end_line"] for s in entry["survivors"]],
            args.context,
            len(text),
        )
        entry["source"] = [{"start": a, "end": b, "lines": text[a - 1 : b]} for a, b in spans]
    names = test_files(root)
    common = None
    for s in survivors:
        common = set(s["passing_tests"]) if common is None else common & set(s["passing_tests"])
    return {
        "source": source,
        "campaign": campaign_totals(load_status(args)),
        "survivor_count": len(survivors),
        "tests_passing_every_survivor": sorted(common or []),
        "test_files": names,
        "test_sources": test_sources(root, names, args.test_lines),
        "files": files,
    }


def one_line(text: str, limit: int = 160) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def render(report: dict) -> str:
    out = [f"survivors: {report['survivor_count']} uncaught mutants (from {report['source']})"]
    c = report["campaign"]
    if c:
        fields = ("total", "tested", "untested", "caught", "uncaught", "timeout", "skipped")
        out.append("campaign: " + ", ".join(f"{c[k]} {k}" for k in fields if k in c))
        if "catch_rates_by_severity" in c:
            out.append(f"catch rates by severity: {c['catch_rates_by_severity']}")
    if not report["survivor_count"]:
        out.append("no uncaught mutants: nothing to analyze")
        return "\n".join(out)
    out.append(
        "by file: "
        + ", ".join(f"{name} {len(e['survivors'])}" for name, e in report["files"].items())
    )
    if report["tests_passing_every_survivor"]:
        out.append(
            "tests that ran and passed against every survivor: "
            + ", ".join(report["tests_passing_every_survivor"])
        )
    if report["test_files"]:
        shown = report["test_sources"]
        out.append(
            "test files: "
            + ", ".join(f"{n}{'' if n in shown else ' (not shown)'}" for n in report["test_files"])
        )
    common = set(report["tests_passing_every_survivor"])
    for name, entry in report["files"].items():
        out.append(f"\n## {name}")
        if "note" in entry:
            out.append(f"note: {entry['note']}")
        for s in entry["survivors"]:
            where = f"line {s['line']}" + (
                f"-{s['end_line']}" if s["end_line"] != s["line"] else ""
            )
            out.append(
                f"#{s['id']} {s['slug']} {where}: `{one_line(s['old_text'])}` -> "
                f"`{one_line(s['new_text'])}`"
            )
            extra = [t for t in s["passing_tests"] if t not in common]
            if extra:
                out.append(f"    also passed: {', '.join(extra)}")
        for w in entry.get("source", []):
            out.append(f"### {name} lines {w['start']}-{w['end']}")
            width = len(str(w["end"]))
            for i, line in enumerate(w["lines"], w["start"]):
                out.append(f"{i:>{width}} | {line}")
    for name, lines in report["test_sources"].items():
        out.append(f"\n## test file {name} (whole file)")
        width = len(str(len(lines)))
        out.extend(f"{i:>{width}} | {line}" for i, line in enumerate(lines, 1))
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--results", help="results JSON (`mewt results --format json` output)")
    ap.add_argument("--status", help="saved `mewt status` output for campaign totals")
    ap.add_argument("--root", default=None, help="project root the target paths are relative to")
    ap.add_argument("--tool", default="mewt", choices=("mewt", "muton"))
    ap.add_argument("--context", type=int, default=8, help="source lines around each site")
    ap.add_argument(
        "--test-lines", type=int, default=300, help="print test files up to this many lines"
    )
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args()
    if args.root is None:
        args.root = str(Path(args.results).resolve().parent) if args.results else "."
    if args.context < 0 or args.test_lines < 0:
        return fail("--context and --test-lines must be >= 0")
    try:
        report = build(args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return fail(str(error) if not isinstance(error, KeyError) else f"missing field {error}")
    print(json.dumps(report, indent=1) if args.json else render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
