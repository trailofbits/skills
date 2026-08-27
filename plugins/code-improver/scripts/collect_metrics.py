#!/usr/bin/env python3
"""Produce metrics.json for a code-improver run from its ledger and git state.

Reads the run's ledger.json (written by /code-improver:improve), plus optionally the
repository and the per-round diff artifacts, and writes the machine-countable metrics
the eval and ablation suites compare:

    rounds_used, fix_rounds, converged, capped, escalated, halted,
    ended_on_unreviewed_fix, refiled_after_verdict,
    max_consecutive_rounds_same_finding, open_blocking, open_minor,
    fixer_failed_rounds, out_of_scope_diff_bytes, narration_hits_final,
    version_bumps, subagent_tokens

A collector that inspects zero items fails rather than passes: a missing or empty
ledger, a ledger without a result block, or a --scope that matches no file under the
repository are all hard errors (exit 2), never a metrics.json full of zeros.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

BLOCKING = {"critical", "major"}

# Mirrors the finalize phase's narration grep. Kept in one place per language so a
# pattern added there must be added here, where the eval graders read the count.
NARRATION_PATTERNS = [
    re.compile(r"\b(round|iteration|pass) [0-9]\b", re.IGNORECASE),
    re.compile(r"previous(ly)? (fix|attempt|version|round)", re.IGNORECASE),
    re.compile(r"(was|were) (added|moved|changed|renamed|removed) (here|to|from)", re.IGNORECASE),
    re.compile(r"per (the )?(review|reviewer|finding)", re.IGNORECASE),
]

VERSION_LINE = re.compile(r'^\+.*"version"\s*:\s*"([^"]+)"', re.MULTILINE)

SKIP_DIRS = {".git", ".code-improver", ".skill-improver", "node_modules", "__pycache__"}


def fail(msg: str) -> NoReturn:
    print(f"collect_metrics.py: {msg}", file=sys.stderr)
    sys.exit(2)


def glob_to_regex(glob: str) -> re.Pattern:
    """`**` crosses directories, `*` does not, everything else is literal."""
    esc = re.escape(glob).replace(r"\*\*", "\x01").replace(r"\*", "[^/]*").replace("\x01", ".*")
    return re.compile(f"^{esc}$")


def in_scope(rel: str, regexes: list[re.Pattern]) -> bool:
    return any(r.match(rel) for r in regexes)


def max_consecutive(rounds_seen: list[int]) -> int:
    u = sorted(set(rounds_seen))
    best = run = 1 if u else 0
    for prev, cur in zip(u, u[1:], strict=False):
        run = run + 1 if cur == prev + 1 else 1
        best = max(best, run)
    return best


def git(repo: Path, *argv: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *argv], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        fail(f"git {' '.join(argv)} failed: {proc.stderr.strip()}")
    return proc.stdout


def scope_files(repo: Path, regexes: list[re.Pattern]) -> list[Path]:
    found = []
    for path in sorted(repo.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(repo).as_posix()
        if any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        if in_scope(rel, regexes):
            found.append(path)
    return found


def narration_hits(files: list[Path]) -> int:
    hits = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: not a narration carrier
        for pattern in NARRATION_PATTERNS:
            hits += len(pattern.findall(text))
    return hits


def out_of_scope_diff_bytes(repo: Path, baseline_sha: str, regexes: list[re.Pattern]) -> int:
    names = git(repo, "diff", "--name-only", baseline_sha).splitlines()
    changed = [line for line in names if line]
    total = 0
    for rel in changed:
        if in_scope(rel, regexes):
            continue
        total += len(git(repo, "diff", baseline_sha, "--", rel).encode("utf-8"))
    return total


def version_bumps(diff_dir: Path | None, repo: Path | None, baseline_sha: str | None) -> int | None:
    """Count how many times the plugin version VALUE changed across the loop.

    The round diffs are cumulative (each is `git diff <baseline>`), so each one shows the
    version the tree held after that round: a `+"version"` line names it, no such line
    means the round left it at the baseline. Adjacent changes in that sequence are the
    bump count — a bump applied and reverted counts twice, which is the churn the metric
    exists to expose.
    """
    sequence: list[str] = ["BASELINE"]
    saw_input = False

    if diff_dir is not None:

        def round_number(p: Path) -> int:
            m = re.search(r"(\d+)", p.stem)
            return int(m.group(1)) if m else 0

        diffs = sorted(diff_dir.glob("fixes-round-*.diff"), key=round_number)
        for diff in diffs:
            saw_input = True
            matches = VERSION_LINE.findall(diff.read_text(encoding="utf-8", errors="replace"))
            sequence.append(matches[-1] if matches else "BASELINE")

    if repo is not None and baseline_sha:
        saw_input = True
        matches = VERSION_LINE.findall(git(repo, "diff", baseline_sha))
        sequence.append(matches[-1] if matches else "BASELINE")

    if not saw_input:
        return None
    return sum(1 for prev, cur in zip(sequence, sequence[1:], strict=False) if prev != cur)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, help="path to the run's ledger.json")
    parser.add_argument("--out", required=True, help="where to write metrics.json")
    parser.add_argument("--repo", help="repository root, enables git-derived metrics")
    parser.add_argument("--baseline-sha", help="the run's baseline commit")
    parser.add_argument("--diff-dir", help="directory holding fixes-round-N.diff artifacts")
    parser.add_argument(
        "--scope", action="append", default=[], help="repo-relative scope glob (repeatable)"
    )
    parser.add_argument("--tokens", type=int, help="output tokens the run spent, if known")
    args = parser.parse_args()

    ledger_path = Path(args.ledger)
    if not ledger_path.is_file():
        fail(f"ledger not found at {ledger_path} — a run that produced no ledger has no metrics")
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"ledger at {ledger_path} is not valid JSON: {exc}")

    rounds = ledger.get("rounds") or []
    if not rounds:
        fail("ledger has zero rounds — a run that did nothing must not score as clean")
    result = ledger.get("result")
    if not isinstance(result, dict):
        fail("ledger has no result block — the run never reached an exit, so its metrics would lie")
    findings = ledger.get("findings") or {}

    review_rounds = [r for r in rounds if r.get("type") == "review"]
    fix_rounds = [r for r in rounds if r.get("type") == "fix"]

    metrics = {
        "rounds_used": len(review_rounds),
        "fix_rounds": len(fix_rounds),
        "converged": bool(result.get("converged")),
        "capped": bool(result.get("capped")),
        "escalated": bool(result.get("escalation")),
        "escalation_type": (result.get("escalation") or {}).get("type", ""),
        "halted": result.get("halted", ""),
        "ended_on_unreviewed_fix": bool(rounds) and rounds[-1].get("type") == "fix",
        "refiled_after_verdict": sum(
            int(f.get("refiled_after_verdict") or 0) for f in findings.values()
        ),
        "max_consecutive_rounds_same_finding": max(
            (max_consecutive(f.get("rounds_seen") or []) for f in findings.values()), default=0
        ),
        "open_blocking": sum(
            1
            for f in findings.values()
            if f.get("status") == "open" and f.get("severity") in BLOCKING
        ),
        "open_minor": sum(
            1
            for f in findings.values()
            if f.get("status") == "open" and f.get("severity") not in BLOCKING
        ),
        "fixer_failed_rounds": sum(1 for r in fix_rounds if r.get("failed")),
        "out_of_scope_diff_bytes": None,
        "narration_hits_final": None,
        "version_bumps": None,
        "subagent_tokens": args.tokens,
    }

    repo = Path(args.repo) if args.repo else None
    if repo is not None and not repo.is_dir():
        fail(f"--repo {repo} is not a directory")

    scope_regexes = [glob_to_regex(g) for g in args.scope]
    if args.scope:
        if repo is None:
            fail("--scope needs --repo to resolve files against")
        files = scope_files(repo, scope_regexes)
        if not files:
            fail(f"scope {args.scope} matched zero files under {repo} — nothing was inspected")
        metrics["narration_hits_final"] = narration_hits(files)
        if args.baseline_sha:
            metrics["out_of_scope_diff_bytes"] = out_of_scope_diff_bytes(
                repo, args.baseline_sha, scope_regexes
            )

    metrics["version_bumps"] = version_bumps(
        Path(args.diff_dir) if args.diff_dir else None, repo, args.baseline_sha
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
