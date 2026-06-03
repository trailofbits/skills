#!/usr/bin/env python3
"""Validate Phase 7 worker artifacts against plan.json."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

FINDING_ID_RE = re.compile(r"\b[A-Z][A-Z0-9_]*-\d{3,}\b")


def normalize_worker_id(value: str) -> str:
    if value.startswith("worker-"):
        suffix = value.removeprefix("worker-")
    else:
        suffix = value
    if not suffix.isdigit():
        raise ValueError(f"invalid worker id: {value!r}")
    return f"worker-{int(suffix)}"


def flatten_claimed_count_args(values: list[list[str]]) -> list[str]:
    return [value for group in values for value in group]


def parse_claimed_counts(values: list[str]) -> dict[str, int]:
    claimed: dict[str, int] = {}
    for value in values:
        worker, sep, count = value.partition("=")
        if not sep:
            raise ValueError(f"invalid --claimed-count {value!r}; expected worker-N=N")
        worker_id = normalize_worker_id(worker)
        try:
            claimed_count = int(count)
        except ValueError as exc:
            raise ValueError(f"invalid claimed count for {worker_id}: {count!r}") from exc
        if claimed_count < 0:
            raise ValueError(f"invalid claimed count for {worker_id}: {claimed_count}")
        claimed[worker_id] = claimed_count
    return claimed


def _output_dir(plan: dict[str, Any], plan_path: Path) -> Path:
    configured = plan.get("run", {}).get("output_dir")
    if configured:
        return Path(configured)
    return plan_path.parent


def _worker_map(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    workers: dict[str, dict[str, Any]] = {}
    for worker in plan.get("workers", []):
        worker_id = normalize_worker_id(str(worker["worker_n"]))
        workers[worker_id] = worker
    return workers


def _read_shard(shard_path: Path, output_dir: Path) -> tuple[list[Path], dict[str, Path]]:
    paths: list[Path] = []
    ids: dict[str, Path] = {}
    for line in shard_path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        path = Path(raw)
        if not path.is_absolute():
            path = output_dir / path
        paths.append(path)
        ids[path.stem] = path
    return paths, ids


def _is_separator(cells: list[str]) -> bool:
    return all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def _parse_coverage_rows(coverage_path: Path) -> tuple[dict[tuple[str, str], str], list[str]]:
    rows: dict[tuple[str, str], str] = {}
    errors: list[str] = []

    for line_no, raw in enumerate(coverage_path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 3:
            continue
        if cells[0].lower() == "pass prefix" or _is_separator(cells):
            continue
        key = (cells[0], cells[1])
        if key in rows:
            errors.append(
                f"{coverage_path}: duplicate coverage row for {cells[0]} / {cells[1]} "
                f"at line {line_no}"
            )
        rows[key] = cells[2]

    return rows, errors


def _valid_cleared(outcome: str) -> bool:
    lowered = outcome.lower()
    return lowered == "cleared" or lowered.startswith("cleared ") or lowered.startswith("cleared(")


def _validate_worker(
    *,
    worker_id: str,
    worker: dict[str, Any],
    output_dir: Path,
    claimed_counts: dict[str, int],
) -> list[str]:
    errors: list[str] = []
    worker_n = int(worker_id.removeprefix("worker-"))
    shard_path = output_dir / "findings-index.d" / f"worker-{worker_n}.txt"
    coverage_path = output_dir / "coverage" / f"worker-{worker_n}.md"

    shard_paths: list[Path] = []
    shard_ids: dict[str, Path] = {}
    if not shard_path.is_file():
        errors.append(f"{worker_id}: missing shard {shard_path}")
    else:
        shard_paths, shard_ids = _read_shard(shard_path, output_dir)
        for path in shard_paths:
            if not path.is_file():
                errors.append(f"{worker_id}: shard references missing finding file {path}")

    if worker_id in claimed_counts and claimed_counts[worker_id] != len(shard_paths):
        errors.append(
            f"{worker_id}: claimed {claimed_counts[worker_id]} finding files but shard has "
            f"{len(shard_paths)} entries"
        )

    if not coverage_path.is_file():
        errors.append(f"{worker_id}: missing coverage file {coverage_path}")
        return errors

    coverage_rows, coverage_errors = _parse_coverage_rows(coverage_path)
    errors.extend(f"{worker_id}: {error}" for error in coverage_errors)

    declared_ids: set[str] = set()
    pass_prefixes = worker.get("pass_prefixes", [])
    bug_classes = worker.get("pass_bug_classes", [])
    for prefix, bug_class in zip(pass_prefixes, bug_classes, strict=True):
        outcome = coverage_rows.get((prefix, bug_class))
        if outcome is None:
            errors.append(f"{worker_id}: missing coverage row for {prefix} / {bug_class}")
            continue

        lowered = outcome.lower()
        if lowered.startswith("filed:"):
            finding_ids = FINDING_ID_RE.findall(outcome)
            if not finding_ids:
                errors.append(f"{worker_id}: filed outcome for {prefix} has no finding IDs")
                continue
            for finding_id in finding_ids:
                declared_ids.add(finding_id)
                if not finding_id.startswith(f"{prefix}-"):
                    errors.append(
                        f"{worker_id}: filed ID {finding_id} does not match pass prefix {prefix}"
                    )
                path = shard_ids.get(finding_id)
                if path is None:
                    errors.append(f"{worker_id}: filed ID {finding_id} is absent from shard")
                elif not path.is_file():
                    errors.append(f"{worker_id}: filed ID {finding_id} points to missing {path}")
        elif _valid_cleared(outcome):
            continue
        else:
            errors.append(f"{worker_id}: invalid coverage outcome for {prefix}: {outcome}")

    extra_ids = sorted(set(shard_ids) - declared_ids)
    for finding_id in extra_ids:
        errors.append(f"{worker_id}: shard ID {finding_id} is not declared in coverage")

    return errors


def validate_plan(
    plan_path: Path,
    *,
    workers: list[str] | None = None,
    claimed_counts: dict[str, int] | None = None,
) -> list[str]:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    output_dir = _output_dir(plan, plan_path)
    worker_by_id = _worker_map(plan)
    claimed_counts = claimed_counts or {}

    if workers is None:
        selected = sorted(worker_by_id)
    else:
        selected = [normalize_worker_id(worker) for worker in workers]

    errors: list[str] = []
    for worker_id in selected:
        worker = worker_by_id.get(worker_id)
        if worker is None:
            errors.append(f"{worker_id}: not present in {plan_path}")
            continue
        errors.extend(
            _validate_worker(
                worker_id=worker_id,
                worker=worker,
                output_dir=output_dir,
                claimed_counts=claimed_counts,
            )
        )
    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate review worker shards and coverage artifacts against plan.json."
    )
    parser.add_argument("plan_json", type=Path)
    parser.add_argument(
        "--worker",
        action="append",
        help="Worker to validate (worker-N or N). Repeat to validate multiple workers.",
    )
    parser.add_argument(
        "--claimed-count",
        action="append",
        nargs="+",
        default=[],
        metavar="worker-N=N",
        help=(
            "Expected finding count parsed from worker complete lines. Repeat the flag or "
            "pass multiple worker-N=N values after one flag."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        claimed_counts = parse_claimed_counts(flatten_claimed_count_args(args.claimed_count))
        errors = validate_plan(
            args.plan_json,
            workers=args.worker,
            claimed_counts=claimed_counts,
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"validate_artifacts: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    worker_label = "all workers" if args.worker is None else ", ".join(args.worker)
    print(f"validate_artifacts: OK ({worker_label})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
