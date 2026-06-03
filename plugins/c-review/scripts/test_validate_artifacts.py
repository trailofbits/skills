"""Regression tests for Phase 7 artifact validation."""

from __future__ import annotations

import json
from pathlib import Path

from validate_artifacts import (
    flatten_claimed_count_args,
    parse_args,
    parse_claimed_counts,
    validate_plan,
)


def _write_plan(tmp_path: Path) -> Path:
    plan = {
        "version": 1,
        "run": {"output_dir": str(tmp_path)},
        "workers": [
            {
                "worker_n": 1,
                "cluster_id": "buffer-write-sinks",
                "pass_prefixes": ["BOF", "UAF"],
                "pass_bug_classes": ["buffer-overflow", "use-after-free"],
            }
        ],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    (tmp_path / "findings").mkdir()
    (tmp_path / "findings-index.d").mkdir()
    (tmp_path / "coverage").mkdir()
    return plan_path


def _write_coverage(tmp_path: Path, rows: list[tuple[str, str, str]]) -> None:
    body = [
        "# Coverage gate - worker-1",
        "",
        "| Pass prefix | Bug class | Outcome |",
        "|-------------|-----------|---------|",
    ]
    body.extend(f"| {prefix} | {bug_class} | {outcome} |" for prefix, bug_class, outcome in rows)
    (tmp_path / "coverage" / "worker-1.md").write_text("\n".join(body) + "\n", encoding="utf-8")


def _touch_shard(tmp_path: Path, lines: list[str] | None = None) -> None:
    content = "" if lines is None else "\n".join(lines) + "\n"
    (tmp_path / "findings-index.d" / "worker-1.txt").write_text(content, encoding="utf-8")


def test_cli_accepts_grouped_claimed_counts(tmp_path: Path) -> None:
    args = parse_args(
        [
            str(tmp_path / "plan.json"),
            "--claimed-count",
            "worker-1=0",
            "worker-2=3",
        ]
    )

    counts = parse_claimed_counts(flatten_claimed_count_args(args.claimed_count))

    assert counts == {"worker-1": 0, "worker-2": 3}


def test_cli_accepts_repeated_claimed_count_flags(tmp_path: Path) -> None:
    args = parse_args(
        [
            str(tmp_path / "plan.json"),
            "--claimed-count",
            "worker-1=0",
            "--claimed-count",
            "worker-2=3",
        ]
    )

    counts = parse_claimed_counts(flatten_claimed_count_args(args.claimed_count))

    assert counts == {"worker-1": 0, "worker-2": 3}


def test_zero_finding_worker_with_cleared_coverage_passes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path)
    _touch_shard(tmp_path)
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "cleared (no unsafe writes)"),
            ("UAF", "use-after-free", "cleared (no free-after-use sites)"),
        ],
    )

    assert validate_plan(plan_path, workers=["worker-1"], claimed_counts={"worker-1": 0}) == []


def test_filed_finding_with_shard_and_coverage_passes(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path)
    finding = tmp_path / "findings" / "BOF-001.md"
    finding.write_text("---\nid: BOF-001\n---\n", encoding="utf-8")
    _touch_shard(tmp_path, [str(finding)])
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "filed: BOF-001"),
            ("UAF", "use-after-free", "cleared (no free-after-use sites)"),
        ],
    )

    assert validate_plan(plan_path, workers=["1"], claimed_counts={"worker-1": 1}) == []


def test_missing_shard_fails(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path)
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "cleared"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("missing shard" in error for error in errors)


def test_missing_coverage_file_fails(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path)
    _touch_shard(tmp_path)

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("missing coverage file" in error for error in errors)


def test_coverage_missing_assigned_pass_fails(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path)
    _touch_shard(tmp_path)
    _write_coverage(tmp_path, [("BOF", "buffer-overflow", "cleared")])

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("missing coverage row for UAF / use-after-free" in error for error in errors)


def test_skipped_coverage_outcome_fails(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path)
    _touch_shard(tmp_path)
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "skipped: no obvious bugs"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("invalid coverage outcome for BOF" in error for error in errors)


def test_filed_id_absent_from_shard_or_disk_fails(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path)
    _touch_shard(tmp_path)
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "filed: BOF-001"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("filed ID BOF-001 is absent from shard" in error for error in errors)


def test_claimed_count_mismatch_fails(tmp_path: Path) -> None:
    plan_path = _write_plan(tmp_path)
    finding = tmp_path / "findings" / "BOF-001.md"
    finding.write_text("---\nid: BOF-001\n---\n", encoding="utf-8")
    _touch_shard(tmp_path, [str(finding)])
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "filed: BOF-001"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"], claimed_counts={"worker-1": 0})

    assert any("claimed 0 finding files but shard has 1 entries" in error for error in errors)
