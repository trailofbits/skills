"""Regression tests for Phase 7 artifact validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from validate_artifacts import (
    flatten_claimed_count_args,
    normalize_worker_id,
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
                "cluster_id": "memory-safety",
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
            ("BOF", "buffer-overflow", "cleared (no unsafe indexing)"),
            ("UAF", "use-after-free", "cleared (no raw pointer frees)"),
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
            ("UAF", "use-after-free", "cleared (no raw pointer frees)"),
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


def test_shard_id_undeclared_in_coverage_fails(tmp_path: Path) -> None:
    """A finding on disk/shard that no coverage row declares (filed under a
    `cleared` row instead) is a misfiling the Phase-7 gate must catch."""
    plan_path = _write_plan(tmp_path)
    finding = tmp_path / "findings" / "BOF-001.md"
    finding.write_text("---\nid: BOF-001\n---\n", encoding="utf-8")
    _touch_shard(tmp_path, [str(finding)])
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "cleared (seed returned empty)"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("shard ID BOF-001 is not declared in coverage" in error for error in errors)


def test_filed_id_prefix_mismatch_fails(tmp_path: Path) -> None:
    """A finding id filed under the wrong pass row (prefix mismatch) is rejected."""
    plan_path = _write_plan(tmp_path)
    finding = tmp_path / "findings" / "UAF-001.md"
    finding.write_text("---\nid: UAF-001\n---\n", encoding="utf-8")
    _touch_shard(tmp_path, [str(finding)])
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "filed: UAF-001"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("filed ID UAF-001 does not match pass prefix BOF" in error for error in errors)


def test_worker_absent_from_plan_fails(tmp_path: Path) -> None:
    """Validating a worker id that plan.json never declared is surfaced, not
    silently passed."""
    plan_path = _write_plan(tmp_path)

    errors = validate_plan(plan_path, workers=["worker-9"])

    assert any("worker-9: not present in" in error for error in errors)


def test_normalize_worker_id_rejects_non_numeric() -> None:
    with pytest.raises(ValueError, match="invalid worker id"):
        normalize_worker_id("worker-abc")


def test_frontmatter_id_mismatch_fails(tmp_path: Path) -> None:
    """A finding file whose frontmatter id disagrees with its filename (e.g.
    BOF-001.md carrying id: UAF-999) must be rejected — Phase 7 otherwise keys on
    the stem while the judges/SARIF trust the frontmatter."""
    plan_path = _write_plan(tmp_path)
    finding = tmp_path / "findings" / "BOF-001.md"
    finding.write_text("---\nid: UAF-999\nbug_class: use-after-free\n---\n", encoding="utf-8")
    _touch_shard(tmp_path, [str(finding)])
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "filed: BOF-001"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("frontmatter id 'UAF-999' does not match" in error for error in errors)


def test_shard_path_outside_findings_fails(tmp_path: Path) -> None:
    """A shard that lists a finding file outside output_dir/findings is rejected —
    Phase 7's canonical index only scans findings/, so an outside file would pass
    validation but never reach the report."""
    plan_path = _write_plan(tmp_path)
    outside = tmp_path / "BOF-001.md"  # NOT under findings/
    outside.write_text("---\nid: BOF-001\n---\n", encoding="utf-8")
    _touch_shard(tmp_path, [str(outside)])
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "filed: BOF-001"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("outside findings/" in error for error in errors)


def test_malformed_frontmatter_fails(tmp_path: Path) -> None:
    """A finding whose frontmatter generate_sarif's parser rejects (a scalar key
    followed by a `  - ` list item) must be a hard validation error — otherwise the
    validator passes a file generate_sarif silently drops from results, so a real
    finding never reaches the report."""
    plan_path = _write_plan(tmp_path)
    finding = tmp_path / "findings" / "BOF-001.md"
    finding.write_text("---\nid: BOF-001\nseverity: HIGH\n  - bogus\n---\n", encoding="utf-8")
    _touch_shard(tmp_path, [str(finding)])
    _write_coverage(
        tmp_path,
        [
            ("BOF", "buffer-overflow", "filed: BOF-001"),
            ("UAF", "use-after-free", "cleared"),
        ],
    )

    errors = validate_plan(plan_path, workers=["worker-1"])

    assert any("unparseable frontmatter" in error for error in errors)


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, *sys.argv[1:]]))
