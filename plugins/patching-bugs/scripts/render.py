# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""Render deterministic local auditor and maintainer patch reports."""

import argparse
import re
import sys
from pathlib import Path, PurePosixPath
from string import Template

from records import RecordError, check, load
from repair_scope import RepairScope, assess_scope
from report_sections import (
    Check,
    Evidence,
    baseline_inconclusive_rows,
    baseline_links_html,
    baseline_rows,
    checks,
    collect_evidence,
    decision_status,
    evidence_html,
    optional,
    patch_html,
    run_metadata_html,
    safe,
    scope_html,
)
from report_views import (
    decisive_checks,
    earlier_attempts,
    grouped_evidence,
    limits_html,
    receipt_links,
    supplied_details,
    variant_summary,
    verification_table,
)
from terminal import assess_baseline, has_attempt_evidence, prepare_report_input
from verdict import MissingRecord, verdict

ASSETS = Path(__file__).resolve().parents[1] / "assets"


def _sentences(value: str) -> int:
    return len([part for part in re.split(r"(?<=[.?!])\s+", value.strip()) if part])


def _step_file(step: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise RecordError(f"{step / name}: unsafe manifest path")
    path = step
    for part in relative.parts:
        path /= part
        if path.is_symlink():
            raise RecordError(f"{path}: unsafe symlink in manifest")
    if not path.resolve().is_relative_to(step.resolve()):
        raise RecordError(f"{path}: unsafe manifest path")
    return path


def _record_paths(run_dir: Path) -> list[Path]:
    paths = [
        run_dir / name
        for name in (
            "run.json",
            "finding.json",
            "report-input.json",
            "reproduce/reproduce.json",
            "validate/validate.json",
            "regression/regression.json",
        )
    ]
    for kind in ("patch", "prove"):
        paths.extend(sorted((run_dir / kind).glob(f"attempt-*/{kind}.json")))
    return [path for path in paths if path.is_file()]


def _evidence(run_dir: Path) -> str:
    """Expose the same safe evidence reader to focused traversal tests."""
    items = collect_evidence(run_dir, False, _step_file, _record_paths)
    return evidence_html(items, {})[1]


def _available_verdict(run_dir: Path) -> tuple[str, list[str]]:
    try:
        return verdict(run_dir)
    except MissingRecord as exc:
        return "NOT_READY", [str(exc)]


def _target_proved(run_dir: Path, attempt: int, rows: list[Check]) -> bool:
    required = {
        "check-reproduction",
        "check-validation",
        "check-patch",
        "check-arms",
        "check-build",
        "check-cases",
    }
    passed = {row.anchor for row in rows if row.state in {"pass", "not-applicable"}}
    reproduce = optional(run_dir, "reproduce/reproduce.json")
    validation = optional(run_dir, "validate/validate.json")
    patch = optional(run_dir, f"patch/attempt-{attempt}/patch.json")
    proof = optional(run_dir, f"prove/attempt-{attempt}/prove.json")
    return bool(
        required <= passed
        and reproduce
        and validation
        and reproduce["agent"] != validation["agent"]
        and patch
        and proof
        and patch["agent"] != proof["agent"]
        and reproduce.get("failure_type", "runtime") == proof.get("failure_type", "runtime")
    )


def _scope_rows(
    run_dir: Path, prose: dict, attempt: int, rows: list[Check], target_proved: bool
) -> tuple[RepairScope, list[Check]]:
    scope = assess_scope(run_dir, attempt, target_proved)
    if attempt == 0:
        scope = assess_baseline(run_dir, scope, prose.get("baseline_checks", []))
        if scope.label == "No patch required":
            rows = baseline_rows(rows)
        elif not has_attempt_evidence(run_dir):
            rows = baseline_inconclusive_rows(rows, scope.detail)
    return scope, rows


def _report_evidence(run_dir: Path, include_poc: bool, scope: RepairScope) -> list[Evidence]:
    return collect_evidence(
        run_dir,
        include_poc,
        _step_file,
        lambda directory: _record_paths(directory) + list(scope.evidence_paths),
    )


def _maintainer_html(finding: dict, prose: dict, shared: dict, commit: str) -> str:
    reported, gaps = supplied_details(finding)
    if not prose["fix_why"]:
        gaps.append("Fix rationale was not recorded")
    gap_html = (
        "<h3>Information to confirm</h3><ul>"
        + "".join(f"<li>{safe(gap)}</li>" for gap in gaps)
        + "</ul>"
        if gaps
        else ""
    )
    return Template(ASSETS.joinpath("maintainer-report.html").read_text()).substitute(
        **shared,
        claim=safe(finding["claim"]),
        reported_behavior=reported,
        reported_gaps=gap_html,
        patch_commit=safe(commit),
    )


def render(run_dir: Path) -> Path:
    """Render the auditor report and, for a verified patch, the maintainer handoff."""
    handoff = run_dir / "maintainer-report.html"
    handoff.unlink(missing_ok=True)
    path = run_dir / "report.html"
    path.unlink(missing_ok=True)
    check(run_dir)
    prose = load(run_dir / "report-input.json", "report-input")
    if _sentences(prose["bug"]) > 3:
        raise RecordError("report-input.bug: exceeds 3 sentences")
    if _sentences(prose["fix_why"]) > 2:
        raise RecordError("report-input.fix_why: exceeds 2 sentences")
    status, reasons = _available_verdict(run_dir)
    run = load(run_dir / "run.json", "run")
    finding = load(run_dir / "finding.json", "finding")
    attempt = run["attempts"]
    items = collect_evidence(run_dir, prose["include_poc"], _step_file, _record_paths)
    rows = checks(run_dir, attempt, items)
    target_proved = _target_proved(run_dir, attempt, rows)
    scope, rows = _scope_rows(run_dir, prose, attempt, rows, target_proved)
    items = _report_evidence(run_dir, prose["include_poc"], scope)
    reproduce = optional(run_dir, "reproduce/reproduce.json")
    baseline_checks = prose.get("baseline_checks", [])
    _, authorized_scope = scope_html(run_dir, scope)
    patch_summary, diff = patch_html(run_dir, attempt)
    label, state, explanation = decision_status(status, reasons, rows, scope, attempt)
    proof = optional(run_dir, f"prove/attempt-{attempt}/prove.json") if attempt else None
    patch = optional(run_dir, f"patch/attempt-{attempt}/patch.json") if attempt else None
    commit = patch["patch_commit"] if patch else None
    limitations = list(proof["unproven"]) if proof else []
    limitations.extend(prose["open_risks"])
    if label == "INCONCLUSIVE":
        limitations.insert(0, scope.detail)
    if label in {"INCONCLUSIVE", "FAILED REPAIR"}:
        limitations = [*reasons, *limitations]
    action = {
        "REPAIR SUCCEEDED": (
            "Review Case selection, patch scope, and disclosure before sharing the patch."
        ),
        "FAILED REPAIR": "Inspect the failed check and request another repair attempt.",
        "INCONCLUSIVE": "Resolve the missing or untrustworthy evidence before accepting a repair.",
        "CONTROL PASSED": "Review the baseline controls and confirm that no patch is needed.",
        "NO PATCH REQUIRED": (
            "Review the named baseline example and confirm that no patch is needed."
        ),
    }[label]
    shared = {
        "styles": ASSETS.joinpath("report.css").read_text(),
        "report_title": safe(finding["title"]),
        "fix_why": safe(prose["fix_why"] or "No fix rationale was recorded."),
        "patch_summary": patch_summary,
        "variant_summary": variant_summary(patch),
        "diff": diff,
        "verification_table": verification_table(rows, attempt, items),
        "limits_html": limits_html(proof, prose["open_risks"], scope.detail, label, reasons),
        "evidence_groups": grouped_evidence(items),
    }
    auditor = Template(ASSETS.joinpath("report.html").read_text()).substitute(
        **shared,
        status=safe(label),
        status_state=safe(state),
        status_explanation=safe(explanation),
        raw_verdict=safe(status),
        auditor_action=safe(action),
        commit_line=f"<p><strong>Local commit:</strong> <code>{safe(commit)}</code></p>"
        if commit
        else "",
        decisive_checks=decisive_checks(rows, attempt, items),
        limit_teaser=safe(
            limitations[0]
            if limitations
            else "No explicit limits were recorded; review the declared scope."
        ),
        bug=safe(prose["bug"]),
        bug_source=receipt_links(items, ["report-input.json"]),
        invariant=safe(finding["invariant"]),
        finding_source=receipt_links(items, ["finding.json"]),
        rationale_source=receipt_links(
            items, ["report-input.json", f"patch/attempt-{attempt}/patch.json"]
        ),
        patch_source=(
            '<p class="source">Patch record: '
            + receipt_links(items, [f"patch/attempt-{attempt}/patch.json"])
            + "</p>"
            if patch
            else ""
        ),
        scope_label=safe(scope.label),
        scope_detail=safe(scope.detail),
        authorized_scope=authorized_scope,
        scope_source=receipt_links(items, ["finding.json", f"prove/attempt-{attempt}/prove.json"]),
        baseline_links=baseline_links_html(
            baseline_checks, items, finding.get("repair_scope", {}).get("cases", [])
        ),
        metadata=run_metadata_html(run, reproduce, prose.get("run_metadata", {})),
        earlier_attempts=earlier_attempts(run_dir, attempt, items),
    )
    path.write_text(auditor)
    if (
        label == "REPAIR SUCCEEDED"
        and status == "READY"
        and commit
        and all(
            (run_dir / "patch" / f"attempt-{attempt}" / name).is_file()
            for name in ("fix.patch", "tests.patch")
        )
    ):
        handoff.write_text(_maintainer_html(finding, prose, shared, commit))
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-input", action="store_true")
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    try:
        if args.prepare_input:
            check(args.run_dir)
            prepare_report_input(args.run_dir)
        print(render(args.run_dir))
        handoff = args.run_dir / "maintainer-report.html"
        if handoff.is_file():
            print(handoff)
    except (OSError, ValueError, KeyError) as exc:
        print(str(exc).splitlines()[0], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
