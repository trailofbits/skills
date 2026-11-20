# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Extract Duvet legacy-JSON requirements and gate an assurance evidence ledger.

Checks accounting and artifact presence, not the truth of semantic judgments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

VERDICTS = {
    "supported",
    "partial",
    "violated",
    "missing",
    "unknown",
    "not_applicable",
    "not_checked",
}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
DIVERGENCES = {"partial", "violated", "missing"}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def implementation_spans(spec: dict[str, Any], annotations: list[Any]) -> dict[int, list[int]]:
    """Count each SPEC span once, taking the union of citation/implication coverage.

    Duvet's legacy sections contain lines of [annotation IDs, status ID, text]
    spans. Its status counts measure UTF-8 bytes, not normalized quotation length.
    Exceptions, tests, and TODOs cannot supply implementation traceability.
    """
    counts: dict[int, list[int]] = {}
    for section in spec.get("sections", []):
        for line in section["lines"]:
            if isinstance(line, str):
                continue
            for ids, _, text in line:
                if (
                    not isinstance(ids, list)
                    or not isinstance(text, str)
                    or any(
                        type(index) is not int
                        or not 0 <= index < len(annotations)
                        or not isinstance(annotations[index], dict)
                        for index in ids
                    )
                ):
                    raise ValueError("Invalid Duvet coverage span")
                types = {annotations[index].get("type", "CITATION") for index in ids}
                size = len(text.encode("utf-8"))
                for index in ids:
                    if annotations[index].get("type") == "SPEC":
                        total, covered = counts.setdefault(index, [0, 0])
                        counts[index] = [
                            total + size,
                            covered + (size if types & {"CITATION", "IMPLICATION"} else 0),
                        ]
    return counts


def specification_key(value: str, root: Path) -> str:
    return value if "://" in value else str((root / value).resolve())


def inventory(
    path: Path, specifications: list[str] | None = None, root: Path | None = None
) -> list[dict[str, Any]]:
    """Retain the full requirement denominator, including uncited obligations."""
    report = read_json(path)
    if not isinstance(report, dict) or not isinstance(report.get("specifications"), dict):
        raise ValueError("Expected Duvet legacy JSON from --json, not --json-v2")
    annotations = report.get("annotations")
    if not isinstance(annotations, list) or not isinstance(report.get("statuses"), dict):
        raise ValueError("Missing Duvet annotations or statuses")
    root = root or Path.cwd()
    configured = {specification_key(value, root) for value in report["specifications"]}
    missing = [
        value for value in specifications or [] if specification_key(value, root) not in configured
    ]
    if missing:
        raise ValueError(f"Requested specifications absent from Duvet report: {missing}")
    requirements = []
    referenced = set()
    for specification, spec in report["specifications"].items():
        if not isinstance(spec, dict) or not isinstance(spec.get("requirements"), list):
            raise ValueError(f"Invalid requirement inventory for {specification}")
        if not spec["requirements"]:
            raise ValueError(f"Duvet extracted zero requirements from {specification}")
        coverage = implementation_spans(spec, annotations)
        for index in spec["requirements"]:
            if type(index) is not int or not 0 <= index < len(annotations):
                raise ValueError("Invalid Duvet requirement annotation index")
            annotation = annotations[index]
            if not isinstance(annotation, dict) or annotation.get("type") != "SPEC":
                raise ValueError("Requirement index does not reference a SPEC annotation")
            if annotation.get("target_path") != specification or not nonempty(
                annotation.get("comment")
            ):
                raise ValueError(
                    "Requirement has no quotation or targets a different specification"
                )
            quote = " ".join(annotation["comment"].split())
            section = annotation.get("target_section", "")
            level = annotation.get("level", "AUTO")
            if not isinstance(section, str) or not nonempty(level):
                raise ValueError("Requirement section and level must be strings")
            identity = json.dumps([specification, section, level, quote], ensure_ascii=False)
            status = report["statuses"].get(str(index), {})
            if not isinstance(status, dict) or any(
                type(status.get(key, 0)) is not int or status.get(key, 0) < 0
                for key in (
                    "spec",
                    "incomplete",
                    "citation",
                    "test",
                    "implication",
                    "exception",
                    "todo",
                )
            ):
                raise ValueError("Duvet status character counts must be nonnegative integers")
            related = status.get("related", [])
            if not isinstance(related, list) or any(
                type(item) is not int or not 0 <= item < len(annotations) for item in related
            ):
                raise ValueError("Invalid related Duvet annotation indices")
            referenced.add(index)
            requirements.append(
                {
                    "id": hashlib.sha256(identity.encode()).hexdigest()[:20],
                    "specification": specification,
                    "section": section,
                    "level": level,
                    "quote": quote,
                    "annotation_index": index,
                    "citation_characters": status.get("citation", 0),
                    "test_characters": status.get("test", 0),
                    "implication_characters": status.get("implication", 0),
                    "implementation_complete": (
                        status.get("spec", 0) > 0
                        and coverage.get(index) == [status["spec"], status["spec"]]
                    ),
                    "related_annotations": related,
                }
            )
    if not requirements:
        raise ValueError("Duvet extracted zero requirements; no assurance assessment was performed")
    ids = [requirement["id"] for requirement in requirements]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate requirement identities; resolve ambiguous extraction")
    if referenced != {
        index
        for index, annotation in enumerate(annotations)
        if isinstance(annotation, dict) and annotation.get("type") == "SPEC"
    }:
        raise ValueError("Duvet inventory omitted SPEC annotations; retain every requirement")
    return requirements


def local_file(root: Path, value: Any) -> Path:
    if not nonempty(value):
        raise ValueError("Evidence file path is empty")
    path = (root / value).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"Evidence file is missing or outside target: {value}")
    return path


def location(root: Path, value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Evidence location must be an object with file and line")
    path = local_file(root, value.get("file"))
    line = value.get("line")
    if type(line) is not int or not 1 <= line <= len(path.read_text().splitlines()):
        raise ValueError(f"Invalid source line in {value.get('file')}")


def record_errors(root: Path, record: dict[str, Any], requirement: dict[str, Any]) -> list[str]:
    errors = []
    try:
        verdict = record.get("verdict")
        if verdict not in VERDICTS or not nonempty(record.get("rationale")):
            raise ValueError("Missing verdict or rationale")
        if verdict in DIVERGENCES and (
            record.get("severity") not in SEVERITIES or not nonempty(record.get("consequence"))
        ):
            raise ValueError(
                "Divergence needs severity (critical/high/medium/low/info) and consequence"
            )
        if not isinstance(record.get("assumptions"), list) or not all(
            nonempty(item) for item in record["assumptions"]
        ):
            raise ValueError("assumptions must be an array of nonempty strings")
        implementations, checks = record.get("implementation"), record.get("checks")
        if not isinstance(implementations, list) or not isinstance(checks, list):
            raise ValueError("implementation and checks must be arrays")
        for anchor in implementations:
            location(root, anchor)
            if anchor.get("role") not in {"production", "model"}:
                raise ValueError("Implementation location needs production/model role")
        passing = 0
        for check in checks:
            if not isinstance(check, dict) or check.get("kind") not in {"test", "formal"}:
                raise ValueError("Check kind must be test or formal")
            if check.get("scope") not in {"implementation", "model"}:
                raise ValueError("Check scope must be implementation or model")
            if check.get("result") not in {"pass", "fail", "unknown", "not_run"}:
                raise ValueError("Invalid native check result")
            if not nonempty(check.get("property")) or not nonempty(check.get("command")):
                raise ValueError("Check needs its exact property and command")
            location(root, check.get("location"))
            if check["result"] != "not_run":
                log = local_file(root, check.get("log"))
                if log.stat().st_size == 0:
                    raise ValueError("Native evidence log is empty")
            if check["result"] == "pass":
                if type(check.get("exit_code")) is not int or check["exit_code"] != 0:
                    raise ValueError("A passing check needs native exit_code 0")
                if check["scope"] == "implementation":
                    if check["kind"] == "formal" and not nonempty(check.get("binding")):
                        raise ValueError(
                            "Formal implementation evidence needs a model-to-code binding"
                        )
                    passing += 1
        if verdict == "supported":
            if not any(anchor["role"] == "production" for anchor in implementations):
                raise ValueError("Supported requirement has no production enforcement location")
            if not passing:
                raise ValueError("Supported requirement has no passing implementation check")
            if any(check["result"] == "fail" for check in checks):
                raise ValueError("Supported requirement has contradictory native failures")
            if not requirement["implementation_complete"]:
                raise ValueError(
                    "Supported requirement lacks complete Duvet implementation traceability"
                )
    except (ValueError, TypeError, KeyError) as error:
        errors.append(f"{requirement['id']}: {error}")
    return errors


def check_ledger(
    baseline: Path,
    report: Path,
    ledger_path: Path,
    root: Path,
    specifications: list[str] | None = None,
    expected_ids: list[str] | None = None,
    failed_ids: list[str] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    before = {item["id"] for item in inventory(baseline, specifications, root)}
    current = {item["id"]: item for item in inventory(report, specifications, root)}
    errors = []
    if before != set(current):
        errors.append(
            "Specification inventory changed; retain the assessed specification and denominator"
        )
    if expected_ids is not None and (
        len(expected_ids) != len(before) or set(expected_ids) != before
    ):
        errors.append("Workflow requirement IDs differ from the retained baseline inventory")
    ledger = read_json(ledger_path)
    if not isinstance(ledger, dict) or not isinstance(ledger.get("requirements"), list):
        raise ValueError("Ledger needs a requirements array")
    recorded_limitations = ledger.get("limitations")
    if not isinstance(recorded_limitations, list) or not all(
        nonempty(item) for item in recorded_limitations
    ):
        raise ValueError("Ledger needs a limitations array of nonempty strings")
    if any(item not in recorded_limitations for item in limitations or []):
        errors.append("Setup limitations were lost from the final ledger")
    records = ledger["requirements"]
    if any(not isinstance(record, dict) or not nonempty(record.get("id")) for record in records):
        raise ValueError("Every requirement record needs an id")
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        errors.append("Duplicate ledger requirement records")
    if set(ids) != set(current):
        errors.append("Ledger omitted or invented requirements")
    by_id = {record["id"]: record for record in records}
    for failed_id in failed_ids or []:
        if failed_id not in before or by_id.get(failed_id, {}).get("verdict") != "not_checked":
            errors.append(f"Failed worker {failed_id} must retain its own not_checked record")
    for record in records:
        if record["id"] in current:
            errors.extend(record_errors(root, record, current[record["id"]]))
    counts = Counter(record.get("verdict", "invalid") for record in records)
    if records and counts.get("not_applicable", 0) == len(records):
        errors.append("No applicable requirements were assessed")
    gaps = any(verdict not in {"supported", "not_applicable"} for verdict in counts) or bool(
        recorded_limitations
    )
    return {
        "valid": not errors,
        "status": "invalid" if errors else "gaps" if gaps else "supported",
        "total": len(current),
        "verdicts": dict(sorted(counts.items())),
        "limitations": recorded_limitations,
        "errors": errors,
    }


def finalize(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    """Run the native artifact gate in the caller's process, outside the workflow VM."""
    run = args.run.resolve(strict=True)
    if not run.is_dir() or not run.is_relative_to(root):
        raise ValueError("Run directory must exist inside the target root")
    for name in ("report.md", "inventory.json", "duvet-before.json", "ledger.json"):
        path = local_file(root, str(run / name))
        if not path.stat().st_size:
            raise ValueError(f"Empty run artifact: {name}")
    before = inventory(run / "duvet-before.json", args.specification, root)
    ids = {item["id"] for item in before}
    retained = read_json(run / "inventory.json")
    if not isinstance(retained, dict) or retained.get("requirements") != before:
        raise ValueError("Retained inventory differs from the native baseline")
    for item in before:
        if item["id"] not in args.failed_requirement:
            record = read_json(local_file(root, str(run / "requirements" / f"{item['id']}.json")))
            if not isinstance(record, dict) or record.get("id") != item["id"]:
                raise ValueError(f"Missing or mismatched worker record: {item['id']}")
    if len(args.requirement) != len(ids) or set(args.requirement) != ids:
        raise ValueError("Workflow requirement IDs differ from the retained baseline inventory")
    if not set(args.failed_requirement) <= ids:
        raise ValueError("Failed worker IDs are absent from the baseline inventory")
    # A fresh directory prevents either a failed command or a no-op from reusing
    # an old native report. Keep each attempt's logs and output for review.
    native = Path(tempfile.mkdtemp(prefix="gate-native-", dir=run))
    report = native / "duvet-after.json"
    html = native / "duvet-after.html"
    command = [
        args.duvet,
        "report",
        "--json",
        str(report),
        "--html",
        str(html),
        "--require-citations",
        "true",
        "--require-tests",
        "true",
        "--ci",
        "false",
    ]
    with (native / "duvet.log").open("w") as log:
        completed = subprocess.run(
            command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=False
        )
    write_path = native / "execution.json"
    write_path.write_text(
        json.dumps({"command": command, "exit_code": completed.returncode}) + "\n"
    )
    if completed.returncode:
        raise ValueError(f"Native Duvet exited {completed.returncode}; see {native / 'duvet.log'}")
    for artifact in (report, html):
        if not local_file(root, str(artifact)).stat().st_size:
            raise ValueError(f"Native Duvet artifact is empty: {artifact}")
    result = check_ledger(
        run / "duvet-before.json",
        report,
        run / "ledger.json",
        root,
        args.specification,
        args.requirement,
        args.failed_requirement,
        args.limitation,
    )
    result.update(
        duvet_report=str(report),
        duvet_log=str(native / "duvet.log"),
        duvet_exit_code=completed.returncode,
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract = subparsers.add_parser("inventory")
    extract.add_argument("--report", type=Path, required=True)
    validate = subparsers.add_parser("check")
    validate.add_argument("--baseline", type=Path, required=True)
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--ledger", type=Path, required=True)
    validate.add_argument("--root", type=Path, required=True)
    finish = subparsers.add_parser("finalize")
    finish.add_argument("--run", type=Path, required=True)
    finish.add_argument("--root", type=Path, required=True)
    finish.add_argument("--duvet", default="duvet", help="Duvet executable (no shell arguments)")
    finish.add_argument("--requirement", action="append", required=True)
    finish.add_argument("--failed-requirement", action="append", default=[])
    finish.add_argument("--limitation", action="append", default=[])
    for command in (extract, validate, finish):
        command.add_argument(
            "--specification",
            action="append",
            required=True,
            help="Requested document path or URL; repeat for every document",
        )
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "inventory":
            result = {"requirements": inventory(args.report, args.specification)}
            code = 0
        else:
            root = args.root.resolve(strict=True)
            if not root.is_dir():
                raise ValueError("Target root must be a directory")
            result = (
                finalize(args, root)
                if args.command == "finalize"
                else check_ledger(args.baseline, args.report, args.ledger, root, args.specification)
            )
            code = 2 if not result["valid"] else 1 if result["status"] == "gaps" else 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        result = {
            "valid": False,
            "status": "invalid",
            "total": 0,
            "verdicts": {},
            "limitations": [],
            "errors": [str(error)],
        }
        code = 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    sys.exit(main())
