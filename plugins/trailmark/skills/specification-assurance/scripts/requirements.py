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
import sys
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


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def inventory(path: Path) -> list[dict[str, Any]]:
    """Retain the full requirement denominator, including uncited obligations."""
    report = read_json(path)
    if not isinstance(report, dict) or not isinstance(report.get("specifications"), dict):
        raise ValueError("Expected Duvet legacy JSON from --json, not --json-v2")
    annotations = report.get("annotations")
    if not isinstance(annotations, list) or not isinstance(report.get("statuses"), dict):
        raise ValueError("Missing Duvet annotations or statuses")
    requirements = []
    referenced = set()
    for specification, spec in report["specifications"].items():
        if not isinstance(spec, dict) or not isinstance(spec.get("requirements"), list):
            raise ValueError(f"Invalid requirement inventory for {specification}")
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
            if not (requirement["citation_characters"] or requirement["implication_characters"]):
                raise ValueError("Supported requirement has no Duvet implementation citation")
    except (ValueError, TypeError, KeyError) as error:
        errors.append(f"{requirement['id']}: {error}")
    return errors


def check_ledger(baseline: Path, report: Path, ledger_path: Path, root: Path) -> dict[str, Any]:
    before = {item["id"] for item in inventory(baseline)}
    current = {item["id"]: item for item in inventory(report)}
    errors = []
    if before != set(current):
        errors.append(
            "Specification inventory changed; retain the assessed specification and denominator"
        )
    ledger = read_json(ledger_path)
    if not isinstance(ledger, dict) or not isinstance(ledger.get("requirements"), list):
        raise ValueError("Ledger needs a requirements array")
    limitations = ledger.get("limitations")
    if not isinstance(limitations, list) or not all(nonempty(item) for item in limitations):
        raise ValueError("Ledger needs a limitations array of nonempty strings")
    records = ledger["requirements"]
    if any(not isinstance(record, dict) or not nonempty(record.get("id")) for record in records):
        raise ValueError("Every requirement record needs an id")
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        errors.append("Duplicate ledger requirement records")
    if set(ids) != set(current):
        errors.append("Ledger omitted or invented requirements")
    for record in records:
        if record["id"] in current:
            errors.extend(record_errors(root, record, current[record["id"]]))
    counts = Counter(record.get("verdict", "invalid") for record in records)
    if records and counts.get("not_applicable", 0) == len(records):
        errors.append("No applicable requirements were assessed")
    gaps = any(verdict not in {"supported", "not_applicable"} for verdict in counts) or bool(
        limitations
    )
    return {
        "valid": not errors,
        "status": "invalid" if errors else "gaps" if gaps else "supported",
        "total": len(current),
        "verdicts": dict(sorted(counts.items())),
        "limitations": limitations,
        "errors": errors,
    }


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
    for command in (extract, validate):
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "inventory":
            result = {"requirements": inventory(args.report)}
            code = 0
        else:
            root = args.root.resolve(strict=True)
            if not root.is_dir():
                raise ValueError("Target root must be a directory")
            result = check_ledger(args.baseline, args.report, args.ledger, root)
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
