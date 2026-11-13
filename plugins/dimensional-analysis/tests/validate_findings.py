#!/usr/bin/env python3
"""Assert a dimensional-analysis run found the planted bugs and annotated the sources.

Deterministic counterpart to the `planted-bugs` LLM grader. The grader reads the
transcript and can be satisfied by a convincing description; this script only
looks at artifacts on disk.

Matching is by enclosing function name, never by line number: the annotation
pass inserts comment lines and shifts every line below it. Each planted bug sits
in a distinct function precisely so this stays possible.

Two things gate the run: recall against the planted bugs, and CRITICAL/HIGH false
positives against the control contract. Nothing else.

The precision gate is deliberately asymmetric. A missed dimensional bug reaches a
client; a spurious low-severity note costs a reviewer a moment to dismiss. So
false negatives always fail, while a LOW or MEDIUM finding on the control contract
is counted and reported but tolerated. Only a false CRITICAL or HIGH fails — that
is the severity that derails an audit and burns client trust.

Annotation coverage is reported but never gated. It is the plugin's deliverable and
the only axis on which the no-plugin baseline reproducibly differs, so it stays
visible in the output — but a run that finds every bug without annotating has still
delivered the findings this eval scores.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TARGET_FILE = "MarginVault.sol"
CONTROL_FILE = "StakingRewards.sol"

# Severities that fail the run when raised against the correct control contract.
BLOCKING_SEVERITIES = ("critical", "high")

# Planted bug -> the function it lives in. See fixtures/ANSWER-KEY.md.
PLANTED: dict[str, str] = {
    "DIM-A": "debtOf",
    "DIM-B": "repaymentAmount",
    "DIM-C": "priceOf",
    "DIM-D": "protocolFee",
    "DIM-E": "totalCollateralRaw",
}

SOURCE_FILES = (
    "MarginVault.sol",
    "UniV3Oracle.sol",
    "AssetRegistry.sol",
    "InterestIndex.sol",
    "StakingRewards.sol",
    "libraries/FixedPointMath.sol",
    "libraries/PriceLib.sol",
)

# A dimensional annotation on a comment line: {tok}, D18{tok}, D27{UoA/tok}.
ANNOTATION = re.compile(r"(?://|/\*|\*|#).*\bD?\d*\{[A-Za-z0-9_/*^ .-]+\}")


def load_findings(path: Path) -> list[dict]:
    """Read findings.json, rejecting a missing, malformed, or empty report.

    A run that inspected nothing must fail rather than pass silently.
    """
    if not path.is_file():
        raise SystemExit(f"error: no findings report at {path}; the run produced no artifact")

    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"error: cannot parse {path}: {error}") from error

    findings = payload.get("findings") if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        raise SystemExit(f"error: {path} has no 'findings' list")
    if not findings:
        raise SystemExit(f"error: {path} reports zero findings; the fixture contains five bugs")

    return [f for f in findings if isinstance(f, dict)]


def finding_text(finding: dict) -> str:
    """Flatten a finding record into one lowercase string for substring matching."""
    return json.dumps(finding).lower()


def missing_planted(findings: list[dict]) -> list[str]:
    """Return the planted-bug ids that no finding accounts for."""
    missing = []
    for bug_id, function in PLANTED.items():
        needle = function.lower()
        if not any(needle in finding_text(f) for f in findings):
            missing.append(f"{bug_id} ({TARGET_FILE}:{function})")
    return missing


def control_findings(findings: list[dict]) -> tuple[list[str], list[str]]:
    """Split control-contract findings into blocking and tolerated, by severity.

    Returns (blocking, tolerated). Blocking means CRITICAL or HIGH raised against
    code that is dimensionally correct.
    """
    blocking: list[str] = []
    tolerated: list[str] = []
    for finding in findings:
        if CONTROL_FILE.lower() not in finding_text(finding):
            continue
        location = finding.get("location", {})
        where = location.get("function") or location.get("line") or "?"
        severity = str(finding.get("severity", "")).lower()
        label = f"{finding.get('id', '?')} [{severity or 'unrated'}] at {CONTROL_FILE}:{where}"
        if severity in BLOCKING_SEVERITIES:
            blocking.append(label)
        else:
            tolerated.append(label)
    return blocking, tolerated


def unannotated(work_src: Path) -> list[str]:
    """Return in-scope source files that gained no dimensional annotation."""
    gaps = []
    for name in SOURCE_FILES:
        path = work_src / name
        if not path.is_file():
            gaps.append(f"{name} (missing from work dir)")
        elif not ANNOTATION.search(path.read_text()):
            gaps.append(f"{name} (no dimensional annotation added)")
    return gaps


def report(label: str, problems: list[str]) -> bool:
    """Print a pass/fail line for one check. Returns True when the check passed."""
    if problems:
        print(f"FAIL: {label}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return False
    print(f"pass: {label}")
    return True


def main() -> int:
    """Validate one completed run's work directory."""
    if len(sys.argv) != 2:
        print("usage: validate_findings.py WORK_DIR", file=sys.stderr)
        return 2

    work = Path(sys.argv[1])
    findings = load_findings(work / "findings.json")
    print(f"parsed {len(findings)} finding(s) from {work / 'findings.json'}")

    blocking, tolerated = control_findings(findings)
    checks = [
        report(f"recall: all {len(PLANTED)} planted bugs reported", missing_planted(findings)),
        report(f"precision: no CRITICAL/HIGH findings in {CONTROL_FILE}", blocking),
    ]

    if tolerated:
        print(f"note: {len(tolerated)} low-severity finding(s) in {CONTROL_FILE}, tolerated:")
        for entry in tolerated:
            print(f"  - {entry}")

    # Reported, never gated: a run that finds every bug without annotating still
    # delivered the findings, which is what this eval scores.
    gaps = unannotated(work / "contracts")
    print(f"note: {len(SOURCE_FILES) - len(gaps)}/{len(SOURCE_FILES)} sources annotated")
    for gap in gaps:
        print(f"  - {gap}")

    if not all(checks):
        return 1

    print(
        f"PASS: {len(PLANTED)}/{len(PLANTED)} planted bugs, "
        f"0 blocking control false positives, {len(tolerated)} tolerated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
