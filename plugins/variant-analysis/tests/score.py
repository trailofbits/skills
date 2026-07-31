#!/usr/bin/env python3
"""Grade a variant-analysis report against ground truth.

Grades the ARTIFACT, not the transcript. A run that talks convincingly about
finding variants but writes no report scores as a failure, not as zero findings.
That distinction is the whole point: an eval that reads the response text will
pass a run that skipped the work.

Usage:
    score.py --report REPORT.md --codebase cpp [--ground-truth ground-truth.json]
    score.py --self-test
"""

import argparse
import json
import pathlib
import re
import sys

# A finding must name a file with one of these extensions to be counted.
PATH_RE = re.compile(
    r"[\w./\\-]+\.(?:c|h|cpp|hpp|go|js|mjs|ts|java|py)\b",
    re.IGNORECASE,
)

# How real reports declare where a finding lives. Observed across actual runs:
# "**Location:** `src/a.cpp:22`" and "- **Location:** `/abs/path/handlers/a.go:23`".
# Both markdown spellings occur: "**Location:**" (colon inside the bold markers,
# which is what the template produces) and "**Location**:".
LOCATION_RE = re.compile(
    r"^\s*[-*]?\s*\*\*\s*(?:location|file)\s*:?\s*\*\*\s*:?",
    re.IGNORECASE,
)

# A block or row carrying one of these is an entry the report itself rejected.
# Without this, a triage table row like
#   | 3 | `handlers/status.go:37` | REFUTED | allowlist severs the flow |
# scores as the decoy being reported as real — the opposite of what happened.
# Matched against block HEADERS and individual table rows only, never against
# block prose. A real finding routinely explains the safe fix ("use argv
# separation instead"), and matching that text inside the body silently voided
# the whole finding. "safe" is dropped for the same reason: too ambiguous to be
# a verdict token.
REFUTED_RE = re.compile(
    r"\b(refuted|false[ -]positive|not a variant|not vulnerable|"
    r"not exploitable|ruled out|no finding)\b",
    re.IGNORECASE,
)


class GradingError(Exception):
    """The report could not be graded at all — distinct from scoring zero."""


def split_sections(text):
    """Map each '## Heading' to its body."""
    sections = {}
    current = None
    buf = []
    for line in text.splitlines():
        if line.startswith("## "):
            if current is not None:
                sections[current] = "\n".join(buf)
            current = line[3:].strip().lower()
            buf = []
        else:
            buf.append(line)
    if current is not None:
        sections[current] = "\n".join(buf)
    return sections


def find_section(sections, *keywords):
    for name, body in sections.items():
        if any(k in name for k in keywords):
            return body
    return None


def paths_in(text):
    """Normalized file paths mentioned in a chunk of report text."""
    if not text:
        return set()
    out = set()
    for m in PATH_RE.finditer(text):
        p = m.group(0).replace("\\", "/").lstrip("./")
        out.add(p)
    return out


def split_blocks(body):
    """Split a section body into '### ' blocks, with the preamble first."""
    blocks = []
    current = []
    for line in body.splitlines():
        if line.startswith("### "):
            blocks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    blocks.append("\n".join(current))
    return blocks


def reported_locations(findings_body):
    """Paths the report asserts are real findings.

    Scraping every path in the Findings section over-counts badly: it picks up
    entry-point files named while tracing data flow ("flows unmodified from
    `main.cpp:28`") and rows in triage tables the report itself refuted.

    So prefer explicit '**Location:**' declarations inside non-refuted blocks,
    which is how every real report observed so far marks a finding. Fall back to
    permissive line scanning only when a report uses no Location fields at all,
    and report which mode was used so a surprising score can be traced.
    """
    strict = set()
    for block in split_blocks(findings_body):
        lines = block.splitlines()
        if not any(line.strip() for line in lines):
            continue
        # Header-only refutation check: "### Ruled out: foo.go" voids the block,
        # but a body sentence about the safe alternative does not.
        header = next((line for line in lines if line.startswith("### ")), "")
        if header and REFUTED_RE.search(header):
            continue
        for line in lines:
            if LOCATION_RE.match(line) and not REFUTED_RE.search(line):
                strict |= paths_in(line)

    if strict:
        return strict, "location-fields"

    loose = set()
    for line in findings_body.splitlines():
        if REFUTED_RE.search(line):
            continue
        loose |= paths_in(line)
    return loose, "permissive-lines"


def matches(reported, truth_file):
    """True if a reported path refers to the ground-truth file.

    Compared by suffix so 'app/orders.py', './app/orders.py' and
    'codebases/python-flask/app/orders.py' all match 'app/orders.py'.
    Basename alone is not enough — two codebases could share a filename.
    """
    truth = truth_file.replace("\\", "/")
    for r in reported:
        if r == truth or r.endswith("/" + truth) or truth.endswith("/" + r):
            return True
        if pathlib.PurePath(r).name == pathlib.PurePath(truth).name:
            return True
    return False


def grade(report_text, entry):
    sections = split_sections(report_text)

    findings_body = find_section(sections, "finding", "variant", "confirmed")
    fp_body = find_section(sections, "false positive", "ruled out", "not a variant")

    if findings_body is None:
        raise GradingError(
            "no findings section in the report — expected a '## Findings' heading. "
            "The run did not produce a gradeable artifact."
        )

    reported, extraction_mode = reported_locations(findings_body)

    # "Examined" is deliberately permissive: any mention anywhere counts as
    # having looked at it, including a refuted row inside Findings.
    examined = paths_in(findings_body) | paths_in(fp_body)

    vulns = entry["vulnerabilities"]
    decoy = entry["decoy"]

    found = [v for v in vulns if matches(reported, v["file"])]
    missed = [v for v in vulns if not matches(reported, v["file"])]

    decoy_reported = matches(reported, decoy["file"])
    decoy_examined = matches(examined, decoy["file"])

    # Every file named in Findings that is not a known vulnerability.
    truth_files = {v["file"] for v in vulns}
    spurious = sorted(
        p
        for p in reported
        if not any(matches({p}, t) for t in truth_files) and not matches({p}, decoy["file"])
    )

    non_seed = [v for v in vulns if not v.get("is_seed")]
    non_seed_found = [v for v in found if not v.get("is_seed")]

    return {
        "codebase": entry["name"],
        "extraction_mode": extraction_mode,
        "true_positives": len(found),
        "found_ids": [v["id"] for v in found],
        "missed_ids": [v["id"] for v in missed],
        "new_variants_found": len(non_seed_found),
        "new_variants_total": len(non_seed),
        "non_seed_recall": f"{len(non_seed_found)}/{len(non_seed)}",
        "decoy_reported_as_real": decoy_reported,
        "decoy_examined_and_ruled_out": decoy_examined and not decoy_reported,
        "spurious_files": spurious,
        "false_positives": (1 if decoy_reported else 0) + len(spurious),
    }


def verdict(score, require_decoy_examined=False):
    """Pass criteria. Kept separate from grading so thresholds are visible.

    Keyed on NEW variants, not total true positives. The seed bug is handed to
    the run, so whether it reappears under '## Findings' or under '## Original
    Vulnerability' is a report-formatting convention — both were observed in
    real runs, and scoring on the total penalized the one that followed the
    template correctly. What the eval is actually measuring is whether the
    second, unseeded vulnerability was found.
    """
    reasons = []
    if score["new_variants_found"] < score["new_variants_total"]:
        reasons.append(
            f"found {score['new_variants_found']}/{score['new_variants_total']} "
            f"new variants; missed {', '.join(score['missed_ids'])}"
        )
    if score["decoy_reported_as_real"]:
        reasons.append("decoy reported as a real finding")
    if score["spurious_files"]:
        reasons.append(f"spurious findings: {', '.join(score['spurious_files'])}")
    if require_decoy_examined and not score["decoy_examined_and_ruled_out"]:
        reasons.append("decoy was never examined (not in the ruled-out section)")
    return (not reasons), reasons


# --------------------------------------------------------------------------
# Self-test: proves the grader still discriminates. A grader that cannot fail
# is worth nothing, so this asserts on both directions and on a fixed count.
# --------------------------------------------------------------------------
SELF_TEST_ENTRY = {
    "name": "selftest",
    "vulnerabilities": [
        {"id": "v1", "file": "src/a.py", "line": 1, "is_seed": True},
        {"id": "v2", "file": "src/b.py", "line": 2, "is_seed": False},
    ],
    "decoy": {"id": "d", "file": "src/decoy.py", "line": 3},
}

PERFECT = """
## Findings
### Variant #1
**Location:** `src/a.py:1`
### Variant #2
**Location:** `src/b.py:2`

## False Positive Patterns
| src/decoy.py | 1 | guarded before comparison |
"""

MISSED_ONE = """
## Findings
### Variant #1
**Location:** `src/a.py:1`

## False Positive Patterns
none
"""

DECOY_AS_REAL = """
## Findings
### Variant #1
**Location:** `src/a.py:1`
### Variant #2
**Location:** `src/b.py:2`
### Variant #3
**Location:** `src/decoy.py:3`
"""

SPURIOUS = """
## Findings
### Variant #1
**Location:** `src/a.py:1`
### Variant #2
**Location:** `src/b.py:2`
### Variant #3
**Location:** `src/unrelated.py:9`
"""

NO_FINDINGS_SECTION = """
## Summary
I looked at everything and found two variants. Trust me.
"""

DECOY_NOT_EXAMINED = """
## Findings
### Variant #1
**Location:** `src/a.py:1`
### Variant #2
**Location:** `src/b.py:2`

## False Positive Patterns
none
"""

# The next three are reduced from reports real runs actually produced. Each one
# scored wrong before the extraction rewrite.

# go/workflow: decoy listed in a triage table inside Findings, marked REFUTED.
# Previously scored as "decoy reported as real".
REFUTED_IN_TABLE = """
## Findings
| # | Location | Verdict | Note |
|---|---|---|---|
| 1 | `src/a.py:1` | CONFIRMED | seed |
| 2 | `src/b.py:2` | CONFIRMED | variant |
| 3 | `src/decoy.py:3` | REFUTED | allowlist severs the flow |

### 1. SEED -- the original
- **Location:** `src/a.py:1`

### 2. VARIANT -- the new one
- **Location:** `src/b.py:2`
"""

# cpp/baseline: entry point named while tracing data flow inside an
# exploitability checklist. Previously scored as a spurious finding.
FLOW_MENTION = """
## Findings
### Variant #1
**Location:** `src/b.py:2`
**Exploitability:**
- [x] User-controlled data — flows unmodified from `src/main.py:28`

## False Positive Patterns
| `src/decoy.py` | 1 | guarded |
"""

# cpp/baseline: seed in its own section per the template, only the new variant
# under Findings. Previously scored 1/2 true positives and failed.
SEED_IN_OWN_SECTION = """
## Original Vulnerability
**Location:** `src/a.py:1`

## Findings
### Variant #1
**Location:** `src/b.py:2`

## False Positive Patterns
| `src/decoy.py` | 1 | guarded |
"""


def self_test():
    checks = 0

    s = grade(PERFECT, SELF_TEST_ENTRY)
    ok, why = verdict(s, require_decoy_examined=True)
    assert ok, f"perfect report should pass: {why}"
    assert s["true_positives"] == 2, s
    assert s["decoy_examined_and_ruled_out"], s
    assert s["non_seed_recall"] == "1/1", s
    checks += 1

    s = grade(MISSED_ONE, SELF_TEST_ENTRY)
    ok, why = verdict(s)
    assert not ok, "missing a variant must fail"
    assert s["true_positives"] == 1, s
    assert s["missed_ids"] == ["v2"], s
    assert s["non_seed_recall"] == "0/1", s
    checks += 1

    s = grade(DECOY_AS_REAL, SELF_TEST_ENTRY)
    ok, why = verdict(s)
    assert not ok, "reporting the decoy as real must fail"
    assert s["decoy_reported_as_real"], s
    assert s["false_positives"] == 1, s
    checks += 1

    s = grade(SPURIOUS, SELF_TEST_ENTRY)
    ok, why = verdict(s)
    assert not ok, "a spurious finding must fail"
    assert s["spurious_files"] == ["src/unrelated.py"], s
    checks += 1

    try:
        grade(NO_FINDINGS_SECTION, SELF_TEST_ENTRY)
    except GradingError:
        checks += 1
    else:  # pragma: no cover
        raise AssertionError("a report with no findings section must not grade as 0")

    s = grade(DECOY_NOT_EXAMINED, SELF_TEST_ENTRY)
    ok, _ = verdict(s, require_decoy_examined=False)
    assert ok, "not examining the decoy is only a failure under the strict flag"
    ok, _ = verdict(s, require_decoy_examined=True)
    assert not ok, "strict mode must require the decoy to be examined"
    checks += 1

    # Regressions from real runs.
    s = grade(REFUTED_IN_TABLE, SELF_TEST_ENTRY)
    ok, why = verdict(s, require_decoy_examined=True)
    assert not s["decoy_reported_as_real"], f"a REFUTED table row is not a finding: {s}"
    assert s["decoy_examined_and_ruled_out"], s
    assert s["extraction_mode"] == "location-fields", s
    assert ok, f"a run that finds both and refutes the decoy must pass: {why}"
    checks += 1

    s = grade(FLOW_MENTION, SELF_TEST_ENTRY)
    assert s["spurious_files"] == [], f"a data-flow mention is not a finding: {s}"
    ok, _ = verdict(s)
    assert ok, f"should pass: {s}"
    checks += 1

    s = grade(SEED_IN_OWN_SECTION, SELF_TEST_ENTRY)
    assert s["new_variants_found"] == 1, s
    ok, why = verdict(s)
    assert ok, f"seed outside Findings is a convention, not a miss: {why}"
    checks += 1

    expected = 9
    if checks != expected:
        raise AssertionError(f"self-test ran {checks} assertions, expected {expected}")
    print(f"score.py self-test: {checks}/{expected} checks passed")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report")
    ap.add_argument("--codebase")
    ap.add_argument(
        "--ground-truth",
        default=str(pathlib.Path(__file__).parent / "ground-truth.json"),
    )
    ap.add_argument("--strict-decoy", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0

    if not args.report or not args.codebase:
        ap.error("--report and --codebase are required unless --self-test")

    truth = json.loads(pathlib.Path(args.ground_truth).read_text())
    entry = next(
        (c for c in truth["codebases"] if c["name"] == args.codebase),
        None,
    )
    if entry is None:
        print(f"unknown codebase: {args.codebase}", file=sys.stderr)
        return 2

    path = pathlib.Path(args.report)
    if not path.exists():
        print(
            json.dumps(
                {
                    "codebase": args.codebase,
                    "error": f"no report at {path} — the run produced no artifact",
                    "gradeable": False,
                }
            )
        )
        return 3

    try:
        score = grade(path.read_text(), entry)
    except GradingError as exc:
        print(json.dumps({"codebase": args.codebase, "error": str(exc), "gradeable": False}))
        return 3

    ok, reasons = verdict(score, require_decoy_examined=args.strict_decoy)
    score["gradeable"] = True
    score["pass"] = ok
    score["fail_reasons"] = reasons
    print(json.dumps(score, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
