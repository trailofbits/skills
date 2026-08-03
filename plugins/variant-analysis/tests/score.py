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

# A finding must name a file with one of these extensions to be counted. Adding a
# codebase in a language that is missing here does not score zero silently:
# reported_locations() raises GradingError when Location fields parse to nothing.
PATH_RE = re.compile(
    r"[\w./\\-]+\.(?:c|h|cpp|hpp|cc|go|js|mjs|ts|tsx|java|kt|py|rb|rs|php|cs|swift|scala)\b",
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
    """Normalized (path, line) pairs mentioned in a chunk of report text.

    Line is None when the report named a file without one. Ranges like
    "foo.py:279-285" keep the first number.
    """
    if not text:
        return set()
    out = set()
    for m in PATH_RE.finditer(text):
        p = m.group(0).replace("\\", "/").lstrip("./")
        tail = text[m.end() : m.end() + 12]
        lm = re.match(r"[:# ]L?(\d+)", tail)
        out.add((p, int(lm.group(1)) if lm else None))
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
    location_lines = 0
    location_paths = 0
    for block in split_blocks(findings_body):
        lines = block.splitlines()
        if not any(line.strip() for line in lines):
            continue
        # Counted before the refutation checks: this is about whether PATH_RE can
        # read the report at all, which has nothing to do with the verdicts in it.
        for ln in lines:
            if LOCATION_RE.match(ln):
                location_lines += 1
                location_paths += len(paths_in(ln))
        # Header-only refutation check: "### Ruled out: foo.go" voids the block,
        # but a body sentence about the safe alternative does not.
        header = next((line for line in lines if line.startswith("### ")), "")
        if header and REFUTED_RE.search(header):
            continue
        # Status-row refutation. variant-report-template.md puts the verdict in its
        # own `| Severity | Confidence | Status |` row, separated from both the
        # header and the **Location:** line — so a decoy written up exactly per the
        # template scored as reported-real, failing a run that triaged correctly.
        # Only rows carrying no path of their own count as a verdict on the block:
        # a triage row that names a file is a verdict on *that* file and is handled
        # by the per-line check below, and treating it as block-wide would void the
        # real findings listed beside it.
        rows = [ln for ln in lines if ln.lstrip().startswith("|") and not paths_in(ln)]
        if any(REFUTED_RE.search(ln) for ln in rows):
            continue
        for line in lines:
            if LOCATION_RE.match(line) and not REFUTED_RE.search(line):
                strict |= paths_in(line)

    if strict:
        return strict, "location-fields"

    # Location fields were declared but PATH_RE recognized nothing in *any* of
    # them: the report names files in a language the extension allowlist does not
    # cover. Falling through to permissive scanning would score every such run as
    # "found nothing", indistinguishable from a run that genuinely found nothing —
    # so add the codebase's extensions to PATH_RE instead. Note this fires only
    # when zero locations parsed; a report whose locations all parsed and were all
    # refuted legitimately scores zero rather than raising.
    if location_lines and not location_paths:
        raise GradingError(
            f"the report declares {location_lines} **Location:** field(s) but no "
            "recognizable file path was extracted from any of them — the codebase's "
            "language is probably missing from PATH_RE's extension allowlist"
        )

    loose = set()
    for line in findings_body.splitlines():
        if REFUTED_RE.search(line):
            continue
        loose |= paths_in(line)
    return loose, "permissive-lines"


# How far a reported line may sit from the ground-truth line and still be the same
# construct. A report may cite the def, the sink inside it, or a range.
LINE_WINDOW = 30


def same_file(reported_path, truth_file):
    """Directory-aware path comparison.

    Suffix matching in both directions already covers every legitimate spelling:
    an absolute path from the run's cwd, the repo-relative path, and a bare
    basename (`flagging.py` is a suffix of `gradio/flagging.py`). A bare-basename
    fallback on top of that would only ever fire for the case suffix matching
    deliberately rejects — a same-named file in a *different* directory, such as
    gradio's `client/python/gradio_client/flagging.py` against a ground truth of
    `gradio/flagging.py` — handing out free true positives in any repo with
    duplicated filenames.
    """
    truth = truth_file.replace("\\", "/")
    r = reported_path.replace("\\", "/")
    return r == truth or r.endswith("/" + truth) or truth.endswith("/" + r)


def matches(reported, truth_file, truth_line=None):
    """True if a reported location refers to the ground-truth construct.

    File match alone is NOT enough. A real codebase puts several unrelated
    constructs in one file: gradio's screen_recording_utils.py holds this eval's
    decoy at line 14 and a genuine upstream finding at line 279. Scoring on
    filename alone counted that upstream finding as "the decoy reported as real"
    — inverting the result on a run that had done nothing wrong.

    A report that names a file with no line at all still matches, since refusing
    to score it would be harsher than the evidence supports.
    """
    for r, line in reported:
        if not same_file(r, truth_file):
            continue
        if truth_line is None or line is None:
            return True
        if abs(line - truth_line) <= LINE_WINDOW:
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

    found = [v for v in vulns if matches(reported, v["file"], v["line"])]
    missed = [v for v in vulns if not matches(reported, v["file"], v["line"])]

    decoy_reported = matches(reported, decoy["file"], decoy["line"])
    decoy_examined = matches(examined, decoy["file"], decoy["line"])

    # Findings that are none of the three injected sites.
    #
    # These are NOT false positives. The fixture is a real 772-file project that
    # contains its own issues: a run found `create_subprocess_shell` with an
    # interpolated path at screen_recording_utils.py:279, which is upstream
    # gradio code and a genuine instance of the same root cause. Ground truth
    # only knows what was injected, so it cannot judge these — calling them false
    # positives punished the workflow for sweeping wider than the baseline, which
    # is the exact behaviour the eval exists to reward.
    #
    # They are surfaced for a human to read and deliberately excluded from the
    # verdict. Only the injected decoy is a definite false positive.
    known = [(v["file"], v["line"]) for v in vulns] + [(decoy["file"], decoy["line"])]
    unreviewed = sorted(
        f"{p}:{ln}" if ln else p
        for p, ln in reported
        if not any(matches({(p, ln)}, kf, kl) for kf, kl in known)
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
        "unreviewed_findings": unreviewed,
        "false_positives": 1 if decoy_reported else 0,
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
    # unreviewed_findings deliberately does NOT fail the run: they are findings in
    # real upstream code that ground truth cannot adjudicate. Read them by hand.
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


# The decoy written up exactly as variant-report-template.md prescribes: verdict in
# its own Status row, **Location:** on a separate line. Distinct from
# REFUTED_IN_TABLE, where the refuted row carries the path itself.
REFUTED_STATUS_ROW = """
## Findings
### Variant #1
**Location:** `src/a.py:1`
### Variant #2
**Location:** `src/b.py:2`
### Variant #3: Decoy -- argv form

| Severity | Confidence | Status |
|----------|------------|--------|
| N/A | High | Refuted |

**Location:** `src/decoy.py:3`

**Analysis:** uses argv form, not shell. Prefer argv separation everywhere.
"""

# A triage table inside a block must not void the block's own finding just because
# one of its rows refutes a different file.
REFUTED_ROW_BESIDE_REAL = """
## Findings
### Variant #1
**Location:** `src/a.py:1`
### Variant #2
| # | Location | Verdict |
|---|---|---|
| a | `src/decoy.py:3` | REFUTED |

**Location:** `src/b.py:2`
"""

# A language PATH_RE does not know. Must be ungradeable, not a silent zero.
UNKNOWN_LANGUAGE = """
## Findings
### Variant #1
**Location:** `src/a.erl:1`
### Variant #2
**Location:** `src/b.erl:2`
"""

# Same basename, different directory. Must NOT credit the ground-truth variant.
SAME_BASENAME_ELSEWHERE = """
## Findings
### Variant #1
**Location:** `src/a.py:1`
### Variant #2
**Location:** `vendor/pkg/b.py:2`
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
    assert ok, "an unreviewed finding must NOT fail the run"
    assert s["unreviewed_findings"] == ["src/unrelated.py:9"], s
    assert s["false_positives"] == 0, "an unreviewed finding is not a false positive"
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
    assert s["unreviewed_findings"] == [], f"a data-flow mention is not a finding: {s}"
    ok, _ = verdict(s)
    assert ok, f"should pass: {s}"
    checks += 1

    s = grade(SEED_IN_OWN_SECTION, SELF_TEST_ENTRY)
    assert s["new_variants_found"] == 1, s
    ok, why = verdict(s)
    assert ok, f"seed outside Findings is a convention, not a miss: {why}"
    checks += 1

    s = grade(REFUTED_STATUS_ROW, SELF_TEST_ENTRY)
    assert not s["decoy_reported_as_real"], f"a Refuted status row voids the block: {s}"
    assert s["decoy_examined_and_ruled_out"], s
    ok, why = verdict(s, require_decoy_examined=True)
    assert ok, f"the shipped template's refutation shape must pass: {why}"
    checks += 1

    s = grade(REFUTED_ROW_BESIDE_REAL, SELF_TEST_ENTRY)
    assert s["true_positives"] == 2, f"a refuted row about another file is not a block verdict: {s}"
    assert not s["decoy_reported_as_real"], s
    checks += 1

    try:
        grade(UNKNOWN_LANGUAGE, SELF_TEST_ENTRY)
    except GradingError:
        checks += 1
    else:  # pragma: no cover
        raise AssertionError("an unparseable language must be ungradeable, not zero")

    s = grade(SAME_BASENAME_ELSEWHERE, SELF_TEST_ENTRY)
    assert s["new_variants_found"] == 0, f"a same-named file elsewhere is not the variant: {s}"
    assert s["unreviewed_findings"] == ["vendor/pkg/b.py:2"], s
    checks += 1

    expected = 13
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
