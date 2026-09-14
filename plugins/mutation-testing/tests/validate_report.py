#!/usr/bin/env python3
"""Assert a mutation-testing analysis report got the vault fixture right.

The eval's LLM grader judges reasoning quality; this script asserts the
structural facts a grader reads past. The load-bearing check is negative: line
37's `balance >= 0` mutant must NOT be listed as equivalent. `balance != 0` on
the same line genuinely is equivalent for `u64`, so a report that filters both
looks superficially correct and is wrong. A regex cannot scope "absent from the
equivalents table specifically" — this can.

Usage: validate_report.py REPORT.md [--expect-fail]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Every uncaught mutant in the captured campaign, keyed by the source line it
# sits on. Regenerate with `mewt results` against evals/weak-suite-analysis/fixture.
SURVIVOR_LINES = {
    24: "the `if !is_admin` authorization guard",
    27: "the `amount > account.balance` funds guard",
    31: "the `record_withdrawal(amount);` call",
    37: "the `balance > 0` comparison",
    41: "the `eprintln!` in `record_withdrawal`",
}

HEADING = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)

# `>= 0` and `!= 0` survive markdown mangling (backticks, bold, HTML escapes) as
# long as we ignore whitespace between the operator and the operand.
MUTANT_GE = re.compile(r">=\s*0")
MUTANT_NE = re.compile(r"!=\s*0")


class ReportError(Exception):
    """A violated expectation, phrased as what the report got wrong."""


def sections(text: str) -> list[tuple[int, str, str]]:
    """Split markdown into (level, title, body) triples, body ending at the next
    heading of the same or a shallower level."""
    marks = [(m.start(), len(m.group(1)), m.group(2).strip()) for m in HEADING.finditer(text)]
    out = []
    for i, (start, level, title) in enumerate(marks):
        end = len(text)
        for later_start, later_level, _ in marks[i + 1 :]:
            if later_level <= level:
                end = later_start
                break
        out.append((level, title, text[start:end]))
    return out


def find_section(secs: list[tuple[int, str, str]], want: re.Pattern[str]) -> tuple[str, str] | None:
    for _, title, body in secs:
        if want.search(title):
            return title, body
    return None


def check(text: str) -> list[str]:
    """Return the list of failures; empty means the report is correct."""
    failures = []
    secs = sections(text)
    if not secs:
        raise ReportError("report has no markdown headings — not a report")

    equivalents = find_section(secs, re.compile(r"equivalent", re.IGNORECASE))
    if equivalents is None:
        raise ReportError(
            "report has no equivalent-mutants section; expected one listing the "
            "`balance != 0` false positive"
        )
    _, equiv_body = equivalents

    # Table rows only. Prose in the section intro explains what equivalence is
    # and will mention both operators without classifying either.
    equiv_rows = [
        line
        for line in equiv_body.splitlines()
        if line.lstrip().startswith("|") and not re.match(r"^\s*\|[\s|:-]*\|?\s*$", line)
    ]
    # Drop the header row; a table with only a header classified nothing.
    equiv_rows = [r for r in equiv_rows if not re.search(r"\bMutation\b.*\bReason\b", r)]
    if not equiv_rows:
        failures.append(
            "the equivalent-mutants section lists no mutants; `balance != 0` on line 37 "
            "is a genuine false positive and must appear there"
        )

    ge_equiv = [r for r in equiv_rows if MUTANT_GE.search(r)]
    ne_equiv = [r for r in equiv_rows if MUTANT_NE.search(r)]

    if ge_equiv:
        failures.append(
            "`balance >= 0` is listed as an equivalent mutant. It is a real finding: it "
            "differs from `balance > 0` at balance == 0, and no test calls has_funds(0). "
            f"Offending row: {ge_equiv[0].strip()}"
        )
    if not ne_equiv:
        failures.append(
            "`balance != 0` is not listed as an equivalent mutant. For an unsigned u64 it "
            "is indistinguishable from `balance > 0` and must be filtered as a false positive"
        )

    # The `>= 0` mutant has to be somewhere — silently dropping it also fails.
    if not MUTANT_GE.search(text.replace(equiv_body, "")):
        failures.append(
            "`balance >= 0` does not appear outside the equivalents section; it is a real "
            "surviving mutant and needs its own finding"
        )

    tier1 = find_section(
        secs,
        re.compile(r"(tier\s*1|critical)(?!.*(distribution|summary))", re.IGNORECASE),
    )
    if tier1 is None:
        failures.append(
            "report has no Tier 1 / Critical section; the two `if !is_admin` mutants are "
            "access-control gaps and belong there"
        )
    else:
        _, tier1_body = tier1
        if "is_admin" not in tier1_body:
            failures.append(
                "the Tier 1 / Critical section never mentions `is_admin`; the authorization "
                "guard mutants are the highest-severity survivors in this campaign"
            )
        for demoted in ("record_withdrawal", "eprintln"):
            if demoted in tier1_body:
                failures.append(
                    f"`{demoted}` is filed under Tier 1 / Critical; it is observability "
                    "code and belongs in the lowest tier"
                )

    for line, what in SURVIVOR_LINES.items():
        # Anchored to something that reads as a line reference. A bare `\b24\b`
        # also matches "24 tested" in the summary table, which would let a
        # report that never discusses line 24 pass this check.
        # Tolerates the markdown between the word and the number in
        # `**Line:** 24`, and accepts a bare table cell such as `| 24 |`.
        cited = re.compile(rf"(?:[Ll]ines?[^\w]{{0,6}}|\|\s*){line}\b")
        if not cited.search(text):
            failures.append(f"line {line} is never referenced — {what} has a surviving mutant")

    return failures


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--expect-fail"]
    expect_fail = "--expect-fail" in sys.argv[1:]
    if len(args) != 1:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2

    path = Path(args[0])
    try:
        text = path.read_text(encoding="utf8")
    except OSError as error:
        print(f"error: cannot read report {path}: {error}", file=sys.stderr)
        return 2

    if len(text.strip()) < 500:
        failures = [f"report is {len(text.strip())} bytes — a stub, not an analysis"]
    else:
        try:
            failures = check(text)
        except ReportError as error:
            failures = [str(error)]

    if expect_fail:
        if failures:
            print(f"{path.name}: correctly rejected ({len(failures)} problem(s))")
            for failure in failures:
                print(f"  - {failure}")
            return 0
        print(
            f"error: {path.name} was expected to fail validation but passed — "
            "the checks have no teeth",
            file=sys.stderr,
        )
        return 1

    if failures:
        print(f"error: {path.name} failed validation:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"{path.name}: all checks passed (8 survivors, 1 equivalent, Tier 1 access control)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
