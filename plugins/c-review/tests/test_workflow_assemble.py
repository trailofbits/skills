"""The assemble step's post-processing, exercised through node against the real file.

`ASSEMBLE_SCHEMA` requires only `ok` — it has to, because the failure return carries just
`ok` and `error` — so every count the assembler prints is optional on the way back. Anything
that reads one of those optionals has to distinguish *absent* from *zero*: an agent that
forgot to transcribe `unrecognised_parts` is a run where nobody looked, not a run where
nothing was found, and part files no rule reads are whole agents' output in no artifact.

The same applies, harder, to `checks_required`. `coverage: null` came back from a healthy
run whose agent did not copy the count, from a run whose units.json never landed in the
output directory, and from a run that wrote no ledger row at all — three different stories,
one return value, and nothing logged for any of them.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "c-review.js"

# Not `skipif`. These are the only tests that exercise workflows/c-review.js at all, and a
# suite of seventeen silent skips exits 0 — the zero-item pass AGENTS.md forbids. CI's
# ubuntu-latest image happens to ship node and nothing asserts it, so a skip would be load
# bearing by accident. Set C_REVIEW_ALLOW_NO_NODE=1 to opt out deliberately.
if shutil.which("node") is None:  # pragma: no cover - environment guard
    import os

    if os.environ.get("C_REVIEW_ALLOW_NO_NODE") == "1":
        pytestmark = pytest.mark.skip(reason="C_REVIEW_ALLOW_NO_NODE=1")
    else:
        pytest.fail(
            "node is not installed, so the workflow contract tests would all skip and this "
            "suite would pass having checked nothing. Install node, or set "
            "C_REVIEW_ALLOW_NO_NODE=1 to accept the gap deliberately.",
            pytrace=False,
        )


def _snippet() -> str:
    """The real count derivations and their logging, as a runnable fragment."""
    src = WORKFLOW.read_text(encoding="utf-8")
    start = src.index("const artifactsWritten =")
    end = src.index("\nreturn {", start)
    return src[start:end]


def _probe(assembled_literal: str) -> dict:
    script = (
        "const PARTS_DIR = '/run/parts';\n"
        "const OUTPUT_DIR = '/run';\n"
        "const logs = [];\n"
        "const log = (m) => logs.push(m);\n"
        f"const assembled = {assembled_literal};\n"
        + _snippet()
        + "\nconsole.log(JSON.stringify({value: unrecognisedParts, "
        "coverage: checksRequired, written: artifactsWritten, logs: logs}));\n"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


HEALTHY = (
    "{ok: true, artifacts_written: true, reported: 12, unrecognised_parts: 0, "
    "checks_required: 41, checks_completed: 41, checks_satisfied: 41}"
)


def test_an_omitted_count_is_unchecked_not_zero():
    """The schema permits `{ok: true, reported: 12}`. Reading that as "no unrecognised parts"
    prints a clean result for a run whose part files nobody counted."""
    result = _probe("{ok: true, reported: 12}")
    assert result["value"] is None
    assert any("UNCHECKED" in line for line in result["logs"])


def test_a_reported_count_still_warns():
    result = _probe("{ok: true, reported: 12, unrecognised_parts: 3, checks_required: 4}")
    assert result["value"] == 3
    assert any("3 part file(s)" in line and "NO artifact" in line for line in result["logs"])


def test_a_healthy_run_is_silent():
    """The one shape in which a 0 really is a count of zero, rather than a count nobody
    took."""
    result = _probe(HEALTHY)
    assert result["value"] == 0
    assert result["coverage"] == 41
    assert result["logs"] == []


def test_an_omitted_coverage_count_is_unmeasured_and_says_so():
    """Unlogged, `coverage: null` is indistinguishable from a fully covered run.

    SKILL.md has no branch for it, and the assembler's own "ledger gate did not run" goes to
    the stderr of a process that exited 0.
    """
    result = _probe("{ok: true, reported: 12, unrecognised_parts: 0}")
    assert result["coverage"] is None
    assert any("UNMEASURED" in line for line in result["logs"])


def test_a_zero_check_run_is_a_measurement_and_still_warns():
    """0 is a number, not an absence — and a gate that required 0 checks verified nothing."""
    result = _probe("{ok: true, reported: 0, unrecognised_parts: 0, checks_required: 0}")
    assert result["coverage"] == 0
    assert any("0 checks" in line for line in result["logs"])


def test_a_gate_rejection_reported_as_ok_still_reaches_the_run_log():
    """The rejection shape that satisfies every log branch: the agent reported `ok`, the
    artifacts are on disk, the counts came back, and only their disagreement makes it a
    failure. `!assembled.ok || !artifactsWritten` is false, `checks_required` is neither
    null nor 0 — so the run log says nothing about the one number the pipeline exists to
    produce, and the rejection survives only in the returned object.
    """
    result = _probe(
        "{ok: true, artifacts_written: true, reported: 12, unrecognised_parts: 0, "
        "checks_required: 445, checks_completed: 445, checks_satisfied: 400}"
    )
    assert any("REJECTED" in line and "400 of 445" in line for line in result["logs"]), result[
        "logs"
    ]


def _gate(assembled_literal: str) -> dict:
    """The real `gateAccepted` / `gateError` derivation, evaluated.

    Through `_snippet` rather than by extracting the `gateAccepted:` line of the return
    block: that line is now a reference, and an expression-scraping helper that stops
    matching is a test that stops testing.
    """
    script = (
        "const PARTS_DIR = '/run/parts';\nconst OUTPUT_DIR = '/run';\n"
        "const log = () => {};\n"
        f"const assembled = {assembled_literal};\n"
        + _snippet()
        + "\nconsole.log(JSON.stringify({accepted: gateAccepted, error: gateError}));\n"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def test_a_gate_rejection_does_not_report_the_artifacts_as_lost():
    """`ok` is not the artifact signal: reading it as one turns
    `{ok: false, error: 'gate rejected'}` into `artifactsWritten: false` and logs "artifacts
    were not written" over a complete findings.json, REPORT.md and REPORT.sarif. Every other
    optional in the same block is null-vs-zero guarded."""
    result = _probe("{ok: false, artifacts_written: true, error: 'gate rejected'}")
    assert result["written"] is True
    assert any("REJECTED" in line for line in result["logs"])
    assert not any("artifacts were not written" in line for line in result["logs"])


def test_ok_with_artifacts_written_false_is_neither_silent_nor_accepted():
    """The one shape meaning "the script says it exited 0 and the directory does not hold
    the artifacts", and it was the quietest return in the block.

    `ASSEMBLE_SCHEMA` makes `artifacts_written` REQUIRED precisely so a lost report can be
    detected, so something has to read it rather than copy it into the return: with log
    branches for `!assembled` and `!assembled.ok` only, this shape produces no line at all,
    `gateAccepted: true` and `artifactError: null` over a run with no findings.json.
    """
    literal = (
        "{ok: true, artifacts_written: false, reported: 12, unrecognised_parts: 0, "
        "checks_required: 41, checks_completed: 41, checks_satisfied: 41}"
    )
    result = _probe(literal)
    assert result["written"] is False
    assert any("artifacts were not written" in line for line in result["logs"]), result["logs"]
    gate = _gate(literal)
    assert gate["accepted"] is False
    assert gate["error"]


def test_the_field_is_required_by_the_schema():
    src = WORKFLOW.read_text(encoding="utf-8")
    block = src[
        src.index("const ASSEMBLE_SCHEMA = {") : src.index(
            "// ------", src.index("const ASSEMBLE_SCHEMA = {")
        )
    ]
    assert "required: ['ok', 'artifacts_written']" in block
    # And the agent is told to answer it from the directory, not from the exit code.
    assert "List the directory" in block


def test_an_assemble_agent_that_returned_nothing_is_unknown_not_false():
    """The `.catch(() => null)` makes a crashed agent indistinguishable from a real failure:
    the command can have exited 0 and written all three artifacts with only the structured
    return rejected. Reporting that as `false` tells the caller a complete report was lost,
    and the workflow never stats a single artifact path."""
    result = _probe("null")
    assert result["written"] is None
    assert any("UNKNOWN" in line for line in result["logs"])


@pytest.mark.parametrize(
    ("assembled", "expected"),
    [
        ("{ok: true, artifacts_written: true, checks_required: 41, checks_satisfied: 41}", True),
        ("{ok: false, artifacts_written: true, checks_required: 41, checks_satisfied: 41}", False),
        # A gate that measured NOTHING is not a gate that passed. `checks_required` is null
        # when there was no units.json, which is reachable because the workflow dispatches
        # on the detect agent's self-reported `units_ok` and nothing checks it against disk.
        ("{ok: true, artifacts_written: true}", False),
        ("null", False),
        # `ok` is the agent's transcription of an exit code and nothing verifies it, while
        # the same object carries the two numbers that answer the same question: the
        # assembler exits 0 only when every required check was satisfied, so this literal
        # contradicts itself and must not be accepted on the strength of `ok` alone.
        (
            "{ok: true, artifacts_written: true, checks_required: 445, "
            "checks_completed: 445, checks_satisfied: 400}",
            False,
        ),
    ],
)
def test_gate_accepted_requires_a_measurement(assembled, expected):
    assert _gate(assembled)["accepted"] is expected


@pytest.mark.parametrize(
    "assembled",
    [
        "null",
        "{ok: true, artifacts_written: true}",
        "{ok: true, artifacts_written: true, checks_required: 445, checks_satisfied: 400}",
        "{ok: false, artifacts_written: true, error: 'gate rejected'}",
        # `error` is OPTIONAL in ASSEMBLE_SCHEMA, so `ok: false` with every other check
        # passing is a schema-valid return that satisfies no branch of the derivation. It is
        # the one rejection that can reach the end of the chain with nothing to say.
        "{ok: false, artifacts_written: true, checks_required: 41, checks_satisfied: 41}",
    ],
)
def test_a_rejected_gate_always_carries_a_reason(assembled):
    """Derive `artifactError` from `ok` alone and every failure the checks above can reach
    comes back with no reason in the returned object at all."""
    result = _gate(assembled)
    assert result["accepted"] is False
    assert result["error"], "gateAccepted is false and artifactError says nothing"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
