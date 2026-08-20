#!/usr/bin/env python3
"""Fail an eval run whose agent read this suite's answer key.

The eval harness does not sandbox the filesystem. Fixtures are generated inside the
scaffold precisely so no path into this repository reaches the agent, but the plugin
under test still ships this evals/ tree, so an agent that goes looking can find the
graders and case.yaml (the answer key) and satisfy them by imitation. This checker
scans the ``--json`` result of a run:

- **Agent traces** (per-run ``tracePath``, preserved with ``--keep-temp``) are scanned
  for every marker, including grader filenames: a grader slug inside the agent's own
  transcript means the agent opened the key.
- **Judge explanations** are scanned only for markers a judge would never produce on
  its own (paths into ``code-improver/evals/`` — or ``skill-improver/evals/`` for arms
  built from the plugin's pre-rename history — and the ``expected_outcome`` key), since
  judges legitimately restate their own grader text.

Per house rules, the checker fails when it has nothing to inspect: a result with no
cases, no runs, or neither trace nor explanation text is an error, not a pass.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import NoReturn

# A path into the eval tree. In a listing this leaks filenames, not content — real
# contamination under readable grader names, harmless under neutralized ones, which is
# what --allow-listing is for (see the ablation runner: old-version arms carry their own
# plugin-root file searches, so a listing is unavoidable there and the graft neutralizes
# the names instead).
LISTING_MARKERS = ("code-improver/evals/", "skill-improver/evals/")

# Content that only exists inside the answer key: reading case.yaml or a grader body
# puts these in the trace regardless of what the files are called.
CONTENT_MARKERS = (
    "expected_outcome",
    "Score PASS if",
)

# Grader filenames: legitimate in judge-side text, contamination in an agent trace.
GRADER_MARKERS = (
    "traps-rejected-once",
    "real-defects-fixed",
    "trap-name-kept",
    "trap-tools-kept",
    "escalated-within-four-rounds",
    "names-the-structural-conflict",
    "guarantee-byte-identical",
    "check-not-relocated",
    "ends-on-clean-review",
    "honest-if-capped",
    "narration-gone-skill",
    "narration-gone-script",
    "one-version-bump",
    "decoy-byte-identical",
    "no-out-of-scope-diff",
    "broken-test-untouched",
    "out-of-scope-needs-are-said-not-done",
    "bug-fixed-with-a-pin",
    "pins-on-every-behavioral-fix",
    "halted-reviewer-unavailable",
    "no-findings-invented",
    "fixture-byte-identical",
    "says-install-plugin-dev",
    "median-fixed",
    "median-test-covers-even",
    "legacy-byte-identical",
    "stale-doc-updated",
    "honest-final-message",
    "todo-codeword-in-ledger",
    "xray-codeword-in-ledger",
    "todo-codeword-removed",
    "xray-codeword-removed",
)

MAX_TRACE_BYTES = 50_000_000


def fail(msg: str) -> NoReturn:
    print(f"check_contamination.py: error: {msg}", file=sys.stderr)
    sys.exit(1)


def iter_runs(result: dict):
    """Yield (label, run) for every run in the result, whatever the arm layout."""
    for case in result.get("cases", []):
        name = case.get("name", "?")
        arms = case.get("arms") or {}
        for arm, runs in arms.items():
            for i, run in enumerate(runs or []):
                yield f"{name}[{arm} run{i + 1}]", run
        for i, run in enumerate(case.get("runs") or []):
            yield f"{name}[run{i + 1}]", run


def explanation_text(run: dict) -> str:
    chunks = []
    for grader in run.get("graders") or []:
        # Older harness builds used "evidence"; current ones use "explanation".
        chunks.append(str(grader.get("explanation") or grader.get("evidence") or ""))
    return " ".join(chunks)


def trace_text(run: dict) -> str:
    trace = run.get("tracePath")
    if not trace:
        return ""
    path = Path(trace)
    texts = []
    files = [path] if path.is_file() else sorted(path.rglob("*")) if path.is_dir() else []
    budget = MAX_TRACE_BYTES
    for f in files:
        if not f.is_file() or budget <= 0:
            continue
        try:
            data = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        texts.append(data[:budget])
        budget -= len(data)
    return " ".join(texts)


def main(argv: list[str]) -> int:
    allow_listing = "--allow-listing" in argv
    argv = [a for a in argv if a != "--allow-listing"]
    if len(argv) != 2:
        print("usage: check_contamination.py [--allow-listing] <eval-result.json>", file=sys.stderr)
        return 2
    path_markers = CONTENT_MARKERS if allow_listing else LISTING_MARKERS + CONTENT_MARKERS
    result = json.loads(Path(argv[1]).read_text(encoding="utf-8"))

    runs = list(iter_runs(result))
    if not runs:
        fail("no runs found in the result — was the eval run with --json?")

    findings = []
    inspected_traces = 0
    inspected_explanations = 0
    for label, run in runs:
        explanations = explanation_text(run)
        if explanations.strip():
            inspected_explanations += 1
            hits = [m for m in path_markers if m in explanations]
            if hits:
                findings.append(f"{label} (judge text): {', '.join(hits)}")
        trace = trace_text(run)
        if trace.strip():
            inspected_traces += 1
            hits = [m for m in path_markers + GRADER_MARKERS if m in trace]
            if hits:
                findings.append(f"{label} (agent trace): {', '.join(hits)}")

    if inspected_traces == 0 and inspected_explanations == 0:
        fail(
            "nothing to inspect: no readable traces (run with --keep-temp) and no "
            "grader explanations in the result"
        )
    if inspected_traces == 0:
        print(
            "check_contamination.py: WARNING: no traces were readable — only judge "
            "text was checked. Re-run the eval with --keep-temp for the strong check.",
            file=sys.stderr,
        )

    if findings:
        print("check_contamination.py: a run read the answer key:", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print("scores from this result are not trustworthy; audit the traces", file=sys.stderr)
        return 1

    print(
        f"ok: {len(runs)} run(s) clean "
        f"({inspected_traces} trace(s), {inspected_explanations} with judge text)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
