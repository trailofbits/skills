#!/usr/bin/env bash
#
# Layer 3 capture, single run. A thin wrapper around capture-runs.sh.
#
# It used to be a second, independent implementation of the same capture, and it
# corrupted the checked-in fixture set every time it ran:
#
#   - it wrote run.stream.jsonl straight into tests/fixtures/ without calling
#     scrub_capture.py, committing transcript dirs and /Users/<you> into a
#     tracked file
#   - it wrote "passed": null, which test_regrade.py asserts against, so the
#     promoted fixture failed its own regrade
#   - it never wrote run.journal.jsonl at all, which test_regrade.py requires —
#     while stream.py told the reader to "run tests/capture-run.sh first"
#   - it echoed CAPTURE_MODEL and CAPTURE_EFFORT and wrote them into
#     run.meta.json without ever passing them to `claude`, so the provenance
#     that test_run_metadata_records_model_effort_and_cli_version checks was
#     fabricated
#
# capture-runs.sh already does all of this correctly, including the regrade and
# the pass/fail verdict that gates promotion. One run is just RUNS=1.
#
# Run this in a git worktree or a container: workflow subagents always run in
# acceptEdits regardless of session mode, and file edits are auto-approved.
# (capture-runs.sh creates the worktree for you.)
#
# Prerequisites:
#   - the fp-check plugin installed from this marketplace
#   - Dynamic workflows enabled (Claude Code >= 2.1.154; Pro: /config)
#
# Usage:
#   tests/capture-run.sh [OUTPUT_DIR]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "capture-run: one run via capture-runs.sh; promoting it to tests/fixtures/" >&2
echo "capture-run: for a pass RATE, use: RUNS=3 tests/capture-runs.sh" >&2

RUNS=1 PROMOTE=1 exec "$HERE/capture-runs.sh" "$@"
