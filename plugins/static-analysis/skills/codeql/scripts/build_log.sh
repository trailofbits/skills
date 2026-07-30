#!/usr/bin/env bash
# Logging helpers shared by the build-database workflow and its reference docs.
# Source it: . "{baseDir}/scripts/build_log.sh"
#
# LOG_FILE defaults below, so sourcing this in a standalone block is safe: an unset
# LOG_FILE would make `tee -a ""` fail, and under pipefail run_logged would then report
# a successful build as failed and send the method ladder to the next rung.
LOG_FILE="${LOG_FILE:-${OUTPUT_DIR:-.}/build.log}"

# Under pipefail, tee's failure is run_logged's failure. So a log file that cannot be
# written makes every build method report failure, and the ladder walks all the way to
# --build-mode=none after a build that actually succeeded — presenting a writable-path
# problem as a CodeQL one. Fail here instead, while the cause is still legible.
if ! : >>"$LOG_FILE" 2>/dev/null; then
  echo "ERROR: cannot write build log $LOG_FILE." >&2
  echo "  Usually \$OUTPUT_DIR was never created: mkdir -p \"\$OUTPUT_DIR\"." >&2
  echo "  Otherwise set LOG_FILE or OUTPUT_DIR to a writable path before sourcing this." >&2
  # Sourced, which is the documented use, `return` leaves the caller's shell running.
  # Run directly it fails, and `exit` is the only way out — shellcheck reads that second
  # path as dead because it cannot tell which way the file was invoked.
  # shellcheck disable=SC2317
  return 1 2>/dev/null || exit 1
fi

# `cmd | tee` reports tee's exit status. Without pipefail a failed build looks like a
# success, and callers that branch on the result take the wrong branch.
set -o pipefail

# Deliberately no `set -e`. The build-database method ladder tries autobuild, then a
# custom command, then multi-step, then no-build, and must survive each failure to reach
# the next. Blocks that should abort on first error set `-e` themselves.

log_step() { echo "[$(date -Iseconds)] $1" >>"$LOG_FILE"; }
log_cmd() { echo "[$(date -Iseconds)] COMMAND: $1" >>"$LOG_FILE"; }
log_result() {
  echo "[$(date -Iseconds)] RESULT: $1" >>"$LOG_FILE"
  echo "" >>"$LOG_FILE"
}

# Run a command, log its output, and keep its exit status.
# Takes arguments as a list. Building a command into a string and running it unquoted
# word-splits on any path containing a space.
run_logged() {
  log_cmd "$*"
  "$@" 2>&1 | tee -a "$LOG_FILE"
}
