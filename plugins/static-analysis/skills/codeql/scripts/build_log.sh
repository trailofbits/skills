#!/usr/bin/env bash
# Logging helpers shared by the build-database workflow and its reference docs.
# Source it: . "{baseDir}/scripts/build_log.sh" || exit 1
#
# The `|| exit 1` is not decoration. The guard below returns 1 without defining the helpers,
# and the blocks that source this do not set -e, so without it the diagnostic scrolls past and
# the next line is `log_step: command not found` — 127, which the caller reads as a failed
# build rather than an unwritable log.
#
# Defaulted, so sourcing this in a standalone block is safe: an unset LOG_FILE makes
# `tee -a ""` fail, which under pipefail reports a successful build as failed.
LOG_FILE="${LOG_FILE:-${OUTPUT_DIR:-.}/build.log}"

# Fail here while the cause is legible: an unwritable log makes every build method report
# failure and walks the ladder to --build-mode=none after a build that succeeded.
if ! : >>"$LOG_FILE" 2>/dev/null; then
  echo "ERROR: cannot write build log $LOG_FILE." >&2
  echo "  Usually \$OUTPUT_DIR was never created: mkdir -p \"\$OUTPUT_DIR\"." >&2
  echo "  Otherwise set LOG_FILE or OUTPUT_DIR to a writable path before sourcing this." >&2
  # `return` when sourced (the documented use), `exit` when run directly. shellcheck
  # cannot tell which, so it reads the second path as dead.
  # shellcheck disable=SC2317
  return 1 2>/dev/null || exit 1
fi

# `cmd | tee` reports tee's exit status. Without pipefail a failed build looks like a
# success, and callers that branch on the result take the wrong branch.
set -o pipefail

# Deliberately no `set -e`: the method ladder must survive each failed method to reach the
# next. Blocks that should abort on first error set `-e` themselves.

log_step() { echo "[$(date -Iseconds)] $1" >>"$LOG_FILE"; }
log_cmd() { echo "[$(date -Iseconds)] COMMAND: $1" >>"$LOG_FILE"; }
log_result() {
  echo "[$(date -Iseconds)] RESULT: $1" >>"$LOG_FILE"
  echo "" >>"$LOG_FILE"
}

# Run a command, log its output, keep its exit status. Arguments as a list: a command built
# into a string and run unquoted word-splits on any path containing a space.
run_logged() {
  log_cmd "$*"
  "$@" 2>&1 | tee -a "$LOG_FILE"
}
