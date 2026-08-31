#!/bin/bash
# burp-search.sh - Search Burp Suite project files using burpsuite-project-file-parser
# Requires: burpsuite-project-file-parser extension installed in Burp Suite

set -euo pipefail

# Platform-specific default paths
case "$(uname -s)" in
  Darwin)
    _default_java="/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java"
    _default_jar="/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar"
    ;;
  Linux)
    _default_java="/opt/BurpSuiteProfessional/jre/bin/java"
    _default_jar="/opt/BurpSuiteProfessional/burpsuite_pro.jar"
    ;;
  *)
    echo "Warning: Unsupported platform '$(uname -s)'. Set BURP_JAVA and BURP_JAR environment variables." >&2
    _default_java=""
    _default_jar=""
    ;;
esac

JAVA_PATH="${BURP_JAVA:-$_default_java}"
BURP_JAR="${BURP_JAR:-$_default_jar}"

usage() {
  cat <<EOF
Usage: burp-search.sh <project-file> [flags...]

Search and extract data from Burp Suite project files.

Arguments:
  project-file    Path to .burp project file

Flags (combine multiple as needed):
  auditItems                    Extract all security audit findings
  proxyHistory                  Dump all proxy history entries
  siteMap                       Dump all site map entries
  responseHeader='regex'        Search response headers with regex
  responseBody='regex'          Search response bodies with regex

Sub-component filters (for proxyHistory/siteMap):
  proxyHistory.request.headers  Only request headers
  proxyHistory.request.body     Only request body
  proxyHistory.response.headers Only response headers
  proxyHistory.response.body    Only response body
  (same patterns work for siteMap)

Environment variables:
  BURP_JAVA   Path to Java executable (default: Burp's bundled JRE)
  BURP_JAR    Path to burpsuite_pro.jar

Examples:
  burp-search.sh project.burp auditItems
  burp-search.sh project.burp "responseHeader='.*nginx.*'"
  burp-search.sh project.burp proxyHistory.request.headers

Output: JSON objects, one per line

Exit codes:
  0   output produced
  1   bad usage, or a missing file, Java or JAR
  3   no output at all -- an empty result set and a missing parser extension look the same
  4   output, but not one JSON object -- Burp ignored the query flags, extension not loaded

Only JSON objects reach stdout; any other line is reported on stderr. Through a pipe the exit
code is invisible, so stderr is the signal to read -- or set -o pipefail and check PIPESTATUS.
EOF
  exit 1
}

if [ $# -lt 2 ]; then
  usage
fi

PROJECT_FILE="$1"
shift

if [ ! -f "$PROJECT_FILE" ]; then
  echo "Error: Project file not found: $PROJECT_FILE" >&2
  exit 1
fi

if [ -z "$JAVA_PATH" ]; then
  echo "Error: No default Java path for this platform." >&2
  echo "Set BURP_JAVA environment variable to your Java path" >&2
  exit 1
elif [ ! -f "$JAVA_PATH" ]; then
  echo "Error: Java not found at: $JAVA_PATH" >&2
  echo "Set BURP_JAVA environment variable to your Java path" >&2
  exit 1
fi

if [ -z "$BURP_JAR" ]; then
  echo "Error: No default Burp JAR path for this platform." >&2
  echo "Set BURP_JAR environment variable to your burpsuite_pro.jar path" >&2
  exit 1
elif [ ! -f "$BURP_JAR" ]; then
  echo "Error: Burp Suite JAR not found at: $BURP_JAR" >&2
  echo "Set BURP_JAR environment variable to your burpsuite_pro.jar path" >&2
  exit 1
fi

# Execute the search.
#
# Burp silently ignores flags it does not recognise, so with the parser extension missing it starts
# normally and drops the query -- producing either its own non-JSON startup output or nothing at all.
# Both look like a successful search that found nothing. Stream the output through awk rather than a
# temp file, so a large dump never lands on disk, and classify the WHOLE stream rather than just its
# first line. Judging line 1 alone breaks both ways: a working install may print a licence or startup
# line before the JSON, and a Java log line like `[main] INFO ...` would pass a check that accepts a
# leading `[`.
#
# `fflush()` on every emitted line is load-bearing, not decoration: awk block-buffers when its stdout
# is a pipe, and the documented workflows all pipe. Without it a long search over a large project
# prints nothing until Burp exits, where the bare `exec` this replaced streamed line by line. The
# flush restores that at the cost of one write per JSON object.
#
# Only JSON objects reach stdout. Anything else goes to stderr rather than being dropped, so a
# downstream `grep` or `jq` can never match a startup banner.
#   exit 3  nothing at all      -- an empty result set and a missing extension are indistinguishable
#   exit 4  output, but no JSON -- the flags were dropped; the extension is not loaded
# `set +e` rather than `|| true`: `true` is a command of its own and would reset PIPESTATUS before it
# could be read.
set +e
"$JAVA_PATH" -jar -Djava.awt.headless=true "$BURP_JAR" \
  --project-file="$PROJECT_FILE" \
  "$@" | awk '
    /^[[:space:]]*\{/ { print; fflush(); json++; next }
    { print "burp-search.sh: ignored non-JSON output: " $0 > "/dev/stderr"; other++ }
    END { if (json == 0 && other == 0) exit 3; if (json == 0) exit 4 }
  '
pipe_status=("${PIPESTATUS[@]}")
set -e
java_status="${pipe_status[0]}"
awk_status="${pipe_status[1]}"

# 141 is SIGPIPE: a downstream `head` or `jq` closed the pipe early, which the documented workflows do
# on purpose. The output already flowed, so it is not a failure.
if [ "$java_status" -ne 0 ] && [ "$java_status" -ne 141 ]; then
  echo "Error: Burp exited with status $java_status." >&2
  exit "$java_status"
fi

case "$awk_status" in
  0 | 141) ;;
  3)
    echo "Error: the parser produced no output." >&2
    echo "Either the query matched nothing, or the burpsuite-project-file-parser extension is not" >&2
    echo "loaded -- this script cannot tell which, so it does not report success." >&2
    echo "Check Burp Suite -> Extensions for burpsuite-project-file-parser, and that it is enabled." >&2
    echo "With the extension confirmed loaded, no output means the query matched nothing." >&2
    exit 3
    ;;
  4)
    echo "Error: Burp produced output, but not one JSON object, so it ignored the query flags." >&2
    echo "This is what a missing burpsuite-project-file-parser extension looks like: Burp starts" >&2
    echo "normally and drops flags it does not recognise." >&2
    echo "Install it from https://github.com/BuffaloWill/burpsuite-project-file-parser and add the" >&2
    echo "JAR under Burp Suite -> Extensions." >&2
    exit 4
    ;;
  *)
    echo "Error: output check failed with status $awk_status." >&2
    exit "$awk_status"
    ;;
esac
