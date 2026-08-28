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
  3   no output -- an empty result set and a missing parser extension look the same
  4   output was not JSON -- Burp ignored the query flags, extension not loaded
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
# Both look like a successful search that found nothing. Stream the output through awk so the common
# case still pipes to jq/head unbuffered by a temp file, and classify what went past:
#   exit 3  no output at all       -- an empty result set and a missing extension are indistinguishable
#   exit 4  output that is not JSON -- the flags were dropped; the extension is not loaded
# `set +e` rather than `|| true`: `true` is a command of its own and would reset PIPESTATUS before it
# could be read.
set +e
"$JAVA_PATH" -jar -Djava.awt.headless=true "$BURP_JAR" \
  --project-file="$PROJECT_FILE" \
  "$@" | awk '
    NR == 1 && $0 !~ /^[[:space:]]*[{[]/ {
      not_json = 1
      print "burp-search.sh: first line of output was not JSON: " $0 > "/dev/stderr"
    }
    { print; lines++ }
    END { if (lines == 0) exit 3; if (not_json) exit 4 }
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
    echo "Error: Burp produced output that is not JSON, so it ignored the query flags." >&2
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
