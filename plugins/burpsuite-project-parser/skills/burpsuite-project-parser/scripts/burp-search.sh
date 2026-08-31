#!/bin/bash
# burp-search.sh - Search Burp Suite project files using burpsuite-project-file-parser
# Requires: burpsuite-project-file-parser extension installed in Burp Suite

set -euo pipefail

# How many non-JSON lines are echoed to stderr before the rest are counted instead of printed.
#
# Uncapped this is a hole, not a diagnostic. When NO line is JSON -- the missing-extension case this script
# exists to catch -- awk never writes to stdout, so it never takes SIGPIPE, so a documented downstream
# `head -c 50000` cannot close the pipeline early. It blocks to EOF while every line Burp produced is mirrored
# to stderr, where the caller captures it and no documented output limit applies. Measured against a 100k-line
# non-JSON stream: 8.4 MB of stderr behind a `head -c 200` that could not terminate. Under the bare exec this
# replaced, those bytes went to stdout where `head` truncated them.
#
# Twenty lines is enough to recognise a licence banner or a Java stack trace; the suppressed count is what says
# the stream kept going.
readonly STDERR_LINE_CAP=20
# And how long any one of those lines may be. The line cap alone bounds nothing when the stream is one very
# long line, which SKILL.md:217 already records as a real shape ("A single 10MB response on one line will show
# high byte count but only 1 line").
readonly STDERR_LINE_MAXLEN=500

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
  "$@" | awk -v cap="$STDERR_LINE_CAP" -v maxlen="$STDERR_LINE_MAXLEN" '
    /^[[:space:]]*\{/ { print; fflush(); json++; next }
    # A blank or whitespace-only line is not output Burp meant to produce, and counting it makes an
    # empty-but-correct result exit 4 with "the extension is not loaded" -- a wrong diagnosis on a healthy
    # install, off one trailing newline. It also mirrors as a diagnostic with nothing after the colon.
    /^[[:space:]]*$/ { next }
    {
      other++
      if (other <= cap) {
        line = $0
        # The cap bounds how many lines are mirrored; this bounds how long one may be. Without it a single
        # 10 MB line -- a raw body or a base64 blob, which SKILL.md documents as a real shape -- passes the
        # count check and is written to stderr in full, where the documented `head -c` on stdout cannot reach
        # it. These bytes come from captured HTTP traffic, so length is attacker-influenced.
        if (length(line) > maxlen) line = substr(line, 1, maxlen) " ... [truncated, " length($0) " bytes]"
        print "burp-search.sh: ignored non-JSON output: " line > "/dev/stderr"
      }
    }
    END {
      if (other > cap) {
        printf "burp-search.sh: %d further non-JSON line(s) suppressed.\n", other - cap > "/dev/stderr"
      }
      if (json == 0 && other == 0) exit 3
      if (json == 0) exit 4
    }
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
    echo "" >&2
    echo "Tell them apart with a control query -- a selector that must return rows if the parser is" >&2
    echo "working at all, run against the same project file:" >&2
    echo "" >&2
    printf '  %s %q proxyHistory.request.headers | head -c 2000\n' "$0" "$PROJECT_FILE" >&2
    echo "" >&2
    echo "  rows on stdout -> the parser works, and your narrower query genuinely matched nothing." >&2
    echo "                    Report that as a result, not as a failure." >&2
    echo "  exit 3 again   -> nothing at all comes back through the parser. Either the extension is" >&2
    echo "                    not loaded, or this project holds no proxy history. Check the project" >&2
    echo "                    file is the one you meant and is non-empty, then check Burp Suite ->" >&2
    echo "                    Extensions for burpsuite-project-file-parser." >&2
    echo "  exit 4 again   -> Burp started and dropped the flags; the extension is not loaded." >&2
    echo "" >&2
    echo "Run the control query before concluding anything about this project's traffic. Assuming the" >&2
    echo "extension is loaded is how an unverified empty result becomes a clean bill of health." >&2
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
