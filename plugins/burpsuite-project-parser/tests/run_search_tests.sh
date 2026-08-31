#!/usr/bin/env bash
# Regression suite for burp-search.sh's output classification.
#
# Deterministic, offline, free. This is the suite `make shell-suites` and CI discover via
# `find plugins -type f -path '*/tests/*' -name 'run_*.sh'`, so it must stay cheap and must
# never need Burp Suite.
#
# What it exists to pin: the script's whole reason for classifying output is that Burp silently
# ignores flags it does not recognise, so a missing parser extension produces a clean-looking
# empty run. Every assertion below distinguishes "the query matched nothing" from "the query
# never ran". Burp Pro is not a CI dependency, so a stub stands in for it -- which means this
# suite proves the classification logic, NOT Burp's real behaviour. See the note at the end.
#
# The assertion count is asserted. A suite that stops running its checks reports success just as
# loudly as one that passes them, which is the failure mode the script under test also exists to
# prevent.

set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$PLUGIN_ROOT/skills/burpsuite-project-parser/scripts/burp-search.sh"
readonly EXPECTED_ASSERTIONS=21

[ -x "$SCRIPT" ] || {
  echo "run_search_tests.sh: not executable: $SCRIPT" >&2
  exit 1
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/burp-search-tests.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

touch "$WORK/project.burp" "$WORK/fake.jar"

# Stands in for Burp. Ignores its arguments and replays STUB_MODE, which is the point: the real
# Burp ignoring --project-file and the query flags is exactly the bug being guarded against.
cat >"$WORK/java" <<'STUB'
#!/usr/bin/env bash
case "$STUB_MODE" in
  json)     printf '{"a":1}\n{"b":2}\n' ;;
  empty)    : ;;
  banner)   printf 'Burp Suite Professional v2024.1\nStarting...\n' ;;
  logline)  printf '[main] INFO burp.Startup - ready\n' ;;
  mixed)    printf 'Burp Suite Professional\n{"a":1}\n' ;;
  indented) printf '   {"a":1}\n' ;;
  fail7)    printf 'boom\n' >&2; exit 7 ;;
  jsonfail) printf '{"a":1}\n'; exit 7 ;;
  big)      awk 'BEGIN{for(i=0;i<100000;i++) printf "{\"i\":%d}\n", i}' ;;
  noisy)    awk 'BEGIN{for(i=0;i<100000;i++) print "Burp Suite Professional startup line " i}' ;;
  longline) awk 'BEGIN{s="x"; while (length(s) < 2000000) s = s s; print s}' ;;
  blank)    printf '\n   \n' ;;
  slow)     for i in 1 2 3; do printf '{"i":%d}\n' "$i"; sleep 1; done ;;
esac
STUB
chmod +x "$WORK/java"

PASS=0
FAIL=0
RAN=0

eq() { # eq <actual> <expected> <description>
  RAN=$((RAN + 1))
  if [ "$1" = "$2" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "  ✗ $3" >&2
    echo "      expected: $2" >&2
    echo "      actual:   $1" >&2
  fi
}

contains() { # contains <haystack> <needle> <description>
  RAN=$((RAN + 1))
  case "$1" in
    *"$2"*) PASS=$((PASS + 1)) ;;
    *)
      FAIL=$((FAIL + 1))
      echo "  ✗ $3" >&2
      echo "      expected to contain: $2" >&2
      echo "      actual:              $1" >&2
      ;;
  esac
}

# Runs the script under a stub. Sets RC, OUT and ERR.
run() { # run <stub-mode> [args...]
  local mode=$1
  shift
  set +e
  OUT=$(STUB_MODE="$mode" BURP_JAVA="$WORK/java" BURP_JAR="$WORK/fake.jar" \
    "$SCRIPT" "$WORK/project.burp" query "$@" 2>"$WORK/err")
  RC=$?
  set -e
  ERR=$(cat "$WORK/err")
}

echo "→ output classification"

# The working case. Nothing else in this suite means anything if this does not hold.
run json
eq "$RC" "0" "JSON output must exit 0"
eq "$(printf '%s' "$OUT" | grep -c '^')" "2" "both JSON lines must reach stdout"

# The bug this PR exists for: no output is NOT a clean result, because an empty result set and an
# unloaded extension are indistinguishable from here.
run empty
eq "$RC" "3" "no output must exit 3, not report success"
contains "$ERR" "burpsuite-project-file-parser" "exit 3 must name the extension as a possibility"

# Burp started normally and dropped the query flags -- what a missing extension looks like.
run banner
eq "$RC" "4" "a startup banner must exit 4"
eq "$OUT" "" "a banner must never reach stdout, where a downstream jq could match it"
contains "$ERR" "Burp Suite Professional v2024.1" "the offending line must be echoed to stderr"

# A Java log line starts with `[`, so a check that accepted a leading bracket as JSON would pass it.
run logline
eq "$RC" "4" "a Java log line must exit 4, not be mistaken for JSON"

# A working install may print a licence or startup line before the JSON. Classifying the whole
# stream keeps that a success; judging line 1 alone would have failed it.
run mixed
eq "$RC" "0" "JSON preceded by a banner must still exit 0"
eq "$OUT" '{"a":1}' "only the JSON half of a mixed stream reaches stdout"

# Leading whitespace is still JSON.
run indented
eq "$RC" "0" "indented JSON must be recognised"

# Burp's own failure must not be masked by the classification layer.
run fail7
eq "$RC" "7" "Burp's non-zero exit must propagate"
run jsonfail
eq "$RC" "7" "Burp's failure must win even when JSON was produced"

echo "→ pipeline behaviour"

# The documented workflows pipe to `head` on every call. SIGPIPE from an early close is not a
# failure, and must not print an error the user will read as one.
set +e
big_out=$(STUB_MODE=big BURP_JAVA="$WORK/java" BURP_JAR="$WORK/fake.jar" \
  "$SCRIPT" "$WORK/project.burp" query 2>"$WORK/err" | head -2)
set -e
eq "$(printf '%s' "$big_out" | grep -c '^')" "2" "a downstream head -2 must get its two lines"
eq "$(wc -c <"$WORK/err" | tr -d ' ')" "0" "an early pipe close must produce no stderr noise"

# awk block-buffers when stdout is a pipe, so without fflush() a long search prints nothing until
# Burp exits. The bare exec this replaced streamed line by line; this keeps that.
# SECONDS is reset inside the subshell, so this measures from the run rather than from suite
# start. Compared as a threshold, not an exact second, so a loaded CI box does not flake: the
# stub takes 3s total, and buffered output cannot appear before then.
first_line_at=$(
  SECONDS=0
  STUB_MODE=slow BURP_JAVA="$WORK/java" BURP_JAR="$WORK/fake.jar" \
    "$SCRIPT" "$WORK/project.burp" query 2>/dev/null |
    while IFS= read -r _; do
      echo "$SECONDS"
      break
    done
)
[ "$first_line_at" -lt 2 ] && streaming=yes || streaming=no
eq "$streaming" "yes" "output must stream, not arrive only when the producer exits"

# A stream with NO JSON is the missing-extension case, and it is the one where awk never writes to stdout --
# so it never takes SIGPIPE, and a downstream `head` cannot close the pipeline early. Uncapped, every line
# Burp produced is mirrored to stderr, which the caller captures and no documented output limit covers.
# Measured before the cap: 8.4 MB behind a `head -c 200` that could not terminate.
set +e
STUB_MODE=noisy BURP_JAVA="$WORK/java" BURP_JAR="$WORK/fake.jar" \
  "$SCRIPT" "$WORK/project.burp" query 2>"$WORK/err" | head -c 200 >/dev/null
set -e
noisy_bytes=$(wc -c <"$WORK/err" | tr -d ' ')
[ "$noisy_bytes" -lt 5000 ] && capped=yes || capped=no
eq "$capped" "yes" "stderr from a no-JSON stream must be capped, not mirrored in full"
contains "$(cat "$WORK/err")" "further non-JSON line(s) suppressed" \
  "the cap must report how many lines it suppressed, so a truncated diagnostic is not mistaken for a short one"

# The line cap bounds how MANY lines are mirrored, not how long one may be. SKILL.md:217 records a single 10MB
# response on one line as a real shape, and those bytes are captured HTTP traffic -- attacker-influenced text
# on a channel the documented `head -c` on stdout cannot reach.
run longline
eq "$RC" "4" "a single huge non-JSON line is still not JSON"
long_bytes=$(printf '%s' "$ERR" | wc -c | tr -d ' ')
[ "$long_bytes" -lt 5000 ] && bounded=yes || bounded=no
eq "$bounded" "yes" "one very long non-JSON line must be truncated, not mirrored in full"

# A trailing newline is not output Burp meant to produce. Counting it flips an empty-but-correct result to
# exit 4 -- "the extension is not loaded" -- on a healthy install, and mirrors a diagnostic with nothing
# after the colon.
run blank
eq "$RC" "3" "whitespace-only output must read as empty (exit 3), not as non-JSON (exit 4)"

echo
if [ "$RAN" -ne "$EXPECTED_ASSERTIONS" ]; then
  echo "✗ ran $RAN assertions, expected $EXPECTED_ASSERTIONS" >&2
  echo "  A suite that stops running its checks passes as loudly as one that does not." >&2
  echo "  Update EXPECTED_ASSERTIONS deliberately when adding or removing a check." >&2
  exit 1
fi

echo "$PASS passed, $FAIL failed, $RAN run"
[ "$FAIL" -eq 0 ] || exit 1
echo "$RAN assertions passed"

# NOT covered, and worth knowing before trusting a green run: the stub proves the classification
# logic, not Burp's actual behaviour with the extension missing. If Burp launches and waits for
# input rather than exiting, neither exit 3 nor exit 4 fires and the script blocks indefinitely --
# no timeout guards that. Settling it needs Burp Pro: rename the extension JAR, run one query, and
# record the exit code and whether it returns at all.
