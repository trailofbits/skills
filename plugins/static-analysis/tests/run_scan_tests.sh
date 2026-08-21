#!/usr/bin/env bash
# Regression suite for scripts/run-scans.sh, discovered by CI's run_*.sh glob.
#
# Command generation is checked with --dry-run; execution, exit codes and clone failures run
# against stub semgrep and git binaries on PATH, so the suite is hermetic.
#
# The negative assertions matter most: a repo that would not clone, and a scan that exited
# non-zero, must not reach `scans`. The counter at the bottom fails the run when fewer
# assertions execute than are written.
set -uo pipefail

command -v uv >/dev/null 2>&1 || {
  echo "uv is required (https://docs.astral.sh/uv/)" >&2
  exit 1
}

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$PLUGIN_ROOT/skills/semgrep/scripts/run-scans.sh"
readonly EXPECTED_ASSERTIONS=78

command -v jq >/dev/null 2>&1 || {
  echo "run_scan_tests.sh: jq not found — required" >&2
  exit 1
}
[ -x "$SCRIPT" ] || [ -r "$SCRIPT" ] || {
  echo "run_scan_tests.sh: cannot read $SCRIPT" >&2
  exit 1
}

PASS=0
FAIL=0
ok() {
  if [ "$1" = "0" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $2" >&2
  fi
}
# Asserts on a value rather than a status, so the failure message can show what was actually got.
eq() {
  if [ "$1" = "$2" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $3 (expected '$2', got '$1')" >&2
  fi
}
contains() {
  case "$1" in
    *"$2"*) PASS=$((PASS + 1)) ;;
    *)
      FAIL=$((FAIL + 1))
      echo "  FAIL: $3" >&2
      ;;
  esac
}
lacks() {
  case "$1" in
    *"$2"*)
      FAIL=$((FAIL + 1))
      echo "  FAIL: $3" >&2
      ;;
    *) PASS=$((PASS + 1)) ;;
  esac
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/run-scan-tests.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

TARGET="$WORK/proj"
mkdir -p "$TARGET/src"
printf 'x = 1\n' >"$TARGET/src/a.py"

plan() { # plan <name> <json>
  printf '%s\n' "$2" >"$WORK/$1.json"
  printf '%s' "$WORK/$1.json"
}

dry() { # dry <plan-file> [extra args...] -> generated commands on stdout
  local p=$1
  shift
  bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all \
    --rulesets "$p" --dry-run "$@" 2>/dev/null
}

# Returns the die() message; used to assert a bad plan is rejected rather than degraded.
fails() { # fails <args...> -> prints stderr, returns 0 if the script exited non-zero
  local out
  if out=$("$@" 2>&1); then
    printf '%s' "$out"
    return 1
  fi
  printf '%s' "$out"
  return 0
}

echo "→ argument validation"

BASIC=$(plan basic '{"baseline":["p/security-audit"],"python":["p/python"],"third_party":[]}')

msg=$(fails bash "$SCRIPT" --target relative/path --output-dir "$WORK/out" --mode run-all --rulesets "$BASIC" --dry-run)
ok $? "a relative --target must be rejected"
contains "$msg" "absolute path" "the message must name the absolute-path requirement"

msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir rel --mode run-all --rulesets "$BASIC" --dry-run)
ok $? "a relative --output-dir must be rejected"

msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode wrong --rulesets "$BASIC" --dry-run)
ok $? "an unknown --mode must be rejected"

msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$TARGET" --mode run-all --rulesets "$BASIC" --dry-run)
ok $? "an output directory equal to the target must be rejected"
contains "$msg" "scan target" "the message must explain the run would scan its own output"

msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$WORK/nope.json" --dry-run)
ok $? "a missing rulesets file must be rejected"

printf 'not json' >"$WORK/bad.json"
msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$WORK/bad.json" --dry-run)
ok $? "a rulesets file that is not JSON must be rejected"

# A single ruleset written without the brackets would otherwise iterate the string.
SCALAR=$(plan scalar '{"docker":"p/dockerfile","third_party":[]}')
msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$SCALAR" --dry-run)
ok $? "a scalar where an array is expected must be rejected"
contains "$msg" "must be an array" "the message must name the array requirement"

URLKEY=$(plan urlkey '{"python":["https://github.com/x/y"],"third_party":[]}')
msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$URLKEY" --dry-run)
ok $? "a repository URL filed under a language key must be rejected"
contains "$msg" "third_party" "the message must point at third_party"

TRAVERSE=$(plan traverse '{"baseline":["p/python/../../.."],"third_party":[]}')
ok "$(
  fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$TRAVERSE" --dry-run >/dev/null
  echo $?
)" "a traversing ruleset id must be rejected"

ABS=$(plan abs '{"baseline":["/etc"],"third_party":[]}')
ok "$(
  fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$ABS" --dry-run >/dev/null
  echo $?
)" "an absolute path is not a registry identifier"

BADURL=$(plan badurl '{"baseline":[],"third_party":["http://insecure/x/y"]}')
ok "$(
  fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$BADURL" --dry-run >/dev/null
  echo $?
)" "a non-https third_party URL must be rejected"

EMPTY=$(plan empty '{"baseline":[],"third_party":[]}')
msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$EMPTY" --dry-run)
ok $? "a plan with no rulesets at all must be rejected, not run as an empty scan"
contains "$msg" "nothing to run" "the message must say there is nothing to run"

RESERVED=$(plan reserved '{"all":["p/python"],"third_party":[]}')
msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$RESERVED" --dry-run)
ok $? "the reserved language name 'all' must be rejected"

# shellcheck disable=SC2016  # the literal $(id) is the payload under test
INJECT=$(plan inject '{"py$(id)":["p/python"],"third_party":[]}')
msg=$(fails bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/out" --mode run-all --rulesets "$INJECT" --dry-run)
ok $? "a language key holding a command substitution must be rejected"

echo "→ command generation"

out=$(dry "$BASIC")
n=$(printf '%s\n' "$out" | grep -c 'semgrep')
eq "$n" "2" "one command per ruleset"
n=$(printf '%s\n' "$out" | grep -c -- '--metrics=off')
eq "$n" "2" "--metrics=off must be on every command"
lacks "$out" "--severity" "run-all mode must add no severity flags"
lacks "$out" "--pro" "--pro must be absent unless asked for"

# The cross-language ruleset scans the whole target: a filter would drop findings in the files
# it does not match.
baseline_cmd=$(printf '%s\n' "$out" | grep 'p/security-audit')
lacks "$baseline_cmd" "--include" "cross-language rulesets must never take --include"
py_cmd=$(printf '%s\n' "$out" | grep 'p/python')
contains "$py_cmd" '"--include=*.py"' "language rulesets must be scoped with --include"
contains "$py_cmd" '"--include=*.pyi"' "every glob for the language must be present"
contains "$baseline_cmd" 'raw/all-security-audit.json' "cross-language output stems start with all-"

out=$(dry "$BASIC" --mode important-only)
n=$(printf '%s\n' "$out" | grep -c -- '--severity WARNING --severity ERROR')
eq "$n" "2" "important-only must add the severity pre-filter to every command"

out=$(dry "$BASIC" --pro)
n=$(printf '%s\n' "$out" | grep -c -- '--pro')
eq "$n" "2" "--pro must reach every command when requested"

echo "→ output directory exclusion"

# The default output directory sits inside the target, where the cloned rule repos and the raw
# JSON of sibling scans would otherwise be scanned as if they were the user's code.
out=$(bash "$SCRIPT" --target "$TARGET" --output-dir "$TARGET/out" --mode run-all --rulesets "$BASIC" --dry-run 2>/dev/null)
n=$(printf '%s\n' "$out" | grep -c -- '--exclude=out')
eq "$n" "2" "--exclude must be on every command, including the cross-language ones"

out=$(dry "$BASIC")
lacks "$out" "--exclude" "no --exclude when the output directory is outside the target"

# The containment test is `case "$OUTPUT_ROOT/" in "$TARGET_ROOT"/*)`. The quotes are what make
# it a string compare: unquoted, a target holding [ ] * or ? is read as a glob and a path like
# proj[1] stops matching itself, so --exclude is never added and every scan then reads raw/ and
# the cloned rule repos, which carry literal example secrets.
GLOBDIR="$WORK/glob[1]/src"
mkdir -p "$GLOBDIR"
printf 'x = 1\n' >"$GLOBDIR/a.py"
out=$(bash "$SCRIPT" --target "$WORK/glob[1]" --output-dir "$WORK/glob[1]/out" \
  --mode run-all --rulesets "$BASIC" --dry-run 2>/dev/null)
contains "$out" "--exclude=out" "a target holding glob metacharacters must still exclude its output directory"

echo "→ cross-language hoisting and dedup"

# p/secrets is in baseline and in the python list. Running it twice would put two findings
# counts in the report for one scan; the merged SARIF dedups the results but a sum does not.
SHARED=$(plan shared '{"baseline":["p/secrets"],"python":["p/python","p/secrets"],"third_party":[]}')
out=$(dry "$SHARED")
n=$(printf '%s\n' "$out" | grep -c 'p/secrets')
eq "$n" "1" "a ruleset already running unscoped must not be scanned again per language"
n=$(printf '%s\n' "$out" | grep -c 'p/python')
eq "$n" "1" "the language keeps the rulesets that are its own"

# js and javascript are the same language. Two units would carry identical --include sets, and
# a ruleset named under both would be scanned and counted twice.
ALIAS=$(plan alias '{"baseline":[],"js":["p/javascript"],"javascript":["p/nodejs"],"third_party":[]}')
out=$(dry "$ALIAS")
n=$(printf '%s\n' "$out" | grep -c 'raw/javascript-')
eq "$n" "2" "aliased keys must fold onto one language, one command per distinct ruleset"

DUPE=$(plan dupe '{"baseline":[],"js":["p/javascript"],"javascript":["p/javascript"],"third_party":[]}')
out=$(dry "$DUPE")
n=$(printf '%s\n' "$out" | grep -c 'p/javascript')
eq "$n" "1" "the same ruleset under two aliases of one language must be scanned once"

# Two spellings of one repository collapse to one clone directory, so the second clone would
# fail into a non-empty tree and both would then read the same result.
GITDUP=$(plan gitdup '{"baseline":[],"third_party":["https://github.com/trailofbits/semgrep-rules","https://github.com/trailofbits/semgrep-rules.git"]}')
out=$(dry "$GITDUP")
n=$(printf '%s\n' "$out" | grep -c 'trailofbits-semgrep-rules')
eq "$n" "1" "two spellings of one repository must clone and scan once"

# Different owners publishing a repo of the same name must stay distinct.
TWOORG=$(plan twoorg '{"baseline":[],"third_party":["https://github.com/trailofbits/semgrep-rules","https://github.com/elttam/semgrep-rules"]}')
out=$(dry "$TWOORG")
contains "$out" "trailofbits-semgrep-rules" "the clone directory must carry the owner"
contains "$out" "elttam-semgrep-rules" "a second org's identically named repo must not collide"

UNKNOWN=$(plan unknown '{"baseline":[],"cobol":["p/cobol"],"third_party":[]}')
out=$(dry "$UNKNOWN")
lacks "$out" "--include" "an unrecognised language must run unscoped rather than guess a glob"

echo "→ execution, exit codes and finding counts"

# Stub semgrep: writes the output files it was told to and exits with $STUB_RC. The real binary
# is not needed to prove how this script reads a result, and stubbing keeps the suite hermetic.
mkdir -p "$WORK/bin"
cat >"$WORK/bin/semgrep" <<'STUB'
#!/usr/bin/env bash
json=""; sarif=""; prev=""
for a in "$@"; do
  case "$prev" in -o) json=$a ;; esac
  case "$a" in --sarif-output=*) sarif=${a#--sarif-output=} ;; esac
  prev=$a
done
if [ "${STUB_WRITE:-1}" = "1" ]; then
  # STUB_PATHS unset means no .paths key at all, which is the "semgrep did not say" case the
  # script must report as -1 rather than as a scan that opened no file.
  if [ -n "${STUB_PATHS:-}" ]; then
    printf '{"results":[%s],"paths":{"scanned":[%s]}}' "${STUB_RESULTS:-}" "$STUB_PATHS" > "$json"
  else
    printf '{"results":[%s]}' "${STUB_RESULTS:-}" > "$json"
  fi
  printf '{"runs":[]}' > "$sarif"
fi
[ -z "${STUB_STDERR:-}" ] || echo "$STUB_STDERR" >&2
exit "${STUB_RC:-0}"
STUB
chmod +x "$WORK/bin/semgrep"

run_real() { # run_real <plan> [env assignments already exported] -> scans.json path
  local p=$1 outdir=$2
  rm -rf "$outdir"
  PATH="$WORK/bin:$PATH" bash "$SCRIPT" --target "$TARGET" --output-dir "$outdir" \
    --mode run-all --rulesets "$p" --jobs 2 >/dev/null 2>&1
  echo $?
}

ONE=$(plan one '{"baseline":[],"python":["p/python"],"third_party":[]}')

export STUB_RC=0 STUB_RESULTS='{"a":1},{"b":2}'
rc=$(run_real "$ONE" "$WORK/o1")
eq "$rc" "0" "a successful scan must exit 0"
eq "$(jq '.scans | length' "$WORK/o1/scans.json")" "1" "the successful scan must appear in scans"
eq "$(jq -r '.scans[0].findings' "$WORK/o1/scans.json")" "2" "findings must be counted from the JSON, not reported"
eq "$(jq '.failed | length' "$WORK/o1/scans.json")" "0" "a successful scan must not appear in failed"

# Exit 1 means "findings present" on older semgrep, so it is a successful scan.
export STUB_RC=1 STUB_RESULTS='{"a":1}'
rc=$(run_real "$ONE" "$WORK/o2")
eq "$(jq '.scans | length' "$WORK/o2/scans.json")" "1" "exit 1 must count as a successful scan"

# Exit 7 is a config that would not load: no scan happened.
export STUB_RC=7 STUB_RESULTS=''
rc=$(run_real "$ONE" "$WORK/o3")
eq "$rc" "1" "a run where every scan failed must exit non-zero"
eq "$(jq '.scans | length' "$WORK/o3/scans.json")" "0" "a scan that exited 7 must not reach scans"
eq "$(jq '.failed | length' "$WORK/o3/scans.json")" "1" "a scan that exited 7 must be reported as failed"
contains "$(jq -r '.failed[0].json' "$WORK/o3/scans.json")" "raw/python-python.json" \
  "a failed entry must carry the paths it may have partly written"

# Exit 0 with no output file is the case the exit code alone cannot catch.
export STUB_RC=0 STUB_WRITE=0
rc=$(run_real "$ONE" "$WORK/o4")
eq "$(jq '.failed | length' "$WORK/o4/scans.json")" "1" "exit 0 with no output file must be a failure, not a clean scan"
unset STUB_WRITE

echo "→ reused output directory"

# merge_sarif.py globs every *.sarif in raw/ and cannot tell one run's output from another's, so
# a ruleset dropped between two runs into the same output directory would still reach
# results.sarif and its total, under a ruleset the current scans.json never mentions.
export STUB_RC=0 STUB_RESULTS='{"a":1}'
rerun() {
  PATH="$WORK/bin:$PATH" bash "$SCRIPT" --target "$TARGET" --output-dir "$WORK/o5" \
    --mode run-all --rulesets "$ONE" --jobs 1 >/dev/null 2>&1
}
rm -rf "$WORK/o5"
rerun
printf '{"runs":[]}' >"$WORK/o5/raw/docker-dockerfile.sarif"
printf '{"results":[]}' >"$WORK/o5/raw/docker-dockerfile.json"
rerun
if [ -e "$WORK/o5/raw/docker-dockerfile.sarif" ]; then stale=present; else stale=gone; fi
eq "$stale" "gone" "a previous run's SARIF must not survive into a rerun's raw/"
eq "$(find "$WORK/o5/raw" -type f | wc -l | tr -d ' ')" "2" "raw/ must hold only the current run's output"
eq "$(jq '.scans | length' "$WORK/o5/scans.json")" "1" "clearing raw/ must not break the rerun itself"

echo "→ clone failures"

export STUB_RC=0 STUB_RESULTS=''
mkdir -p "$WORK/gitbin"
cat >"$WORK/gitbin/git" <<'GITSTUB'
#!/usr/bin/env bash
# clone <flags> <url> <dest>
dest=${*: -1}
case "${GIT_STUB_MODE:-fail}" in
  fail)  echo "fatal: repository not found" >&2; exit 128 ;;
  empty) mkdir -p "$dest"; exit 0 ;;
  # Enough rule files that `find` output passes the 64 KiB pipe buffer. A single rules.yaml
  # fits well inside it, so the old `find | head -1` pipeline never got SIGPIPE and this case
  # passed against a repo shape no real rule repository has.
  ok)
    mkdir -p "$dest"
    i=1
    while [ "$i" -le 2000 ]; do
      printf 'rules: []\n' >"$dest/rule-with-a-fairly-long-filename-to-fill-the-buffer-$i.yaml"
      i=$((i + 1))
    done
    exit 0
    ;;
esac
GITSTUB
chmod +x "$WORK/gitbin/git"

REPO=$(plan repo '{"baseline":["p/security-audit"],"third_party":["https://github.com/x/rules"]}')

run_clone() {
  rm -rf "$2"
  PATH="$WORK/gitbin:$WORK/bin:$PATH" GIT_STUB_MODE="$1" bash "$SCRIPT" --target "$TARGET" \
    --output-dir "$2" --mode run-all --rulesets "$REPO" --jobs 1 >/dev/null 2>&1
  echo $?
}

run_clone fail "$WORK/c1" >/dev/null
eq "$(jq '.skipped | length' "$WORK/c1/scans.json")" "1" "a repo that will not clone must be reported as skipped"
eq "$(jq -r '.skipped[0].ruleset' "$WORK/c1/scans.json")" "https://github.com/x/rules" \
  "the skipped entry must name the repository the user approved"
eq "$(jq '[.scans[].ruleset | select(test("github"))] | length' "$WORK/c1/scans.json")" "0" \
  "a repo that failed to clone must not appear as a scanned ruleset"

# A clone that succeeds but carries no rules scans nothing; reporting it as fine would show a
# completed scan against a ruleset that never ran.
run_clone empty "$WORK/c2" >/dev/null
eq "$(jq '.skipped | length' "$WORK/c2/scans.json")" "1" "a clone with no rule files must be skipped"

run_clone ok "$WORK/c3" >/dev/null
eq "$(jq '.skipped | length' "$WORK/c3/scans.json")" "0" "a healthy clone must not be skipped"
eq "$(jq '.scans | length' "$WORK/c3/scans.json")" "2" "a healthy clone must be scanned alongside the baseline"

# ------------------------------------------------------------------------- coverage reporting
# A ruleset whose --include globs match nothing exits 0 with an empty result, which reads in the
# report exactly like a ruleset that ran and found nothing. That is how a plan naming the wrong
# languages — p/python on a Go tree — comes back as a clean audit.
echo "→ rulesets that covered nothing"

unset STUB_PATHS
export STUB_RC=0 STUB_RESULTS=''

# semgrep opened files: a real scan that happened to find nothing.
export STUB_PATHS='"a.py","b.py"'
run_real "$ONE" "$WORK/cn1" >/dev/null
eq "$(jq -r '.scans[0].filesScanned' "$WORK/cn1/scans.json")" "2" "filesScanned must come from .paths.scanned"
eq "$(jq '.coveredNothing | length' "$WORK/cn1/scans.json")" "0" \
  "a scan that opened files must not be reported as covering nothing"

# semgrep opened nothing: the ruleset does not apply to this tree at all.
export STUB_PATHS=' '
run_real "$ONE" "$WORK/cn2" >/dev/null
eq "$(jq -r '.scans[0].filesScanned' "$WORK/cn2/scans.json")" "0" "an empty scanned list must be 0, not unknown"
eq "$(jq -r '.coveredNothing | join(",")' "$WORK/cn2/scans.json")" "python/p/python" \
  "a ruleset that opened no file must be named in coveredNothing"
eq "$(jq '.scans | length' "$WORK/cn2/scans.json")" "1" \
  "it still ran, so it stays in scans rather than moving to failed"

# No .paths key at all. Unknown is not the same answer as zero, and reporting every scan as
# covering nothing would make the field worthless on any semgrep that does not emit it.
unset STUB_PATHS
run_real "$ONE" "$WORK/cn3" >/dev/null
eq "$(jq -r '.scans[0].filesScanned' "$WORK/cn3/scans.json")" "-1" "a missing .paths must report -1, not 0"
eq "$(jq '.coveredNothing | length' "$WORK/cn3/scans.json")" "0" \
  "an unknown file count must not be reported as covering nothing"

# --------------------------------------------------------------- the recorded exclude pattern
# semgrep matches --exclude anywhere in the tree, so an output directory named `out` inside the
# target also drops the target's own src/out/. Announced only on stderr that is invisible to the
# report and the missing files read as clean coverage.
echo "→ the recorded exclude pattern"

unset STUB_PATHS
export STUB_RC=0 STUB_RESULTS=''

rm -rf "$TARGET/out"
PATH="$WORK/bin:$PATH" bash "$SCRIPT" --target "$TARGET" --output-dir "$TARGET/out" \
  --mode run-all --rulesets "$BASIC" --jobs 2 >/dev/null 2>&1
# Asserted before the value is read: jq on a missing file prints nothing, which compares equal
# to the empty string the second case expects, so both would pass having checked nothing.
ok "$([ -f "$TARGET/out/scans.json" ] && echo 0 || echo 1)" "the excluded run must write scans.json"
eq "$(jq -r '.excludePattern' "$TARGET/out/scans.json" 2>/dev/null || echo NOFILE)" "out" \
  "scans.json must record the pattern excluded from every scan"
rm -rf "$TARGET/out"

run_real "$BASIC" "$WORK/ex2" >/dev/null
ok "$([ -f "$WORK/ex2/scans.json" ] && echo 0 || echo 1)" "the unexcluded run must write scans.json"
eq "$(jq -r '.excludePattern' "$WORK/ex2/scans.json" 2>/dev/null || echo NOFILE)" "" \
  "excludePattern must be empty when nothing was excluded"

# ------------------------------------------------------------------ the documented post-filter
# The important-only loop lives in scan-modes.md rather than in a script, so it is extracted and
# run here. Redirection creates the output before jq does, and merge_sarif.py --important treats
# a zero-byte filter file as corrupt and refuses the whole merge — one unfilterable scan would
# take every other scan's findings with it.
echo "→ documented post-filter loop"

MODES="$PLUGIN_ROOT/skills/semgrep/references/scan-modes.md"
FILTER_LOOP=$(awk '
  /^### Filter All Result Files in a Directory$/ { found = 1 }
  found && /^```bash$/ { inblock = 1; next }
  inblock && /^```$/   { exit }
  inblock              { print }
' "$MODES")

# Extraction is itself a checker: a renamed heading or fence would otherwise run an empty
# string through bash and pass every assertion below.
contains "$FILTER_LOOP" "jq" "the post-filter loop must be extractable from scan-modes.md"
contains "$FILTER_LOOP" "important.json" "the extracted block must be the important-only filter"

FRAW="$WORK/filter/raw"
mkdir -p "$FRAW"
# One finding passes the filter, one is excluded by confidence.
cat >"$FRAW/python-good.json" <<'JSON'
{"results":[
  {"check_id":"r.keep","path":"a.py","start":{"line":5},
   "extra":{"metadata":{"category":"security","confidence":"HIGH","impact":"HIGH"}}},
  {"check_id":"r.drop","path":"a.py","start":{"line":9},
   "extra":{"metadata":{"category":"security","confidence":"LOW","impact":"HIGH"}}}
],"errors":[],"paths":{}}
JSON
# Whatever the cause (a truncated write, a disk that filled), jq cannot read this one.
printf '{"results":[{"check_id":"r.x"' >"$FRAW/python-broken.json"

FILTER_ERR=$(OUTPUT_DIR="$WORK/filter" bash -c "$FILTER_LOOP" 2>&1 >/dev/null)

eq "$(jq '.results | length' "$FRAW/python-good-important.json" 2>/dev/null)" "1" \
  "a readable scan must still be filtered when a sibling fails"
eq "$(find "$FRAW" -name '*-important.json' -size 0 | wc -l | tr -d ' ')" "0" \
  "a failed filter must not leave a zero-byte -important.json for the merge to choke on"
ok "$([ -e "$FRAW/python-broken-important.json" ] && echo 1 || echo 0)" \
  "the unfilterable scan must have no -important.json at all"
contains "$FILTER_ERR" "python-broken.json" "the failure must name the file it happened on"

# The merge is the gate that must still refuse: the scan is unfiltered, so its findings cannot
# be included or excluded honestly. It now fails naming the missing file rather than reporting
# a corrupt one.
MERGE="$PLUGIN_ROOT/skills/semgrep/scripts/merge_sarif.py"
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[]}},"results":[]}]}\n' \
  >"$FRAW/python-good.sarif"
cp "$FRAW/python-good.sarif" "$FRAW/python-broken.sarif"
MERGE_ERR=$(uv run --no-project "$MERGE" "$FRAW" "$WORK/filter/results.sarif" --important 2>&1 >/dev/null)
ok "$([ -e "$WORK/filter/results.sarif" ] && echo 1 || echo 0)" \
  "the merge must write nothing while a scan is unfiltered"
contains "$MERGE_ERR" "python-broken-important.json" \
  "the merge error must name the scan that has no filtered JSON"

TOTAL=$((PASS + FAIL))
echo
echo "$PASS passed, $FAIL failed, $TOTAL run"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
# A suite that stopped early would otherwise exit 0 having proved nothing.
if [ "$TOTAL" -ne "$EXPECTED_ASSERTIONS" ]; then
  echo "ran $TOTAL assertions, expected $EXPECTED_ASSERTIONS, so the suite did not run in full" >&2
  exit 1
fi
echo "$TOTAL assertions passed"
