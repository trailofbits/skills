#!/usr/bin/env bash
# Step 4 of the semgrep skill: run the selected rulesets and report what each scan produced.
# Generating every command here is what keeps --metrics=off, --include and --exclude out of a
# model's hands. Exit codes and counts come from the processes and the JSON they wrote.
# No `declare -A` and no `wait -n`, so this runs on macOS's bash 3.2.
set -euo pipefail

readonly METRICS_OFF="--metrics=off"
# semgrep --severity accepts INFO, WARNING and ERROR only, and rejects anything else with exit 2
# before scanning. The metadata thresholds LOW/MEDIUM/HIGH are applied by the post-filter in
# references/scan-modes.md, not here.
SEVERITY_FLAGS=(--severity WARNING --severity ERROR)
readonly DEFAULT_JOBS=4

# A semgrep join rule carries `mode: join` and the `join:` block that mode needs, and requiring
# both is what keeps the prune below off a rule that merely mentions the words. Each is anchored
# as a YAML key on its own line — optionally the first key of a list item, optionally quoted,
# with a trailing comment allowed — because one file holds many rules and deleting it on a
# `message:` that quotes the docs would take every sibling rule with it. A rule that names the
# mode without the block is not a valid join rule; semgrep rejects it per-rule, which the exit-2
# handling below now survives, so leaving it in place costs nothing.
readonly JOIN_MODE_RE="^[[:space:]]*(-[[:space:]]+)?mode:[[:space:]]*(join|\"join\"|'join')[[:space:]]*(#.*)?\$"
readonly JOIN_BLOCK_RE="^[[:space:]]*join:[[:space:]]*(#.*)?\$"

usage() {
  cat <<'USAGE'
Usage: run-scans.sh --target DIR --output-dir DIR --mode MODE --rulesets FILE [options]

  --target DIR       absolute path to the tree to scan
  --output-dir DIR   absolute path for results; raw/ and repos/ are created under it
  --mode MODE        run-all | important-only
  --rulesets FILE    JSON: {"baseline":[...], "<language>":[...], "third_party":["https://..."]}
  --pro              add --pro to every command (Semgrep Pro engine)
  --jobs N           concurrent semgrep processes (default 4)
  --dry-run          print the commands that would run, then exit; clones nothing

Writes OUTPUT_DIR/scans.json:
  {scans:[{lang,ruleset,json,sarif,findings,filesScanned,partial,exitCode}],
   failed:[...], skipped:[...], unscoped:[lang], alsoShared:["lang/ruleset"]}
  partial is a scan that wrote complete output while some of its rules failed to compile.
USAGE
}

die() {
  echo "run-scans.sh: $*" >&2
  exit 1
}

# --include globs per language. Checked against semgrep by scanning one file per extension;
# re-run that when bumping it, because a type omitted here is excluded with no signal and the
# ruleset reads clean rather than incomplete. Absent because semgrep does not parse them:
# .mts, .cts, .C, Containerfile, Dockerfile.prod. javascript carries the TypeScript globs
# because one detection category covers both.
includes_for() {
  case "$1" in
    python) echo '*.py *.pyi' ;;
    javascript) echo '*.js *.jsx *.mjs *.cjs *.ts *.tsx' ;;
    typescript) echo '*.ts *.tsx' ;;
    go) echo '*.go' ;;
    ruby) echo '*.rb' ;;
    java) echo '*.java *.jsp' ;;
    kotlin) echo '*.kt *.kts' ;;
    php) echo '*.php *.phtml' ;;
    c) echo '*.c *.h' ;;
    cpp) echo '*.c *.cc *.cpp *.cxx *.h *.hh *.hpp *.hxx' ;;
    csharp) echo '*.cs' ;;
    rust) echo '*.rs' ;;
    scala) echo '*.scala' ;;
    swift) echo '*.swift' ;;
    elixir) echo '*.ex *.exs' ;;
    solidity) echo '*.sol' ;;
    docker) echo 'Dockerfile *.dockerfile' ;;
    terraform) echo '*.tf *.tfvars *.hcl' ;;
    json) echo '*.json' ;;
    apex) echo '*.cls *.trigger' ;;
    cloudformation) echo '*.yaml *.yml *.json' ;;
    github-actions) echo '*.yml *.yaml' ;;
    kubernetes) echo '*.yaml *.yml' ;;
    yaml) echo '*.yaml *.yml' ;;
    *) echo '' ;;
  esac
}

# Folds plan spellings onto the keys includes_for knows, so `js` and `javascript` do not
# become two units and scan the same ruleset twice.
canonical_lang() {
  local k
  k=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$k" in
    js | jsx | node | nodejs | 'js/ts' | 'javascript/typescript') echo javascript ;;
    ts | tsx) echo typescript ;;
    golang) echo go ;;
    'c/c++' | 'c++' | cxx) echo cpp ;;
    dockerfile) echo docker ;;
    k8s) echo kubernetes ;;
    'c#' | dotnet) echo csharp ;;
    sol) echo solidity ;;
    tf | hcl) echo terraform ;;
    cfn) echo cloudformation ;;
    'github actions' | githubactions | gha) echo github-actions ;;
    salesforce) echo apex ;;
    *) echo "$k" ;;
  esac
}

# Filenames, not identifiers: a registry id and a clone path must both reduce to something safe
# to concatenate into a shell-quoted path.
slug() {
  case "$1" in
    *://*) repo_dir_name "$1" ;;
    *) printf '%s' "${1##*/}" | sed 's/[^A-Za-z0-9._-]\{1,\}/-/g; s/^-\{1,\}//; s/-\{1,\}$//' ;;
  esac
}

# The clone directory carries the owner: several orgs publish a repo named semgrep-rules, and
# keying on the basename alone would collide them into one directory.
repo_dir_name() {
  local u=$1 repo owner
  u=${u%.git}
  u=${u%/}
  repo=${u##*/}
  u=${u%/*}
  owner=${u##*/}
  printf '%s' "${owner:-unknown}-${repo:-rules}" | sed 's/[^A-Za-z0-9._-]\{1,\}/-/g'
}

# Deletes every .yaml/.yml under $1 that the remaining arguments select, printing what it took.
# The status is returned rather than swallowed: the prunes that use this keep files semgrep
# cannot handle out of a --config directory, and one that quietly stops matching puts the bug it
# exists to prevent straight back, with nothing on stderr to say so.
prune_yaml() { # prune_yaml <dir> <find-predicate...>
  local dir=$1
  shift
  find "$dir" \( -name '*.yaml' -o -name '*.yml' \) -type f "$@" -print -delete
}

# `wc -l` reads one line in the empty string, so the zero case comes from the string itself.
count_lines() {
  if [ -z "$1" ]; then
    echo 0
  else
    printf '%s\n' "$1" | wc -l | tr -d ' '
  fi
}

TARGET="" OUTPUT_DIR="" MODE="" RULESETS_FILE="" PRO="" DRY_RUN=""
JOBS=$DEFAULT_JOBS
while [ $# -gt 0 ]; do
  case "$1" in
    --target)
      TARGET=${2:-}
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR=${2:-}
      shift 2
      ;;
    --mode)
      MODE=${2:-}
      shift 2
      ;;
    --rulesets)
      RULESETS_FILE=${2:-}
      shift 2
      ;;
    --jobs)
      JOBS=${2:-}
      shift 2
      ;;
    --pro)
      PRO=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

command -v jq >/dev/null 2>&1 || die "jq is required"
[ -n "$DRY_RUN" ] || command -v semgrep >/dev/null 2>&1 || die "semgrep is required"

# Each check fails the run rather than degrading it: a scan with no rulesets, or against the
# wrong path, produces a clean-looking empty report.
case "$TARGET" in /*) ;; *) die "--target must be an absolute path, got '${TARGET}'" ;; esac
case "$OUTPUT_DIR" in /*) ;; *) die "--output-dir must be an absolute path, got '${OUTPUT_DIR}'" ;; esac
[ -d "$TARGET" ] || die "--target is not a directory: $TARGET"
case "$MODE" in run-all | important-only) ;; *) die "--mode must be run-all or important-only, got '${MODE}'" ;; esac
if [ -z "$RULESETS_FILE" ] || [ ! -r "$RULESETS_FILE" ]; then
  die "--rulesets file is missing or unreadable: ${RULESETS_FILE}"
fi
jq -e . "$RULESETS_FILE" >/dev/null 2>&1 || die "--rulesets is not valid JSON: $RULESETS_FILE"
case "$JOBS" in '' | *[!0-9]*) die "--jobs must be a positive integer, got '${JOBS}'" ;; esac
[ "$JOBS" -ge 1 ] || die "--jobs must be at least 1"

# Both paths resolve the same way before being compared. Resolving only one makes the equality
# and inside-the-target checks miss on any symlinked path (every /var path on macOS), and the
# run then scans its own cloned rules. The output dir may not exist yet, so the deepest
# existing ancestor is resolved and the rest appended.
resolve_path() {
  local p=$1 tail=""
  while [ ! -d "$p" ]; do
    tail="/${p##*/}$tail"
    p=${p%/*}
    [ -n "$p" ] || p=/
  done
  printf '%s' "$(cd "$p" && pwd)$tail"
}

TARGET=$(resolve_path "$TARGET")
TARGET_ROOT=${TARGET%/}
OUTPUT_ROOT=$(resolve_path "${OUTPUT_DIR%/}")
[ "$OUTPUT_ROOT" != "$TARGET_ROOT" ] ||
  die "--output-dir is the scan target; the run would scan its own output and its cloned rules"

# A denylist, not an allowlist: real directories contain spaces and parentheses, which are
# inert. These four stay live inside double quotes and a control character can smuggle in a
# newline. One pattern each, since one bracket expression cannot hold both quote styles.
has_unsafe_char() {
  case "$1" in
    *'"'*) return 0 ;;
    *'$'*) return 0 ;;
    *'`'*) return 0 ;;
    *[\\]*) return 0 ;;
    *[[:cntrl:]]*) return 0 ;;
  esac
  return 1
}

for p in "$TARGET" "$OUTPUT_ROOT"; do
  ! has_unsafe_char "$p" || die "path contains a character that is not safe to splice: $p"
done

# jq -e over the whole file, so a bad entry stops the run before anything is fetched.
jq -e '
  to_entries
  | all(.value | type == "array")
' "$RULESETS_FILE" >/dev/null 2>&1 || die "every value in --rulesets must be an array"

jq -e '
  to_entries
  | map(select(.key != "third_party") | .value[])
  | all(type == "string" and test("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
        and (split("/") | index("..") | not))
' "$RULESETS_FILE" >/dev/null 2>&1 ||
  die "ruleset entries must be registry identifiers like p/python; repository URLs go under third_party"

jq -e '
  (.third_party // [])
  | all(type == "string" and test("^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._-]+)+(\\.git)?/?$"))
' "$RULESETS_FILE" >/dev/null 2>&1 || die "third_party entries must be https git URLs"

RAW_DIR="$OUTPUT_ROOT/raw"
REPOS_DIR="$OUTPUT_ROOT/repos"

# The default output dir lands inside the target, so without --exclude every scan also reads
# the cloned rule repos (full of literal example secrets) and the raw JSON siblings are still
# writing. --exclude takes a pattern, not a rooted path: `out` also excludes `vendor/out`, and
# there is no anchored form, so it is announced rather than applied quietly.
EXCLUDE_ARG=""
EXCLUDE_PATTERN=""
case "$OUTPUT_ROOT/" in
  "$TARGET_ROOT"/*)
    rel=${OUTPUT_ROOT#"$TARGET_ROOT"/}
    EXCLUDE_ARG="--exclude=$rel"
    # Recorded in scans.json, not just announced here. This drops files from every scan, and an
    # unanchored pattern drops more than the output directory: --exclude=out also skips
    # src/out/. On stderr alone the report has nothing to show, so the gap looks like clean
    # coverage — the same silent truncation `coveredNothing` and the unparseable list exist to
    # prevent.
    EXCLUDE_PATTERN="$rel"
    echo "note: output directory is inside the target; excluding '$rel' from every scan." >&2
    echo "      semgrep matches that pattern anywhere in the tree." >&2
    ;;
esac

WORK=$(mktemp -d "${TMPDIR:-/tmp}/run-scans.XXXXXX")
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

SCAN_LIST="$WORK/scans.tsv"
SKIPPED="$WORK/skipped.tsv"
ALSO_SHARED="$WORK/also-shared.txt"
UNSCOPED="$WORK/unscoped.txt"
# A ruleset whose --include globs matched no file exits 0 with an empty result, which is
# indistinguishable in scans.json from a ruleset that ran and found nothing. That is how a plan
# naming the wrong languages reads as a clean audit: p/python on a Go tree reports 0 findings
# exactly like p/gosec would have. semgrep counts what it opened in .paths.scanned, so the two
# can be told apart and the ones that covered nothing named.
COVERED_NOTHING="$WORK/covered-nothing.txt"
: >"$SCAN_LIST"
: >"$SKIPPED"
: >"$ALSO_SHARED"
: >"$UNSCOPED"
: >"$COVERED_NOTHING"

# Stems are the filename half of every output path and the key results are matched on, so a
# collision would let one scan's result be read as another's.
USED_STEMS="$WORK/stems.txt"
: >"$USED_STEMS"
unique_stem() {
  local base=$1 n=2 candidate=$1
  while grep -Fxq "$candidate" "$USED_STEMS" 2>/dev/null; do
    candidate="$base-$n"
    n=$((n + 1))
  done
  printf '%s\n' "$candidate" >>"$USED_STEMS"
  printf '%s' "$candidate"
}

add_scan() {
  local lang=$1 ruleset=$2 config=$3 includes=$4 stem
  stem=$(unique_stem "$(printf '%s' "$lang" | sed 's/[^A-Za-z0-9._-]\{1,\}/-/g')-$(slug "$ruleset")")
  printf '%s\t%s\t%s\t%s\t%s\n' "$stem" "$lang" "$ruleset" "$config" "$includes" >>"$SCAN_LIST"
}

mapfile_compat() { # read newline-separated stdin into a named array, bash 3.2 safe
  local __name=$1 __line
  eval "$__name=()"
  while IFS= read -r __line; do
    [ -n "$__line" ] || continue
    eval "$__name+=(\"\$__line\")"
  done
}

BASELINE=()
THIRD_PARTY=()
LANG_KEYS=()
mapfile_compat BASELINE < <(jq -r '(.baseline // []) | unique[]' "$RULESETS_FILE")
mapfile_compat THIRD_PARTY < <(jq -r '(.third_party // [])[]' "$RULESETS_FILE")
mapfile_compat LANG_KEYS < <(jq -r 'to_entries[] | select(.key != "baseline" and .key != "third_party" and (.value | length) > 0) | .key' "$RULESETS_FILE")

# Deduplicated by clone directory rather than by exact string: two spellings of one repository
# (with and without .git) survive a string comparison but collide on one destination, and the
# second clone would fail into a non-empty tree.
CLONE_URLS=()
CLONE_NAMES=()
for url in ${THIRD_PARTY[@]+"${THIRD_PARTY[@]}"}; do
  name=$(repo_dir_name "$url")
  seen=""
  for existing in ${CLONE_NAMES[@]+"${CLONE_NAMES[@]}"}; do
    [ "$existing" = "$name" ] && seen=1 && break
  done
  [ -n "$seen" ] && continue
  CLONE_URLS+=("$url")
  CLONE_NAMES+=("$name")
done

if [ -z "$DRY_RUN" ]; then
  # Cleared for the same reason each clone destination is. merge_sarif.py globs every *.sarif
  # in here, so into a reused output directory a run that drops a ruleset still merges the
  # previous run's output for it: results.sarif and its total then cover a ruleset this run's
  # scans.json never mentions. Only this script's own output lives here.
  rm -rf "$RAW_DIR"
  mkdir -p "$RAW_DIR"
  [ ${#CLONE_URLS[@]} -eq 0 ] || mkdir -p "$REPOS_DIR"
fi

# ------------------------------------------------------------------ clone phase
CLONED_URLS=()
CLONED_PATHS=()
i=0
while [ $i -lt ${#CLONE_URLS[@]} ]; do
  url=${CLONE_URLS[$i]}
  name=${CLONE_NAMES[$i]}
  i=$((i + 1))
  dest="$REPOS_DIR/$name"
  if [ -n "$DRY_RUN" ]; then
    CLONED_URLS+=("$url")
    CLONED_PATHS+=("$dest")
    continue
  fi
  # Cleared first: git clone refuses a non-empty directory, so a reused output directory would
  # drop an approved ruleset while usable rules sat on disk.
  rm -rf "$dest"
  if ! err=$(git clone --depth 1 "$url" "$dest" 2>&1); then
    printf '%s\t%s\n' "$url" "$(printf '%s' "$err" | tail -n 3 | tr '\n' ' ')" >>"$SKIPPED"
    continue
  fi
  # semgrep parses EVERY .yaml/.yml under a --config directory as a rule file, and a single
  # unparseable one aborts the whole scan with exit 7 — no findings from any of the rules that
  # were fine. Rule repos ship their own CI config alongside their rules, and a workflow's
  # `on: pull_request:` is a null value, which semgrep rejects outright. Observed killing both
  # trailofbits/semgrep-rules (.github/workflows/semgrep-rules-format.yml) and
  # elttam/semgrep-rules (perf-templates/benchmark-tests.yml) — two required rulesets silently
  # contributing nothing.
  #
  # A semgrep rule file always has a top-level `rules:` key; nothing else here does. Pruning on
  # that also drops the `*.test.yaml` fixtures, which are rule test inputs rather than rules.
  # Measured on this prune alone: keeps 118/145 files for trailofbits and 80/94 for elttam,
  # losing no real rule. The join prune below then takes elttam's one join rule, leaving 79.
  #
  # `mode: join` rules are the second thing semgrep 1.173 cannot take: they crash it outright
  # (AttributeError in join_rule.py), which kills the whole batch and writes no output at all —
  # a hard process failure rather than the rule-level error a bad rule produces. elttam's
  # rules/generic/jsp-likely-xss.yaml is one. Only .yaml/.yml are considered, so a README
  # quoting the docs is not a candidate, and the pair of keys above is what makes it a rule.
  #
  # A prune that deletes nothing is a legitimate outcome — a repo may ship rules and nothing
  # else — but a prune that cannot run is not, so its status is checked and the ruleset is
  # skipped with a reason rather than scanned from a half-pruned tree.
  if ! non_rules=$(prune_yaml "$dest" ! -exec grep -q '^rules:' {} \;) ||
    ! join_rules=$(prune_yaml "$dest" -exec grep -qE "$JOIN_MODE_RE" {} \; \
      -exec grep -qE "$JOIN_BLOCK_RE" {} \;); then
    printf '%s\t%s\n' "$url" "could not prune unscannable YAML from the clone" >>"$SKIPPED"
    rm -rf "$dest"
    continue
  fi
  # Reported every time, including as zeroes. These two prunes are the difference between a
  # ruleset that runs and one that contributes nothing, and a run that stopped pruning would
  # otherwise look exactly like a run with nothing to prune.
  printf '%s: pruned %s non-rule YAML file(s) and %s join-mode rule file(s)\n' \
    "$name" "$(count_lines "$non_rules")" "$(count_lines "$join_rules")" >&2

  # A repository that cloned but carries no rules scans nothing, and reporting it as fine would
  # show a completed scan against a ruleset that never ran.
  #
  # -print -quit rather than `find … | head -1`: under pipefail, head exits after the first line
  # and find dies on SIGPIPE with 141 once its output passes the pipe buffer. pipefail makes the
  # pipeline non-zero, so a repository with enough rules to fill 64 KiB of pathnames — which is
  # every real rule repo, trailofbits/semgrep-rules included — was recorded as carrying none.
  # The required third-party rules then silently did not run. -quit stops at the first match
  # with no reader to race.
  if [ -z "$(find "$dest" \( -name '*.yaml' -o -name '*.yml' \) -type f -print -quit)" ]; then
    printf '%s\t%s\n' "$url" "cloned but contains no rule files" >>"$SKIPPED"
    continue
  fi
  CLONED_URLS+=("$url")
  CLONED_PATHS+=("$dest")
done

# ------------------------------------------------------------- build the scan list
# Cross-language rulesets scan the whole target unscoped, so they run once for the run rather
# than once per language, and they never take --include: they carry rules for every language
# and a filter would drop findings in the files it does not match.
for ruleset in ${BASELINE[@]+"${BASELINE[@]}"}; do
  add_scan "all" "$ruleset" "$ruleset" ""
done
i=0
while [ $i -lt ${#CLONED_URLS[@]} ]; do
  add_scan "all" "${CLONED_URLS[$i]}" "${CLONED_PATHS[$i]}" ""
  i=$((i + 1))
done

is_baseline() {
  for b in ${BASELINE[@]+"${BASELINE[@]}"}; do
    [ "$b" = "$1" ] && return 0
  done
  return 1
}

# Language keys are folded onto their canonical name before any unit exists, so `js` and
# `javascript` in one plan produce one unit rather than two with identical globs.
CANON_SEEN="$WORK/canon.txt"
: >"$CANON_SEEN"
for key in ${LANG_KEYS[@]+"${LANG_KEYS[@]}"}; do
  # The key reaches the scan command as the language half of the output filename, and it
  # arrives as free-form generated text, so it gets the same treatment the paths do.
  ! has_unsafe_char "$key" || die "ruleset key reaches the scan command as a filename; '$key' is not a language"
  lang=$(canonical_lang "$key")
  [ "$lang" != "all" ] || die "ruleset key '$key' names the reserved language 'all' used by the cross-language unit"
  printf '%s\n' "$lang" >>"$CANON_SEEN"
done

# Redirected rather than piped: a `for … in $(…)` splits on every whitespace character, and a
# pipeline would put the loop in a subshell.
sort -u "$CANON_SEEN" >"$WORK/langs.txt"
while IFS= read -r lang; do
  [ -n "$lang" ] || continue
  # jq cannot express canonical_lang, so the union happens here: every key folding onto this
  # language contributes its rulesets, deduplicated. A ruleset listed twice for one language
  # would otherwise scan twice, and the second copy's failure would read as the first's success.
  own=""
  for key in ${LANG_KEYS[@]+"${LANG_KEYS[@]}"}; do
    [ "$(canonical_lang "$key")" = "$lang" ] || continue
    own="$own$(jq -r --arg k "$key" '.[$k][]' "$RULESETS_FILE")
"
  done
  own=$(printf '%s' "$own" | grep -v '^$' | sort -u || true)
  [ -n "$own" ] || continue

  globs=$(includes_for "$lang")
  had_own=""
  while IFS= read -r ruleset; do
    [ -n "$ruleset" ] || continue
    # A ruleset already running unscoped over the whole target does not need a narrower second
    # run. The merged SARIF dedups the copies; a per-scan sum of findings does not.
    if is_baseline "$ruleset"; then
      printf '%s/%s\n' "$lang" "$ruleset" >>"$ALSO_SHARED"
      continue
    fi
    add_scan "$lang" "$ruleset" "$ruleset" "$globs"
    had_own=1
  done <<EOF
$own
EOF
  # Reported only when the language actually got a unit. An unrecognized name costs the
  # --include optimization, not coverage: the rules run against every file and fail to match
  # what they do not understand. A language emptied by the baseline dedup ran nothing at all,
  # so naming it here would point at a scan that never happened.
  if [ -n "$had_own" ] && [ -z "$globs" ]; then
    printf '%s\n' "$lang" >>"$UNSCOPED"
  fi
done <"$WORK/langs.txt"

[ -s "$SCAN_LIST" ] || die "the ruleset plan produced no scans; there is nothing to run"

# ---------------------------------------------------------------------- commands
# Populates the global ARGV with the command for one scan. An array executed directly rather
# than a string run through eval: `eval "$cmd" &` reports exit status 1 whatever the command
# actually exited with, which would mark every failed scan as a success, and building argv also
# leaves no shell-quoting surface for a ruleset or path to escape through.
ARGV=()
build_argv() {
  local config=$1 includes=$2 json=$3 sarif=$4 g
  ARGV=(semgrep)
  [ -z "$PRO" ] || ARGV+=(--pro)
  ARGV+=("$METRICS_OFF")
  [ "$MODE" != "important-only" ] || ARGV+=("${SEVERITY_FLAGS[@]}")
  # Unquoted on purpose: includes is a space-separated glob list and must word-split here.
  # shellcheck disable=SC2086
  for g in $includes; do ARGV+=("--include=$g"); done
  # On every command including the unscoped cross-language ones: those are precisely the
  # rulesets that would otherwise read the cloned rule repositories.
  [ -z "$EXCLUDE_ARG" ] || ARGV+=("$EXCLUDE_ARG")
  ARGV+=(--config "$config" --json -o "$json" "--sarif-output=$sarif" "$TARGET")
}

# A pasteable rendering of ARGV for --dry-run. Anything outside a plainly safe set is wrapped
# whole, so a glob reaches semgrep rather than being expanded by the shell it is pasted into.
render_argv() {
  local out="" a
  for a in "${ARGV[@]}"; do
    case "$a" in
      *[!A-Za-z0-9._=/:-]*) out="$out \"$a\"" ;;
      *) out="$out $a" ;;
    esac
  done
  printf '%s' "${out# }"
}

if [ -n "$DRY_RUN" ]; then
  while IFS=$'\t' read -r stem lang ruleset config includes; do
    build_argv "$config" "$includes" "$RAW_DIR/$stem.json" "$RAW_DIR/$stem.sarif"
    render_argv
    printf '\n'
  done <"$SCAN_LIST"
  exit 0
fi

# ------------------------------------------------------------------- run the scans
# Batched rather than a rolling slot count, because `wait -n` needs bash 4.3 and this has to run
# on the bash 3.2 that ships with macOS. semgrep holds the rules and the scanned ASTs in memory,
# so an unbounded fan-out gets processes OOM-killed and those come back as ordinary scan
# failures with nothing pointing at memory as the cause.
total=$(wc -l <"$SCAN_LIST" | tr -d ' ')
echo "running $total scan(s), $JOBS at a time" >&2

pids=()
stems=()
run_batch() {
  local idx=0
  for idx in "${!pids[@]}"; do
    if wait "${pids[$idx]}"; then
      echo 0 >"$WORK/rc.${stems[$idx]}"
    else
      echo $? >"$WORK/rc.${stems[$idx]}"
    fi
  done
  pids=()
  stems=()
}

while IFS=$'\t' read -r stem lang ruleset config includes; do
  json="$RAW_DIR/$stem.json"
  sarif="$RAW_DIR/$stem.sarif"
  build_argv "$config" "$includes" "$json" "$sarif"
  "${ARGV[@]}" >"$WORK/out.$stem" 2>"$WORK/err.$stem" &
  pids+=("$!")
  stems+=("$stem")
  [ ${#pids[@]} -lt "$JOBS" ] || run_batch
done <"$SCAN_LIST"
[ ${#pids[@]} -eq 0 ] || run_batch

# ---------------------------------------------------------------------- assemble
: >"$WORK/scans.jsonl"
: >"$WORK/failed.jsonl"
while IFS=$'\t' read -r stem lang ruleset config includes; do
  json="$RAW_DIR/$stem.json"
  sarif="$RAW_DIR/$stem.sarif"
  rc=$(cat "$WORK/rc.$stem" 2>/dev/null || echo 127)
  findings=-1
  scanned=-1
  ok=""
  # Exit 0 covers both "found nothing" and "found plenty", so it says nothing about findings.
  # Exit 1 is a successful scan on older versions.
  #
  # Exit 2 is not only "no scan happened". semgrep also returns 2 when individual rules fail
  # to compile while the rest of the run completes and writes complete output — e.g. 12 Java
  # rules in elttam/semgrep-rules that current semgrep cannot parse, alongside 107 that ran
  # fine, and apiiro/malicious-code-ruleset whose own log read "Scan completed successfully
  # • Findings: 51". Both were thrown away. Exit 2 also still covers a bad argument, where
  # nothing is written at all; the artifact checks below tell the two apart, so 2 is allowed
  # through and flagged partial rather than trusted outright.
  #
  # Anything outside 0/1/2 stays fatal however plausible the artifacts look, exit 7 (config
  # would not load) included. Verified on semgrep 1.173: the exit code for an unloadable
  # config depends on the OUTPUT FLAGS, which is worth knowing before trusting either number.
  # Same rules directory, same target, back to back:
  #
  #   semgrep --config rules target                              -> 7, nothing written
  #   semgrep --config rules -o out.json --sarif-output=out.sarif -> 2, nothing written
  #
  # This script uses the second form, so a config that will not load reaches here as 2 with
  # no artifacts, and the -s checks below reject it on their own. The fatal branch is
  # therefore belt-and-braces rather than the thing doing the work — but it costs nothing,
  # it is what the suite pins, and it means a future semgrep that writes an empty result set
  # alongside a hard failure cannot be read as a clean scan.
  partial=""
  fatal=""
  case "$rc" in
    0 | 1) ;;
    2) partial=1 ;;
    *) fatal=1 ;;
  esac
  if [ -z "$fatal" ] && [ -s "$json" ] && [ -s "$sarif" ]; then
    if findings=$(jq -e '.results | length' "$json" 2>/dev/null); then
      ok=1
      # null and empty are different answers: a semgrep that does not report .paths gives -1,
      # "not known", while a present-but-empty list is a scan that genuinely opened no file.
      # Collapsing them with `// []` would report every scan as covering nothing.
      scanned=$(jq 'if .paths.scanned == null then -1 else (.paths.scanned | length) end' \
        "$json" 2>/dev/null || echo -1)
    else
      findings=-1
    fi
  fi
  if [ -n "$ok" ]; then
    [ "$scanned" -ne 0 ] || printf '%s/%s\n' "$lang" "$ruleset" >>"$COVERED_NOTHING"
    # `partial` marks a run whose results are real but incomplete — some rules failed to
    # compile. Reporting it as an unqualified success would overstate coverage; dropping it
    # entirely (the old behaviour) understated it far worse.
    jq -nc --arg lang "$lang" --arg ruleset "$ruleset" --arg json "$json" \
      --arg sarif "$sarif" --argjson findings "$findings" --argjson scanned "$scanned" \
      --argjson partial "$([ -n "$partial" ] && echo true || echo false)" --arg rc "$rc" \
      '{lang:$lang, ruleset:$ruleset, json:$json, sarif:$sarif, findings:$findings,
        filesScanned:$scanned, partial:$partial, exitCode:($rc|tonumber)}' \
      >>"$WORK/scans.jsonl"
  else
    # Carries the same paths a success does: a scan that crashed part-way may still have
    # written a partial file, and the report needs to be able to name it.
    err=$(tail -c 800 "$WORK/err.$stem" 2>/dev/null || true)
    [ -n "$err" ] || err="semgrep exited $rc"
    jq -nc --arg lang "$lang" --arg ruleset "$ruleset" --arg json "$json" \
      --arg sarif "$sarif" --arg error "$err" \
      '{lang:$lang, ruleset:$ruleset, json:$json, sarif:$sarif, error:$error}' \
      >>"$WORK/failed.jsonl"
  fi
done <"$SCAN_LIST"

PRO_JSON=false
[ -z "$PRO" ] || PRO_JSON=true

jq -n \
  --arg outputDir "$OUTPUT_ROOT" \
  --arg rawDir "$RAW_DIR" \
  --arg reposPath "$REPOS_DIR" \
  --arg mode "$MODE" \
  --arg excludePattern "$EXCLUDE_PATTERN" \
  --argjson pro "$PRO_JSON" \
  --slurpfile scans "$WORK/scans.jsonl" \
  --slurpfile failed "$WORK/failed.jsonl" \
  --rawfile skippedRaw "$SKIPPED" \
  --rawfile alsoSharedRaw "$ALSO_SHARED" \
  --rawfile unscopedRaw "$UNSCOPED" \
  --rawfile coveredNothingRaw "$COVERED_NOTHING" \
  '{
     outputDir: $outputDir, rawDir: $rawDir, reposPath: $reposPath, mode: $mode, pro: $pro,
     excludePattern: $excludePattern,
     scans: $scans, failed: $failed,
     skipped: ($skippedRaw | split("\n") | map(select(length > 0)) | map(split("\t"))
               | map({ruleset: .[0], reason: (.[1] // "clone failed")})),
     alsoShared: ($alsoSharedRaw | split("\n") | map(select(length > 0)) | unique),
     unscoped: ($unscopedRaw | split("\n") | map(select(length > 0)) | unique),
     coveredNothing: ($coveredNothingRaw | split("\n") | map(select(length > 0)) | unique)
   }' >"$OUTPUT_ROOT/scans.json"

n_ok=$(jq '.scans | length' "$OUTPUT_ROOT/scans.json")
n_failed=$(jq '.failed | length' "$OUTPUT_ROOT/scans.json")
n_skipped=$(jq '.skipped | length' "$OUTPUT_ROOT/scans.json")
echo "$n_ok scan(s) succeeded, $n_failed failed, $n_skipped skipped" >&2
echo "$OUTPUT_ROOT/scans.json"

# A run where nothing succeeded is a failed run, not a clean one. Reporting zero findings from
# it is the failure this whole script is shaped to avoid.
[ "$n_ok" -gt 0 ] || exit 1
