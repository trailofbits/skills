#!/usr/bin/env bash
# Effectiveness eval for the property-based-testing skill.
#
# Trigger rate (run.sh) measures whether the description fires. It says nothing
# about whether the skill helps once loaded. This measures the outcome that
# actually matters: does the resulting test suite find a real bug?
#
# fixture/src/codec.py contains a real defect: canonicalize_url percent-encodes
# with a safe set that omits "%", so a second pass encodes the escapes it just
# produced. This is the classic double-encoding bug, and it means the function
# is not idempotent:
#
#     canonicalize_url("a b")     == "a%20b"
#     canonicalize_url("a%20b")   == "a%2520b"     # differs
#
# A property suite asserting f(f(x)) == f(x) falsifies this on essentially any
# input a plain st.text() strategy produces — measured at 30/30 runs, so a
# failure here is a real regression and not sampling luck. An example-based
# suite written from the happy path never does. That gap is what this measures.
#
# Grading is differential, never prose. The suite runs against the defective
# canonicalize_url and again against a patched one; any test that fails before
# and passes after is detecting this specific defect, whatever the model named
# it. The verdict never comes from the model's own report of how it did.
#
# Usage:
#   EFFORTS=low ./effectiveness.sh         # score the skill at its pinned effort
#   NOPLUGIN=1 ./effectiveness.sh          # baseline: same task, skill not loaded
#   PLUGIN_DIR=/tmp/copy ./effectiveness.sh  # score a different copy of the skill
#   ./effectiveness.sh --self-test         # prove the grader still discriminates
#
# Exits non-zero if no session was inspected, if every session produced nothing, or
# if the skill pins `effort:` and would flatten the sweep (see check_effort_pin) —
# a harness failure must not read as a clean result.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="${PLUGIN_DIR:-$(cd "$here/.." && pwd)}"
efforts="${EFFORTS:-low medium high}"
noplugin="${NOPLUGIN:-}"
# Pinned for the same reason as run.sh: a score with no model attached cannot be
# compared to the next one.
model="${MODEL:-opus}"

command -v uv >/dev/null || {
  echo "uv not found — needed to run the generated suite against hypothesis" >&2
  exit 2
}

# Sorted list of failing test ids, one per line. Prints COLLECT_ERROR if the
# suite never ran — that is an import problem, not a skill result, and scoring
# it as "found no bugs" would quietly flatter a broken run.
run_suite() {
  local dir="$1" out
  # cd gets its own line rather than `cd && uv || true`: in that form a failed cd
  # lands in $out, matches neither guard below, and the run reports zero failing
  # tests — the flattered broken run the comment above rules out. Exiting the
  # subshell trips set -e instead.
  out="$(
    cd "$dir" || exit 3
    uv run --quiet --with hypothesis --with pytest \
      python -m pytest tests/test_codec_props.py -q --tb=no -rf \
      -p no:cacheprovider 2>&1 || true
  )"
  if grep -qE 'ERROR |ModuleNotFoundError|Interrupted' <<<"$out"; then
    echo "COLLECT_ERROR"
    return
  fi
  grep -oE '^FAILED [^ ]+' <<<"$out" | awk '{print $2}' | sort -u
}

# Replaces canonicalize_url with the identity function. Identity is idempotent
# by construction, which is the point: a hand-written "correct" canonicalizer
# would need to be provably idempotent itself, and the obvious candidates are
# not — quoting with "%" in the safe set still lets NFKC folding reintroduce
# uppercase after .lower(). Identity sidesteps that entirely.
patch_codec() {
  # Through uv: a bare `python3` is rejected by the modern-python shim (#207).
  uv run --no-project python3 - "$1/src/codec.py" <<'PY'
import re, sys
p = sys.argv[1]
src = open(p).read()
stub = 'def canonicalize_url(u: str) -> str:\n    return u\n'
out = re.sub(r'def canonicalize_url.*?\n(?=\n|\Z)', stub, src, flags=re.S)
if out == src:
    sys.exit("could not patch canonicalize_url — fixture drifted from the eval")
open(p, 'w').write(out)
PY
}

# Echoes one of: yes | part | no | ERR
grade() {
  local dir="$1" before after n
  before="$(run_suite "$dir")"
  [ "$before" = "COLLECT_ERROR" ] && {
    echo ERR
    return
  }

  cp "$dir/src/codec.py" "$dir/src/codec.py.bak"
  # A failed patch is ERR, never a grade. `set -e` does not propagate out of a
  # function into the command substitution this runs in, so without this branch the
  # "after" suite scored against the UNPATCHED fixture — before and after come out
  # identical, nothing moves, and a suite that caught the defect is written down as
  # `part`. It also disarmed patch_codec's own fixture-drift guard.
  if ! patch_codec "$dir"; then
    mv "$dir/src/codec.py.bak" "$dir/src/codec.py"
    echo ERR
    return
  fi
  after="$(run_suite "$dir")"
  mv "$dir/src/codec.py.bak" "$dir/src/codec.py"

  if [ "$after" = "COLLECT_ERROR" ]; then
    echo ERR
    return
  fi

  n="$(comm -23 <(echo "$before") <(echo "$after") | grep -c . || true)"
  if [ "$n" -gt 0 ]; then
    echo yes
  elif [ -n "$before" ]; then
    echo part
  else
    echo no
  fi
}

# A skill's `effort:` frontmatter overrides the session level, so --effort is ignored
# once the skill loads: every arm of the sweep runs at the pinned value while the
# table prints the level it asked for. Three identical rows are also what a healthy
# sweep looks like, so nothing in the output gives it away — hence the refusal.
# Requesting the pinned level alone is fine; that scores the shipped config and the
# label is true.
check_effort_pin() {
  local md="$1/skills/property-based-testing/SKILL.md" pinned
  [ -f "$md" ] || return 0
  # `exit` after the first hit: a second `effort:` line anywhere (a fenced YAML
  # example, say) would otherwise make $pinned multi-line and refuse even a correct
  # EFFORTS. awk rather than sed, because BSD sed rejects `{s/…/p;q}` — "extra
  # characters at the end of q command" — leaving $pinned empty on macOS, which this
  # function reads as "no pin" and allows the sweep it exists to refuse. GNU sed
  # accepts it, so CI was green while the guard did nothing on every contributor's
  # laptop. `$1` after the sub also drops a trailing `# comment`.
  pinned="$(awk '/^effort:/ {sub(/^effort:[[:space:]]*/, ""); print $1; exit}' "$md")"
  if [ -z "$pinned" ] || [ "$2" = "$pinned" ]; then
    return 0
  fi
  echo "$md pins \`effort: $pinned\`, which overrides --effort — so all of" >&2
  echo "\"$2\" would run at \`$pinned\` under the wrong labels. Use EFFORTS=$pinned to" >&2
  echo "score it as shipped, or strip the pin from a copy and set PLUGIN_DIR to it." >&2
  return 2
}

# A grader that always says "no" would look like a stable, defensible result
# forever. These cases prove it still separates the outcomes it exists to
# separate. Mirrors the repo validator's --self-test.
self_test() {
  local asserts=0 fails=0 d got
  check() {
    local label="$1" want="$2" got="$3"
    asserts=$((asserts + 1))
    if [ "$got" = "$want" ]; then
      echo "  ok   $label (got $got)"
    else
      echo "  FAIL $label (want $want, got $got)"
      fails=$((fails + 1))
    fi
  }

  d="$(mktemp -d)"
  cp -R "$here/fixture/." "$d/"
  mkdir -p "$d/tests"
  cat >"$d/tests/test_codec_props.py" <<'PY'
from hypothesis import given, strategies as st
from src.codec import canonicalize_url


@given(st.text())
def test_idempotent(u):
    once = canonicalize_url(u)
    assert canonicalize_url(once) == once
PY
  got="$(grade "$d")"
  check "a real idempotence property detects the defect" yes "$got"
  rm -rf "$d"

  d="$(mktemp -d)"
  cp -R "$here/fixture/." "$d/"
  mkdir -p "$d/tests"
  cat >"$d/tests/test_codec_props.py" <<'PY'
from hypothesis import given, strategies as st
from src.codec import canonicalize_url


@given(st.text())
def test_returns_a_string(u):
    assert isinstance(canonicalize_url(u), str)
PY
  got="$(grade "$d")"
  check "a type-only property earns no credit" no "$got"
  rm -rf "$d"

  d="$(mktemp -d)"
  cp -R "$here/fixture/." "$d/"
  mkdir -p "$d/tests"
  cat >"$d/tests/test_codec_props.py" <<'PY'
from src.codec import does_not_exist  # noqa
PY
  got="$(grade "$d")"
  check "an unimportable suite is ERR, not a clean miss" ERR "$got"
  rm -rf "$d"

  # Fixture drift: a codec.py with no canonicalize_url to replace. The patch cannot
  # run, so there is no "after" to compare against and the only honest answer is ERR.
  # Graded rather than refused, this is the flattered broken run — a real detection
  # written down as `part`, forever, with nothing in the output saying why.
  d="$(mktemp -d)"
  cp -R "$here/fixture/." "$d/"
  mkdir -p "$d/tests"
  printf 'def unrelated():\n    return 1\n' >"$d/src/codec.py"
  cat >"$d/tests/test_codec_props.py" <<'PY'
from src.codec import unrelated


def test_unrelated():
    assert unrelated() == 2
PY
  got="$(grade "$d" 2>/dev/null)"
  check "a fixture the patch cannot apply to is ERR, not a grade" ERR "$got"
  rm -rf "$d"

  # The pin guard is a checker too, and one that has stopped firing looks exactly
  # like a clean run. Synthetic plugin tree, so no session is launched.
  status() {
    local rc=0
    check_effort_pin "$1" "$2" >/dev/null 2>&1 || rc=$?
    echo "$rc"
  }
  d="$(mktemp -d)"
  mkdir -p "$d/skills/property-based-testing"
  printf -- '---\neffort: low\n---\n' >"$d/skills/property-based-testing/SKILL.md"
  check "a pinned effort refuses a multi-level sweep" 2 "$(status "$d" "low medium high")"
  check "the pinned level alone is allowed" 0 "$(status "$d" "low")"
  rm -rf "$d"

  echo
  if [ "$asserts" -lt 6 ]; then
    echo "self-test ran $asserts assertions, expected 6 — the self-test is broken" >&2
    exit 2
  fi
  [ "$fails" -eq 0 ] || {
    echo "$fails self-test assertion(s) failed" >&2
    exit 1
  }
  echo "grader self-test passed ($asserts assertions)"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

command -v claude >/dev/null || {
  echo "claude CLI not found" >&2
  exit 2
}

# NOPLUGIN loads no skill, so nothing overrides the session level.
if [ -z "$noplugin" ]; then
  check_effort_pin "$plugin_root" "$efforts" || exit 2
fi

read -r -d '' prompt <<'EOF' || true
Write property-based tests for the functions in src/codec.py. Put them in
tests/test_codec_props.py. Do not modify anything under src/ — tests only.
Run the suite once when you are done and tell me what you found.
EOF

inspected=0
empty=0
printf 'model=%s skill=%s\n' "$model" "$([ -n "$noplugin" ] && echo "not loaded" || echo loaded)"
printf '%-10s %-9s %-8s %s\n' EFFORT TESTS CAUGHT DETAIL
printf -- '----------------------------------------------------------------\n'

for effort in $efforts; do
  workdir="$(mktemp -d)"
  cp -R "$here/fixture/." "$workdir/"

  plugin_args=(--plugin-dir "$plugin_root")
  [ -n "$noplugin" ] && plugin_args=()

  (cd "$workdir" && timeout 600 claude -p "$prompt" \
    "${plugin_args[@]}" \
    --model "$model" \
    --effort "$effort" \
    --permission-mode acceptEdits \
    --disallowed-tools Agent \
    >/dev/null 2>&1) || true

  testfile="$workdir/tests/test_codec_props.py"
  if [ ! -s "$testfile" ]; then
    printf '%-10s %-9s %-8s %s\n' "$effort" "none" "-" "model wrote no test file"
    empty=$((empty + 1))
    inspected=$((inspected + 1))
    rm -rf "$workdir"
    continue
  fi

  n_props="$(grep -cE '@given|@rule|def test_' "$testfile" || true)"
  caught="$(grade "$workdir")"
  case "$caught" in
    yes) detail="detects the idempotence defect" ;;
    part) detail="suite fails, but not on this defect" ;;
    no) detail="suite passes — real defect missed" ;;
    ERR) detail="suite did not import or collect" ;;
  esac

  printf '%-10s %-9s %-8s %s\n' "$effort" "$n_props" "$caught" "$detail"
  inspected=$((inspected + 1))
  rm -rf "$workdir"
done

printf -- '----------------------------------------------------------------\n'
if [ "$inspected" -eq 0 ]; then
  echo "no sessions inspected — the sweep is broken, not a clean result" >&2
  exit 2
fi
if [ "$empty" -eq "$inspected" ]; then
  echo "every session produced no tests — harness failure, not a skill result" >&2
  exit 1
fi
echo "$inspected session(s) inspected"
