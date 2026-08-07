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
#   ./effectiveness.sh                     # sweep low/medium/high with the skill
#   EFFORTS="high" ./effectiveness.sh      # single level
#   NOPLUGIN=1 ./effectiveness.sh          # baseline: same task, skill not loaded
#   PLUGIN_DIR=/tmp/copy ./effectiveness.sh  # score a different copy of the skill
#   ./effectiveness.sh --self-test         # prove the grader still discriminates
#
# Exits non-zero if no session was inspected, or if every session produced
# nothing — a harness failure must not read as a clean result.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# SKILL.md sets `effort: low`, and a skill's effort overrides the session level — so
# --effort below is ignored once the skill loads, and the EFFORTS sweep that chose
# that value cannot be reproduced against the plugin as shipped. To re-sweep, copy
# the plugin, strip the `effort:` line from the copy, and point PLUGIN_DIR at it.
plugin_root="${PLUGIN_DIR:-$(cd "$here/../../.." && pwd)}"
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
  python3 - "$1/src/codec.py" <<'PY'
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
  patch_codec "$dir"
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

# A grader that always says "no" would look like a stable, defensible result
# forever. These three cases prove it still separates the outcomes it exists to
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

  echo
  if [ "$asserts" -lt 3 ]; then
    echo "self-test ran $asserts assertions, expected 3 — the self-test is broken" >&2
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
