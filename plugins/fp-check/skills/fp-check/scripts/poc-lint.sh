#!/usr/bin/env bash
#
# poc-lint.sh — reject PoCs that describe an exploit instead of performing one.
#
# Replaces the hand-run grep lists that used to live in ANTI_PATTERNS.md. Those
# lists could not be used as written:
#
#   - bare "..." matched Python's Ellipsis, .pyi stubs, and any prose
#   - "XXX" in the TODO list collided with the "$XX" monetary placeholder
#   - 'print.*would' fired on any string containing the word "would"
#
# The patterns below are narrowed to the shape a placeholder actually takes, so
# that tightening them does not quietly switch detection off. tests/poc-lint.bats
# holds a dirty fixture and a clean one; if a pattern stops detecting, that suite
# fails rather than the linter silently passing everything.
#
# Exit codes:
#   0  clean
#   1  violations found
#   2  usage error, unreadable file, a file with no code in it, an input list
#      that leaves the .pyi-skipping rules with nothing to read, or grep failure
#
# Usage:
#   poc-lint.sh FILE [FILE...]
#   poc-lint.sh --symbol vulnerable_fn FILE     # + Principle 5, rules 6 and 8
# shellcheck disable=SC2016
# The single-quoted strings here are grep/awk PATTERNS, not shell text: `$XX`,
# `${...}` and `$` anchors are meant to reach the matcher literally. Double
# quotes would have the shell expand them first, which is how a placeholder
# detector silently stops detecting placeholders. This repo's pre-commit applies
# no severity floor, so the info-level advice has to be refused explicitly rather
# than filtered out.

set -euo pipefail

SYMBOL=""
FILES=()

usage() {
  cat >&2 <<'EOF'
usage: poc-lint.sh [--symbol NAME] FILE [FILE...]

  --symbol NAME  Fail if the PoC never NAMES NAME (Principle 5: call the real
                 code, never reimplement it). A definition of the same name is
                 reported as a note, not a violation — see rule 6.
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --symbol)
      [ $# -ge 2 ] || usage
      SYMBOL="$2"
      # Both symbol rules key on the LAST segment of a qualified name, split on
      # `.` and on `::`. A qualified symbol — `target_app.ledger.transfer_balance`,
      # `Ledger.debit`, `ledger::transfer_balance` — never appears contiguously in
      # a Python, Go, JS or Rust call: the import binds the last segment and the
      # call site uses that. Splitting on `.` alone treated every `::` symbol as
      # unqualified, so a Rust PoC was checked for the literal string
      # `ledger::transfer_balance`.
      #
      # `--symbol ''`, `--symbol 'Ledger.'` and `--symbol 'ledger::'` all leave
      # that segment empty, and both rules are guarded by [ -n "$SYMBOL" ], so
      # they silently switched off and printed "clean". Refuse instead: the
      # caller passing one of those is the caller that most needs the check.
      LEAF="${SYMBOL##*.}"
      LEAF="${LEAF##*::}"
      if [ -z "$LEAF" ]; then
        echo "poc-lint: --symbol requires a non-empty final segment (got '$SYMBOL'); refusing to skip the Principle 5 checks silently" >&2
        exit 2
      fi
      shift 2
      ;;
    -h | --help) usage ;;
    -*) usage ;;
    *)
      FILES+=("$1")
      shift
      ;;
  esac
done

# A checker that inspects nothing must fail, not pass.
if [ ${#FILES[@]} -eq 0 ]; then
  echo "poc-lint: no files given; refusing to report success" >&2
  exit 2
fi

for f in "${FILES[@]}"; do
  if [ ! -r "$f" ]; then
    echo "poc-lint: cannot read '$f'; refusing to report success" >&2
    exit 2
  fi
  # Same rule as the zero-files case one level down. Bytes are not content, and
  # `[ ! -s ]` only caught the truly empty file: a lone newline, a stray space
  # and a UTF-8 BOM each satisfied every pattern below by having nothing to
  # match, and were reported as a clean PoC — through triage-poc's independent
  # artifact check, which re-runs this linter. One alphanumeric character covers
  # all three.
  #
  # Deliberately not "has a line of code". Rules 2 to 5 all match INSIDE
  # comments, so a file of nothing but comments is something they read rather
  # than something they skip, and a placeholder comment must be reported as the
  # violation it is — exit 1 with a rule name — not as an unusable input.
  # Rejecting it here made `# ... exploit logic here ...` exit 2 and took the
  # flagship elided-code case with it.
  if ! grep -q '[[:alnum:]]' "$f"; then
    echo "poc-lint: '$f' has no content; refusing to report success" >&2
    exit 2
  fi
done

violations=0

# report RULE EXPLANATION LINES — shared by the grep rules below and the awk
# pass at the end, which is the only other thing that produces hits.
report() {
  local rule="$1" explanation="$2" lines="$3"
  [ -n "$lines" ] || return 0
  printf '\n%s\n  %s\n' "$rule" "$explanation" >&2
  printf '%s\n' "$lines" | sed 's/^/    /' >&2
  violations=$((violations + 1))
}

# escape_re TEXT — TEXT as an ERE matching itself.
escape_re() {
  printf '%s' "$1" | sed 's/[][\.*^$(){}?+|/]/\\&/g'
}

# scan RULE EXPLANATION PATTERN [FILE...]
#
# Defaults to every input file. stderr from grep is deliberately left on the
# terminal rather than folded into the match output: a grep that fails must not
# be indistinguishable from a grep that matched.
scan() {
  local rule="$1" explanation="$2" pattern="$3"
  shift 3
  local targets=()
  if [ $# -gt 0 ]; then
    targets=("$@")
  else
    targets=("${FILES[@]}")
  fi
  [ ${#targets[@]} -gt 0 ] || return 0

  local hits status
  set +e
  hits=$(grep -nE -- "$pattern" "${targets[@]}")
  status=$?
  set -e

  case "$status" in
    0) report "$rule" "$explanation" "$hits" ;;
    1) : ;; # no match, which is the passing case
    *)
      echo "poc-lint: grep failed (status $status) on rule '$rule'" >&2
      exit 2
      ;;
  esac
}

# 1. Monetary placeholders. Anchored on the currency sigil so that this rule
#    cannot collide with the XXX todo marker below.
scan "monetary-placeholder" \
  "Unfilled figure. State the real amount or delete the claim." \
  '\$X{2,}[MKB]?|\$\$\$|X{2,},X{3}|(^|[^[:alnum:]])X-X([^[:alnum:]]|$)'

# 2. Todo markers. XXX must stand alone: not preceded by '$' or ',' and not
#    adjacent to another X. That keeps "$XXM", "XX,XXX" and "MAXXX_RETRIES" out
#    of this rule — monetary placeholders are rule 1's job and must be reported
#    once, not twice.
#
#    The markers are word-bounded, and TEMPORARY is gone. Unanchored, they
#    rejected working exploits on ordinary vocabulary: an open-redirect PoC
#    asserting on HTTPStatus.TEMPORARY_REDIRECT, a stacked-query SQLi whose
#    payload is "CREATE TEMPORARY TABLE pwn(x int)", and a stored-XSS PoC
#    storing alert('HACKED') were all reported as unfinished work. A linter that
#    fails a correct PoC is worse than one that misses a marker, because the
#    agent's only recourse is to work around it.
#
#    Case is the other half of it. Uppercase TODO/FIXME/HACK are markers
#    wherever they appear, but lowercase "todo" is ordinary prose — this file's
#    own clean fixture says "not a todo marker" in a comment — so lowercase
#    counts only in the shape a marker actually takes: followed by ':' or '!'
#    (`# todo: finish this`, Rust's `todo!()`). HACK stays uppercase-only;
#    "hack" as a word is unremarkable in an exploit.
scan "todo-marker" \
  "Unfinished work. A PoC with a TODO in it is not a PoC." \
  '(^|[^[:alnum:]_])(TODO|FIXME|HACK)([^[:alnum:]_]|$)|(^|[^[:alnum:]_])([Tt][Oo][Dd][Oo]|[Ff][Ii][Xx][Mm][Ee])[[:space:]]*[:!]|(^|[^$X,[:alnum:]])XXX([^X[:alnum:]]|$)'

# Rules 3, 6 and 7 skip .pyi files: a type stub legitimately declares
# `def transfer(a, b): ...`, and flagging that is the "linter rejects
# correct-by-construction code" failure rule 2 was narrowed to avoid. The
# filtering is a shell loop rather than grep's --exclude because that flag
# applies inconsistently to explicitly listed files across GNU and BSD grep.
PY_FILES=()
for f in "${FILES[@]}"; do
  case "$f" in
    *.pyi) : ;;
    *) PY_FILES+=("$f") ;;
  esac
done
# An input list that is nothing but stubs leaves three of the seven rules with
# no file to read, and the old per-rule `-gt 0` guards reported that as "clean"
# — the zero-items failure this script rejects two guards up for the empty file
# and the empty argument list. A .pyi is not a PoC; refuse rather than skip.
if [ ${#PY_FILES[@]} -eq 0 ]; then
  echo "poc-lint: every input is a .pyi stub, which rules 3, 6 and 7 skip; refusing to report success" >&2
  exit 2
fi
# Rule 3 lives with rules 6 and 7 in the awk pass at the end of this file; all
# three have to know where a docstring ends and grep cannot see across lines.

# 4. Narration instead of execution. Requires "would" to sit inside a quoted
#    string being printed, which is the shape of "print what would happen" —
#    not merely anywhere on a line that also prints.
#
#    Both halves of "printed" were too narrow. Only double-quoted strings were
#    matched, so print('the attacker would drain the pool') was clean; and the
#    printer list stopped at print/echo/console/fmt, so the same sentence
#    through logging.info() or sys.stdout.write() was clean too.
#
#    The three logging spellings share one level list. They did not: `logger?\.`
#    binds the `?` to the single preceding character, so it meant `logge` plus an
#    optional `r` and could never match `log.` — the shape `log =
#    logging.getLogger(__name__)` produces and the one most Python PoCs use. Its
#    level list was also short of the sibling `logging\.` branch by two, so
#    logger.error("this would drop the table") was clean while logging.error was
#    a violation. One `log(ger|ging)?\.` with one list cannot drift like that.
#
#    System.out.print(ln)? is gone rather than fixed: the bare `print`
#    alternation already matches the "print" inside "println", so the branch
#    matched nothing the rule did not already catch.
scan "narrated-exploit" \
  "This describes the attack. Replace it with code that performs the attack." \
  "(print|echo|console\.(log|info|debug|warn|error)|fmt\.Print(ln|f)?|log(ger|ging)?\.(info|debug|warn|warning|error|critical)|sys\.stdout\.write)[^\"']*(\"[^\"]*would[^\"]*\"|'[^']*would[^']*')"

# 5. Commented-out attacks: the exploit is written down but never called.
#
#    The `"Step N:"` label alternation is gone rather than narrowed. A numbered
#    progress line is the ordinary shape of a multi-stage exploit and nothing
#    in the text distinguishes one from tutorial scaffolding — print("Step 1:
#    authenticating as the low-privilege user") beside a real login() call, and
#    an assertion on a captured server response reading "Step 1: verify your
#    email", were both reported as unfinished work. Same call as TEMPORARY in
#    rule 2, for the same reason given there: a linter that fails a correct PoC
#    is worse than one that misses a marker.
scan "placeholder-attack" \
  "The exploit is commented out, not called." \
  "(^|[[:space:]])(//|#)[[:space:]]*attacker\.[a-zA-Z_]+\("

# 3, 6 and 7, in one awk pass. All three have to ignore code quoted inside a
# docstring or a block comment, which grep cannot see across lines. As three
# separate greps they got it wrong together: a PoC that imported the real symbol
# and quoted the vulnerable definition in its MODULE docstring was reported as
# reimplementing it (6), as leaving a stub body (7) and as eliding code (3) —
# three violations against a PoC doing exactly what Principle 5 asks, which is
# the failure this file repeatedly calls the worse of its two. One pass also
# stops the rules disagreeing about where a docstring ends.
#
# 3. Ellipsis placeholders: a comment whose whole body is "...", or a line that
#    is nothing but "...". Two shapes, deliberately different in strictness:
#
#    (a) a whole line that is nothing but "...";
#    (b) a COMMENT whose body starts with "..." — `// ... exploit logic here ...`
#        and `# ... send the payload ...`. The anchored rule alone missed both,
#        which is the flagship elided-code example the linter is named for: any
#        narration after the dots defeated the `$`, and no other rule covers a
#        bare comment (narrated-exploit needs a printer). Anchoring on the START
#        of the comment body keeps ordinary prose that merely trails off —
#        "# see the docs for more..." — out of the rule.
#
# 6. A definition, in this PoC, of something with the symbol's name. REPORTED,
#    NOT ENFORCED — it does not affect the exit code.
#
#    The pattern itself is sound: it catches every shape of definition a leading
#    modifier used to hide, all of which reported clean before it was widened —
#
#      async def SYM        export function SYM     pub fn SYM
#      func (r *Repo) SYM   SYM = function (...)
#
#    — but what a match MEANS is not decidable by grep. `def transfer_balance`
#    under `--symbol target_app.ledger.transfer_balance` is a verbatim copy of the
#    code under test; `def main()` under `--symbol cli.main`, in a PoC whose next
#    line is `cli.main(argv)`, is the ordinary driver every standalone PoC has.
#    `run`, `handler` and `parse` collide the same way. Three consecutive attempts
#    to separate the two by adding a condition each fixed one direction and broke
#    the other, because the fact that separates them — is this body a copy of the
#    target's? — is not in the text a grep can see.
#
#    So it reports the fact and leaves the judgement to a reader who can open both
#    files. A non-zero exit is BUILD_FAILED at the builder and BLOCKED at the
#    reviewer's re-run, which discards a real, executed, reproducing finding; this
#    file's standing rule is that failing a correct PoC is the worse of its two
#    errors, because the agent's only recourse is to stop calling the real code.
#
#    Known boundary: a C/C++/Java/C# definition carries no keyword at all
#    (`public static void SYM(int a) {`), and the patterns that would catch it
#    also match `if SYM(x) {`. That form is deliberately not matched.
REIMPL_RE=""
if [ -n "$SYMBOL" ]; then
  esc=$(escape_re "$LEAF")
  # Any run of leading keywords (async, pub, export, public, static, ...).
  mods='([A-Za-z_][A-Za-z_0-9]*[[:space:]]+)*'
  kw='(def|function|fn|func|class|sub)'
  # The right-hand side of an assignment has to be a function LITERAL. The
  # `const|let|var` alternative carried no such constraint, so it fired on the
  # canonical Principle-5-COMPLIANT way to pull the real symbol into a Node PoC:
  #
  #   const SYM = require('../lib/vuln').SYM
  #   const SYM = (await import('../lib/vuln')).SYM
  #   var   SYM = global.app.SYM
  #
  # Rejecting those is the worse failure of the two this rule can make: the
  # agent's only recourse is to rename the import and stop calling the real
  # code, which is the exact thing Principle 5 exists to prevent. Shared by both
  # assignment alternatives so they cannot drift apart again. The bare-parameter
  # arrow (`SYM = q => ...`) is in the list because constraining the RHS would
  # otherwise stop catching a form the unconstrained rule did catch.
  fnlit='(async[[:space:]]+)?(function|lambda|\([^)]*\)[[:space:]]*=>|[A-Za-z_][A-Za-z_0-9]*[[:space:]]*=>)'
  REIMPL_RE="^[[:space:]]*${mods}${kw}[[:space:]]+${esc}([^[:alnum:]_]|$)|^[[:space:]]*func[[:space:]]*\([^)]*\)[[:space:]]*${esc}([^[:alnum:]_]|$)|^[[:space:]]*(const|let|var)[[:space:]]+${esc}[[:space:]]*=[[:space:]]*${fnlit}|^[[:space:]]*${esc}[[:space:]]*=[[:space:]]*${fnlit}"
fi
# Through the environment rather than -v: awk expands backslash escapes in a -v
# value, so every `\.` and `\(` above would arrive unescaped. The program checks
# it for emptiness before using it, because `$0 ~ ""` matches every line.
export REIMPL_RE

# 7. Stub bodies: a definition whose entire body is `pass`, `...`, or a
#    not-implemented raise. This is the shape a half-written PoC actually takes,
#    and it passed every grep rule above — `def exploit(): pass` was reported
#    clean while SKILL.md claims placeholders are enforced here rather than by
#    good intentions.
#
#    A docstring or a comment between the signature and the body used to clear
#    `expect`, so every stub that documented itself first was reported clean:
#
#      def test_negative_transfer_drains_ledger():
#          """Transferring -500 credits the attacker and underflows."""
#          pass
#
#    That is not an exotic shape — triage-poc.js instructs the builder to "write
#    the docstring to match the assertion" on a test-integrated PoC, so it is
#    precisely what a half-written one looks like. Comment and docstring lines
#    are therefore not read as the body. The delimiters arrive as awk variables
#    because the program below is single-quoted and so cannot contain a ' of its
#    own; they hold no backslashes, so -v is safe for them.
hits=$(awk -v TQD='"""' -v TQS="'''" -v BCO='/*' -v BCC='*/' '
BEGIN { reimpl = ENVIRON["REIMPL_RE"] }
function flag(rule, n, t) { printf "%s %s:%d:%s\n", rule, FILENAME, n, t }
FNR == 1 { expect = 0; closer = "" }
# A docstring or block comment opened on an earlier line runs to its terminator.
closer != "" { if (index($0, closer)) closer = ""; next }
# Rule 3, before the comment skip below because a comment body is exactly what
# its second shape matches. No `next`: `def f():` followed by `...` is both an
# elided line and a stub body, as it was when these were separate greps.
/^[[:space:]]*(#|\/\/|\/\*)?[[:space:]]*\.\.\.[[:space:]]*(\*\/)?[[:space:]]*$|^[[:space:]]*(#|\/\/|\/\*)[[:space:]]*\.\.\./ {
  flag("ellipsis-placeholder", FNR, $0)
}
# Comments, and the opening line of a docstring or block comment, at ANY nesting
# level. This ran only between a signature and its body, so a module- or
# class-level docstring was invisible and the code quoted inside one reached
# both rules below as a definition.
{
  body = $0
  sub(/^[[:space:]]+/, "", body)
  if (body ~ /^(#|\/\/)/) next
  sub(/^[rRbBuUfF]+/, "", body)
  opener = ""
  if (index(body, TQD) == 1) { opener = TQD; terminator = TQD }
  else if (index(body, TQS) == 1) { opener = TQS; terminator = TQS }
  else if (index(body, BCO) == 1) { opener = BCO; terminator = BCC }
  if (opener != "") {
    if (index(substr(body, length(opener) + 1), terminator) == 0) closer = terminator
    next
  }
}
# Rule 6. No `next`: one line can be both a reimplementation and a stub
# signature, and each rule reports it once.
reimpl != "" && $0 ~ reimpl { flag("reimplementation", FNR, $0) }
# Rule 7, body on the same line as the signature.
/^[[:space:]]*(async[[:space:]]+)?(def|function|fn|func)[^:{]*[:{][[:space:]]*(pass|\.\.\.)[[:space:]]*$/ {
  flag("stub-body", FNR, $0); expect = 0; next
}
/^[[:space:]]*(async[[:space:]]+)?(def|function|fn|func)[[:space:]]/ {
  expect = 1; def_line = FNR; def_text = $0; next
}
expect && /^[[:space:]]*$/ { next }
expect && /^[[:space:]]*(pass|\.\.\.|raise[[:space:]]+NotImplementedError|throw[[:space:]]+new[[:space:]]+Error|unimplemented!|todo!)/ {
  flag("stub-body", def_line, def_text); expect = 0; next
}
{ expect = 0 }
' "${PY_FILES[@]}")

report "ellipsis-placeholder" \
  "Elided code. Write the statements out." \
  "$(printf '%s\n' "$hits" | sed -n 's/^ellipsis-placeholder //p')"
redefined=$(printf '%s\n' "$hits" | sed -n 's/^reimplementation //p')
if [ -n "$redefined" ]; then
  printf '\npossible-reimplementation (NOTE — not a violation, does not fail this lint)\n  This PoC defines "%s" itself. That is either a copy of the code under test, which Principle 5 forbids, or an ordinary local driver that happens to share the name. Grep cannot tell those apart; open the file and decide.\n' "$LEAF" >&2
  printf '%s\n' "$redefined" | sed 's/^/    /' >&2
fi
report "stub-body" \
  "A definition whose whole body is a placeholder. Implement it." \
  "$(printf '%s\n' "$hits" | sed -n 's/^stub-body //p')"

# 8. The half of Principle 5 a grep can actually decide: the symbol's last
#    segment appears somewhere in the PoC's code. A file that never names the
#    symbol under test cannot be calling it, and rule 6 does not cover that — a
#    PoC that never mentions the symbol trivially does not redefine it.
#
#    That mention is ALL this establishes, and the clean line says so. It does
#    not distinguish a call from a coincidence: `--symbol app.io.read` is
#    satisfied by `open(p).read()`, and `read`, `get`, `run` and `parse` are
#    leaves a PoC hits by accident.
#
#    Requiring the PARENT segment as well was the attempt to close that, and it
#    blocked the canonical shapes of a COMPLIANT PoC instead — a façade
#    re-export (`from flask import send_file` under `flask.helpers.send_file`), a
#    pytest fixture (`def test_idor(client): client.get(...)` under
#    `FlaskClient.get`) and a factory (`a = make_account();
#    a.transfer_balance(...)` under `Ledger.transfer_balance`) name no parent —
#    while matching common parents by accident anyway, since the test was
#    unanchored, case-insensitive and whole-file: `http` inside a
#    `requests.get("http://...")` URL satisfied `werkzeug.http.*`. A non-zero
#    exit here is BUILD_FAILED at the builder and BLOCKED at the reviewer's
#    re-run, so it discards a real, executed, reproducing finding. The rule
#    claims less rather than guessing.
#
#    PY_FILES, not FILES, for the reason rules 3, 6 and 7 use it: a `.pyi` stub
#    declaring `def parse_request(...): ...` is not a call site, and reading it
#    let a PoC with no mention of the symbol anywhere in its code report clean.
#
#    The status is inspected rather than inverted. `! grep` reads exit 2 — the
#    failure `scan()` deliberately exits 2 for, and which the header reserves
#    exit 2 for — as "no match", so a broken grep was reported as a rule
#    violation with exit 1.
#
# names PATTERN — is PATTERN word-bounded anywhere in the code?
names() {
  local status
  set +e
  grep -qE -- "(^|[^[:alnum:]_])${1}([^[:alnum:]_]|$)" "${PY_FILES[@]}"
  status=$?
  set -e
  [ "$status" -le 1 ] || {
    echo "poc-lint: grep failed (status $status) on rule 'symbol-not-invoked'" >&2
    exit 2
  }
  return "$status"
}

if [ -n "$SYMBOL" ] && ! names "$esc"; then
  report "symbol-not-invoked" \
    "The PoC never mentions '$LEAF', the last segment of '$SYMBOL'. Import and call the real code under test." \
    "$SYMBOL"
fi

if [ "$violations" -gt 0 ]; then
  printf '\npoc-lint: %d rule(s) violated across %d file(s)\n' \
    "$violations" "${#FILES[@]}" >&2
  exit 1
fi

# Say what was enforced, and say it exactly. Without --symbol neither symbol rule
# runs, and a bare "clean" reads as though they did — the build agent
# self-reports lintPassed from this output. With one, the claim is deliberately
# small: the name is present. Whether it is a CALL, and whether a definition of
# the same name is a copy, are both beyond grep and are stated as open rather
# than implied as settled.
if [ -n "$SYMBOL" ]; then
  printf 'poc-lint: %d file(s) clean (Principle 5 checked against %s as far as grep can: "%s" is named in the code. That is MENTION, not invocation, and a definition of that name is reported above as a note rather than judged — a copy is the reviewers job)\n' \
    "${#FILES[@]}" "$SYMBOL" "$LEAF"
else
  printf 'poc-lint: %d file(s) clean (Principle 5 NOT checked: no --symbol given)\n' \
    "${#FILES[@]}"
fi
