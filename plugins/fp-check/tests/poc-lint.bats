#!/usr/bin/env bats
#
# Proves poc-lint still detects what it is for. The patterns were deliberately
# narrowed to kill false positives; without this suite that narrowing could
# silently reduce the linter to something that passes everything.
#
# shellcheck disable=SC2016
# The single-quoted fixture bodies are Python source containing `$XXM` and
# `XX,XXX` placeholders — the exact strings the linter must detect. Double quotes
# would have the shell expand them to nothing before the linter ever saw them,
# turning a detection test into a test that the linter accepts empty input.

setup() {
  LINT="$BATS_TEST_DIRNAME/../skills/fp-check/scripts/poc-lint.sh"
  DIRTY="$BATS_TEST_DIRNAME/fixtures/dirty_poc.py"
  CLEAN="$BATS_TEST_DIRNAME/fixtures/clean_poc.py"
  TMP="$(mktemp -d)"
}

teardown() {
  rm -rf "$TMP"
}

# Write $2 to a scratch file named $1 and echo its path.
scratch() {
  printf '%s\n' "$2" >"$TMP/$1"
  echo "$TMP/$1"
}

# --------------------------------------------------------------------------
# Most rules are a single ERE with several alternations, and "dirty fixture
# trips every base rule" below greps only for the rule NAME — so it pins
# whichever alternation the fixture happens to hit and nothing else. Proven
# live: cutting rule 4's printer list down to (print|logging\.info) left this
# suite at 22/22 while the shipped rule does flag console.log. The helpers
# below make one assertion per alternation affordable.
#
# A bare call to either fails the test: bats runs the body under errexit, and a
# function returning 1 trips it (unlike a bare `[[ ]]` — see the note further
# down). The echoed diagnostics land in the failure output.
# --------------------------------------------------------------------------

# trips NAME RULE CONTENT — CONTENT, written to a file called NAME, must be
# reported as a violation of RULE. NAME carries the extension because .pyi
# changes which rules run.
trips() {
  run "$LINT" "$(scratch "$1" "$3")"
  if [ "$status" -ne 1 ] || ! echo "$output" | grep -q "$2"; then
    echo "expected rule '$2' to fire on $1 (status was $status)"
    printf '%s\n' "$3"
    echo "$output"
    return 1
  fi
}

# passes NAME CONTENT — CONTENT must produce no violation at all.
passes() {
  run "$LINT" "$(scratch "$1" "$2")"
  if [ "$status" -ne 0 ]; then
    echo "expected $1 to be clean (status was $status)"
    printf '%s\n' "$2"
    echo "$output"
    return 1
  fi
}

# redefines / imports — the same two, for the --symbol rule. Rule 6 REPORTS a
# definition of the symbol's name and does not fail the lint, so both assert exit
# 0 and differ on whether the note fired. Without the negative half the note
# would be free to fire on everything and nothing would notice.
redefines() {
  run "$LINT" --symbol vulnFn "$(scratch "$1" "$2")"
  if [ "$status" -ne 0 ] || ! echo "$output" | grep -q possible-reimplementation; then
    echo "expected the redefinition NOTE on $1, and exit 0 (status was $status)"
    printf '%s\n' "$2"
    echo "$output"
    return 1
  fi
}

imports() {
  run "$LINT" --symbol vulnFn "$(scratch "$1" "$2")"
  if [ "$status" -ne 0 ] || echo "$output" | grep -q possible-reimplementation; then
    echo "expected $1 to be clean and unremarked under --symbol vulnFn (status was $status)"
    printf '%s\n' "$2"
    echo "$output"
    return 1
  fi
}

@test "dirty fixture fails" {
  run "$LINT" "$DIRTY"
  [ "$status" -eq 1 ]
}

@test "dirty fixture trips every base rule" {
  run "$LINT" "$DIRTY"
  for rule in monetary-placeholder todo-marker ellipsis-placeholder \
    narrated-exploit placeholder-attack stub-body; do
    echo "$output" | grep -q "$rule" || {
      echo "rule '$rule' did not fire on the dirty fixture"
      echo "$output"
      return 1
    }
  done
}

@test "clean fixture passes" {
  # The fixture carries every historical false positive: "would" in a comment, a
  # prose ellipsis, MAXXX, and a real dollar figure. All four tripped the
  # original patterns.
  run "$LINT" "$CLEAN"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "1 file(s) clean"
}

@test "zero files inspected is a failure, not a pass" {
  run "$LINT"
  [ "$status" -eq 2 ]
  echo "$output" | grep -q "refusing to report success"
}

@test "unreadable file is a failure, not a pass" {
  run "$LINT" "$BATS_TEST_DIRNAME/fixtures/does-not-exist.py"
  [ "$status" -eq 2 ]
  echo "$output" | grep -q "refusing to report success"
}

@test "--symbol reports a PoC that redefines the code under test" {
  run "$LINT" --symbol transfer_balance "$DIRTY"
  # 1 for the placeholder rules the dirty fixture also trips; the redefinition
  # itself is a note and contributes nothing to the exit code.
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "possible-reimplementation"
}

@test "--symbol without a value is a usage error" {
  run "$LINT" --symbol
  [ "$status" -eq 2 ]
}

# --------------------------------------------------------------------------
# Rules 6 and 8 are the two carrying Principle 5, and both are guarded by
# [ -n "$SYMBOL" ] — so an empty symbol silently switched them off and printed
# "clean" on a PoC that reimplements the code under test.
#
# `Ledger.` and `ledger::` are the same hole reached by the other door: both
# rules key on the LAST segment, which a trailing separator leaves empty, and
# rule 8's pattern then degenerated into one matching any two adjacent
# non-alphanumerics — so a file naming neither `Ledger` nor `debit` was clean.
# --------------------------------------------------------------------------

@test "a symbol with no final segment is a usage error, not a silent skip" {
  f=$(scratch reimpl.py 'def transfer_balance(a, b, amount):
    return amount')
  for sym in '' 'Ledger.' 'a.b.' 'ledger::'; do
    run "$LINT" --symbol "$sym" "$f"
    if [ "$status" -ne 2 ] || ! echo "$output" | grep -q "non-empty final segment"; then
      echo "expected --symbol '$sym' to be a usage error (status was $status)"
      echo "$output"
      return 1
    fi
  done
}

@test "the clean message says whether Principle 5 was checked" {
  run "$LINT" "$CLEAN"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "Principle 5 NOT checked"

  run "$LINT" --symbol transfer_balance "$CLEAN"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "Principle 5 checked against transfer_balance"
}

@test "a redefinition is spotted behind a leading modifier or a receiver" {
  # Every one of these defeated the line-start keyword anchor and was invisible.
  redefines a.py 'async def vulnFn(a):
    return 1'
  redefines b.js 'export function vulnFn(a) {
  return 1;
}'
  redefines c.rs 'pub fn vulnFn(a: u32) -> u32 {
    1
}'
  redefines d.go 'func (r *Repo) vulnFn(a int) int {
	return 1
}'
  redefines e.js 'vulnFn = function (a) {
  return 1;
}'
}

# The rule keys on the last segment for BOTH separators, so a qualified symbol
# gets the same note. Keyed on `.` alone, a Rust PoC was checked for the literal
# `ledger::transfer_balance` and a copy of the function went unremarked; keyed on
# the whole dotted string, so did a verbatim Python copy under
# `target_app.ledger.transfer_balance`.
@test "a qualified symbol is reduced to its last segment, dot or colon" {
  f=$(scratch copy.py 'def transfer_balance(src, dst, amount):
    src.balance -= amount')
  for sym in target_app.ledger.transfer_balance 'ledger::transfer_balance' Ledger.transfer_balance; do
    run "$LINT" --symbol "$sym" "$f"
    if [ "$status" -ne 0 ] || ! echo "$output" | grep -q possible-reimplementation; then
      echo "expected the redefinition NOTE under --symbol $sym (status was $status)"
      echo "$output"
      return 1
    fi
  done
}

@test "a function literal bound to const, let or var is a redefinition" {
  redefines v1.js 'const vulnFn = function (q) { return db.query(q) }'
  redefines v2.js 'const vulnFn = (q) => db.query(q)'
  redefines v3.js 'let vulnFn = async (q) => db.query(q)'
  redefines v4.js 'var vulnFn = q => db.query(q)'
  redefines v5.py 'vulnFn = lambda q: db.query(q)'
}

@test "binding the real symbol to a const is not a reimplementation" {
  # The `const|let|var` alternation had no constraint on its right-hand side,
  # so it rejected every one of these — the canonical way a Node PoC pulls the
  # real function in under the name it is tested by. A rule that fails a
  # correct PoC is the worse half of this linter's two failure modes: the
  # agent's only recourse is to stop calling the real code.
  imports i1.js "const vulnFn = require('../lib/vuln').vulnFn"
  imports i2.js "let   vulnFn = require('../lib/vuln').vulnFn"
  imports i3.js "const vulnFn = (await import('../lib/vuln')).vulnFn"
  imports i4.js 'var   vulnFn = global.app.vulnFn'
  imports i5.js 'const { vulnFn } = require("../lib/vuln")'
}

# Rule 6 only proves the PoC does not DEFINE the symbol, which a PoC that never
# mentions it satisfies trivially — and the clean line then claimed Principle 5
# had been "checked". A builder copying the vulnerable body under another name
# while reporting the real symbol as invokedSymbol passed clean.
@test "a PoC that never names the symbol under test is not clean" {
  f=$(scratch copy.py 'def vulnerable_parse(data):
    return data["offset"]

vulnerable_parse({"offset": 1})')
  run "$LINT" --symbol parse_request "$f"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "symbol-not-invoked"
}

@test "calling and importing the real symbol is not a reimplementation" {
  f=$(scratch caller.py 'from target_app.ledger import transfer_balance

def test_it():
    result = transfer_balance({}, "a", "b", -500)
    assert result is None')
  run "$LINT" --symbol transfer_balance "$f"
  [ "$status" -eq 0 ]
}

# A QUALIFIED symbol is what triage-poc's POC_SCHEMA asks the builder to report
# as invokedSymbol, and the dotted string never appears contiguously in any of
# these call forms. Matching it whole rejected a Principle-5-COMPLIANT PoC —
# BUILD_FAILED at the builder's own lint, or BLOCKED at the reviewer's re-run of
# it. Only the bare-identifier case was covered, so nothing caught that.
@test "a qualified symbol matches the call site that imports its last segment" {
  f=$(scratch qualified.py 'from target_app.ledger import transfer_balance

def test_it():
    assert transfer_balance({}, "a", "b", -500) is None')
  for sym in target_app.ledger.transfer_balance Ledger.transfer_balance transfer_balance; do
    run "$LINT" --symbol "$sym" "$f"
    if [ "$status" -ne 0 ]; then
      echo "expected --symbol $sym to be clean (status was $status)"
      echo "$output"
      return 1
    fi
  done
}

# `def main():` is the ordinary shape of a standalone PoC, and under
# `--symbol cli.main` it was reported as REIMPLEMENTING `cli.main`: the lint
# fails, the builder returns BUILD_FAILED, and an attempt is burnt on a PoC that
# was calling the real code all along. `run`, `handler` and `parse` collide the
# same way, and no condition added to the pattern told the two apart. The fact is
# now reported and the exit code left alone.
@test "a local helper sharing the leaf of a qualified symbol does not fail the lint" {
  f=$(scratch wrapper.py 'import cli

def main():
    cli.main(["--user", "../../etc/passwd"])

main()')
  run "$LINT" --symbol cli.main "$f"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "Principle 5 checked against cli.main"
  echo "$output" | grep -q "possible-reimplementation"
}

# The three canonical shapes of a COMPLIANT PoC that the parent-segment
# requirement rejected: a façade re-export, a pytest fixture and a factory. None
# of them spells the parent, and each exited 1 — BUILD_FAILED at the builder or
# BLOCKED at the reviewer's re-run, on a PoC that ran and reproduced.
@test "a facade, a fixture and a factory all satisfy the symbol rule" {
  # clean_under SYMBOL NAME CONTENT
  clean_under() {
    run "$LINT" --symbol "$1" "$(scratch "$2" "$3")"
    if [ "$status" -ne 0 ]; then
      echo "expected --symbol $1 on $2 to be clean (status was $status)"
      echo "$output"
      return 1
    fi
  }
  clean_under flask.helpers.send_file facade.py 'from flask import send_file

def run():
    send_file("/etc/passwd")'
  clean_under FlaskClient.get fixture.py 'def test_idor(client):
    r = client.get("/api/orders/2")
    assert r.status_code == 200'
  clean_under Ledger.transfer_balance factory.py 'from helpers import make_account

a = make_account()
a.transfer_balance(a, -500)'
}

# What the rule gives up in exchange, stated rather than implied: a leaf this
# common is satisfied by code with nothing to do with the symbol. The clean line
# has to say MENTION rather than let the reader hear "invocation" — that wording
# is the whole of what stops this from being an overclaim.
@test "a coincidental leaf match is clean, and the clean line says only mention" {
  f=$(scratch unrelated.py 'def main():
    data = open("/etc/passwd").read()
    print(data)

main()')
  run "$LINT" --symbol app.io.read "$f"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "MENTION, not invocation"
}

@test "a qualified symbol still fails a PoC that names no part of it" {
  f=$(scratch nomention.py 'def test_it():
    assert 1 == 1')
  run "$LINT" --symbol target_app.ledger.transfer_balance "$f"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "symbol-not-invoked"
}

# Rules 3, 6 and 7 skip .pyi because a stub legitimately elides its bodies. Rule
# 8 read FILES, so a stub DECLARING the symbol satisfied "the PoC names it" for
# a PoC whose actual code never mentioned it.
@test "a .pyi stub does not satisfy the symbol-is-named rule" {
  real=$(scratch real.py 'x = 1')
  stub=$(scratch s.pyi 'def parse_request(data): ...')
  run "$LINT" --symbol parse_request "$real" "$stub"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "symbol-not-invoked"
}

# --------------------------------------------------------------------------
# Rule 2: markers must be word-bounded. Unanchored, they rejected working
# exploits on ordinary exploit vocabulary.
# --------------------------------------------------------------------------

@test "ordinary exploit vocabulary is not a todo marker" {
  f=$(scratch vocab.py 'from http import HTTPStatus
from target_app.web import handle_redirect

def test_open_redirect():
    resp = handle_redirect("//evil.example")
    assert resp.status_code == HTTPStatus.TEMPORARY_REDIRECT
    payload = "1'"'"'; CREATE TEMPORARY TABLE pwn(x int); --"
    store_comment("<script>alert(\"HACKED\")</script>")
    return payload')
  run "$LINT" "$f"
  [ "$status" -eq 0 ]
}

@test "a lowercase todo marker is caught but lowercase prose is not" {
  run "$LINT" "$(scratch m.py 'x = 1  # todo: finish the payload')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "todo-marker"

  run "$LINT" "$(scratch p.py 'x = 1  # this is not a todo marker at all')"
  [ "$status" -eq 0 ]
}

@test "every todo-marker alternation fires" {
  # The dirty fixture only reaches TODO, FIXME and XXX, so the lowercase and
  # HACK alternations were unpinned. Rust's todo!() is the shape the lowercase
  # branch exists for besides `# todo:`.
  trips m1.py todo-marker '# XXX revisit'
  trips m2.py todo-marker '# HACK: bypass the signature check'
  trips m3.py todo-marker '# FIXME: this does not run yet'
  trips m4.rs todo-marker 'fn f() { todo!() }'
  trips m5.py todo-marker 'x = 1  # fixme: wrong offset'
  # Bare, without the colon. Every marker case above and in the dirty fixture
  # carries one, which routes them all through the LOWERCASE alternation — so
  # deleting TODO and FIXME from the uppercase one left this suite at 34/34
  # while `# TODO revisit` flipped to clean. The commonest marker there is was
  # the one nothing pinned.
  trips m6.py todo-marker '# TODO revisit'
  trips m7.py todo-marker '# FIXME wrong offset'
}

@test "every monetary-placeholder alternation fires" {
  # Only $XXM appears in the dirty fixture; the other three were unpinned.
  trips mp1.py monetary-placeholder 'report_impact("$XXM at risk")'
  trips mp2.py monetary-placeholder 'report_impact("XX,XXX users affected")'
  trips mp3.py monetary-placeholder 'report_impact("$$$ drained from the pool")'
  trips mp4.py monetary-placeholder 'report_impact("X-X accounts per block")'
}

@test "a monetary placeholder is reported once, not twice" {
  # Rule 2's XXX branch excludes a preceding '$' or ',' precisely so that
  # "$XXM" and "XX,XXX" stay rule 1's business. Without that, one placeholder
  # produced two rule names and the count in the summary line was wrong.
  run "$LINT" "$(scratch dbl.py 'report_impact("$XXM lost, XX,XXX users affected")')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "monetary-placeholder"
  if echo "$output" | grep -q "todo-marker"; then
    echo "a monetary placeholder was also reported as a todo marker"
    echo "$output"
    return 1
  fi
  # The other side of the same boundary: a triple-X run inside an identifier.
  passes maxxx.py 'MAXXX_RETRIES = 3'
}

# --------------------------------------------------------------------------
# Rule 4: narration through any printer, in either quote style.
# --------------------------------------------------------------------------

@test "narration is caught in single quotes and through a logger" {
  run "$LINT" "$(scratch n1.py 'print('"'"'the attacker would drain the pool here'"'"')')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "narrated-exploit"

  run "$LINT" "$(scratch n2.py 'import logging
logging.info("this would overwrite the admin record")')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "narrated-exploit"
}

@test "every printer in the narration rule fires" {
  # print, logging.info and the single-quote branch are pinned by the test
  # above and by the dirty fixture; these are the rest of the list, which
  # nothing reached. Reducing the shipped rule to (print|logging\.info) used to
  # leave the whole suite green.
  #
  # System.out.println has no alternation of its own: the `print` branch matches
  # the lowercase "print" inside "println", which is why the dedicated branch
  # was removed as dead. Asserted here so the shape stays covered.
  trips pr1.js narrated-exploit 'console.log("the attacker would drain the pool")'
  trips pr2.js narrated-exploit "console.error('the attacker would own the box')"
  trips pr3.go narrated-exploit 'fmt.Println("this would overwrite the admin record")'
  trips pr4.go narrated-exploit 'fmt.Printf("this would overwrite %s", name)'
  trips pr5.java narrated-exploit 'System.out.println("this would overwrite the record")'
  trips pr6.py narrated-exploit 'sys.stdout.write("this would overwrite the record")'
  trips pr7.py narrated-exploit 'logger.info("this would overwrite the record")'
  trips pr8.sh narrated-exploit 'echo "the attacker would drain the pool"'
}

@test "all three logging spellings fire, at every level" {
  # `logger?\.` bound the `?` to one character, so it meant `logge` plus an
  # optional `r` and could not match `log.` — what `log =
  # logging.getLogger(__name__)` produces. Its level list was also two short of
  # the `logging\.` branch beside it, so logger.error was clean while
  # logging.error was a violation. Both halves are pinned here because one
  # shared alternation is the only thing keeping them from drifting again.
  trips lg1.py narrated-exploit 'log.info("the attacker would drain the pool")'
  trips lg2.py narrated-exploit 'logger.error("this would drop the table")'
  trips lg3.py narrated-exploit 'logging.critical("this would take the cluster down")'
  trips lg4.js narrated-exploit 'console.debug("the attacker would own the box")'
}

# --------------------------------------------------------------------------
# Rule 5, which is now only the commented-out attack.
# --------------------------------------------------------------------------

@test "a commented-out attack is caught in either comment style" {
  trips ca1.py placeholder-attack '# attacker.drain(pool)'
  trips ca2.js placeholder-attack '// attacker.drain(pool)'
}

@test "numbered progress output beside real calls is not tutorial scaffolding" {
  # The `"Step N:"` alternation could not tell a multi-stage exploit narrating
  # its own progress from a tutorial that never attacks anything, and there is
  # nothing in the text that would let it. It was dropped rather than narrowed;
  # these are the shapes it used to fail.
  passes sl1.py 'from app.auth import login
from app.ledger import transfer
print("Step 1: authenticating as the low-privilege user")
s = login("bob", "hunter2")
print("Step 2: draining the account")
transfer(s, -500)'
  # An assertion on a captured real response that happens to contain the label.
  passes sl2.py 'from app.web import signup
resp = signup("mallory@evil.example")
assert resp.text == "Step 1: verify your email"'
}

# --------------------------------------------------------------------------
# Rule 7: a definition whose whole body is a placeholder. SKILL.md claims
# placeholders are enforced here rather than by good intentions.
# --------------------------------------------------------------------------

@test "a stub body is caught" {
  run "$LINT" "$(scratch s1.py 'def exploit():
    pass')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "stub-body"

  run "$LINT" "$(scratch s2.py 'def verify_impact():
    raise NotImplementedError("wire this to the real ledger")')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "stub-body"

  run "$LINT" "$(scratch s3.py 'def exploit(): pass')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "stub-body"
}

@test "every stub-body marker fires" {
  # The dirty fixture only reaches `pass`; the raise is pinned by the test
  # above. These three were unpinned.
  trips sb1.js stub-body 'function exploit() {
  throw new Error("not wired yet");
}'
  trips sb2.rs stub-body 'fn exploit() {
    unimplemented!()
}'
  trips sb3.rs stub-body 'fn exploit() {
    todo!()
}'
}

@test "a stub is caught through the docstring or comment in front of it" {
  # awk cleared `expect` on the first line that was neither blank nor a
  # placeholder, so a docstring or a comment hid the body behind it. That is
  # not an exotic shape: build-poc.js tells the builder to "write the docstring
  # to match the assertion" on a test-integrated PoC, so it is exactly what a
  # half-written one looks like.
  trips ds1.py stub-body 'def test_negative_transfer_drains_ledger():
    """Transferring -500 from '"'"'merchant'"'"' credits the attacker and underflows."""
    pass'
  trips ds2.js stub-body 'function exploit() {
  // set up the payload
  throw new Error('"'"'not wired yet'"'"');
}'
  # Multi-line docstring, and the r-prefixed spelling.
  trips ds3.py stub-body 'def exploit():
    r"""Drain the pool.

    The assertion below fails while the bug is live.
    """
    raise NotImplementedError("wire this up")'
  # Block comment, opened and closed on separate lines.
  trips ds4.js stub-body 'function exploit() {
  /* set up
     the payload */
  throw new Error("not wired yet");
}'
}

@test "skipping docstrings does not start flagging real bodies" {
  # The skip must not swallow the body itself, and code quoted INSIDE a
  # docstring must not be read as a definition — that would flag a correct PoC,
  # which is the failure this file treats as the worse one.
  passes k1.py 'def exploit():
    """Drives the real ledger.

    The shape under test, for the reader:
        def helper(): pass
    """
    return transfer_balance(1)'
  passes k2.py 'def exploit():
    """One-liner doc."""
    return transfer_balance(1)'
  passes k3.js 'function exploit() {
  /* multi
     line
     pass */
  return real();
}'
  # A triple-quoted string that is assigned, not a docstring: `expect` must
  # clear on it like any other statement.
  passes k4.py 'def exploit():
    payload = """
    pass
    """
    return payload'
}

@test "a real body that merely contains pass is not a stub" {
  f=$(scratch real.py 'from target_app.ledger import transfer_balance

def exploit():
    ledger = {"alice": 100}
    try:
        transfer_balance(ledger, "m", "alice", -500)
    except KeyError:
        pass
    return ledger')
  run "$LINT" "$f"
  [ "$status" -eq 0 ]
}

# --------------------------------------------------------------------------
# Zero-content inputs. Same rule as the zero-files case: a checker that
# inspects nothing must fail, not pass.
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Rule 3: the flagship elided-code shape. The rule was anchored `^...$`, so it
# only fired on a line that was NOTHING but the dots — any narration after them
# defeated it, and no other rule covers a bare comment (narrated-exploit needs
# a printer, placeholder-attack needs "Step N:").
# --------------------------------------------------------------------------

@test "a narrated ellipsis comment is caught" {
  run "$LINT" "$(scratch e1.js '    // ... exploit logic here ...')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "ellipsis-placeholder"

  run "$LINT" "$(scratch e2.py '    # ... send the payload and check the result ...')"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "ellipsis-placeholder"
}

@test "a whole line of nothing but dots is caught" {
  # The other alternation of rule 3. Deliberately not inside a definition, so
  # it is rule 3 answering and not rule 7's stub body.
  trips e5.py ellipsis-placeholder 'setup_target()
...'
  trips e6.js ellipsis-placeholder 'setup();
  /* ... */'
}

@test "prose that merely trails off is not an elided-code placeholder" {
  # The rule anchors on the START of the comment body, so a comment ending in
  # an ellipsis stays clean. Widening it to "contains ..." would fail these.
  run "$LINT" "$(scratch e3.py '# see the docs for more...')"
  [ "$status" -eq 0 ]

  run "$LINT" "$(scratch e4.py 'x = 1  # the result is ... complicated')"
  [ "$status" -eq 0 ]
}

@test "a .pyi stub is not reported as a stub body, but a real stub still is" {
  # `def f(a, b): ...` is how a type stub is spelled. Rule 3 already excluded
  # .pyi; rule 7 matches the same bodies and needs the same exclusion, or the
  # linter rejects a correct-by-construction file.
  #
  # Both files in ONE invocation, deliberately. Passing only the .pyi would let
  # this test pass because the rule inspected nothing, which is exactly the
  # failure mode below — it could not tell correct exclusion from zero coverage.
  # Two-line form on purpose: an annotated one-liner is not matched by the rule
  # at all (the `:` in `a: int` defeats it), so the .pyi exclusion would not be
  # what made this pass and the test would prove nothing.
  stub=$(scratch stubs.pyi 'def transfer_balance(a, b):
    ...')
  real=$(scratch real.py 'def exploit():
    pass')
  run "$LINT" "$stub" "$real"
  [ "$status" -eq 1 ]
  echo "$output" | grep -q "stub-body"
  echo "$output" | grep -q "real.py"
  # Asserting ABSENCE in bats needs an explicit `return 1`. Three shorter
  # spellings were tried here and all three are no-ops: `grep -qv` succeeds
  # whenever ANY line fails to match; `! cmd` never trips errexit, which bash
  # documents explicitly; and a bare `[[ ]]` returning 1 mid-test does not fail
  # a bats test either (verified — a failing pipeline does, a failing `[[ ]]`
  # does not). Each was caught only because the mutation gate kept reporting
  # this assertion as not covering its mutation.
  if echo "$output" | grep -q "stubs.pyi"; then
    echo "the .pyi stub was reported despite the exclusion"
    return 1
  fi
}

@test "an input list of nothing but .pyi is a failure, not a clean PoC" {
  # Rules 3, 6 and 7 all skip .pyi, so a lone stub left three of the seven
  # inspecting no file at all — and the per-rule guards reported that as
  # "clean", exit 0, through review-poc's independent checkpoint 4.3 re-check.
  # Same rule as the empty file and the empty argument list below.
  stub=$(scratch stubs.pyi 'def transfer_balance(a, b):
    ...')
  run "$LINT" "$stub"
  [ "$status" -eq 2 ]
  echo "$output" | grep -q "refusing to report success"

  # awk with zero file operands reads STDIN, so this case used to report a
  # stub-body at ":1:" sourced from data that was never under test. Refusing
  # before awk runs closes that too; assert it stays closed.
  run bash -c "printf 'def exploit():\n    pass\n' | '$LINT' '$stub'"
  [ "$status" -eq 2 ]
  if echo "$output" | grep -q "stub-body"; then
    echo "stdin leaked into the stub rule"
    return 1
  fi
}

@test "a file with no content is a failure, not a clean PoC" {
  # Bytes are not content. `[ ! -s ]` caught only the truly empty file, so each
  # of these reported "1 file(s) clean" and exit 0 by having nothing for any
  # pattern to match — the zero-items failure the argument-list guard rejects.
  # A comments-only file is deliberately NOT here: rules 2 to 5 read comments,
  # so a placeholder in one must come back as that rule's violation.
  : >"$TMP/empty.py"
  printf '\n' >"$TMP/newline.py"
  printf ' ' >"$TMP/space.py"
  printf '\357\273\277' >"$TMP/bom.py"
  for f in empty newline space bom; do
    run "$LINT" "$TMP/$f.py"
    if [ "$status" -ne 2 ] || ! echo "$output" | grep -q "refusing to report success"; then
      echo "$f.py was not rejected (status $status)"
      echo "$output"
      return 1
    fi
  done
}

@test "/dev/null is a failure, not a clean PoC" {
  run "$LINT" /dev/null
  [ "$status" -eq 2 ]
  echo "$output" | grep -q "refusing to report success"
}

@test "code quoted in a module docstring is not a definition" {
  # Rules 3, 6 and 7 all read across a definition and grep cannot see across
  # lines, so quoting the vulnerable shape below produced three violations at
  # once against a PoC doing exactly what Principle 5 asks: reimplementation on
  # the signature, stub-body on the `pass`, ellipsis-placeholder on the dots.
  # Docstring tracking used to start only after a signature, so a module- or
  # class-level one was invisible to all three.
  imports doc1.py '"""PoC for the ledger underflow.

The vulnerable shape, quoted from billing/ledger.py:

    def vulnFn(a, b):
        pass

    def vulnFn_async(a, b):
        ...
"""
from billing.ledger import vulnFn

vulnFn(-500, 1)'
  # The same at class level, and through a block comment.
  imports doc2.js '/* The shape under test:
 *   function vulnFn(q) { ... }
 */
const { vulnFn } = require("../lib/vuln")
vulnFn("x")'
}
