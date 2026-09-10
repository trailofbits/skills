#!/usr/bin/env bash
#
# The gate. For each assertion in the suite, break the thing it covers and
# confirm the suite goes red. An assertion that stays green under mutation is
# testing the model, not the plugin.
#
# Every mutation is applied to a COPY under a scratch dir; the working tree is
# never modified.
#
# Usage: tests/mutation-gate.sh
# Exit:  0 = every mutation was caught; 1 = at least one survived
# shellcheck disable=SC2016
# Every mutation is a pair of single-quoted command STRINGS that run_mutation
# passes to `eval` after exporting $SANDBOX. Expanding them here would point
# each mutation at a sandbox that does not exist yet, and PYTEST would flatten
# to one word. Deferred expansion is the mechanism; this is not an oversight.
# This repo's pre-commit applies no severity floor, so the info-level advice has
# to be refused explicitly.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN="$(cd "$HERE/.." && pwd)"
# REPO and PYTEST are referenced from inside the eval'd TEST_CMD strings below,
# which shellcheck cannot see into. They are used; the warning is a false
# positive of the eval indirection this script is built on.
# shellcheck disable=SC2034
REPO="$(cd "$PLUGIN/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --with pyyaml is load-bearing: the Layer 4 mutations run test_eval_suite.py,
# which imports yaml at module scope. Without it that import fails, pytest exits
# 2, and this harness reads the failure as "mutation caught" — eight mutations
# reporting coverage they never had. It only ever worked because pyyaml leaked
# in from the author's active venv.
# shellcheck disable=SC2034
PYTEST=(uv run --with pytest --with jsonschema --with pyyaml --no-project pytest -q -x)

survived=0
ran=0
deferred=0

# A mutation whose test command cannot run yet. Recorded and counted, NOT dropped
# and NOT run: a skipped pytest exits 0, which this harness reads as "the mutation
# survived", so leaving these in place would report 12 phantom coverage gaps and
# leaving them out would quietly shrink the gate. Either way the number at the
# bottom stops meaning anything.
#
# defer_mutation NAME LAYER WHY
defer_mutation() {
  local name="$1" layer="$2" why="$3"
  deferred=$((deferred + 1))
  echo "  deferred  [$layer] $name  <-- $why"
}

# Test commands already proven to pass on unmutated code, keyed by a checksum of
# the command text. A plain file, not an associative array: macOS ships bash 3.2.
BASELINE_OK="$WORK/baseline-verified"
: >"$BASELINE_OK"

# run_mutation NAME LAYER MUTATE_CMD TEST_CMD
#
# MUTATE_CMD operates on $SANDBOX. TEST_CMD must FAIL for the mutation to count
# as caught.
run_mutation() {
  local name="$1" layer="$2" mutate="$3" test_cmd="$4"
  ran=$((ran + 1))

  local sandbox="$WORK/$ran"
  mkdir -p "$sandbox"
  cp -R "$PLUGIN" "$sandbox/fp-check"
  local SANDBOX="$sandbox/fp-check"
  export SANDBOX

  # A mutation is "caught" when TEST_CMD fails. That inference only holds if
  # TEST_CMD passes on UNMUTATED code — otherwise anything that makes it fail
  # for an unrelated reason reads as full coverage. Two such reasons were live
  # here: `bats` was not installed, so its command exited 127 and every run
  # since has reported the poc-lint mutation as caught without executing a
  # single assertion; and `pytest -k renamed_test` exits 5 for "no tests
  # collected", so a renamed test would silently stop covering its mutation
  # while the gate still said PASS. The sandbox is pristine at this point, so
  # this is the moment to check. Memoised: most commands are shared by several
  # mutations.
  local key
  key=$(printf '%s' "$test_cmd" | cksum | tr -d ' ')
  if ! grep -qx "$key" "$BASELINE_OK"; then
    if eval "$test_cmd" >"$sandbox/baseline.txt" 2>&1; then
      echo "$key" >>"$BASELINE_OK"
    else
      echo "  ERROR  $name: test command fails on UNMUTATED code, so a failure" >&2
      echo "         after mutation would prove nothing. Command: $test_cmd" >&2
      sed 's/^/      /' "$sandbox/baseline.txt" | tail -5 >&2
      survived=$((survived + 1))
      return
    fi
  fi

  # Checksum before/after: `perl -pi` exits 0 when its pattern matches nothing,
  # so a mutation that silently stopped applying would be reported as SURVIVED —
  # sending the reader to "fix" a test that is actually fine.
  local before after
  before=$(find "$SANDBOX" -type f -exec cksum {} + | sort | cksum)

  if ! eval "$mutate"; then
    echo "  ERROR  $name: mutation command itself failed" >&2
    survived=$((survived + 1))
    return
  fi

  after=$(find "$SANDBOX" -type f -exec cksum {} + | sort | cksum)
  if [ "$before" = "$after" ]; then
    echo "  ERROR  $name: mutation changed nothing — the pattern is stale" >&2
    survived=$((survived + 1))
    return
  fi

  if eval "$test_cmd" >"$sandbox/out.txt" 2>&1; then
    echo "  SURVIVED  [$layer] $name  <-- assertion does not cover this" >&2
    sed 's/^/      /' "$sandbox/out.txt" | tail -5 >&2
    survived=$((survived + 1))
  else
    echo "  caught    [$layer] $name"
  fi
}

echo "Mutation gate: breaking each covered behaviour in a sandbox copy"
echo

# --- Layer 1 -------------------------------------------------------------

run_mutation "delete a schema from an agent() call" "L1" \
  'perl -0pi -e "s/, schema: LAYER_SCHEMA//" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k every_agent_call_has_a_schema'

run_mutation "remove a phase() call from the body" "L1" \
  'perl -0pi -e "s/^phase\(.Impact.\)\n//m" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k phases_match_body_calls'

run_mutation "introduce Math.random() into a script" "L1" \
  'printf "\nconst jitter = Math.random()\n" >> "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k no_nondeterminism'

run_mutation "introduce argless new Date()" "L1" \
  'printf "\nconst t = new Date()\n" >> "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k no_nondeterminism'

run_mutation "break the script syntax" "L1" \
  'printf "\nfunction broken( {\n" >> "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k script_parses'

run_mutation "make a schema invalid JSON Schema" "L1" \
  'perl -0pi -e "s/  type: .object.,/  type: 42,/" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k schemas_are_valid'

run_mutation "de-namespace a Workflow dispatch in SKILL.md" "L1" \
  'perl -0pi -e "s/fp-check:triage-static/verify-attack-path/" "$SANDBOX/skills/fp-check/SKILL.md"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k namespaced_name'

run_mutation "drop the null filter after parallel()" "L1" \
  'perl -0pi -e "s/raw\.slice\(0, layers\.length\)\.filter\(Boolean\)/raw.slice(0, layers.length)/" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k null_filtered'

run_mutation "add verification scaffolding to a prompt" "L1" \
  'perl -0pi -e "s/State the strongest form of the challenge/Double-check your answer. State the strongest form of the challenge/" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k verification_scaffolding'

# --- Layer 2 -------------------------------------------------------------

run_mutation "gate proceeds when every layer agent died" "L2" \
  'perl -0pi -e "s/  const missing = attemptedLayers - verdicts\.length/  const missing = 0/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

# The cap branch this used to mutate is gone: missingArgs rejects >MAX_LAYERS
# before dispatch, so the truncation and its uncheckedLayers gate were dead code.
# What replaced it as the thing that must not weaken is the affirmative read —
# grading by exclusion made PROCEED the fall-through for an unrecognised verdict.
# The brocard pre-gate was removed before 2.0.0 and its four tests became guidance in
# references/dismissal-grounds.md. A removal that deletes the mechanism and loses
# the content is not what was decided, and the failure mode is silent: a prompt
# that no longer points at the file reads exactly the same, and the agent simply
# never applies the grounds. Traced once already, on a different reference — an
# agent reported "its bundled brocards.md reference file is absent" and carried on.
run_mutation "the dismissal grounds no longer reach the agent that classifies" "L2" \
  'perl -0pi -e "s|\\$\{baseDir\}/references/dismissal-grounds\.md\. It is the list|\${baseDir}/references/gate-reviews.md. It is the list|" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs"'

# And the other half: nothing may bring back the machinery that dismissed on the
# shape of the claim. Reintroducing the pre-gate is a decision, not an accident,
# and it should fail here rather than quietly re-run the experiment that was
# reverted after 65 measured runs.
run_mutation "the brocard gate machinery is reintroduced" "L2" \
  'perl -0pi -e "s/const MAX_LAYERS = 4/const BROCARD_SCHEMA = { type: 0 }\nconst MAX_LAYERS = 4/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs"'

# `baseDir` shape, added after it was measured as the largest single source
# of variance: two of three sweep runs on identical input passed the target repo's
# path, every reference read 404'd, and they scored 0.000 and 0.333 against the
# third's 1.000. The failure is invisible without this guard — an agent that
# cannot open its reference file does not error, it answers from memory.
run_mutation "any baseDir shape is accepted again" "L2" \
  'perl -0pi -e "s/if \\(base && !shaped\\)/if (false)/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

# The external-precondition prohibition. Two directions, because the
# fix is a deliberate, BOUNDED relaxation and both bounds have to hold: it must
# reach a non-internal finding, and it must NOT reach an internal one. An
# unconditional version would weaken gateReachability for every finding, including
# the internal ones where all the measured delta lives.
#
# Both patterns are written without a single quote in them. Two earlier attempts
# in this file used \x27 inside a single-quoted shell string that is later eval'd;
# it resolved to a literal quote, closed the string, and the mutation silently
# became something else. `.internal.` matches the quoted literal without needing
# to reproduce the quotes.
#
# /g is load-bearing. Without it perl replaces only the FIRST match, and the
# first `impact.rootCause === 'internal'` in this script is the "Root cause:" line
# further up — so the mutation edited a different conditional, the prohibition
# stayed correctly scoped, and it SURVIVED while appearing to test the bound.
run_mutation "the root-cause conditionals stop being conditional" "L2" \
  'perl -0pi -e "s/!externalRootCause\(impact\.rootCause\) \?/false ?/g" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs"'

run_mutation "the gate agent is no longer told not to price the precondition twice" "L2" \
  'perl -0pi -e "s/Do NOT fail gateReachability/Consider failing gateReachability/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs"'

# The prohibition is only worth what the positive rule under it allows. The first
# draft of that rule listed "or has no caller at all" as a permitted gateReachability
# FAIL — which is the forbidden ground restated as an affirmative licence, and the
# licence is what an agent acts on. It is also verbatim the sweep251 run1 trace this
# fix exists to close. This mutation puts the licence back; the coverage test has to
# see it. No newline in the pattern: the eval-then-perl path in this file mangles
# backslash escapes, and `second ground` is unique in the file on its own.
run_mutation "the no-caller FAIL ground is re-licensed under the prohibition" "L2" \
  'perl -0pi -e "s/second ground/second ground unless it has no caller at all/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs"'

# Ablation isolation, added after looking at how c-review's bench solves the same
# problem. Its host cells ran with 20 plugins and 48 skills reaching EVERY arm —
# c-review's own skill included, in the arm meant to be without it — which voided a
# real run, and they built a Docker container for it. `claude plugin eval` scopes
# plugins already (verified: `plugins: []` in sweep251's baseline, exactly one in
# the other, across 42 runs), so what was worth taking is the assertion, not the
# container. A contaminated baseline makes the delta a measure of what else was
# installed that day, and nothing here checked it.
# Points at the contamination branch itself, not at the arm-name test: the tuple
# moved out to BASELINE_ARM_NAMES and the old pattern went stale, matching nothing
# and reporting a phantom gap. Mutating `if plugins:` also keeps the mutation on
# the behaviour the test names — silently accepting a baseline that loaded a
# plugin — instead of on arm classification, which would fail for a second reason.
run_mutation "a contaminated no-plugin baseline stops being reported" "L2" \
  'perl -0pi -e "s/^            if plugins:$/            if False:/m" "$SANDBOX/tests/validate_eval_result.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_validate_eval_result.py"'

# The mutation above edits the function BODY, which the direct-call tests reach.
# That left the CALL SITE in main() — the only path the shipping validator takes —
# covered by nothing: dropping the call kept every test green while the gate
# printed `ablation isolation NOT verified` forever and passed contaminated
# baselines. This is the mutation that pins the wiring.
# The plugins-only check was less than it claimed: c-review's void was its own
# SKILL in the baseline, and a skill reaches a session from ~/.claude/skills or a
# globally installed plugin with `plugins` still empty. Dropping this leaves a
# baseline holding the plugin under test's own skill printing `isolation verified`.
run_mutation "a skill from an unloaded plugin stops being reported" "L2" \
  'perl -0pi -e "s/foreign = _foreign_skills\(plugins, skills\)/foreign = []/" "$SANDBOX/tests/validate_eval_result.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_validate_eval_result.py"'

# `Counter()`, not `0`: the call now returns a per-arm Counter, and `0` would kill
# this mutation with a TypeError from the caller rather than with the behaviour
# being pinned — an unwired check that reports NOT verified forever.
run_mutation "the isolation check is unwired from main()" "L2" \
  'perl -0pi -e "s/isolation_checked = check_ablation_isolation\(result, problems\)/isolation_checked = Counter()/" "$SANDBOX/tests/validate_eval_result.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_validate_eval_result.py"'

# The count is per arm because "verified" has to mean BOTH arms were read. This
# mutation restores the scalar it replaced: any surviving trace counts for every
# arm, so a sweep whose baseline temp dirs were reaped while one `with` trace
# survived printed `isolation verified on 1 session(s)` — certifying an ablation
# whose no-plugin arm, the only arm the check exists to police, was never opened.
run_mutation "one arm's surviving trace speaks for the other" "L2" \
  'perl -0pi -e "s/if not isolation_checked\[arm\]/if not sum(isolation_checked.values())/" "$SANDBOX/tests/validate_eval_result.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_validate_eval_result.py"'

run_mutation "gate infers PAYLOAD_REACHES_SINK instead of reading it" "L2" \
  'perl -0pi -e "s/passed\.length !== attemptedLayers/false/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

# Checkpoint 2.2's second half — "or confirmed none exist" — restored in the rebuild
# after the probe measured what its absence cost. Two directions, and the first is
# the one that already shipped: with no declared path, the orchestrator is forced
# to invent a layer, and the agent asked to rule on a layer that does not exist
# answers incoherently.
run_mutation "an audited empty layers list is still the vacuous pass" "L2" \
  'perl -0pi -e "s/if \(attemptedLayers === 0 && !declaredNone\)/if (attemptedLayers === 0)/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

# And the other direction: a blank or forgotten declaration must NOT buy the empty
# path, or a dispatch that simply omitted `layers` proceeds having inspected
# nothing — which is the bug the zero-layer guard was written for.
run_mutation "any layersSearched value confirms none exist" "L2" \
  'perl -0pi -e "s/const declaredNone = auditedSearch\(layersSearched\) !== null$/const declaredNone = layersSearched !== undefined/m" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

run_mutation "the arg validator accepts an undeclared empty layers list" "L2" \
  'perl -0pi -e "s/    if \(!declaredNone\) \{/    if (false) {/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

# `fixed` is the field that RETRACTS, so both directions of reading it cost a
# finding and they cost it opposite ways. Reading it case-exactly let `Yes` with a
# real sha ship an already-fixed bug as TRUE_POSITIVE; coercing it with `String()`
# read `['YES']` and any object with a toString AS the retraction and discarded a
# live one terminally. This puts the coercion back.
run_mutation "the already-fixed answer is coerced instead of typed" "L2" \
  'perl -0pi -e "s/  const raw = historyVerdict && historyVerdict\.fixed\n  if \(typeof raw !== .string.\) return .UNCERTAIN.\n  const answer = raw\.trim\(\)\.toUpperCase\(\)/  const answer = String((historyVerdict \&\& historyVerdict.fixed) || \x27\x27).trim().toUpperCase()/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/static.test.mjs" "$SANDBOX/tests/wiring.test.mjs"'

# The route keywords as raw substrings: `race` fires inside `stack trace` and
# `grace period`, so an information-disclosure finding buys the deep route and
# three proof agents that answer a question it never asked — and any one of them
# returning nothing is BLOCKED. The anchor is what stops that, and `ddos`/`redos`
# are in the list because the anchor cannot reach `dos` through their first
# letters, so this mutation is the only thing pinning them together.
run_mutation "an escalation keyword is matched as a raw substring again" "L2" \
  'perl -0pi -e "s/if \(escalates\.some\(\(k\) => spaced\.includes\(. \\\$\{words\(k\)\}.\)\)\) return .deep./if (escalates.some((k) => bugClass.includes(k))) return \x27deep\x27/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/static.test.mjs" "$SANDBOX/tests/wiring.test.mjs"'

run_mutation "gate reads any non-NO scope as in scope" "L2" \
  'perl -0pi -e "s/threatVerdict\.inScope !== .YES./threatVerdict.inScope === \x27UNCERTAIN\x27/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

run_mutation "gate treats UNCERTAIN as passing" "L2" \
  'perl -0pi -e "s/l\.verdict === .UNCERTAIN./false/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

# The fp-check analogue of dedup-against-seen: tally against what came
# back rather than against what was expected, so a dead agent silently raises
# confidence instead of counting against the finding.
run_mutation "tally against returned verdicts instead of expected keys" "L2" \
  'perl -0pi -e "s/for \(const key of expectedKeys\)/for (const key of Array.from(byKey.keys()))/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

# `defeated === 5` became `defeated === total` when the band was parameterised, so
# the old pattern went stale. Mutating the COMPARISON rather than the literal keeps
# this pointed at the boundary itself.
run_mutation "confidence band off by one at the HIGH boundary" "L2" \
  'perl -0pi -e "s/if \(defeated === total\)/if (defeated >= total - 1)/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

# And the default the band falls back to, which is what a caller that forgets to
# pass CHALLENGES.length gets. Pinned by a contract test rather than a unit test,
# so this mutation runs pytest.
run_mutation "the band default drifts from the challenge count" "L1" \
  'perl -0pi -e "s/function confidenceBand\(defeated, total = 5\)/function confidenceBand(defeated, total = 6)/" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k band_total_matches'

run_mutation "build accepts a PoC that failed lint" "L2" \
  'perl -0pi -e "s/ \|\| result\.lintPassed !== true//" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/build.test.mjs"'

run_mutation "build cap removed, retry loop unbounded" "L2" \
  'perl -0pi -e "s/const chosen = Array\.isArray\(all\) \? all\.slice\(0, max\) : \[\]/const chosen = Array.isArray(all) ? all : []/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/build.test.mjs"'

run_mutation "build-poc arg guard removed" "L2" \
  'perl -0pi -e "s/^const argProblems = missingArgs\\(args\\)/const argProblems = []/m" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k validates_them'

run_mutation "review-poc arg guard removed" "L2" \
  'perl -0pi -e "s/^function missingArgs/function unusedMissingArgs/m" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k validates_them'

run_mutation "envelope.destructive=false read as missing" "L2" \
  'perl -0pi -e "s/if \\(typeof envelope\\.destructive !== .boolean.\\) \\{/if (!envelope.destructive) {/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "envelope.hosts array check dropped" "L2" \
  'perl -0pi -e "s/if \\(!Array\\.isArray\\(envelope\\.hosts\\)\\)[^\\n]*\\n//" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

# The scope-only type guard this used to mutate is gone: `need` now makes that
# decision for every required field, so the mutation points at `need` instead. A
# pattern left on the deleted guard would have matched the comment that explains
# the deletion, edited prose, and passed — reported as SURVIVED on a rule that is
# in fact enforced.
run_mutation "the arg validator stops type-checking its required fields" "L2" \
  'perl -0pi -e "s/if \\(kind === .string. && typeof value !== .string.\\) \\{/if (false) {/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "a documented arg field is removed from SKILL.md" "L1" \
  'perl -0pi -e "s/^    component:.*\\n//m" "$SANDBOX/skills/fp-check/SKILL.md"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k documents_every_field'

run_mutation "dead challenge agent becomes a truthy phantom" "L2" \
  'perl -0pi -e "s/\\.then\\(\\(v\\) => \\(v \\? \\{ \\.\\.\\.v, key: c\\.key \\} : null\\)\\)/.then((v) => ({ ...v, key: c.key }))/" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k spread_without_a_null_guard'

run_mutation "build gate stops requiring what review-poc needs" "L2" \
  'perl -0pi -e "s/, .command., .output., .invokedSymbol.//" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/build.test.mjs"'

# The gate list and review-poc's need() calls are now pinned to each other, so
# dropping a field must fail the contract test as well as the unit tests.
run_mutation "build gate drops the fields review-poc requires" "L1" \
  'perl -0pi -e "s/.absolutePath., .path., .pocType., /\x27absolutePath\x27, /" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k build_gate_covers'

run_mutation "non-array candidates throws out of the validator" "L2" \
  'perl -0pi -e "s/\\(Array\\.isArray\\(cands\\) \\? cands : \\[\\]\\)/(cands || [])/" "$SANDBOX/workflows/triage-poc.js"; perl -0pi -e "s/if \\(cands !== undefined && cands !== null && !Array\\.isArray\\(cands\\)\\) \\{\\n    missing\\.push\\(.candidates \\(must be an array\\).\\)\\n  \\} else \\{/if (false) {} else {/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "non-array layers throws out of the validator" "L2" \
  'perl -0pi -e "s/\\(Array\\.isArray\\(layers\\) \\? layers : \\[\\]\\)/(layers || [])/" "$SANDBOX/workflows/triage-static.js"; perl -0pi -e "s/if \\(layers !== undefined && layers !== null && !Array\\.isArray\\(layers\\)\\) \\{\\n    missing\\.push\\(.layers \\(must be an array\\).\\)\\n  \\} else \\{/if (false) {} else {/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "a terminal status loses its reason" "L2" \
  'perl -0pi -e "s/return \\{ status: .NO_CANDIDATES., reason: .no candidate attack paths supplied. \\}/return { status: \x27NO_CANDIDATES\x27 }/" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k terminal_returns_carry_a_reason'

# Checkpoint 2.2's vacuous pass. `layers` defaults to [] in the destructure, so
# an omitted field dispatched zero layer agents, left every filter in the gate
# matching nothing, and returned PROCEED having inspected nothing.
run_mutation "gate proceeds having inspected zero layers" "L2" \
  'perl -0pi -e "s/if \(attemptedLayers === 0 && !declaredNone\)/if (false)/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

run_mutation "empty layers list slips past the arg validator" "L2" \
  'perl -0pi -e "s/if \(layers === undefined \|\| layers === null \|\| \(Array\.isArray\(layers\) && layers\.length === 0\)\)/if (false)/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

# Checkpoint 2.3 passes on "checked for recovery (not assumed absent)". A dead
# agent used to reach the impact prompt as "not established" and proceed.
run_mutation "dead recovery agent no longer blocks checkpoint 2.3" "L2" \
  'perl -0pi -e "s/if \(!recoveryVerdict\)/if (false)/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

# OUT_OF_SCOPE and NOT_VULNERABLE are the only two reasons taken straight from
# an agent. THREAT_SCHEMA's `required` checks presence, not content, so
# `evidence: ''` is schema-valid and the halt reached the orchestrator with
# nothing after the colon.
run_mutation "an agent-supplied halt reason loses its fallback" "L2" \
  'perl -0pi -e "s/const why = \(fallback\) => String\(threatVerdict\.evidence \|\| ..\)\.trim\(\) \|\| fallback/const why = (fallback) => threatVerdict.evidence/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

run_mutation "2.4b stops requiring the external precondition" "L2" \
  'perl -0pi -e "s/return !String\(verified\.externalPrecondition[^\n]*/return false/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

# safety-guidelines.md allows destructive operations only at levels 1-2.
run_mutation "envelope authorises destruction against production" "L2" \
  'perl -0pi -e "s/envelope\.destructive === true && Number\.isInteger\(envelope\.level\) && envelope\.level >= 3/false/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "envelope.level range check dropped" "L2" \
  'perl -0pi -e "s/if \(!Number\.isInteger\(envelope\.level\) \|\| envelope\.level < 1 \|\| envelope\.level > 5\)/if (false)/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

# The builder works in an isolated worktree; without an absolute path the PoC is
# unreadable for its five reviewers, for the report, and for the user.
run_mutation "build gate stops requiring the PoC absolute path" "L2" \
  'perl -0pi -e "s/.absolutePath., //" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/build.test.mjs"'

# The PoC used to cross a dispatch boundary, and review-poc's validator held
# build-poc's output to a `need('poc.absolutePath', ...)` list. One script now, so
# the guarantee is the build gate's: the reviewers read `poc.absolutePath` out of
# whatever the builder returned, and a build the gate lets through with a blank
# one reaches five agents as the file they are meant to open.
run_mutation "the build gate stops covering a field the reviewers read" "L2" \
  'perl -0pi -e "s/\x27absolutePath\x27, //" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k covers_every_field_the_reviewers_read'

# Was `absolutePath`, which is no longer in the dispatch contract: the PoC stopped
# crossing a workflow boundary when build and review merged, so it is a local and
# nothing documents it. `severity` replaces it — a field on a DIFFERENT arg object
# from the one the mutation above uses, so the two are not the same check twice.
run_mutation "a forwarded verification field is undocumented" "L1" \
  'perl -0pi -e "s/\bseverity\b/sev/g" "$SANDBOX/skills/fp-check/SKILL.md"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k documents_every_field'

# checkpoints.md 5.1 challenge 4 overrides the band. Reading it off the returned
# verdicts let a dead challenge-4 agent escape the one unconditional rule.
run_mutation "already-fixed rule skips a challenge that never answered" "L2" \
  'perl -0pi -e "s/if \(!\(unrebutted \|\| \[\]\)\.some\([^\n]*/return null;/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

# checkpoints.md 2.4b and 2.5 cap severity. The report prompt states the caps;
# the returned severity is whatever the agent chose.
run_mutation "integration root cause no longer caps severity" "L2" \
  'perl -0pi -e "s/if \(externalRootCause\(rootCause\)\)/if (false)/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

run_mutation "hardening gap no longer caps severity" "L2" \
  'perl -0pi -e "s/if \(classification === .hardening_gap.\)/if (false)/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

# The cap's two halves, which took three rounds to get right and were unpinned
# each time. The rating is the HIGHEST level the string names, matched
# WORD-BOUNDED, and the cap applies only where it lowers. Drop the boundaries and
# 'high' matches inside "highly", so a Low is raised to Medium under a note saying
# it was lowered; read the lowest instead of the highest and 'Medium/High' or
# 'Allowlist bypass — High' escape the cap entirely, which is the one mechanism
# the head-to-head credits 3/3 against 0/3.
run_mutation "severity level names lose their word boundaries" "L2" \
  'perl -0pi -e "s/\\\\\\\\b\\\$\{name\}\\\\\\\\b/\\\$\{name\}/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/static.test.mjs"'

# Every positional rule tried here — leftmost name, highest name, highest-only-
# where-it-lowers — traded a false accept for a false reject, because
# 'Critical (affects low-privilege users)' and 'Low (the path is not
# business-critical)' are the same shape with opposite intent. The refusal is what
# replaced them, and it is the part with no fallback: let the ambiguity through
# and whichever level the code happens to read becomes the finding's rating.
run_mutation "the cap guesses at an ambiguous rating instead of refusing it" "L2" \
  'perl -0pi -e "s/  if \(named\.length !== 1\) \{/  if (false) {/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/static.test.mjs"'

# And the routing, which is the half a unit test cannot see: `capSeverity` can
# refuse perfectly and the run still ship the string if nothing acts on it.
run_mutation "Stage 1 carries an ambiguous severity into the verdict" "L2" \
  'perl -0pi -e "s/if \(capped\.ambiguous\) \{\n  log/if (false) {\n  log/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/static.test.mjs"'

run_mutation "Stage 2 adopts an unreadable severity from the summary agent" "L2" \
  'perl -0pi -e "s/  : claimed\.ambiguous/  : \x27\x27/" "$SANDBOX/workflows/triage-online.js"' \
  'node --test "$SANDBOX/tests/online.test.mjs"'

# Stage 3 refuses in two places: the report gate, which is what the author sees,
# and the cap itself as a backstop. Neither may become a silent pass — a rating
# the code cannot read is the one SKILL.md tells the orchestrator to ship.
#
# This one guard covers all three unreadable shapes, which is why the separate
# blank-severity mutation it replaced became equivalent: deleting the blank check
# stopped changing the outcome once the level count caught blanks too.
run_mutation "the report gate accepts a severity that is not exactly one level" "L2" \
  'perl -0pi -e "s/  if \(levels\.length !== 1\) \{/  if (false) {/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

run_mutation "the Stage 3 cap passes an ambiguous rating as no violation" "L2" \
  'perl -0pi -e "s/  if \(named\.length !== 1\) \{/  if (false) {/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

# A citation rule that rejects a real advisory ID does not merely report a false
# positive: it writes "no commit, PR, issue or advisory reference" over a
# reference that is there, and the fixed bug is reported as live. Every SHAPE
# rule tried did that in one direction or the other — "ends in a digit" threw out
# 1 real GHSA ID in 20, "four-character segments" then threw out PYSEC-2021-19 and
# USN-5678-1. This puts the shape rule back.
run_mutation "the registry allowlist reverts to a shape rule" "L2" \
  'perl -0pi -e "s/bound \+ .ghsa\(-\[0-9a-z\]\{4\}\)\{3\}.,\n(.*\n)*?      bound \+ .\(cve\|[^\n]*\n/bound + \x27[a-z]{2,}-(?=[0-9a-z-]*[0-9])[0-9a-z]{4,}(-[0-9a-z]{4,})+\x27,\n/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/static.test.mjs"'

# The other direction, and the one that contradicted this function's own rule that
# a bare `file:line` is not a citation: with `/` in the shared keyword separator
# class, `src/bug/12.go` and `tests/issues/42/repro.py` became citations.
run_mutation "a file path counts as a GitHub shorthand citation again" "L2" \
  'perl -0pi -e "s/\x27\(\^\|\[\^0-9a-z\/\]\)\(pr\|pull/\x27(^|[^0-9a-z])(pr|pull/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/static.test.mjs"'

# `required` checks presence, not content: a blank `evidence` clears Principle 5
# on a comparison nobody made — the one check that decides it, turned back into a
# self-report. (Its blank-`severity` twin is now covered by the one-level guard
# above, which subsumed it.)
run_mutation "Principle 5 clears without saying what was compared" "L2" \
  'perl -0pi -e "s/  if \(!String\(check\.evidence \|\| ..\)\.trim\(\)\) \{\n[^\n]*\n  \}\n//" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

# Checkpoint 4.3's "the output demonstrates the vulnerability", decided by the one
# reader who did not build the PoC. Nothing in code required it for as long as
# `reRunSucceeded` was one boolean over two opposite results — a reviewer's "ran
# it; the balance is unchanged" came back REPORTED at High, which SKILL.md maps to
# TRUE POSITIVE. This turns the branch back off.
run_mutation "a PoC that demonstrably did not reproduce still reports" "L2" \
  'perl -0pi -e "s/  if \(check\.reRun === .DID_NOT_REPRODUCE.\) \{/  if (false) {/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs" "$SANDBOX/tests/wiring.test.mjs"'

# "Only a TRUE POSITIVE justifies building." A failed Stage 1 return carries a
# populated `impact`, `severity` and `history`, so forwarding one verbatim
# satisfies every other field.
run_mutation "the PoC stage accepts a failed verification" "L2" \
  'perl -0pi -e "s/  if \(status !== .TRUE_POSITIVE.\) \{/  if (false) {/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

# And the same rule for the online stage, which had no mutation at all: it accepts
# three Stage 1 statuses and must reject the rest, or the public evidence gets to
# argue a finding that was already dismissed on the code back to life.
run_mutation "the online stage accepts a dismissed finding" "L2" \
  'perl -0pi -e "s/  if \(!actionable\.includes\(status\)\) \{/  if (false) {/" "$SANDBOX/workflows/triage-online.js"' \
  'node --test "$SANDBOX/tests/online.test.mjs"'

# The downstream-users census, restored in the rebuild. Its failure mode is not a wrong
# answer, it is never firing — `capSeverity`, `upstreamFixStands` and
# `decideVerdict` each fired 0 times in 63 measured runs while every unit test
# covering them was green. So the first two mutations break the gate in the
# direction that silently loses the capability.
run_mutation "the census gate answers no on a client-driven sink" "L2" \
  'perl -0pi -e "s/  return driver !== .in-repo-caller./  return false/" "$SANDBOX/workflows/triage-online.js"' \
  'node --test "$SANDBOX/tests/online.test.mjs"'

# The affirmative pair this used to anchor on is gone: the census reads root
# cause through `externalRootCause`, the predicate the cap reads it through, so
# `third-party` cannot be priced as external by 2.4b and as in-repo here.
run_mutation "a non-internal root cause no longer needs a consumer census" "L2" \
  'perl -0pi -e "s/  if \(externalRootCause\(impact\.rootCause\)\) return true/  if (false) return true/" "$SANDBOX/workflows/triage-online.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs" "$SANDBOX/tests/online.test.mjs"'

# And the one that matters most in the other direction: a census that searched
# nothing must never reach the summary as "no consumer is affected".
run_mutation "a census that never reached the network reads as a clean result" "L2" \
  'perl -0pi -e "s/  if \(result\.reachedNetwork !== true\) \{\n    return \`no consumer index/  if (false) {\n    return \`no consumer index/" "$SANDBOX/workflows/triage-online.js"' \
  'node --test "$SANDBOX/tests/online.test.mjs"'

# Batch triage and the exploit-chain check, restored in the rebuild. Both are
# false-NEGATIVE guards, which is what makes them worth mutating: a finding that
# is silently dropped and a pair that is never compared look exactly like a clean
# run, so nothing but an assertion on the ledger and on the pairing can see them.
# Four of the five break in the direction that loses the capability quietly.
run_mutation "a finding whose sub-workflow died vanishes from the ledger" "L2" \
  'perl -0pi -e "s/      unverified\.push\(\{ id, why: .the sub-workflow returned nothing/      [].push({ id, why: '"'"'the sub-workflow returned nothing/" "$SANDBOX/workflows/triage-batch.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs"'

run_mutation "a batch where nothing was verified reports as triaged" "L2" \
  'perl -0pi -e "s/if \(ledger\.verified\.length === 0\) \{/if (false) {/" "$SANDBOX/workflows/triage-batch.js"' \
  'node --test "$SANDBOX/tests/batch.test.mjs"'

run_mutation "two findings behind the same wall are paid for anyway" "L2" \
  'perl -0pi -e "s/    if \(first\.join\(. \| .\) === second\.join\(. \| .\)\) return ..$/    if (false) return \x27\x27/m" "$SANDBOX/workflows/triage-batch.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs"'

run_mutation "an already-fixed finding is argued back to life by the chain agent" "L2" \
  'perl -0pi -e "s/  return \[.NOT_EXPLOITABLE., .TRUE_POSITIVE., .NEEDS_MORE_INFO.\]\.includes\(status\)/  return status !== \x27NOTHING\x27/" "$SANDBOX/workflows/triage-batch.js"' \
  'node --test "$SANDBOX/tests/batch.test.mjs"'

run_mutation "a chain is reported without the mechanism connecting the two" "L2" \
  'perl -0pi -e "s/  if \(supplies === ..\) blank\.push\(.supplies.\)/  if (false) blank.push(\x27supplies\x27)/" "$SANDBOX/workflows/triage-batch.js"' \
  'node --test "$SANDBOX/tests/batch.test.mjs"'

# The shared context is the batch's cost argument, and it lives in the CHILD:
# triage-static ignores args it does not read, so a context that never reaches a
# prompt is dropped in silence and the Context phase becomes decoration.
run_mutation "the shared context stops reaching the prompts that would re-derive it" "L2" \
  'perl -0pi -e "s/\\\$\{contextBlock\}Layer under test/Layer under test/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/coverage.test.mjs"'

# --- Layer 3 -------------------------------------------------------------

defer_mutation "a blocking layer loses its file:line" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "a layer verdict flips from stopped to reaching" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "an agent returns an unknown enum value" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "an agent dies, leaving fewer results than starts" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "a stopping verdict asserts without quoting code" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "workflow launch carries an error but says async_launched" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "a PoC is built despite the path being blocked" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "the skill was never invoked (workflow dispatched unprompted)" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "the fixture is relabelled as synthetic" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

run_mutation "the scrubber destroys file:line evidence" "L3" \
  'perl -0pi -e "s|\\(re\\.compile\\(r\"/\\(\\?:private/tmp\\|Users\\|home\\)/\\[\\^\\\\s\\\\\"\x27\\]\\*\\?/\\(\\?=plugins/\\)\"\\), \"REPO/\"\\),||" "$SANDBOX/tests/scrub_capture.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_scrub.py" -k repo_relative_path_survives'

# --- Layer 4 -------------------------------------------------------------

run_mutation "an LLM grader loses its deterministic pairing" "L4" \
  'uv run --with pyyaml --no-project python -c "
import yaml,sys
p=\"$SANDBOX/evals/blocked-attack-path/case.yaml\"
d=yaml.safe_load(open(p)); d[\"graders\"]=[g for g in d[\"graders\"] if g[\"type\"]==\"llm\"]
yaml.safe_dump(d, open(p,\"w\"), sort_keys=False)"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k pairs_llm_with_deterministic'

run_mutation "the should-NOT-fire case is deleted" "L4" \
  'rm -r "$SANDBOX/evals/should-not-fire"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k should_not_fire_case'

run_mutation "the negative case withholds Skill, making it vacuous" "L4" \
  'perl -0pi -e "s/^  - Skill\n//m" "$SANDBOX/evals/should-not-fire/case.yaml"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k actually_allows_the_plugin_to_fire'

run_mutation "runs dropped below 3" "L4" \
  'perl -0pi -e "s/^runs: 3$/runs: 1/m" "$SANDBOX/evals/inflated-impact/case.yaml"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k runs_at_least_three'

# Without the opt-in phrase the Workflow tool refuses to dispatch, so the whole
# pipeline silently does not run and the eval grades the skill's prose. That is
# not hypothetical — it is what the 2026-08-04 run measured. re.S because the
# phrase wraps across lines in the block-scalar prompts.
run_mutation "a case prompt loses its workflow opt-in" "L4" \
  'uv run --with pyyaml --no-project python -c "
import re,yaml
p=\"$SANDBOX/evals/integration-cap/case.yaml\"
d=yaml.safe_load(open(p))
d[\"execution\"][\"prompt\"]=re.sub(r\"Multi-agent orchestration.*?calls for it\.\",\"\",d[\"execution\"][\"prompt\"],flags=re.S)
yaml.safe_dump(d, open(p,\"w\"), sort_keys=False)"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k opts_into_workflow_orchestration'

# Naming the plugin in the prompt hands the with-plugin arm an instruction the
# baseline arm cannot act on, inflating the delta by construction. This is the
# tempting "fix" for the mutation above.
run_mutation "the workflow opt-in names the plugin under test" "L4" \
  'uv run --with pyyaml --no-project python -c "
import yaml
p=\"$SANDBOX/evals/integration-cap/case.yaml\"
d=yaml.safe_load(open(p))
d[\"execution\"][\"prompt\"]+=\"\n\nUse the fp-check skill and follow its workflow dispatch exactly.\"
yaml.safe_dump(d, open(p,\"w\"), sort_keys=False)"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k opt_in_is_plugin_neutral'

run_mutation "tool_used max:0 loses its min:0" "L4" \
  'perl -0pi -e "s/^  min: 0\n//m" "$SANDBOX/evals/should-not-fire/case.yaml"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k max_zero_also_sets_min_zero'

run_mutation "a not_contains grader targets a negatable phrase" "L4" \
  'uv run --with pyyaml --no-project python -c "
import yaml
p=\"$SANDBOX/evals/inflated-impact/case.yaml\"
d=yaml.safe_load(open(p))
for g in d[\"graders\"]:
    if g[\"name\"]==\"downgrades-to-connection-scoped\":
        g[\"match\"]=\"not_contains\"; g[\"pattern\"]=\"process crash\"
yaml.safe_dump(d, open(p,\"w\"), sort_keys=False)"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k not_negatable_phrases'

run_mutation "a case drops its scaffold" "L4" \
  'perl -0pi -e "s/^  scaffold_script: scaffold\.sh\n//m" "$SANDBOX/evals/blocked-attack-path/case.yaml"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k declares_a_scaffold'

run_mutation "the scaffold drifts from the checked-in fixture" "L4" \
  'perl -0pi -e "s/ALLOWED_TERM/ALLOWED_TERMX/" "$SANDBOX/evals/blocked-attack-path/scaffold.sh"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k scaffold_fixture_matches'

# --- poc-lint ------------------------------------------------------------

run_mutation "poc-lint narration rule neutered" "L4" \
  'perl -0pi -e "s/\(print\|echo\|console/(ZZZNEVER|echo|console/" "$SANDBOX/skills/fp-check/scripts/poc-lint.sh"' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint narration misses single-quoted strings" "L4" \
  'perl -0pi -e "s/\|\x27\[\^\x27\]\*would\[\^\x27\]\*\x27//" "$SANDBOX/skills/fp-check/scripts/poc-lint.sh"' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint empty --symbol silently skips Principle 5" "L4" \
  'perl -0pi -e "s/      if \[ -z \"\\\$LEAF\" \]; then/      if false; then/" "$SANDBOX/skills/fp-check/scripts/poc-lint.sh"' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint accepts a file with no content as a clean PoC" "L4" \
  'perl -0pi -e "s/  if ! grep -q .\[\[:alnum:\]\]. \"\\\$f\"; then/  if false; then/" "$SANDBOX/skills/fp-check/scripts/poc-lint.sh"' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint reimplementation rule loses leading modifiers" "L4" \
  'perl -0pi -e "s/  mods=.\(\[A-Za-z_\]\[A-Za-z_0-9\]\*\[\[:space:\]\]\+\)\*./  mods=\x27\x27/" "$SANDBOX/skills/fp-check/scripts/poc-lint.sh"' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint stub-body rule neutered" "L4" \
  'perl -0pi -e "s/expect && \/\^\[\[:space:\]\]\*\(pass\|/expect \&\& \/^ZZZNEVER(pass|/" "$SANDBOX/skills/fp-check/scripts/poc-lint.sh"' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

# The other direction: a rule that starts rejecting correct PoCs is as bad as
# one that misses. Unanchored markers failed a stored-XSS PoC on alert(HACKED)
# and an open-redirect PoC on HTTPStatus.TEMPORARY_REDIRECT.
run_mutation "poc-lint todo markers lose their word boundaries" "L4" \
  'perl -0pi -e "s/\(\^\|\[\^\[:alnum:\]_\]\)\(TODO\|FIXME\|HACK\)\(\[\^\[:alnum:\]_\]\|\\\$\)/(TODO|FIXME|HACK|TEMPORARY)/" "$SANDBOX/skills/fp-check/scripts/poc-lint.sh"' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

# --- PR review findings ---------------------------------------------------

run_mutation "build gate field neither required nor named in the prompt" "L1" \
  'perl -0pi -e "s/if \(!result \|\| result\.built/if (!result || !result.verifiedByHuman || result.built/" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k names_every_field'

run_mutation "the layer cap and the arg gate drift apart" "L1" \
  'perl -0pi -e "s/function missingArgs\(a, maxLayers = 4\)/function missingArgs(a, maxLayers = 9)/" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k layer_cap_default'

run_mutation "over-cap layers dispatch agents instead of failing closed" "L2" \
  'perl -0pi -e "s/if \(Array\.isArray\(layers\) && layers\.length > maxLayers\)/if (false)/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "checkpoint 4.3 trusts the builder self-report again" "L2" \
  'perl -0pi -e "s/  if \(check\.lintExitZero !== true\) \{/  if (false) {/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

run_mutation "a dead artifact-check agent reads as a pass" "L2" \
  'perl -0pi -e "s/  if \(!check\) return .the artifact-check agent returned nothing; the PoC was never independently verified./  if (!check) return null/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

# Principle 5. poc-lint.sh cannot decide facade-vs-copy with a grep, so it prints a
# NOTE and exits 0; this gate is the only code that reads the reviewer's answer.
# Demoted with the question routed nowhere, a PoC that pasted the vulnerable
# function in passed the note AND the symbol rule and came back REPORTED.
run_mutation "a PoC that copies the code under test is no longer blocked" "L2" \
  'perl -0pi -e "s/  if \(check\.reimplementation !== .NOT_DEFINED. && check\.reimplementation !== .LOCAL_DRIVER.\) \{/  if (false) {/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

run_mutation "an unguarded spread returns to a layer result" "L1" \
  'perl -0pi -e "s/\.then\(\(v\) => \(v \? \{ layer: layer\.name \|\| .layer-\\\$\{i \+ 1\}., location: layer\.location, \.\.\.v \} : null\)\)/.then((v) => ({ layer: layer.name, location: layer.location, ...v }))/" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k spread_without_a_null_guard'

run_mutation "poc-lint stops catching a narrated ellipsis comment" "L4" \
  'python3 - "$SANDBOX/skills/fp-check/scripts/poc-lint.sh" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = r"|^[[:space:]]*(#|\/\/|\/\*)[[:space:]]*\.\.\."
assert old in s, "ellipsis comment branch not found"
p.write_text(s.replace(old, "", 1))
PY' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint stub rule stops excluding .pyi stubs" "L4" \
  'python3 - "$SANDBOX/skills/fp-check/scripts/poc-lint.sh" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "\x27 \"${PY_FILES[@]}\")"
new = "\x27 \"${FILES[@]}\")"
assert old in s, "stub-rule file list not found"
p.write_text(s.replace(old, new, 1))
PY' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

# --- call sites -----------------------------------------------------------
#
# Every pure helper above is tested in isolation, which left the WIRING
# untested: a review disabled twelve call sites and the whole free suite stayed
# green. Twenty assertions about decideGate cannot tell you whether its answer
# was acted on. These mutate the call sites; wiring.test.mjs runs the real
# script bodies against scripted agents and catches them.

WIRING='node --test "$SANDBOX/tests/wiring.test.mjs"'

run_mutation "the gate decision is computed and ignored" "L2b" \
  'perl -0pi -e "s/^if \(gate\.status !== .PROCEED.\) \{/if (false) {/m" "$SANDBOX/workflows/triage-static.js"' \
  "$WIRING"

run_mutation "dead-agent detection is disconnected from the gate" "L2b" \
  'perl -0pi -e "s/decideGate\(layerVerdicts, recovery, threat, history, layers\.length, layersSearched\)/decideGate(layerVerdicts, recovery, threat, history, layerVerdicts.length, layersSearched)/" "$SANDBOX/workflows/triage-static.js"' \
  "$WIRING"

run_mutation "the impact result is checked and ignored" "L2b" \
  'perl -0pi -e "s/^if \(!impact \|\| impact\.result !== .VERIFIED.\) \{/if (false) {/m" "$SANDBOX/workflows/triage-static.js"' \
  "$WIRING"

run_mutation "checkpoint 2.4b is computed and ignored" "L2b" \
  'perl -0pi -e "s/^if \(missingPrecondition\(impact\)\) \{/if (false) {/m" "$SANDBOX/workflows/triage-static.js"' \
  "$WIRING"

run_mutation "an empty candidate list falls into the retry loop" "L2b" \
  'perl -0pi -e "s/^if \(attempts\.length === 0\) \{/if (false) {/m" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

run_mutation "checkpoint 4.3 accepts every build" "L2b" \
  'perl -0pi -e "s/  if \(isAcceptableBuild\(result\)\) \{/  if (true) {/" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

run_mutation "the artifact re-check is computed and ignored" "L2b" \
  'perl -0pi -e "s/^if \(artifactIssue\) \{/if (false) {/m" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

run_mutation "the tally denominator shrinks to what came back" "L2b" \
  'perl -0pi -e "s/const tally = tallyChallenges\(verdicts, CHALLENGES\.map\(\(c\) => c\.key\)\)/const tally = tallyChallenges(verdicts, verdicts.map((c) => c.key))/" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

run_mutation "the already-fixed override is computed and ignored" "L2b" \
  'perl -0pi -e "s/^if \(fixCitation\) \{/if (false) {/m" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

run_mutation "a LOW confidence band proceeds to the report" "L2b" \
  'perl -0pi -e "s/^if \(band\.action === .DO_NOT_SUBMIT.\) \{/if (false) {/m" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

# Silence can withhold a PROCEED; it cannot produce a REFUTATION. Five agents that
# never ran produced the byte-identical `confidence NONE (0/5 defeated)` prefix
# SKILL.md maps to FALSE POSITIVE, on a built, executed, independently verified
# PoC. This puts the conflation back.
run_mutation "a silent challenge agent reads as a refutation" "L2b" \
  'perl -0pi -e "s/^  if \(silent\.length > 0\) \{/  if (false) {/m" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

run_mutation "checkpoint 6.1 accepts an empty unproven field" "L2b" \
  'perl -0pi -e "s/  if \(!String\(result\.unproven \|\| ..\)\.trim\(\)\) return .report omitted what remains unproven.\n//" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

run_mutation "the severity cap is computed and ignored" "L2b" \
  'perl -0pi -e "s/^if \(capViolation\) \{/if (false) {/m" "$SANDBOX/workflows/triage-poc.js"' \
  "$WIRING"

run_mutation "a gated build field stops being schema-required" "L1" \
  'perl -0pi -e "s/^    .invokedSymbol.,\n//m" "$SANDBOX/workflows/triage-poc.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k names_every_field'

# The extractor grades a comment. Proven live: breaking confidenceBand while
# leaving a correct copy in a block comment kept review.test.mjs at 32/0.
run_mutation "loadFn extracts a commented-out copy instead of the live one" "L2" \
  'python3 - "$SANDBOX/tests/extract.mjs" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "    if (opens > closes) continue"
assert old in s, "block-comment guard not found"
p.write_text(s.replace(old, "    if (false) continue", 1))
PY' \
  'node --test "$SANDBOX/tests/gate.test.mjs"'

# An eval target that states its own verdict grades "did you read the comment"
# rather than "did you do the analysis". All three fixtures shipped that way and
# it is the largest single reason the ablation shows no delta.
run_mutation "an eval target states its own verdict again" "L4" \
  'python3 - "$SANDBOX/evals/fixtures/case2_search/search.py" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = chr(34) * 3
assert s.startswith(old), "docstring not found at the top of the fixture"
p.write_text(s.replace(old, old + "A SQL concatenation that LOOKS injectable but is not reachable.\\n\\nCheckpoint 2.2 exists for exactly this shape.\\n", 1))
PY' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k does_not_state_its_own_verdict'

# Most contract assertions scan for things that only exist inside a string —
# prompt text, phase: 'X', status: 'Y' — so they read source with comments
# blanked but string contents kept. If that degrades to raw source, a comment
# decides the outcome: a commented-out `// schema: X` satisfies the schema check
# and a stale one fails it.
run_mutation "comment stripping degrades to raw source" "L1" \
  'python3 - "$SANDBOX/tests/test_workflow_contract.py" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "    return _strip(src, blank_strings=False)"
assert old in s, "strip_comments body not found"
p.write_text(s.replace(old, "    return src", 1))
PY' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py"'

# The two cases that reach PROCEED are the only ones that exercise Phases 4-6.
# Their fixtures are multi-file, so the byte-identity guarantee has to hold for
# every file, not just the first one registered.
run_mutation "a multi-file fixture drifts from its scaffold" "L4" \
  'perl -0pi -e "s/BILLING_LEDGER_ENV/BILLING_LEDGER_ENVX/" "$SANDBOX/evals/integration-cap/scaffold.sh"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k scaffold_fixture_matches'

run_mutation "a case is registered with only its first fixture" "L4" \
  'python3 - "$SANDBOX/tests/test_eval_suite.py" <<"PY"
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
m = re.search(r"\"integration-cap\": \(\s*(\([^)]*\),)", s)
assert m, "integration-cap registration not found"
s = s[: m.start(1)] + m.group(1) + "\n    ),\n" + s[s.index("\n", m.end(0)) :]
p.write_text(s)
PY' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k has_a_checked_in_fixture'

# Workflow returns on launch, so the wait is enforced by instruction alone.
# A measured run lost review-poc 2.4s after dispatch because nothing said so.
run_mutation "SKILL.md stops telling the orchestrator to wait" "L1" \
  'perl -0pi -e "s/\*\*Do not end your turn until the workflow has returned\.\*\*//" "$SANDBOX/skills/fp-check/SKILL.md"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k wait_for_each_workflow'

# --- 2026-08 review fixes -------------------------------------------------
#
# One entry per defect found reviewing this branch. Every one of these was a
# behaviour the free suite could not tell you about: each mutation below left
# the whole suite green before its fix landed.

run_mutation "parallel results disaggregated by shape instead of position" "L2" \
  'perl -0pi -e "s/const threat = raw\[at\.threat\] \|\| null/const threat = raw.filter(Boolean).find((r) => r.inScope) || null/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/wiring.test.mjs"'

run_mutation "a schema stops forbidding extra keys" "L1" \
  'perl -0pi -e "s/  additionalProperties: false,\n//" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k every_schema_forbids_extra_keys'

run_mutation "a schema stops requiring the evidence it grades on" "L1" \
  'perl -0pi -e "s/  required: \[.verdict., .evidence.\],/  required: [\x27verdict\x27],/" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k evidence_is_never_an_optional_field'

run_mutation "a schema stops requiring a field its gate branches on" "L2" \
  'perl -0pi -e "s/  required: \[.inScope., .byDesign., .byDesignIndicators., .evidence.\],/  required: [\x27byDesign\x27, \x27byDesignIndicators\x27, \x27evidence\x27],/" "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k gate_reads_only_fields'

run_mutation "a new fan-out over a caller-supplied collection" "L1" \
  'printf "\nconst extra = await parallel(args.reviewers.map((r) => () => agent(r)))\n" >> "$SANDBOX/workflows/triage-static.js"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_workflow_contract.py" -k no_unbounded_fanout'

run_mutation "the 2.4 halt reason loses its fallback" "L2" \
  'perl -0pi -e "s/String\(impact\.evidence \|\| ..\)\.trim\(\) \|\|\s+.impact agent reported[^\n]+/impact.evidence/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/wiring.test.mjs"'

run_mutation "build gate accepts whitespace for a field it requires" "L2" \
  'perl -0pi -e "s/typeof result\[f\] === .string. && result\[f\]\.trim\(\) !== ../Boolean(result[f])/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/build.test.mjs"'

run_mutation "verify-attack-path arg validator accepts whitespace as a value" "L2" \
  'perl -0pi -e "s/const blank = typeof value === .string. && value\.trim\(\) === ../const blank = false/" "$SANDBOX/workflows/triage-static.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "build-poc arg validator accepts whitespace as a value" "L2" \
  'perl -0pi -e "s/const blank = typeof value === .string. && value\.trim\(\) === ../const blank = false/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "review-poc arg validator accepts whitespace as a value" "L2" \
  'perl -0pi -e "s/const blank = typeof value === .string. && value\.trim\(\) === ../const blank = false/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/args.test.mjs"'

run_mutation "checkpoint 6.1 stops gating reportPath content" "L2" \
  'perl -0pi -e "s/if \(!String\(result\.reportPath \|\| ..\)\.trim\(\)\)/if (false)/" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/review.test.mjs"'

# Same relocation. poc-lint exits 2 on an empty --symbol rather than skipping the
# real-code rule in silence, so a PoC without the field does not weaken the review
# — it breaks it, and blames the builder's lintPassed claim. The build gate is what
# stops one being produced.
run_mutation "the build gate stops requiring the symbol the re-check needs" "L2" \
  'perl -0pi -e "s/\x27invokedSymbol\x27, //; s/, \x27invokedSymbol\x27//" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/wiring.test.mjs"'

run_mutation "the Principle 5 re-check loses its symbol argument" "L2" \
  'perl -0pi -e "s/ --symbol .\\\$\{poc\.invokedSymbol\}.//" "$SANDBOX/workflows/triage-poc.js"' \
  'node --test "$SANDBOX/tests/wiring.test.mjs"'

# The Make target stages under a plugins/ tree because the target's `find` is
# cwd-relative. mktemp under $SANDBOX/.. keeps it inside $WORK for the trap.
MAKE_WORKFLOW_TESTS='tree=$(mktemp -d "$SANDBOX/../tree.XXXXXX") && mkdir -p "$tree/plugins" && cp -R "$SANDBOX" "$tree/plugins/fp-check" && cd "$tree" && make -f "$REPO/Makefile" js-tests'

run_mutation "every .test.mjs is emptied, so node --test asserts nothing" "L2" \
  'for f in "$SANDBOX"/tests/*.test.mjs; do printf "// emptied\n" >"$f"; done' \
  "$MAKE_WORKFLOW_TESTS"

run_mutation "the plugin ships workflows/ where the discovery cannot see it" "L1" \
  'mv "$SANDBOX/workflows" "$SANDBOX/skills/fp-check/workflows"' \
  "$MAKE_WORKFLOW_TESTS"

run_mutation "scrubber treats an unknown username as nothing to scrub" "L3" \
  'python3 - "$SANDBOX/tests/scrub_capture.py" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "    username = home.name\n    if not username:"
assert old in s, "the empty-username guard was not found"
p.write_text(s.replace(old, "    username = home.name\n    if False:", 1))
PY' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_scrub.py" -k home_that_yields_no_username'

run_mutation "eval validator treats a missing overall score as full marks" "L4" \
  'perl -0pi -e "s/    if score is None:/    if False:/" "$SANDBOX/tests/validate_eval_result.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_validate_eval_result.py" -k missing_score'

run_mutation "the scaffold runner inherits the caller's GIT_* again" "L4" \
  'python3 - "$SANDBOX/tests/test_eval_suite.py" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "        cwd=workdir,\n        env=scaffold_env(),\n"
assert old in s, "the scaffold runner env strip was not found"
p.write_text(s.replace(old, "        cwd=workdir,\n", 1))
PY' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k inherited_repository'

run_mutation "no scaffold is recognised as initialising a repository" "L4" \
  'perl -0pi -e "s/\^\\\\s\*git\\\\b\.\*\\\\binit\\\\b/ZZZNEVER/" "$SANDBOX/tests/test_eval_suite.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k scaffold_initialises_a_repository'

defer_mutation "the regrade hardcodes the blocking line numbers again" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

defer_mutation "the blocking guards can no longer be located in search.py" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

# --- poc-lint, 2026-08 review fixes ---------------------------------------
#
# Rules 6 and 7 and the step-label rule. Each of these shipped as either a
# false positive on a correct PoC or a miss on the shape a half-written one
# actually takes, and the bats suite stayed at 22/22 throughout.

# --- CRITICAL 3: the RHS constraint on the const|let|var alternative ---
run_mutation "poc-lint rejects the const-import idiom again" "L4" \
  'python3 - "$SANDBOX/skills/fp-check/scripts/poc-lint.sh" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "(const|let|var)[[:space:]]+${esc}[[:space:]]*=[[:space:]]*${fnlit}"
new = "(const|let|var)[[:space:]]+${esc}[[:space:]]*="
assert old in s, "const/let/var alternative not found"
p.write_text(s.replace(old, new, 1))
PY' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint stops flagging a function literal bound to const" "L4" \
  'python3 - "$SANDBOX/skills/fp-check/scripts/poc-lint.sh" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "|^[[:space:]]*(const|let|var)[[:space:]]+${esc}[[:space:]]*=[[:space:]]*${fnlit}"
assert old in s, "const/let/var alternative not found"
p.write_text(s.replace(old, "", 1))
PY' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

# --- CRITICAL 4: the comment/docstring skip in the stub rule ---
run_mutation "poc-lint stub rule stops skipping comments" "L4" \
  'python3 - "$SANDBOX/skills/fp-check/scripts/poc-lint.sh" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "  if (body ~ /^(#|\\/\\/)/) next\n"
assert old in s, "comment skip not found"
p.write_text(s.replace(old, "", 1))
PY' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint stub rule stops skipping docstrings" "L4" \
  'python3 - "$SANDBOX/skills/fp-check/scripts/poc-lint.sh" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "  if (opener != \"\") {"
assert old in s, "docstring skip not found"
p.write_text(s.replace(old, "  if (0) {", 1))
PY' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

run_mutation "poc-lint reads a definition quoted inside a docstring" "L4" \
  'python3 - "$SANDBOX/skills/fp-check/scripts/poc-lint.sh" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "closer != \"\" { if (index($0, closer)) closer = \"\"; next }\n"
assert old in s, "open-docstring rule not found"
s = s.replace(old, "", 1)
anchor = "expect && /^[[:space:]]*$/ { next }\n"
assert anchor in s, "blank-line rule not found"
p.write_text(s.replace(anchor, anchor + old, 1))
PY' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

# --- IMPORTANT 8a: the step label stays deleted ---
# It was removed, not narrowed: print("Step 1: authenticating as the
# low-privilege user") beside a real login() call is indistinguishable from
# tutorial scaffolding, and failing a correct PoC is the worse of this linter's
# two errors. Reinstating it must fail the suite.
run_mutation "poc-lint step label rule comes back" "L4" \
  'python3 - "$SANDBOX/skills/fp-check/scripts/poc-lint.sh" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "  \x22(^|[[:space:]])(//|#)[[:space:]]*attacker"
new = "  \x22[\\\"\x27]Step [0-9]+:|(^|[[:space:]])(//|#)[[:space:]]*attacker"
assert old in s, "placeholder-attack pattern not found"
p.write_text(s.replace(old, new, 1))
PY' \
  'cd "$REPO" && bats "$SANDBOX/tests/poc-lint.bats"'

# --- the harness itself ---------------------------------------------------
#
# These cover the scripts the other layers depend on. Each one shipped green
# while checking nothing.

run_mutation "eval validator reads a run-count key the CLI does not emit" "L4" \
  'perl -0pi -e "s/_get\(case, .runsPerCase., .runs., .runCount.\)/_get(case, \x27runs\x27, \x27runCount\x27)/" "$SANDBOX/tests/validate_eval_result.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_validate_eval_result.py" -k one_run'

run_mutation "eval validator skips a case with no run count" "L4" \
  'perl -0pi -e "s/    if not isinstance\(runs, int\):/    if False:/" "$SANDBOX/tests/validate_eval_result.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_validate_eval_result.py" -k no_run_count'

run_mutation "a regex grader reverts to grading the trace" "L4" \
  'perl -0pi -e "s/  target: last_message\n  pattern: ALLOWED_TERM/  target: trace\n  pattern: ALLOWED_TERM/" "$SANDBOX/evals/blocked-attack-path/case.yaml"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_eval_suite.py" -k satisfied_by_the_scaffold'

run_mutation "scrubber leak check disagrees with the substitution" "L3" \
  'python3 - "$SANDBOX/tests/scrub_capture.py" <<"PY"
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
old = "    leaked = [p for p in paths if (written := p.read_text()) != scrub(written, username)]"
assert old in s, "the leak check was not found"
new = "    leaked = [p for p in paths if username and username in p.read_text()]"
p.write_text(s.replace(old, new, 1))
PY' \
  'cd "$SANDBOX/tests" && "${PYTEST[@]}" test_scrub.py -k does_not_abort'

run_mutation "scrubber blanket-substitutes an ambiguous username" "L3" \
  'perl -0pi -e "s/    if len\(username\) < 4 or username\.lower\(\) in AMBIGUOUS_USERNAMES:/    if False:/" "$SANDBOX/tests/scrub_capture.py"' \
  '"${PYTEST[@]}" "$SANDBOX/tests/test_scrub.py" -k ambiguous_username'

defer_mutation "an unanswered workflow launch counts as started" "L3" \
  "test_regrade.py skips: its capture recorded concept-prover"

echo
echo "-------------------------------------------------------------"
echo "mutations run:      $ran"
echo "mutations survived: $survived"
if [ "$deferred" -gt 0 ]; then
  echo "mutations deferred: $deferred  (Layer 3; see tests/README.md)"
  echo
  echo "  Those $deferred mutations break the recorded run that test_regrade.py grades."
  echo "  That capture is a recording of concept-prover:verify-attack-path, so the"
  echo "  module skips and its pytest exits 0 — which this harness would read as"
  echo "  'the mutation survived'. They are neither run nor dropped until a capture"
  echo "  is taken against fp-check:triage-static: tests/capture-runs.sh, one paid run."
else
  echo "mutations deferred: 0"
fi
if [ "$ran" -eq 0 ]; then
  echo "RESULT: FAIL - zero mutations run; this gate inspected nothing" >&2
  exit 1
fi
if [ "$survived" -gt 0 ]; then
  echo "RESULT: FAIL - $survived mutation(s) survived" >&2
  exit 1
fi
echo "RESULT: PASS - every mutation was caught"
