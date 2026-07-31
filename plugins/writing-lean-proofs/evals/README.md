# Evals: writing-lean-proofs (review flow)

This suite tests one flow of the `writing-lean-proofs` skill: **reviewing an
existing Lean file** ("review this Lean file", "how could these proofs be
improved"). It does not test proof writing, library design from scratch, or
refactoring.

## What a case is

Each case under `cases/<name>/` is:

- `input/*.lean` — a small, self-contained fixture with *known planted
  flaws* and *known non-flaws* (correct code that folk advice wrongly
  flags). Fixtures are close derivatives of a real Trail of Bits
  formal-verification project; the flaws are real patterns observed
  there, not inventions.
- `prompt.md` — the user prompt, phrased the way a user actually asks
  ("Please review the Lean file X.lean").
- `rubric.md` — grading criteria. `must-flag`: the review names the
  specific declaration, explains why it's a problem, and proposes a fix.
  `must-not-flag`: the review does not assert a known non-issue as a
  problem.

Every case also gets a deterministic **no-rewrite** check: the reviewer was
asked for a review, so the fixture files must be byte-identical afterwards.

## The cases

| Case | Planted flaws | Non-flaws (must not flag) |
|------|---------------|---------------------------|
| 01-definitions-review | global `Fact` instance; Prop/Bool dual spelling of `IsU32`; copy-pasted doc comment | scoped `set_option ... in`; junk-value `toU32` |
| 02-missing-api | downstream `unfold GOLDILOCKS_PRIME` while `u32_lt_prime` sits unused above | `@[simp] ... := rfl` projection lemmas (they ARE the API) |
| 03-normal-form | statements in `>` form; `gt_iff_lt` tax visible in a proof | unsqueezed terminal `simp` |
| 04-structural | unscoped `set_option`s; dishonest `show`; unfocused goals; squeezed *terminal* simp **and** bare *non-terminal* simp (direction test) | — |
| 05-clean-restraint | none — the file is deliberately good | terminal simp, redundant `show` lines, `:= rfl` def lemma; no invented rules |

Cases 03/05 and the non-flaw columns carry the uplift signal: the skill
contradicts popular folk advice there (squeeze everything, delete redundant
`show`s, split proofs over N lines), so a baseline run tends to fail them
while a skill run should not.

## Running

Requires the `claude` CLI and `python3`. Fixtures are **not compiled** —
no Lean toolchain is needed; the flaws are stylistic/structural and
reviewable from source.

```sh
./run.sh                        # all cases, baseline + skill arms
./run.sh --arm skill            # skill arm only
./run.sh --arm baseline 03-normal-form 05-clean-restraint
EVAL_MODEL=claude-sonnet-4-6 ./run.sh   # pin a model
```

- The **skill arm** copies `skills/writing-lean-proofs` into the work dir's
  `.claude/skills/`, so the reviewer discovers it the way a plugin user
  would. The **baseline arm** runs bare. Comparing arms measures uplift.
- Both arms run with `--setting-sources project`, so user-level config is
  excluded: a globally installed copy of this skill (or the marketplace
  plugin) cannot silently contaminate the baseline arm.
- Each reviewer runs headless (`claude -p`) in a throwaway copy of the
  fixture with `--permission-mode acceptEdits`: edits are *possible*, so
  the no-rewrite check is meaningful.
- Grading is an LLM judge (`claude -p`) applying `rubric.md` to the review
  transcript via `grade-prompt.md`, emitting one pass/fail + evidence per
  criterion. The runner fails hard on an empty transcript, a rubric with
  zero criteria, or a verdict count that doesn't match the rubric.
- Results: `results/<timestamp>/<arm>/<case>/{transcript.md,grades.json,no-rewrite.txt,...}`
  plus a printed summary. Results are gitignored.

## Grader self-test

```sh
./run.sh --self-test
```

Feeds `selftest/bad-review.md` — a canned review that misses every planted
flaw in case 01 and commits every forbidden move (invents "one tactic per
line" and a 20-line threshold, flags the scoped `set_option`, demands
squeezing terminal simp, wants `Option` instead of junk values) — through
the real grader and asserts it fails **every** criterion. If the grader
passes it on anything, the self-test exits non-zero. Run this after editing
rubrics or the grader prompt.

## Interpreting results

- A `must-flag` fail on the skill arm means the skill didn't surface its
  own rule — look at whether the SKILL.md wording is reachable from a plain
  "review this file" prompt.
- A `must-not-flag` fail on the skill arm is worse: the skill's
  anti-folk-advice guidance lost to the model's prior. Those rules may need
  to be more prominent (they live in the "Rationalizations to reject" and
  anti-patterns tables).
- Baseline-arm failures are expected and are the point: cases the baseline
  already aces provide no signal about the skill.

## Provenance and caveats

- Fixtures derive from an internal Trail of Bits Lean project with
  identifiers and structure simplified; used with permission.
- Fixtures were written to be plausible Lean 4 + Mathlib but are not
  compiled in CI. If a fixture contains an accidental error a reviewer
  fixates on, treat that as fixture debt and fix the fixture, not the
  rubric.
- The LLM judge makes borderline calls on hedged reviews ("you *might*
  consider squeezing..."). `grade-prompt.md` instructs it to fail only
  actual recommendations; spot-check `grades.json` evidence fields when a
  number looks surprising.
