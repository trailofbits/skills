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
A rewritten fixture fails the run — the check gates the exit status, it is
not only reported in the summary.

## The cases

| Case | Planted flaws | Non-flaws (must not flag) |
|------|---------------|---------------------------|
| 01-definitions-review | global `Fact` instance; `native_decide` in library code; Prop/Bool dual spelling of `IsU32`; copy-pasted doc comment | scoped `set_option ... in`; junk-value `toU32` |
| 02-missing-api | downstream `unfold GOLDILOCKS_PRIME` while `u32_lt_prime` sits unused above | `@[simp] ... := rfl` projection lemmas (they ARE the API) |
| 03-normal-form | statements in `>` form; `gt_iff_lt` tax visible in a proof | unsqueezed terminal `simp` |
| 04-structural | unscoped `set_option`s; dishonest `show`; unfocused goals; squeezed *terminal* simp **and** bare *non-terminal* simp (direction test) | — |
| 05-clean-restraint | none — the file is deliberately good (an engagement criterion requires the review to name specific declarations, so an empty "looks fine" cannot score by omission) | terminal simp, redundant `show` lines, `:= rfl` def lemma; no invented rules |

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
EVAL_MODEL=<model-id-or-alias> ./run.sh # pin a model accepted by your CLI
```

- The **skill arm** copies `skills/writing-lean-proofs` into the work dir's
  `.claude/skills/`, so the reviewer discovers it the way a plugin user
  would. The **baseline arm** runs bare. Comparing arms measures uplift.
- Both arms run with `--setting-sources project`. [Claude Code's skill-location
  documentation][claude-skill-locations] puts personal skills in the `user`
  source and project skills in the `project` source, so the flag excludes
  personal skills while retaining the copied skill in the skill arm. Before
  any model call, the runner also rejects a personal or enabled-plugin copy of
  `writing-lean-proofs`; this converts a future isolation regression into a
  preflight failure. A baseline transcript that names the skill is a final
  runtime backstop.
- The skill arm has the mirror of that backstop: one canary call per run asks
  the CLI to list the skills it can see under `--setting-sources project` and
  fails the run if the copied skill is not among them. Copying the skill in
  does not prove the CLI *discovered* it; without this, a change to project-
  skill discovery would silently make the skill arm run bare, and the suite
  would report the two arms as tied — indistinguishable from a true "no
  uplift" result.
- Each reviewer runs headless (`claude -p`) in a throwaway copy of the
  fixture with `--permission-mode acceptEdits`: edits are *possible*, so
  the no-rewrite check is meaningful.
- Grading is an LLM judge (`claude -p`) in an empty working directory with
  project-only settings, applying `rubric.md` to the review transcript via
  `grade-prompt.md`. The runner requires exactly one JSON array whose ids are
  unique and exactly match the rubric in order, and rejects missing evidence,
  extra keys, an empty transcript, a zero-criterion rubric, or a fixture with
  zero Lean files.
- Results: `results/<timestamp>/<arm>/<case>/{transcript.md,grades.json,no-rewrite.txt,...}`
  plus a printed summary. Results are gitignored.

## Grader self-test

```sh
./run.sh --self-test
```

Two-sided, both against case 01's rubric:

- Before calling the judge, deterministic malformed-output fixtures prove
  that the validator rejects duplicate, reordered, and unknown criterion ids,
  and an enabled-plugin fixture proves that the isolation preflight detects a
  colliding copy of the skill. This half makes no model call and runs before
  the CLI preflight, so it works on a machine with no `claude` on `PATH` and
  no authentication — which is where you would want to run it, e.g. from a
  CI shell-test suite.

- `selftest/bad-review.md` — misses every planted flaw and commits every
  forbidden move (turns one tactic per line into an exceptionless rule,
  invents a 20-line threshold, flags the scoped `set_option`, demands
  squeezing terminal simp, and wants `Option` instead of junk values) — must
  **fail every** criterion. This catches a grader that has become too
  permissive.
- `selftest/good-review.md` — flags all four planted flaws with location,
  rationale, and fix, and commits none of the forbidden moves — must
  **pass every** criterion. This catches a grader that has become too
  strict (which would otherwise read as "the skill provides no uplift").

Run this after editing rubric 01, `grade-prompt.md`, or when changing
`EVAL_MODEL`. Model aliases change over time, so prefer the CLI's stable
family alias or a full model id reported by the installed `claude` version
instead of copying an id from this README. Rubrics 02–05 have no canned
coverage; after editing those, spot-check a live run's `grades.json` evidence
fields instead.

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

[claude-skill-locations]: https://code.claude.com/docs/en/agent-sdk/skills#skill-locations
