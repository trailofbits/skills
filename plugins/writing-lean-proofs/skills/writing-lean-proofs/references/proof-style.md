# Tactic proof style

How to structure the inside of a proof. Sources: Mathlib style and PR review
guides, Mathematics in Lean (MIL), Theorem Proving in Lean 4 (TPiL4), and
Massot's ITP 2024 paper on structured proofs. TPiL4's framing: structuring
devices exist because long unstructured tactic sequences "obscure the
structure of the argument" — structure makes proofs "more readable and
robust".

## Skeleton first

Outline the proof with `sorry` (or `_`) justifications, get Lean to accept
the structure, then fill each step. Keeping the skeleton intact is what
yields localized, useful error messages while you work. Filling in the
sorry skeleton from [SKILL.md](../SKILL.md) step 2 yields:

```lean
example (a b c d : ℝ) (h : c = d * a + b) (h' : b = a * d) : c = 2 * a * d := by
  calc
    c = d * a + b     := h
    _ = d * a + a * d := by rw [h']
    _ = 2 * a * d     := by ring
```

## calc replaces rewrite chains

A bare sequence of `rw` steps can only be understood by replaying it in an
editor. When rewrites chain equalities or inequalities, restate the chain as
`calc`: it works for any transitivity-supporting relation (`=`, `≤`, `<`,
`↔`, mixtures), each step discharged by `rw`/`simp`/`ring`/a lemma. Style:
align the relation symbols vertically; left-justify the continuation `_`.

There is no "N rewrites" threshold — the test is whether the intermediate
expressions carry information a reader needs.

## have and suffices

- `have h : X := ...` — forward stepping stone: "we first establish X".
  Intermediate `have`s are the primary structuring device of long proofs.
- `suffices h : X by ...` — backward reduction: "it suffices to show X".
  Use it when the natural narration reduces the goal; you prove the
  reduction first, then the reduced claim.

Always give `have` an explicit statement (`have h : X := ...`, not
`have h := someLemma foo`) when the type is not obvious — the explicitly
typed form is what makes the proof skimmable without an editor.

## Announce goals with show

Open each block of a multi-goal proof with a `show` stating the goal. It is
semantically redundant and structurally essential: MIL — using `show` "makes
the proof easier to read and maintain."

`show` must be honest: if the tactic would actually *change* the goal (up to
more than reducible defeq), use `change` instead. Mathlib's `show` linter
enforces the distinction.

## One focused goal at a time

Every tactic that produces multiple goals is followed by one `·`-focused,
indented block per goal:

```lean
  apply le_antisymm
  · show min a b ≤ min b a
    ...
  · show min b a ≤ min a b
    ...
```

Never operate on goal 2 while goal 1 is open — that couples the proof to
Lean's goal ordering, the classic source of fragility. Enforced by the
`multiGoal` linter. `<;>` and `all_goals` are fine when one tactic
uniformly closes all goals; named `case` blocks are a permitted alternative
to `·` when the case names add information.

## simp discipline

- **Terminal** `simp` (closes the goal): leave it as `simp` — do *not*
  squeeze it into `simp only [...]`. A squeezed terminal call names many
  lemmas, breaks when any is renamed, and buries the one that matters.
- **Non-terminal** `simp` (leaves a goal for later tactics): squeeze it to
  `simp only [...]` so the intermediate goal is stable; a non-terminal bare
  `simp` couples every following tactic to the current simp set.
- Adding a `@[simp]` lemma: its left-hand side must itself be in
  simp-normal form (checked by the `simpNF` linter).

## Structure at the decisions, terseness at the routine

Massot's taxonomy: proofs alternate *safe, reversible* steps (introducing a
variable, destructuring an existential — no initiative required) with
*risky, irreversible* steps (choosing a witness, specializing a universal,
picking an induction). Spend the structural markers — `show`, explicitly
typed `have`, a comment — at the risky steps, where the reader needs to see
the decision. Routine steps can stay terse.

## Golfing

Mathlib review policy: "code golfing is okay as long as it doesn't sacrifice
readability, although golfing trivial results is generally okay." Shorten a
proof only when the short form reads at least as well; a trivial result
closed by `simp`/`omega`/`decide` needs no ceremony. Never golf away the
skeleton of a nontrivial argument.

## When review says "split it"

Mathlib's review guide: "Long standalone proofs are frequently an indication
that there is a worthwhile refactor lurking close at hand." The criterion is
qualitative ("long and unwieldy"); the only numeric threshold in the guide
(1000 lines) is for files. Apply the extraction ladder from
[SKILL.md](../SKILL.md); when
unsure, attempt the extraction — a fragment with a clean statement wanted to
be a lemma.
