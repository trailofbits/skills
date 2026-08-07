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

## One tactic invocation per line, in general

Mathlib's
[style guide](https://leanprover-community.github.io/contribute/style.html)
recommends one tactic invocation per line **in general**, except when a proof
that closes the goal fits entirely on one line. It also permits short sequences
that express one mathematical idea, while preferring newlines. Apply this as
readability guidance, not as a parser-like rule: do not split a clear terminal
`by simpa using h` merely to satisfy a slogan, and do not compress unrelated
state-changing tactics onto one line. This is separate from goal focusing;
`linter.style.multiGoal` protects goal ownership, while line layout is reviewed
qualitatively.

## simp discipline

- **Terminal** `simp` (closes the goal): leave it as `simp` — do *not*
  squeeze it into `simp only [...]`. A squeezed terminal call names many
  lemmas, breaks when any is renamed, and buries the one that matters.
- **Non-terminal** `simp` (leaves a goal for later tactics): squeeze it to
  `simp only [...]` so the intermediate goal is stable; a non-terminal bare
  `simp` couples every following tactic to the current simp set.
- **Whether a `simp` is terminal is a property of the declaration, not the
  idiom.** Three sibling lemmas can look identical while one has a trailing
  `rw` that makes its `simp` non-terminal. Read each proof to the end before
  classifying; "the previous two were terminal" is not evidence about the
  third.
- **Derive every `simp only` list with `simp?` run at that site.** Lists do
  not transfer between look-alike goals — near-identical copy-pasted call
  sites routinely need different lists (one needs `or_self`, the next
  doesn't; one goal's numerals are already reduced, the next's aren't). The
  cost of probing each site is seconds; the cost of assuming transfer is a
  broken proof that looks like a typo.
- Adding a `@[simp]` lemma: its left-hand side must itself be in
  simp-normal form (checked by the `simpNF` linter).
- **One canonical spelling per domain constant — including numerals.**
  `u32Max`, `2 ^ 32`, and `4294967296` are one value in three spellings; if
  the definition, the API lemmas, and the normalized goal each use a
  different one, nothing matches, no rewrite fires, and simp burns its whole
  budget failing. Stronger form: prefer LHS patterns keyed on *structure*
  (a function application over operands) with no numeral in the pattern at
  all — those cannot miss for spelling reasons.
- **`simp`'s default `maxDischargeDepth = 2` silently truncates chained side
  conditions.** A conditional rewrite whose hypothesis is discharged by
  another conditional rewrite (and so on) stops firing past depth 2 — no
  diagnostic, just a goal that does not close and a burned heartbeat budget.
  If a conditional lemma provably applies but never fires on deeper
  instances, raise `maxDischargeDepth` before suspecting the lemma.
- **Traversal order can make a lemma unreachable.** simp rewrites subterms
  first, so a fusion lemma about `f (g x)` never fires if `g x` has already
  been rewritten away. Register such lemmas pre-order with `@[simp ↓]`.
  Symptom: a lemma that is obviously applicable, provably true, and never
  used.
- **"Redundant `@[simp]`" and "useful lemma" are independent.** When
  `simpNF` reports the default set already proves a lemma, drop the global
  `@[simp]` but consider keeping its membership in a scoped simp set —
  `simp only [myScopedSet]` does not include the default set, so the entry
  still does work there. Relatedly, a lemma reached only through
  `simp [mySet]` has zero by-name references and is fully live: check
  attribute consumption before deleting "dead" lemmas.

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
