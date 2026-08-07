---
name: writing-lean-proofs
description: "Writes and reviews structured Lean 4 proofs and designs Lean libraries following Mathlib conventions. Use when proving theorems in Lean, formalizing mathematics or specifications in Lean 4, defining new types or definitions in a Lean library, reviewing Lean proofs for readability and maintainability, refactoring long tactic proofs into lemmas, filling in sorry placeholders in a Lean development, setting up CI or linters for a Lean project, diagnosing slow proofs or maxHeartbeats timeouts, or writing custom tactics, macros, or linters."
---

# Writing Lean Proofs

## Contents

- [When to Use](#when-to-use)
- [When NOT to Use](#when-not-to-use)
- [The workflow](#the-workflow)
- [The extraction ladder](#the-extraction-ladder)
- [Quick reference](#quick-reference)
- [Rationalizations to reject](#rationalizations-to-reject)
- [References](#references)

Structured Lean 4 proof writing and library design, distilled from Mathlib's
style and review conventions and from the methodology of large formalization
projects (Liquid Tensor Experiment, PFR, Fermat's Last Theorem).

**Core principle: design top-down, prove bottom-up.** Lean propositions are
proof-irrelevant — only a theorem's *statement* can affect later declarations.
Statements are the stable interface; proofs are disposable and freely
replaceable. Put design effort into definitions and statements, then fill in
proofs against skeletons that already compile (modulo `sorry`).

## When to Use

- Proving theorems in Lean 4, from single lemmas to multi-file developments
- Formalizing mathematics, protocols, or software specifications in Lean
- Defining new types, structures, or functions in a Lean library
- Reviewing Lean code for readability, maintainability, or Mathlib readiness
- Refactoring a long or fragile tactic proof into lemmas
- Setting up a formalization project that several people or agents will
  contribute to in parallel
- Setting up CI, linters, or verification gates for a Lean project — do this
  at project start, before patterns propagate
- Diagnosing slow proofs, `maxHeartbeats` timeouts, or expensive reduction
- Writing custom tactics, macros, or project-specific linters

## When NOT to Use

- Lean 4 as a general-purpose programming language (no proofs involved) —
  most of this skill targets proof and API structure
- Coq, Isabelle, Agda, or Lean 3 — conventions and tactic names differ;
  Lean 3 idioms (`ge_or_gt` linting, `discrete_field`) are obsolete
- Verified-software Lean projects with their own house style (e.g.
  spec-traceability-first codebases): Mathlib conventions are the community
  default, but check the project's CONTRIBUTING first and defer to it

## The workflow

### 1. Design definitions and their API first

Definitions carry the design weight. Before proving anything about a new
concept:

- **Prefer total functions with junk values** over subtypes or `Option` in
  signatures (Mathlib: `(0 : ℝ)⁻¹ = 0`). Side conditions then appear only on
  the lemmas that need them, not at every use site.
- **Bundle**: new morphism kinds are structures with a `FunLike` instance;
  new subobject kinds use `SetLike`; carry property proofs as structure
  fields, not separate `IsHom`-style predicates.
- **Pick the canonical spelling** (simp-normal form) for every concept with
  multiple equivalent forms, and state all API lemmas for that form only.
- **Write the API in the same file, immediately**: `ext`, `@[simp]`,
  coercion, and injectivity lemmas — before the definition is used anywhere.
  Downstream proofs use the API, never `unfold`/`show ... from rfl`.

See [library-design.md](references/library-design.md) for the full set of
design rules with rationale.

### 2. Build a sorry skeleton

State everything before proving anything, at every scale:

- **Project scale**: state the target theorem and the lemmas it needs, all
  with `:= sorry`, and make the file compile. Each `sorry` is now an
  independent work unit — a contributor (human or LLM) can discharge one
  without understanding the rest. This is how LTE, PFR, and FLT scale to
  dozens of parallel contributors.
- **Proof scale**: inside a proof, lay out the `have`/`suffices`/`calc`
  skeleton with `sorry` justifications, get Lean to accept the structure,
  then fill each step. Keeping the structure intact is what produces useful
  error messages while you work.

```lean
example (a b c d : ℝ) (h : c = d * a + b) (h' : b = a * d) : c = 2 * a * d := by
  calc
    c = d * a + b     := sorry
    _ = d * a + a * d := sorry
    _ = 2 * a * d     := sorry
```

### 3. Fill goals, one focused goal at a time

- Every new subgoal gets a focusing dot `·` with an indented block — never
  leave several goals active in unfocused sequence (Mathlib's `multiGoal`
  linter enforces this). This is what kills fragile goal-ordering dependence.
- Open each block with a redundant `show` stating its goal. The proof works
  without it; reviewers and future editors need it. If `show` would *change*
  the goal, use `change` instead — keep stated goals honest.
- Chained rewrites of (in)equalities become `calc` blocks, relations aligned
  vertically.
- `have` for forward stepping stones ("we first establish X"); `suffices`
  for backward reduction ("it suffices to show X").
- While drafting, annotate the goal state as a comment before non-obvious
  tactics — emitted by Lean, never imagined. In a headless workflow, insert
  `trace_state` at the point of interest or a deliberate `done` where goals
  should be closed, then run `lake env lean Path/To/File.lean`; copy the
  reported hypotheses, case name, and target. Strip routine probes after the
  proof works. This is the single most effective technique for LLM-written
  proofs (see [llm-techniques.md](references/llm-techniques.md)).

See [proof-style.md](references/proof-style.md) for the full tactic-style
rules, and [naming-conventions.md](references/naming-conventions.md) for
naming lemmas so their names are guessable from their statements.

### 4. Verify mechanically

Do not eyeball-check style — run the checkers. `lake build` is the floor,
and it is *only* the floor: `sorry` is a warning, so a green build exits 0
with sorries still present.

- **Gate unproved obligations by asking the kernel, never by grepping.**
  `#print axioms myTheorem` for a spot check; for CI, collect axioms per
  declaration with `Lean.collectAxioms` and assert the *whole* expected
  footprint (`[propext, Classical.choice, Quot.sound]` unless deliberately
  widened), so a stray `sorry` *or* a new trust assumption like
  `native_decide` fails loudly. Grep is wrong in both directions: it matches
  the word in comments, and it misses a theorem whose own text is clean but
  which applies an unproved helper. Working script in
  [linting.md](references/linting.md).
- **Choose lints by project role and put them in CI at project start.** Do not
  enable `linter.mathlibStandardSet` wholesale in a downstream project: it
  combines proof-maintenance checks with public-API checks, house style, and
  Mathlib-specific repository policy. For a self-contained proof, start with
  `linter.auxLemma`, `linter.style.maxHeartbeats`,
  `linter.style.multiGoal`, `linter.style.setOption`, and
  `linter.style.show`. A reusable library should additionally enable
  `linter.flexible`, `linter.style.missingEnd`,
  `linter.style.openClassical`, and the two `unused*InType` checks. Treat
  `nativeDecide` as a trust-policy choice and formatting or deprecated-syntax
  checks as project style. No warning gates anything unless warnings fail
  the build. Run Batteries' declaration-level `#lint` checks, including
  `simpNF`, separately. Verify every option against the pinned Mathlib source
  and with a known-trigger fixture: a misspelled `weak.` option is
  intentionally ignored. The complete 26-member audit and lakefile profiles
  are in [linting.md](references/linting.md).
- **Write a custom linter for every project-specific convention** (simp-set
  discipline, summary-lemma coverage, required attributes) — a
  declaration-level `@[env_linter]` is one structure, and it is the only
  thing that reliably catches "the attribute is missing on 29 of 30
  declarations". See [linting.md](references/linting.md) for the recipe and
  the engineering rules (vacuity anchors, prove-it-can-fail, allowlists).

## The extraction ladder

When does proof structure graduate into separate lemmas?

0. **Before extracting, state the fragment's type and search by shape.** Put
   the proposed statement in a scratch `example`, run `exact?` and `apply?`
   on the bare goal, then try a type-pattern and source search. If an existing
   theorem fits, use it. Do not report an API gap without recording the
   searches that failed.

1. **A sub-argument repeats within one proof** → name it as a local `have`.

   ```lean
   theorem min_comm (a b : ℝ) : min a b = min b a := by
     have h : ∀ x y : ℝ, min x y ≤ min y x := by
       intro x y
       apply le_min
       · show min x y ≤ y
         exact min_le_right x y
       · show min x y ≤ x
         exact min_le_left x y
     apply le_antisymm
     · show min a b ≤ min b a
       exact h a b
     · show min b a ≤ min a b
       exact h b a
   ```

2. **The statement is independently interesting, or extraction sheds
   hypotheses the sub-argument does not need** → standalone lemma. Dropping
   unneeded hypotheses is the stronger trigger: the extracted lemma becomes
   more general than the proof it came from.
3. **The proof reads as "long and unwieldy"** → split it. This is Mathlib's
   review criterion, and it is deliberately qualitative — there is no line
   threshold. Resolve doubt by attempting the extraction: if a fragment has
   a clean statement, it wanted to be a lemma.

## Quick reference

| Rule | Why | Enforced by |
|------|-----|-------------|
| Never unfold definitions downstream; `erw` or trailing `rfl` = missing API | API lemmas are the abstraction boundary | review ("missing API" smell) |
| Terminal `simp` stays unsqueezed; non-terminal `simp` becomes `simp only [...]` | squeezed terminal calls bury the key lemmas and break on renames | style guide |
| One focused goal at a time (`·` blocks) | kills goal-ordering fragility | `linter.style.multiGoal` |
| `show` must not change the goal (use `change`) | stated goals stay honest | `linter.style.show` |
| No `set_option` debug/trace/profiler or unscoped `maxHeartbeats` in final code | debugging scaffolding | `linter.style.setOption` |
| State lemmas in simp-normal form, `<` not `>` | simp matches syntactically | `simpNF` linter |
| Golf only when the result is at least as readable; trivial results exempt | short ≠ better | review |
| `Fact` instances are local, never global | global instances degrade all typeclass search | review |
| Name lemmas from their statements (see naming reference) | names become guessable without search | `linter.style.nameCheck` catches only `__`; `#lint defsWithUnderscore` and review cover more |
| Search a bare goal by shape before writing a helper or claiming an API gap | names are not always guessable from the target | `exact?`, `apply?`, type/source search |
| Generally one tactic invocation per line; a one-line closing proof is the exception | preserves readable proof structure without inventing an absolute rule | style guide |
| Gate `sorry` with `collectAxioms`/`#print axioms`, never grep | grep matches comments, misses unproved helpers | axiom audit in CI |
| Prefer simp-lemma LHSs keyed on structure, not numerals; one spelling per constant | `2 ^ 32` never matches a goal normalized to `4294967296` | `simpNF`, review |
| Re-derive every `simp only` list with `simp?` at its own site | lists do not transfer between look-alike goals | `linter.flexible` |
| Every `maxHeartbeats` override is an unproven claim — measure before believing | copy-pasted budgets carry no information | `#count_heartbeats`, bisection |
| Conditional simp lemma fires shallow but not deep → raise `maxDischargeDepth` (default 2) | chained side conditions truncate silently, no diagnostic | diagnosis (proof-style, simp discipline) |
| Every project-specific convention gets a custom linter, in CI from day one | review misses the 29-of-30 failure mode | `@[env_linter]` + `#lint` |

Full rationale for each row, plus the library-level anti-patterns, in
[anti-patterns.md](references/anti-patterns.md).

## Rationalizations to reject

| Excuse | Reality |
|--------|---------|
| "The proof compiles, ship it" | Compiling is the floor. A monolithic tactic block that only Lean can read will break silently at the next Mathlib bump and no one will be able to repair it. |
| "Unfolding the definition is simpler than writing API lemmas" | Every downstream `unfold` couples a proof to the implementation. The first refactor breaks all of them at once. Write the missing lemma. |
| "Squeezing every simp makes the proof faster and more robust" | Backwards for *terminal* simp calls: the squeezed list breaks on every rename and drowns the signal. Squeeze non-terminal calls only. |
| "It's shorter, therefore better" | Mathlib review policy: golfing is fine *only* when it does not sacrifice readability. Length is not the target; legibility is. |
| "I'll restructure it into lemmas after it works" | After it works, the structure is load-bearing and tangled. State the skeleton first; the lemmas fall out for free. |
| "Adding `show` lines is redundant noise" | They are redundant to the kernel and essential to every human or model that reads the proof next. |
| "This helper is too specific to be a lemma" | If it has a clean statement, extract it — dropping the hypotheses it doesn't need usually reveals it was general all along. |
| "We'll add linters once the library stabilizes" | Backwards: patterns propagate by copy-paste, so a deferred linter meets a 400-warning backlog instead of one bad line. Enable what is already clean and gate it now. |
| "The check passed, so we're clean" | A check that can't fail proves nothing — sweeps reach zero files, misspelled `weak.` options are ignored, pipelines swallow exit codes. Prove every gate can fail before trusting that it passes. |
| "The proof is slow, raise maxHeartbeats" | An unmeasured budget is a claim, not a fix — and it masks the regression the next reader needs to see. Measure with `#count_heartbeats`; restructure the definition or decompose the goal. |

## References

- [library-design.md](references/library-design.md) — definitions, APIs,
  bundling, abstraction boundaries, spec-driven project decomposition
- [proof-style.md](references/proof-style.md) — tactic proof structure:
  calc, have/suffices, focusing, and simp discipline including the
  why-doesn't-this-lemma-fire diagnoses (discharge depth, traversal order,
  numeral spellings)
- [naming-conventions.md](references/naming-conventions.md) — Mathlib naming
  so lemma names are computable from statements
- [anti-patterns.md](references/anti-patterns.md) — recognized anti-patterns,
  why each is harmful, and which linter catches it
- [llm-techniques.md](references/llm-techniques.md) — evidence-based
  techniques specific to LLM-written proofs
- [linting.md](references/linting.md) — axiom-based sorry gates, enabling
  project-specific linter profiles in CI early, the full Mathlib standard-set
  audit, adopting linters with a backlog, writing custom linters for
  project-specific constructs, and proving every gate can fail
- [performance.md](references/performance.md) — measuring per-declaration
  cost, where reduction cost comes from, optimizing definitions without
  losing semantics
- [tactics.md](references/tactics.md) — metaprogramming discipline:
  extension-point selection, metavariable and recovery safeguards, bounded
  search, actionable errors, structured tracing, generated declarations,
  and failure-surface testing
