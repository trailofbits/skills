---
name: writing-lean-proofs
description: "Writes and reviews structured Lean 4 proofs and designs Lean libraries following Mathlib conventions. Use when proving theorems in Lean, formalizing mathematics or specifications in Lean 4, defining new types or definitions in a Lean library, reviewing Lean proofs for readability and maintainability, refactoring long tactic proofs into lemmas, or filling in sorry placeholders in a Lean development."
---

# Writing Lean Proofs

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
  tactics — copied from the InfoView, not imagined. This is the single most
  effective technique for LLM-written proofs (see
  [llm-techniques.md](references/llm-techniques.md)).

See [proof-style.md](references/proof-style.md) for the full tactic-style
rules, and [naming-conventions.md](references/naming-conventions.md) for
naming lemmas so their names are guessable from their statements.

### 4. Verify mechanically

Do not eyeball-check style — run the checkers:

```sh
lake build                                    # everything compiles
! grep -rn --include='*.lean' sorry MyProject # fails if any sorry remains
```

`sorry` is only a *warning*, so `lake build` alone exits 0 with sorries
still present — hence the grep, with `!` inverting its exit status so a
match fails the check. The grep also matches `sorry` inside comments and
docstrings; inspect the hits rather than trusting the exit code blindly
(or check the target theorem with `#print axioms`, which reports
`sorryAx`).

The style linters (`multiGoal`, `show`, `setOption`, ...) run as part of
Mathlib's own build but are **off by default elsewhere** — in a
Mathlib-dependent project, opt in per option (`set_option
linter.style.multiGoal true`, ideally in the lakefile's `leanOptions`).
Run Batteries' `#lint` (which includes `simpNF`) in a scratch file or CI.
The evidence for tooling over review: the first simp-normal-form linter
found 100+ redundant simp lemmas in Mathlib that had all passed expert
maintainer review.

## The extraction ladder

When does proof structure graduate into separate lemmas?

1. **A sub-argument repeats within one proof** → name it as a local `have`.

   ```lean
   theorem min_comm (a b : ℝ) : min a b = min b a := by
     have h : ∀ x y : ℝ, min x y ≤ min y x := by
       intro x y
       apply le_min
       · apply min_le_right
       · apply min_le_left
     apply le_antisymm
     · apply h
     · apply h
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
| One focused goal at a time (`·` blocks) | kills goal-ordering fragility | `multiGoal` linter |
| `show` must not change the goal (use `change`) | stated goals stay honest | `show` linter |
| No `set_option` debug/trace/profiler or unscoped `maxHeartbeats` in final code | debugging scaffolding | `setOption` linter |
| State lemmas in simp-normal form, `<` not `>` | simp matches syntactically | `simpNF` linter |
| Golf only when the result is at least as readable; trivial results exempt | short ≠ better | review |
| `Fact` instances are local, never global | global instances degrade all typeclass search | review |
| Name lemmas from their statements (see naming reference) | names become guessable without search | `nameCheck` linter, review |

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

## References

- [library-design.md](references/library-design.md) — definitions, APIs,
  bundling, abstraction boundaries, spec-driven project decomposition
- [proof-style.md](references/proof-style.md) — tactic proof structure:
  calc, have/suffices, focusing, simp discipline
- [naming-conventions.md](references/naming-conventions.md) — Mathlib naming
  so lemma names are computable from statements
- [anti-patterns.md](references/anti-patterns.md) — recognized anti-patterns,
  why each is harmful, and which linter catches it
- [llm-techniques.md](references/llm-techniques.md) — evidence-based
  techniques specific to LLM-written proofs
