# Library design: definitions, APIs, and project decomposition

How Mathlib and the large formalization projects structure theory
development. Sources are Mathlib's style and PR review guides, the Mathlib
papers (CPP 2020; van Doorn–Ebner–Lewis, CICM 2020), the perfectoid spaces
retrospective (Buzzard–Commelin–Massot, CPP 2020), and Commelin–Topaz,
"Abstraction boundaries and spec driven development in pure mathematics"
(Bull. AMS, from the Liquid Tensor Experiment).

## Spec-driven development

Decompose before proving. The LTE methodology, recursively:

1. Isolate a target (definition or theorem).
2. Write its spec: the statement, plus the API lemmas it should satisfy.
3. Break both into lower-complexity parts.
4. Recurse, using `sorry` as a placeholder for **both data and proofs**.

State API lemmas *before the definition exists*:

```lean
def condensedAb : Type := sorry            -- data placeholder

lemma val_app_add (f g : condensedAb) : val (f + g) = val f + val g := sorry
```

Nobody can depend on an implementation detail, because there is no
implementation yet. Collaborators immediately build on the sorried
assertions in parallel and fill targets independently. Tao's PFR project
formalized a 33-page proof with ~20 collaborators in three weeks this way;
Tao: formalization "allows for individual subtasks in the project to be
precisely defined and verified independently of the other subtasks", so
projects "routinely involve scores of people who may have had no prior
interaction". Buzzard (FLT): "you do not have to understand the whole proof
of FLT in order to contribute."

For multi-contributor projects, consider a
[leanblueprint](https://github.com/PatrickMassot/leanblueprint) — a
human-readable outline whose `\uses{...}` annotations generate the
dependency graph and whose `\lean{...}`/`\leanok` links track formalization
status per node. No source prescribes node size; the working criterion is
that **one contributor can complete one node without global context**.

## Statements are the interface; proofs are disposable

Lean propositions are proof-irrelevant: only a theorem's statement can
affect later declarations. Consequences:

- Design effort concentrates on definitions and statements. Mathlib requires
  doc strings on definitions but not on ordinary theorems — statements are
  self-documenting; definitions need justification.
- Refactoring a proof is always safe; refactoring a statement or definition
  is a breaking change. Get statements right first (the sorry skeleton).

## Every definition ships its API, immediately, in the same file

Before a definition is used anywhere, write:

- the `@[simp]` lemmas that compute with it in its canonical form,
- an `@[ext]` lemma (stated *partially applied* — Mathlib's
  "partially-applied ext lemmas" convention — so later ext lemmas compose
  step-wise),
- coercion/`FunLike` lemmas, injectivity lemmas, and the rewrite lemmas that
  let users avoid definitional reasoning.

Explain the design decisions (typeclass choices, simp-normal form) in the
module docstring.

**The smell test**: needing `erw`, or a trailing `rfl` after `simp`/`rw`, is
the style guide's official signal of *missing API*. The fix is a new lemma,
never unfolding. Do not confuse this with the API lemmas themselves: an
`@[simp]` projection lemma *proved by* `rfl` next to its definition is the
boundary working as intended — the smell is a downstream proof *needing*
`rfl` to see through the definition.

## Abstraction boundaries are explicit decisions

- Definitions default to **semireducible** transparency; any deviation must
  be justified (in Mathlib: in the PR description).
- A **sealed** boundary is a one-field structure wrapper, not `irreducible`:

  ```lean
  structure MyDef where
    underlying : UnderlyingTerm
  ```

- `irreducible_def` only with a documented profiling reason.

## Optimized definitions keep a readable reference

When a definition must be rewritten for elaboration or reduction speed, do
not replace it — keep the readable definition as the reference semantics,
add the fast form beside it, and prove them equal for *every* input
(including degenerate and failure cases). Downstream proofs keep using the
readable form and repoint with a single `rw` where they touched the old
shape; the optimization cannot silently change meaning; and the intended
semantics stay legible. This is "statements are the interface" applied to
definitions under optimization. Mechanics and the reduction-cost diagnosis
that motivates it: [performance.md](performance.md).

## Simp-normal form

When a term has multiple equivalent spellings, designate one canonical form
— prefer the generic one (`‖x‖` over a concrete `padicNorm`, `<` over `>`) —
orient `@[simp]` lemmas to rewrite toward it, and state every subsequent API
lemma only for it. The simplifier matches up to syntactic equality; without
a normal form, every lemma needs restating for every spelling. The `simpNF`
linter checks that simp lemma left-hand sides are themselves in normal form.

## Total functions with junk values

Prefer totalizing a function with a junk value over restricting its domain:
in Mathlib, `(0 : ℝ)⁻¹ = 0` and division is total. The payoff is
modularity: the `x ≠ 0` side condition disappears from every use site, and
hypotheses appear only on the lemmas that genuinely need them —

```lean
theorem div_add_div_same (a b c : α) : a / c + b / c = (a + b) / c := ...
  -- unconditional: holds also when c = 0, both sides are junk

theorem mul_inv_cancel₀ (h : a ≠ 0) : a * a⁻¹ = 1 := ...
  -- the hypothesis lives only where the mathematics requires it
```

The perfectoid-spaces authors tried the alternative (a bundled subtype of
units) and reported that it made "every step slightly painful, because
inclusions are harder to ignore in formalised type theory."

## Bundling

- **Morphisms**: define a bundled structure plus a `FunLike`-style class,
  never an `IsHom f` predicate — instance search cannot reliably solve
  goals like `IsHom (f ∘ g)`, while a bundled `Hom` type gets its own
  composition and its own algebraic structure.

  ```lean
  structure MonoidHom (M N : Type*) [Monoid M] [Monoid N] where
    toFun : M → N
    map_one' : toFun 1 = 1
    map_mul' : ∀ a b, toFun (a * b) = toFun a * toFun b
  ```

- **Subobjects**: bundled carrier + `SetLike` instance.
- **Type classes**: semi-bundled — bundle all operations, leave only the
  carrier type as a parameter (`Monoid M`, not fully-bundled `Monoid` nor
  unbundled `IsMonoid M mul one`).

## Restraint on new abstractions

- Introduce a new algebraic typeclass only when there is real mathematics to
  do with it, or a genuine simplification from factoring out a shared
  substructure. Prefer `extends` over mixin parameters.
- `Fact` bridges a proposition into typeclass search *locally*:

  ```lean
  theorem foo (p : ℕ) (hp : p.Prime) : ... := by
    have := Fact.mk hp   -- local instance, scoped to this proof
    ...
  ```

  Never declare global `Fact` instances — they degrade instance search
  everywhere.

## Choosing the abstraction level is the dominant proof-shortener

Work at the highest level that expresses the mathematics. The perfectoid
retrospective's example: stating uniform continuity via filters instead of
unfolding to sets of pairs "allows to break the proofs into small lemmas
that are needed anyway", collapsing "uniformly continuous implies
continuous" to roughly twice the length of the sentence "this follows
immediately from definitions".

When informal mathematics silently identifies isomorphic constructions,
don't fight the identification — introduce a predicate characterizing the
object by its properties (the "abstract completion" move) and prove your
theorems for anything satisfying the predicate.
