# Anti-patterns

Each entry: what it is, why it is harmful (not just that it is), and which
mechanism catches it. The meta-lesson from Mathlib's history: **review alone
does not catch these** — the first simp-normal-form linter found over one
hundred redundant simp lemmas that had all passed expert maintainer review.
Put the check in tooling.

## Proof-level

### Monolithic tactic blocks

One long unstructured tactic sequence. Harmful because the argument's
structure is invisible — the only way to follow it is to replay it in an
editor, and the only way to repair it after a library bump is to rebuild it
from scratch. Caught by: review ("long and unwieldy" → split). Fix: sorry
skeleton first, extraction ladder after.

### Unfocused multiple goals

Running tactics while several goals are active, relying on goal order.
Harmful because any change to an earlier tactic silently redirects later
tactics to different goals. Caught by: `multiGoal` linter. Fix: `·` blocks,
one per goal.

### Squeezed terminal simp

`simp only [thirty, lemmas, ...]` closing a goal. Harmful because it breaks
on any rename among the thirty and hides the one lemma that mattered.
Terminal `simp` calls stay unsqueezed; only _non-terminal_ calls get
squeezed (a bare non-terminal `simp` is the mirror-image anti-pattern: it
couples following tactics to the ambient simp set). Caught by: review; the
style guide states the rule.

### Dishonest `show`

`show` that actually changes the goal. Harmful because readers trust `show`
lines as documentation of the goal state; a goal-changing one is
documentation that lies. Caught by: `show` linter. Fix: `change`.

### `native_decide` in library code

Proves a proposition by compiling it to native code and trusting the
result (the `Lean.ofReduceBool` axiom). Harmful because it silently widens
the trust base from the kernel to the entire compiler and runtime;
Mathlib disallows it. Caught by: `#print axioms` (reports
`Lean.ofReduceBool`); Mathlib CI. Fix: `decide` where the kernel can
afford the computation, a certificate-based `norm_num` proof, or an
explicitly documented decision to accept the axiom.

### Leftover debugging scaffolding

`set_option pp.all true`, `trace`/`profiler`/`debug` options, unscoped
`maxHeartbeats`. Harmful as noise and as behavioral drift (heartbeat
overrides mask performance regressions). Caught by: `setOption` linter.

### Golfed nontrivial proofs

Compressing a real argument into a one-liner of chained combinators.
Harmful because review policy subordinates golfing to readability — the
short form is only acceptable when it reads at least as well. Trivial
results are the carve-out. Caught by: review.

### Non-canonical statements

Stating with `>` instead of `<`, or against a concrete spelling instead of
the designated simp-normal form. Harmful because simp and every API lemma
match syntactically — off-normal statements need duplicate API or never get
rewritten. Caught by: `simpNF` linter (for simp lemmas); review. The numeral
special case is easy to miss: a simp lemma keyed on `2 ^ 32` never fires on
a goal normalized to `4294967296` — the lemma is true, applicable-looking,
and dead. Prefer structural LHS patterns with no numeral at all.

### Copy-pasted resource budgets

The same `set_option maxHeartbeats N in` value on many declarations.
Harmful because at that density the annotations carry no information about
which proof is actually expensive, and every unmeasured budget masks the
regression it was meant to surface — audits have found "6.4M-heartbeat"
proofs that run at the default budget once measured. Caught by:
`#count_heartbeats` bisection; Mathlib's `maxHeartbeats` style linter (which
demands a justification comment on every override — the unscoped file-level
form is the `setOption` linter's, see "Leftover debugging scaffolding"
above). Fix: measure, keep only the overrides that are real, each scoped to
its declaration.

## Library-level

### Project conventions enforced only by review

A project-specific construct — a simp-set discipline, a required attribute,
a coverage rule like "every constructor the executor handles has a soundness
lemma" — with no linter behind it. Harmful because the failure mode is
forgetting the step on 1 of 30 declarations with no visible symptom, which
is precisely what review does not catch (and what models writing Lean get
wrong). Caught by: nothing — that is the problem. Fix: a declaration-level
`@[env_linter]` wired into CI's `#lint`, written alongside the construct,
not after the first regression. See [linting.md](linting.md).

### Definitional transparency abuse

Downstream proofs that `unfold`, use `erw`, or need a trailing `rfl` to see
through a definition. Harmful because each one couples a proof to the
implementation; the first refactor breaks them all. The style guide calls
this _missing API_. Caught by: review; the `erw`/trailing-`rfl` smell. Fix:
add the missing lemma next to the definition.

### Definitions without API

A definition used bare, with lemmas about it scattered where they were
first needed. Harmful because every user re-derives basic facts, usually by
unfolding (see above). Caught by: PR review checklist ("do new definitions
come with lemmas about them?"). Fix: same-file `ext`/`simp`/coe/injectivity
lemmas before first use.

### Unbundled predicates for morphisms/subobjects

`IsHom f` predicates instead of a bundled `Hom` structure with `FunLike`.
Harmful because instance search cannot reliably discharge `IsHom (f ∘ g)`,
and the predicate form forfeits the algebraic structure of the hom-type
itself. Caught by: review guide (directs to FunLike/SetLike).

### Side conditions instead of junk values

Partial operations via subtypes or hypotheses on the _operation_ rather
than junk-value totalization. Harmful because the side condition reappears
at every use site ("every step slightly painful" — perfectoid retrospective
on the subtype approach). Fix: total function + junk value; hypotheses only
on the lemmas that need them.

### Global `Fact` instances

`instance : Fact (Nat.Prime 37)` at top level. Harmful because every
typeclass search everywhere now considers it. Fix: state as lemma, make a
local instance where needed.

### Premature typeclasses

A new class with no theory behind it. The bar: real mathematics to be done
with it, or genuine simplification from a factored substructure. Prefer
`extends` to mixin parameters.

## Claims to avoid making

When editing or reviewing, do **not** cite these as rules — they are
commonly repeated but unsupported or wrong:

- "One tactic per line is an absolute requirement" — Mathlib recommends one
  tactic invocation per line in general, but explicitly excepts a proof that
  closes the goal and fits entirely on one line. Apply the recommendation
  with that exception instead of inventing a hard rule.
- Any numeric proof-length threshold ("proofs over 20 lines must be split")
  — the review criterion is deliberately qualitative.
