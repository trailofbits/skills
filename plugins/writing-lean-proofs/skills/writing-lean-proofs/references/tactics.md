# Writing tactics and metaprograms

## Contents

- [Choose the smallest extension point](#choose-the-smallest-extension-point)
- [Define the tactic contract](#define-the-tactic-contract)
- [Normalize inputs deliberately](#normalize-inputs-deliberately)
- [Make speculative state transactional](#make-speculative-state-transactional)
- [Make failures local and actionable](#make-failures-local-and-actionable)
- [Bound proof search](#bound-proof-search)
- [Build tracing in from the start](#build-tracing-in-from-the-start)
- [Generate syntax and declarations safely](#generate-syntax-and-declarations-safely)
- [Structure tactic code for change](#structure-tactic-code-for-change)
- [Test the failure surface](#test-the-failure-surface)
- [Review checklist](#review-checklist)
- [Research sources](#research-sources)

Custom tactics, macros, simprocs, and elaborators have distinctive failure modes. A bug can
surface much later as a kernel error, silently leave automation in a partial state, or turn a
fast failure into an unbounded search. Design the extension so invalid states are hard to create
and every failure is attributable to one stage.

## Choose the smallest extension point

| Need | Prefer | Safeguard |
|------|--------|-----------|
| Syntax-only expansion | hygienic `macro` | preserve syntax refs; avoid `unhygienic` |
| One local simplification step | simp lemma, `simproc`, or `dsimproc` | return `.continue` when inapplicable |
| Reusable goal-directed search | a scoped Aesop rule set | classify rules by semantic safety |
| Custom input elaboration or goal mutation | tactic elaborator | define state, failure, and goal-list contracts |
| Repeated low-level operation | typed `MetaM` helper | test it independently of parser syntax |

Use ordinary lemmas before meta code. Recent Mathlib guidance treats simprocs as small steps in
a larger simplification algorithm, not as general-purpose automation. Prefer `Qq` typed
quotations for expression matching and proof construction when practical: raw `Expr` APIs allow
ill-typed proof terms to exist until a later check.

## Define the tactic contract

Before implementation, write down four observable outcomes:

1. **Applicable and successful:** which goals are closed or replaced, and in what order?
2. **Inapplicable:** is this an expected rule miss or a user-facing tactic error?
3. **Malformed input:** which syntax range receives which diagnostic?
4. **Resource exhaustion or invariant failure:** which error escapes, and what trace identifies
   the last completed phase?

An Aesop rule or simproc should normally fail softly when its pattern does not match. A tactic the
user invoked directly should fail loudly when the target has the wrong shape. Never convert an
internal invariant violation into a successful no-op.

Define success from the resulting goals, not from the helper's return value. A finishing tactic
must leave no owned subgoals; a normalizer may leave one demonstrably changed goal. Tactics such as
`simp` can return successfully after changing but not closing a goal, so wrap them in a terminal
combinator when “finish” is part of the interface.

Preserve goals the tactic does not own. Use `liftMetaTactic` or `replaceMainGoal` for a tactic that
transforms only the main goal; do not rebuild the whole goal list with `setGoals` unless reordering
all goals is part of the documented contract.

## Normalize inputs deliberately

- **Enter the goal context.** Wrap tactic entry points in `withMainContext`, and run lower-level
  goal operations inside `goal.withContext`. Operations such as `inferType` and `isDefEq` need the
  correct local context; otherwise dependent local hypotheses become unknown free variables.
- **Do not pattern-match a stale expression.** Use `instantiateMVars` before structural matching
  when assigned metavariables may remain in the expression. Use `cleanupAnnotations` when wrapper
  annotations are irrelevant, or `whnfR` when matching should unfold reducible definitions.
  Choose the weakest normalization that matches the tactic's stated semantics.
- **State the transparency mode.** A tactic that happens to work under an ambient transparency
  setting is not stable. Pass the intended mode to matching, reduction, and unification helpers.
- **Finish elaboration checkpoints.** After elaborating internal terms, use
  `synthesizeSyntheticMVarsNoPostponing` or an appropriate `withSynthesize` boundary. Otherwise a
  tactic can report success with pending coercion, typeclass, tactic, or postponed metavariables.
- **Assign only after a type check.** Raw `MVarId.assign` skips occurs, scope, and type checks. Use
  `assignIfDefeq`, `isDefEq` against the metavariable type, or an elaborator such as
  `elabTermEnsuringType` that performs the check before assignment.
- **Prefer optional destructors over panics.** A shape mismatch is ordinary for a rule. Prefer
  `foo?`, `let some`, and `let_expr ... | return .continue` over `foo!` and unreachable branches
  for inputs controlled by users or other tactics.

## Make speculative state transactional

Unification and definitional equality checks can assign metavariables even when they look like
queries. Treat every speculative branch as a transaction.

- In `MetaM`, raw `try`/`catch` does **not** restore state. Use `observing?` for an optional result,
  `withoutModifyingState` for a read-only probe, or `commitIfNoEx` before a catch-and-fallback path.
- In `TacticM`, exception handling backtracks tactic state. Do not expect the catch branch to see
  intermediate assignments or messages from the failed branch. If a diagnostic needs that state,
  collect it before failing or perform the narrow probe in `MetaM`/`TermElabM` with an explicit
  state contract.
- Keep recovery scopes small. Wrap the one expected-to-fail probe, not the entire tactic. A broad
  catch can misclassify heartbeat exhaustion, recursion limits, or implementation bugs as “rule
  did not apply.”
- Do not assume rollback erases everything. Caches, trace messages, and the global name generator
  are intentionally not fully backtracked. Traces should identify attempts without relying on
  generated names being reused.

## Make failures local and actionable

- **Disable recovery for generated tactic syntax.** If tactic code calls `evalTactic` on syntax it
  generated and expects to be correct, wrap the call in `withoutRecover`. Interactive recovery may
  otherwise log an error, insert `sorry`, and let the outer tactic appear to succeed.
- **Attach errors to the narrowest user syntax.** Use `withRef`/`withRef?` around parsing and
  elaboration of an argument. Use `throwTacticEx` for a goal-specific failure so the diagnostic
  includes the tactic name and current goal.
- **Use `MessageData`, not pre-rendered strings, for Lean expressions.** `m!"{expr}"` delaborates in
  context and remains readable; raw AST formatting usually hides the actual problem.
- **Name the failed phase and expectation.** “Expected a target of the form `P ∧ Q`; got …” is
  repairable. “Tactic failed” is not. Distinguish input validation, normalization, candidate
  selection, proof construction, metavariable synthesis, and final assignment.
- **Do not swallow resource failures.** If Lean cannot reliably distinguish an expected miss from
  a timeout in a broad handler, redesign the probe to return `Option` on ordinary misses and reserve
  exceptions for abnormal failures.

## Bound proof search

Every loop needs a progress argument and a machine-checkable limit. Heartbeats alone are not a
complete guard: a tactic can grow goals dramatically before hitting them, and some low-allocation
loops are poor heartbeat clients.

- Bound iterations, rule applications, recursion depth, generated candidates, and—where growth is
  possible—expression or goal size. Report which bound fired and include counters in the trace.
- Make normalization loops prove progress with a decreasing or non-repeating measure. A rule that
  “succeeds” without changing the normalized state must not restart the loop.
- In Aesop, mark a rule `safe` only if it preserves provability relative to the entire active rule
  set and is non-branching. A convenient rule is not automatically safe. Keep speculative choices
  unsafe so search can backtrack.
- Scope expensive or aggressive rules to named rule sets. Do not put a domain-specific finishing
  tactic in the global default set where it will run on every unrelated goal.
- Give optional fast paths a small local budget. A fail-soft fast path that consumes the ambient
  budget before falling back merely changes a quick failure into a slow one.
- When search can emit a deterministic script (`aesop?`, `simp?`, or a custom suggestion), validate
  the emitted script before replacing the search call. Metavariable dependencies can make apparently
  harmless tactic reorderings change behavior.

## Build tracing in from the start

Register a project-specific trace hierarchy with `registerTraceClass`; use `trace[...]` for leaves
and `withTraceNode` for nested phases. Follow Lean's trace design rules:

- Put the outcome in the collapsed top-level node.
- Emit one child per phase or candidate decision, with rejection reasons only at deeper levels.
- Record the input goal, normalized goal, active options/rule set, candidates tried, counters, and
  final subgoals or proof term. Keep the default view concise.
- Use the caller's syntax ref so messages and trace nodes navigate to the relevant token.
- Add a separate statistics trace for iteration counts, cache hits, goal size, and time. Do not make
  users infer a performance failure from thousands of low-level messages.

Keep `dbg_trace`, broad `pp.all`, and profiler options in local reproductions, not committed proof
files. For proof-construction bugs, inspect what automation produced with `show_term`, `by?`, an
Aesop proof trace, or the tactic's own final-proof trace. This separates “wrong search decision”
from “right decision, malformed proof term.”

## Generate syntax and declarations safely

- Prefer hygienic quotations and antiquotations. Use `unhygienic` only when name capture is the
  explicit interface, and cover that behavior with tests.
- Preserve source locations with quotations, `withRef`, `mkIdentFrom`, or `mkIdentFromRef`.
  Synthetic syntax whose ref spans a whole command produces unusable diagnostics and hover data.
- Treat names as structured data. `` `foo ++ `bar `` is the dotted name `foo.bar`, not `foo_bar`.
  Build atomic generated names with `Name.mkSimple` on an explicitly constructed string.
- Macro-generate repetitive lemma families, but verify the migration mechanically. For every old
  statement, compile an `example` proving that exact statement with the generated declaration under
  the calling convention downstream code uses. Also assert the expected declarations exist by name.

## Structure tactic code for change

- Separate parsing, normalization, search, proof construction, and goal mutation. Pure or narrowly
  stateful helpers are easier to test than one elaborator that performs every phase.
- Extract shared cores from near-duplicate tactic families. Two ladders differing only in “recurse”
  versus “return” will drift when only one receives a new fast path or guard.
- When two canonical variants are plausible, build the full proof suite both ways and record the
  result near the decision: which input failed, which invariant differed, and the measured cost.
- An identity function at deliberate call sites may be a reserved normalization hook. Before
  deleting it, decide whether the call sites mark a stable phase boundary; if so, document the
  intended future invariant rather than leaving an unexplained no-op.
- Verify dependency trigger conditions from source. “Runs only on failure” versus “runs on every
  call” changes an optimization from free to pay-per-call.

## Test the failure surface

Test behavior, not private helper order. Every expected failure path needs a test that demonstrates
both the diagnostic and the absence of state leakage.

| Case | Assertion |
|------|-----------|
| Dependent local context | local variables remain in scope and generated terms type-check |
| Wrong target or malformed syntax | direct tactic fails at the relevant token with an actionable message |
| Rule or simproc miss | reports “not applicable” to its caller and leaves expression/state unchanged |
| Assigned metavariables, annotations, abbreviations | matching behavior follows the documented normalization |
| Multiple active goals | only owned goals change; remaining goal order is preserved |
| Pending synthetic metavariables | tactic completes synthesis or fails before reporting success |
| Non-terminal helper success | a finisher backtracks or fails if owned subgoals remain |
| Speculative branch mutates then fails | fallback observes the original metavariable and goal state |
| Looping or goal-growing rule | explicit bound fires and trace reports the responsible rule and counters |
| Generated proof or declaration family | exact old statements compile; negative fixtures are rejected |
| Trace disabled/enabled | default output stays quiet; trace identifies the failed phase and source ref |

Use `fail_if_success`, `guard_target`, `#check_failure`, and `#guard_msgs` where appropriate. Include
at least one known-trigger fixture: a checker or rule suite that is only tested on clean inputs can
silently match zero items forever.

## Review checklist

- [ ] The extension point is no more powerful than the job requires.
- [ ] Applicable, inapplicable, malformed, and exhausted outcomes are distinct.
- [ ] Local context, normalization, transparency, and synthesis boundaries are explicit.
- [ ] Every metavariable assignment is type-checked.
- [ ] Every speculative mutation has rollback semantics and a narrow recovery scope.
- [ ] Generated `evalTactic` syntax runs under `withoutRecover`.
- [ ] Errors carry a source ref, tactic name, goal, phase, and expected shape.
- [ ] Search has progress checks, explicit bounds, and scoped rules.
- [ ] Opt-in traces show outcomes, decisions, counters, and final proof/subgoals.
- [ ] Negative, state-leakage, multiple-goal, and pathological-growth tests exist.

## Research sources

Community articles and guides:

- Yaël Dillies and Paul Lezeau,
  [Fantastic Simprocs and How to Write Them](https://leanprover-community.github.io/blog/posts/simprocs-tutorial/)
- Yaël Dillies and Paul Lezeau,
  [Simp, made simple](https://leanprover-community.github.io/blog/posts/simp-made-simple/)
- Mathlib community,
  [Metaprogramming gotchas](https://github.com/leanprover-community/mathlib4/wiki/Metaprogramming-gotchas)
- Lean community,
  [Metaprogramming in Lean 4: `MetaM`](https://leanprover-community.github.io/lean4-metaprogramming-book/main/04_metam.html)
  and [Tactics](https://leanprover-community.github.io/lean4-metaprogramming-book/main/09_tactics.html)
- Lean API documentation,
  [trace messages and trace-class design](https://leanprover-community.github.io/mathlib4_docs/Lean/Util/Trace.html)

Forum discussions:

- Kyle Miller on
  [`withoutRecover` for generated `evalTactic` code](https://leanprover-community.github.io/archive/stream/217875-Is-there-code-for-X%3F/topic/pretty.20print.20of.20Nat.html)
- Eric Wieser and Kyle Miller on
  [broad exception handling in tactics](https://leanprover-community.github.io/archive/stream/287929-mathlib4/topic/bug.20in.20convert.html)
- Jannis Limperg and Sebastian Ullrich on
  [diagnosing unbounded Aesop goal growth](https://leanprover-community.github.io/archive/stream/270676-lean4/topic/aesop.20gets.20stuck.html)
- Jannis Limperg on
  [Aesop's safe-rule and debugging semantics](https://leanprover-community.github.io/archive/stream/270676-lean4/topic/Aesop.20dev.20updates.html)

Papers by Lean tactic and metaprogramming developers:

- Jannis Limperg and Asta Halkjær From,
  [Aesop: White-Box Best-First Proof Search for Lean](https://people.compute.dtu.dk/ahfrom/aesop-camera-ready.pdf)
- Jannis Limperg,
  [Tactic Script Optimisation for Aesop](https://doi.org/10.1145/3703595.3705877)
- Sebastian Ullrich and Leonardo de Moura,
  [Beyond Notations: Hygienic Macro Expansion for Theorem Proving Languages](https://arxiv.org/abs/2001.10490)
- Gabriel Ebner, Sebastian Ullrich, Jared Roesch, Jeremy Avigad, and Leonardo de Moura,
  [A Metaprogramming Framework for Formal Verification](https://lean-lang.org/papers/tactic.pdf)
