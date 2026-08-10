# Elaboration and reduction cost

Slow proofs and heartbeat timeouts are measurement problems before they are
optimization problems: most reported "regressions" dissolve under the right
probe, and most real ones live in the *shape of a definition*, not in the
tactic script. Evidence here is from a reflection-heavy program-verification
project; the mechanisms are general.

## Measure per-declaration cost, nothing else

- Use `#count_heartbeats in <decl>` (or time an isolated goal) with
  dependencies prebuilt. Build wall-clock misleads twice over: it mixes in
  parallelism and dependency rebuilds, and `lake`'s per-module figure is
  *cumulative* wall-clock, not that module's cost. One "regression" was
  reported as 500–1000×, then 2×, and finally measured at **+1 heartbeat**.
- **Treat every existing `set_option maxHeartbeats` as an unproven claim.**
  Measure by bisection before believing it: budgets get copy-pasted between
  declarations until they carry no information about which proof is actually
  expensive (one file held 82 identical per-lemma overrides; a
  "6.4M-heartbeat monolith" ran at the default budget once restructured).
  Keep overrides scoped per declaration (`set_option maxHeartbeats N in`) and
  only where measured; an unscoped file-level budget hands every later
  declaration in the file an allowance nobody measured for it.
- **Match the probe to what the consumer forces.** `whnf` is lazy: it stops
  at the head constructor, so a pathological definition and its fix can both
  probe at ~3 ms while the tactic's actual `Meta.reduce` costs 3000 ms vs
  5 ms. A lazy probe produces false "unreproducible" verdicts.
- **When a bottleneck resists diagnosis, build a payload-free control**: the
  emptiest input that still exhibits the cost. A body of pure `nop`s costing
  the same as the real body excludes every payload-level hypothesis at once.
  Cost that scales with the *number of steps* rather than the payload points
  at the fold or accumulator, not at the instructions.

## Where reduction cost actually comes from

- **When a goal is closed by `Eq.refl`/`rfl`/`decide`, the kernel replays the
  whole reduction.** Making the *tactic* reduce more cleverly buys nothing;
  only restructuring the proof term or the definition being reduced helps.
  Check which of the two you are optimizing before spending effort.
- **Count reduction paths, not term size.** Cost tracks how many times a
  definition's body mentions its recursive argument: those occurrences
  compose *multiplicatively* along a fold (~kⁿ distinct paths the evaluator
  cache cannot share), while the result term itself stays linear (sharing
  works — for the term). A case built from `List.set`/`eraseIdx`/index
  lookups that mentions the stack 9 times can be 150× the cost of an
  equivalent that destructures once with explicit patterns and rebuilds.
  Diagnose by counting occurrences per case; fix by pattern-matching instead
  of indexing-and-rebuilding.
- **A left-nested `++` on a fold accumulator is exponential** — even when
  everything appended is empty, because each step forces the whole
  accumulated list. Accumulate by reverse-prepending and reverse once at the
  end.
- **Unreduced intermediate terms compound.** Feeding one step's output to the
  next as an unreduced wrapper nests a level per step (~1.8× growth per
  iteration measured). Normalize between steps.
- **Know your kernel-reduction size ceiling.** Closing goals by reflection
  has a steep cost curve (measured: ~11 ms at 6 interpreted instructions,
  ~1.7 s at 28, unbounded past ~44). Past the knee no lemma work helps —
  decompose the goal into smaller units. Measure the curve before blaming
  your lemma set.

## Optimize the definition, keep the semantics

When a definition on the trusted path is too expensive to reduce, do not
rewrite it in place. Keep the readable definition as the reference semantics
and add the fast form beside it with an equality theorem:

```lean
/-- Reference semantics: the readable, obviously-correct form. -/
def execOps (ops : List Op) (s : State) : Option State := ...

/-- Reduction-friendly form (reverse-prepending accumulator). -/
def execOps' (ops : List Op) (s : State) : Option State := ...

theorem execOps'_eq_execOps : execOps' = execOps := ...
```

The equivalence covers every input, including degenerate and failure cases,
so the optimization cannot silently change meaning — and downstream proofs
keep folding over the original, swapping an `unfold` for one `rw`. That is
far cheaper than re-proving a soundness stack against a new shape, and the
intended meaning stays legible. (This is the library-design "statements are
the interface" rule applied to definitions under optimization.)

## Working habits that keep cost visible

- Land performance changes **independently** of functional ones; when a
  bundled pair regresses, the two are indistinguishable and both get
  reverted.
- A changed failure mode is progress: "goal is not an equation" → `whnf`
  timeout → `unsolved goals` is three distinct blockers stacked behind one
  symptom, each fix confirmed by the *category* of the next failure. Decide
  up front what partial success looks like.
- A well-evidenced negative result — "this construct is past the reduction
  ceiling, decompose instead" — is a deliverable that redirects effort;
  record it where the next person will look.
