# LLM-specific techniques

Techniques with direct evidence for model-written Lean, primarily from
ImProver (Ahuja, Avigad, Tetali, Welleck; ICLR 2025), plus the structural
practices that make proofs extendable by *other* models.

## Verification in the loop, always

Naively prompting a model to write or optimize Lean proofs largely fails
(ImProver: GPT-4o at 26% accuracy on length optimization, 19% on
readability rewriting). The same system with symbolic Lean context,
error-correction against compiler feedback, retrieval, and
verification-gated output scores 100% on the paper's accuracy metric — by
construction: when no rewritten proof verifies, ImProver falls back to the
unchanged input, so the gate guarantees a correct output rather than a
successful rewrite. That is the lesson: the guarantee comes from the gate,
not from better generation. Practical rule: never emit a proof you have not
compiled (`lake build` / `lake env lean file.lean`). Treat compiler errors
as the feedback channel, not as failure.

## Chain-of-States: annotate goal states while drafting

The single most impactful technique in ImProver's ablations: before each
tactic, record the current goal state as a comment — *extracted from Lean's
InfoView or compiler output, never imagined*. Goal states contain
information the tactic script omits (the expression after simplification,
the instantiated types).

```lean
theorem foo (h : a ≤ b) : a + c ≤ b + c := by
  -- ⊢ a + c ≤ b + c
  apply add_le_add_right
  -- ⊢ a ≤ b
  exact h
```

Drafting annotations are scaffolding: keep them while working, then strip
routine ones and keep only those marking non-obvious states (after a big
`simp`, before a witness choice) in the final proof — the same information
belongs in `show` lines where possible, since those are checked by Lean.

## Declarativity: typed `have` skeletons

ImProver operationalizes readable structure as the ratio of explicitly
typed `have` steps to total tactic invocations. Use it as a *signal*, not a
target (it is trivially gameable by stuffing unused `have`s): a proof whose
spine is explicitly-typed `have`/`suffices`/`calc` statements can be read —
and extended, and repaired — statement-by-statement without replaying
tactics. This is the property that lets a *different* model (or human) pick
up the proof later.

## Sorry skeletons are the multi-agent protocol

The spec-driven decomposition described in the library-design reference is
directly an LLM
workflow: one agent (or one pass) states the target, its lemmas, and their
API as compiling `sorry` stubs; independent agents then discharge
individual sorries with no shared context beyond the file. This is exactly
how PFR ran ~20 human contributors in parallel — the proof assistant
verifies each contribution independently, so contributors need not
understand the whole. Rules:

- Every stub must compile before fan-out (`lake build` on the skeleton).
- A filled sorry must not change any statement — statements are frozen
  interface; if a statement is wrong, that is a design change, surfaced
  rather than silently patched.
- Prefer many small stubs over few large ones: the granularity criterion is
  "one agent can discharge one stub without global context".

## Name-guessing over search

Because Mathlib names are computable from statements (see the
naming-conventions reference), the fastest way to find a
lemma is often to guess
the name (`add_le_add_left`, `Finset.sum_comm`) and check with
`exact?`/`apply?` or a direct reference. When a guessed name fails,
`exact?` and `rw?` are the sanctioned search tactics — use them in
drafting, but replace their output with the named lemma in the final proof
(their suggestions are already explicit lemma applications).

## Automation tactics: draft freely, finalize deliberately

`omega`, `decide`, `norm_num`, `ring`, `positivity`, `gcongr` are the right
tool for goals genuinely in their fragment — using them there is not an
anti-pattern, and golfing trivial results is accepted review policy. The
failure mode to avoid is using heavyweight closers (`nlinarith`,
`polyrith`, `aesop` with wide search, `decide` on large instances) to skip
*structuring* a nontrivial argument: the proof becomes a black box that
breaks opaquely and slowly. If a closer needs hand-fed auxiliary terms to
succeed, that is the signal the argument has structure worth writing out.
