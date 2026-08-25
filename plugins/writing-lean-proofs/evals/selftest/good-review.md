I reviewed Felt.lean. The definitions are mostly sound, but there are four
issues worth fixing, ordered by importance.

1. **Global `Fact` instance (line 19).** `instance : Fact (Nat.Prime
   GOLDILOCKS_PRIME)` is declared at top level, so every typeclass search
   in every downstream file now considers it. `Fact` instances should be
   local: keep the statement as a lemma (`theorem goldilocks_prime :
   Nat.Prime GOLDILOCKS_PRIME`) and materialize it where needed with
   `haveI := Fact.mk goldilocks_prime`, or declare it `scoped instance` in
   a namespace users opt into.

2. **`native_decide` in that same instance.** The primality proof `⟨by
   native_decide⟩` widens the trust base from the Lean kernel to the whole
   compiler and runtime (it relies on the `Lean.ofReduceBool` axiom), and
   Mathlib disallows it. Prefer a kernel-checked route — a
   certificate-based `norm_num` primality proof — or, if compile time
   forces `native_decide`, document the accepted axiom next to the
   instance so `#print axioms` surprises no one.

3. **Two spellings of the same concept.** `Felt.IsU32 : Prop` (line 22)
   and `Felt.isU32 : Bool` (line 25) both express "fits in 32 bits", and
   the API lemmas below (`Felt.zero_isU32`, `Felt.isU32_of_IsU32`) target
   the Bool form as `_.isU32 = true`, forcing every proof through
   `decide_eq_true_eq` conversion boilerplate. Pick one canonical
   spelling — the `Prop` form is the Mathlib-idiomatic choice, with a
   `[Decidable]` instance for the executable check — and state all API
   lemmas against it, deleting the other.

4. **Copy-pasted doc comment on `Felt.IsU32` (line 21).** "The canonical
   natural number representative of a field element" describes `ZMod.val`,
   not this predicate. Replace it with something like "Whether a felt fits
   in 32 bits."

Things I checked that are fine as they are: the `set_option maxHeartbeats
800000 in` is scoped to the single instance with `in`, which is the
accepted form for an expensive one-off proof; and `Felt.toU32` totalizing
via `% 2 ^ 32` is the junk-value pattern Mathlib favors — do not change it
to `Option Nat` or add a validity hypothesis to the definition.
