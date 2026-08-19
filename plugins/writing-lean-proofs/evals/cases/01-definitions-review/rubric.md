# Rubric: 01 definitions review

The reviewed file defines field elements over the Goldilocks prime. It
contains four planted flaws and two pieces of correct code that naive
reviewers commonly flag by mistake.

A `must-flag` criterion passes only if the review (a) names the specific
declaration or line, (b) explains why it is a problem, and (c) proposes a
concrete fix. A generic mention without location or without a fix does not
pass. A `must-not-flag` criterion passes if the review does NOT raise the
described non-issue as a problem (mentioning it approvingly is fine).

## Criteria

- id: global-fact
  type: must-flag
  pass-when: The review flags the top-level `instance : Fact (Nat.Prime GOLDILOCKS_PRIME)`
    as a global `Fact` instance that should be local/scoped (e.g. declared
    where needed, or via `scoped instance`/`haveI`), because a global `Fact`
    instance is considered by every typeclass search.

- id: dual-spelling
  type: must-flag
  pass-when: The review flags the coexistence of `Felt.IsU32 : Prop` and
    `Felt.isU32 : Bool` as two spellings of the same concept with no single
    canonical (simp-normal) form, and recommends picking one spelling and
    stating the API against it. Pointing at the recurring
    `decide_eq_true_eq` conversion boilerplate in the proofs counts as
    supporting evidence but is not required.

- id: native-decide
  type: must-flag
  pass-when: The review flags the `by native_decide` proof in the `Fact`
    instance as widening the trust base (it trusts the compiler and
    runtime via the `Lean.ofReduceBool` axiom, and Mathlib disallows it),
    and proposes an alternative or at least an explicit, documented
    decision to accept the axiom.

- id: wrong-doc-comment
  type: must-flag
  pass-when: The review flags the doc comment on `Felt.IsU32` ("The canonical
    natural number representative of a field element") as incorrect for the
    definition it documents (it describes `val`, not the u32 predicate).

- id: no-flag-scoped-heartbeats
  type: must-not-flag
  pass-when: The review does NOT claim that `set_option maxHeartbeats 800000 in`
    violates the no-set_option rule or must be removed. The option is scoped
    to a single declaration with `in`, which is the accepted form. (Flagging
    the global `Fact` instance on the next line is expected and does not
    fail this criterion; questioning the magnitude of the value without
    calling the scoped form a violation also passes.)

- id: no-flag-junk-value
  type: must-not-flag
  pass-when: The review does NOT flag `Felt.toU32` (total via `% 2 ^ 32`
    truncation) as wrong for being defined on all inputs, e.g. by demanding
    an `Option` return type, a subtype, or a validity hypothesis on the
    definition. Junk-value totalization is the intended design.

- id: no-invented-rules
  type: must-not-flag
  pass-when: The review does not cite fabricated style rules, in particular
    "one tactic per line is required", any numeric proof-length threshold
    ("proofs over N lines must be split"), or a claim that terminal `simp`
    calls must be squeezed to `simp only`.
