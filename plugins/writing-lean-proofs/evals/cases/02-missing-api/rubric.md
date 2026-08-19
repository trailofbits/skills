# Rubric: 02 missing API

The reviewed file proves bound lemmas about the Goldilocks prime. The
planted flaw: `u32_lt_prime` provides exactly the API needed for several
later proofs, yet those proofs bypass it and re-derive the fact inline via
`unfold GOLDILOCKS_PRIME`. The file also contains correct `:= rfl` API
lemmas that naive reviewers flag by mistake.

A `must-flag` criterion passes only if the review (a) names the specific
declaration or line, (b) explains why it is a problem, and (c) proposes a
concrete fix. A `must-not-flag` criterion passes if the review does NOT
raise the described non-issue as a problem.

## Criteria

- id: unfold-instead-of-api
  type: must-flag
  pass-when: The review flags the repeated `unfold GOLDILOCKS_PRIME` in
    downstream proofs (`u32_mod_lt_prime`, `sum_div_lt_prime`,
    `pow2_lt_prime`, and/or `u32_prod_div_lt_prime` — naming at least two)
    as coupling proofs to the definition's numeral instead of going through
    bound lemmas, and proposes routing them through existing or new API
    (e.g. `u32_lt_prime`, a `2 ^ 32 < GOLDILOCKS_PRIME`-style lemma).

- id: notices-existing-lemma
  type: must-flag
  pass-when: The review observes that suitable API already exists or nearly
    exists — `u32_lt_prime` (and `felt_val_lt_prime`) — i.e. it does not
    merely say "add a lemma" but connects the unfolds to the lemma sitting
    a few lines above them (e.g. `u32_mod_lt_prime` follows from
    `u32_lt_prime` plus `Nat.mod_lt`).

- id: no-flag-rfl-api
  type: must-not-flag
  pass-when: The review does NOT flag the `@[simp] ... := rfl` projection
    lemmas for `State.withStack` as a smell, redundant, or in need of
    change. These lemmas ARE the definition's API layer, stated in the same
    file as the definition, which is the recommended structure.

- id: no-invented-rules
  type: must-not-flag
  pass-when: The review does not cite fabricated style rules, in particular
    "one tactic per line is required", any numeric proof-length threshold,
    or a claim that terminal `simp` calls must be squeezed to `simp only`.
