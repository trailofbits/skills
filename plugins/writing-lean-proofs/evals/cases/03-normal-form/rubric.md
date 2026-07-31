# Rubric: 03 normal form

The reviewed file encodes VM comparisons as field elements. The planted
flaw: statements and hypotheses are written with `>` where Mathlib's
simp-normal form is `<` (`gt_iff_lt` even appears inside one proof to paper
over it). The file also contains correct unsqueezed terminal `simp` calls
that folk advice says to squeeze.

A `must-flag` criterion passes only if the review (a) names the specific
declaration or line, (b) explains why it is a problem, and (c) proposes a
concrete fix. A `must-not-flag` criterion passes if the review does NOT
raise the described non-issue as a problem.

## Criteria

- id: gt-statements
  type: must-flag
  pass-when: The review flags statements/hypotheses written with `>`
    (any of `gtFelt`'s `if a.val > b.val`, `gtFelt_of_gt`,
    `gtFelt_eq_one_iff`, `ltFelt_eq_one_iff`, `hfuel : fuel > 0`,
    `hfuel : fuel > 1`) as non-canonical: Mathlib states in `<`/`≤` form
    because `simp` and lemma search match syntactically. The proposed fix
    restates with `<` (e.g. `b.val < a.val`, `0 < fuel`).

- id: gt-iff-lt-evidence
  type: must-flag
  pass-when: The review points at a concrete cost the `>` spelling already
    incurs in this file — the `simp only [gt_iff_lt] at hfuel` step in
    `cmpLoop_singleton` (or equivalently the `gt_iff_lt`/`decide` juggling
    around `gtFelt`) — as evidence, rather than citing the convention in
    the abstract.

- id: no-flag-terminal-simp
  type: must-not-flag
  pass-when: The review does NOT recommend squeezing the terminal `simp`
    calls (e.g. in `gtFelt_of_gt`, `gtFelt_of_not_gt`,
    `gtFelt_eq_ite_decide`) into `simp only [...]` lists. Terminal `simp`
    stays unsqueezed by convention.

- id: no-invented-rules
  type: must-not-flag
  pass-when: The review does not cite fabricated style rules, in particular
    "one tactic per line is required" or any numeric proof-length
    threshold.
