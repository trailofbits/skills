# Rubric: 04 structural anti-patterns

The reviewed file contains one planted instance of each proof-level
structural anti-pattern. The two simp criteria test direction: the file has
a squeezed *terminal* simp (should be unsqueezed) and a bare *non-terminal*
simp (should be squeezed) — a reviewer parroting "always squeeze" or "never
squeeze" gets exactly one of them wrong.

A `must-flag` criterion passes only if the review (a) names the specific
declaration or line, (b) explains why it is a problem, and (c) proposes a
concrete fix. A `must-not-flag` criterion passes if the review does NOT
raise the described non-issue as a problem.

## Criteria

- id: unscoped-set-options
  type: must-flag
  pass-when: The review flags the file-level `set_option pp.all true`
    (debugging leftover) and/or the file-level unscoped
    `set_option maxHeartbeats 1000000`, and proposes removing them or
    scoping with `in` to the declaration that needs them. Flagging at least
    one of the two passes; flagging both is better.

- id: dishonest-show
  type: must-flag
  pass-when: The review flags the `show a % 2 ^ 32 < 2 ^ 32 ∧ ...` line in
    `u32Pair_mod` as a `show` that changes the goal (it unfolds `U32Pair`),
    and proposes either `change`, or better, an API lemma / constructor-based
    proof that avoids seeing through the definition.

- id: unfocused-goals
  type: must-flag
  pass-when: The review flags the unfocused tactic sequence after
    `constructor` in `u32Pair_mod` (two goals active while `apply`/`norm_num`
    run in sequence) as fragile goal-ordering dependence, and proposes `·`
    focusing blocks (or `<;>`) so each goal is closed in its own block.

- id: squeezed-terminal-simp
  type: must-flag
  pass-when: The review flags the long `simp only [...]` list closing
    `carry_le_one` as a squeezed *terminal* simp call — brittle under
    renames and hiding the relevant lemmas — and proposes a plain terminal
    `simp` (optionally with the couple of lemmas that matter) instead.

- id: bare-nonterminal-simp
  type: must-flag
  pass-when: The review flags the unsqueezed `simp [carry]` in
    `mod_add_carry_mul` as *non-terminal* (tactics follow it), coupling
    the rest of the proof to the ambient simp set, and proposes squeezing
    it to `simp only [...]`.

- id: no-invented-rules
  type: must-not-flag
  pass-when: The review does not cite fabricated style rules, in particular
    "one tactic per line is required" or any numeric proof-length
    threshold.
