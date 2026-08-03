---
type: llm
focus: last_message
weight: 1
---
This bug is not a taint-flow bug. There is no untrusted value flowing into a dangerous
sink; the defect is that a property checked at one moment is relied upon at a later moment,
and nothing holds it true in between.

Pass if the response's characterization of the root cause is about that separation — the
gap between check and use, the fact that the checked state can change, the absence of
atomicity, or the invariant that the path identity must not change between check and use.
Any wording is fine.

Fail if the response instead frames the root cause purely as untrusted or user-controlled
data reaching a dangerous operation, in the shape of an injection or taint finding, without
ever identifying the check-then-use separation as the actual defect.

Judge only the characterization of *why the code is wrong*. Whether the response found the
right variants is graded separately — do not consider that here. Mentioning that the
staging directory is attacker-writable is fine and expected; that is a precondition for
exploitation, and stating it alongside the separation still passes. Stating it *instead of*
the separation does not.
